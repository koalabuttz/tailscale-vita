//! POST `/machine/register` through the open Noise+HTTP/2 tunnel.
//!
//! Wire shape we send: Version, NodeKey, NLKey, Auth, Timestamp,
//! Ephemeral, and a Hostinfo of Hostname + App + IPNVersion +
//! BackendLogID. Deliberately omitted: Hostinfo.OS / OSVersion (sent
//! empty, so `skip_serializing_if` drops them) and NetInfo (not a
//! field of this request at all).
//!
//! History: setting `OS` to a concrete value (e.g. "linux") or
//! attaching NetInfo to the *RegisterRequest* empirically broke the
//! DiscoKey-commit path on real Tailscale's coord server (M14M Phase 11
//! bisection). Timestamp and BackendLogID were initially suspected too,
//! but the real DiscoKey-zero fix turned out to be the separate NetInfo
//! "lite" MapRequest (M12) — so Timestamp + BackendLogID are safe and
//! are kept.

use http::Method;
use serde::{Deserialize, Serialize};
use vita_log::{info, warn};

use crate::http2::Http2Conn;
use crate::types::{NLPublic, NodePublic};
use crate::ControlError;

const IPN_VERSION: &str = "tailscale-vita/0.1.0";
const APP_NAME: &str = "tailscale-vita/0.1.0";
const HOSTINFO_OS: &str = "linux";
const HOSTINFO_OS_VERSION: &str = "vita-3.74";
const REGISTER_VERSION: u32 = crate::CAPVER as u32;

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub machine_authorized: bool,
    pub node_key_expired: bool,
    /// Set (Ok, not Err) on the interactive login path: the server replied
    /// with a non-empty AuthURL and `MachineAuthorized=false` and NO auth
    /// key was supplied. The caller shows this URL (as a QR) and re-POSTs
    /// with `followup = Some(url)` to long-poll until the user approves.
    /// `None` on the authorized (or genuinely-rejected) paths.
    pub pending_auth_url: Option<String>,
}

pub fn register(
    conn: &mut Http2Conn,
    auth_key: &str,
    node_pub: &NodePublic,
    nl_pub: &NLPublic,
    backend_log_id: &str,
    hostname: &str,
    host_authority: &str,
    followup: Option<&str>,
) -> Result<RegistrationOutcome, ControlError> {
    let req = RegisterRequestWire {
        version: REGISTER_VERSION,
        node_key: node_pub.to_nodekey_string(),
        nl_key: nl_pub.to_nlkey_string(),
        // Empty auth key => omit the whole Auth struct: that is the trigger
        // for the server's interactive (QR) login flow.
        auth: auth_field(auth_key),
        // Present only during the interactive wait-loop: re-POSTing with
        // Followup=<AuthURL> makes the server long-poll until approval.
        followup: followup.map(str::to_string),
        hostinfo: HostinfoWire {
            hostname: hostname.to_string(),
            app: APP_NAME.to_string(),
            ipn_version: IPN_VERSION.to_string(),
            // OS / OSVersion deliberately NOT sent. Setting OS="linux"
            // (or apparently any value) on RegisterRequest empirically
            // breaks the DiscoKey-commit path on real Tailscale's coord
            // server (M14M Phase 11 bisection: register body without OS
            // → DiscoKey commits, with OS → DiscoKey stays zero).
            // Suspected cause: Tailscale's enum routes Linux clients
            // through stricter Go-client validation that we don't
            // satisfy. Leaving the fields empty puts us in the
            // "unspecified-OS" path that does commit DiscoKey.
            os: String::new(),
            os_version: String::new(),
            backend_log_id: backend_log_id.to_string(),
        },
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| ControlError::Transport(format!("rfc3339 format: {e}")))?,
        ephemeral: true,
    };

    let body = serde_json::to_vec(&req)?;
    let lb = node_pub.to_nodekey_string();
    info!(node_key = %lb, hostname, body_len = body.len(), "control.register.sent");

    let resp = conn.request(
        Method::POST,
        "/machine/register",
        &body,
        &[
            ("content-type", "application/json"),
            ("ts-lb", &lb),
        ],
        host_authority,
    )?;

    if resp.status != 200 {
        let body_str = String::from_utf8_lossy(&resp.body).into_owned();
        warn!(status = resp.status, body = %body_str, "control.register.fail.http");
        return Err(ControlError::Http {
            status: resp.status,
            body: body_str,
        });
    }

    let parsed: RegisterResponseWire = serde_json::from_slice(&resp.body)?;
    // `!auth_key.is_empty()` tells the interpreter whether a key was
    // supplied: a non-empty AuthURL is a hard rejection when it was, but the
    // expected interactive-login prompt when it was not.
    interpret_register_response(parsed, !auth_key.is_empty())
}

/// Build the optional `Auth` object. An empty auth key omits it entirely,
/// which is what triggers the server's interactive (QR) login flow.
fn auth_field(auth_key: &str) -> Option<RegisterAuthWire> {
    if auth_key.is_empty() {
        None
    } else {
        Some(RegisterAuthWire {
            auth_key: auth_key.to_string(),
        })
    }
}

/// Map a parsed `RegisterResponse` to a `RegistrationOutcome`. Split out of
/// `register()` so it is unit-testable without a live Noise/HTTP2 tunnel.
///
/// `auth_key_supplied` distinguishes the two AuthURL cases:
/// - key supplied + AuthURL back  => genuine `AuthRejected` (hard error),
/// - no key + AuthURL back         => interactive login, surfaced as
///   `pending_auth_url` on an `Ok` outcome (NOT fatal).
fn interpret_register_response(
    parsed: RegisterResponseWire,
    auth_key_supplied: bool,
) -> Result<RegistrationOutcome, ControlError> {
    if !parsed.error.is_empty() {
        warn!(server_error = %parsed.error, "control.register.fail.server");
        return Err(ControlError::Transport(format!(
            "register: server Error={}",
            parsed.error
        )));
    }

    if !parsed.auth_url.is_empty() && !parsed.machine_authorized {
        if auth_key_supplied {
            warn!(auth_url = %parsed.auth_url, "control.register.fail.auth_url");
            return Err(ControlError::AuthRejected {
                auth_url: parsed.auth_url,
            });
        }
        // Interactive path: not fatal. Bubble the URL up so the runtime can
        // publish it (for the on-screen QR) and then re-POST with Followup.
        info!(auth_url = %parsed.auth_url, "control.register.pending_auth");
        return Ok(RegistrationOutcome {
            machine_authorized: false,
            node_key_expired: parsed.node_key_expired,
            pending_auth_url: Some(parsed.auth_url),
        });
    }

    if !parsed.machine_authorized {
        // Unauthorized with no AuthURL: if the node key expired, surface
        // that as a non-fatal outcome so the interactive-login loop can
        // regenerate the key and retry (rather than losing the signal in
        // a generic transport error).
        if parsed.node_key_expired {
            info!("control.register.node_key_expired (no AuthURL)");
            return Ok(RegistrationOutcome {
                machine_authorized: false,
                node_key_expired: true,
                pending_auth_url: None,
            });
        }
        warn!("control.register.fail.unauthorized");
        return Err(ControlError::Transport(
            "register: MachineAuthorized=false (no AuthURL)".into(),
        ));
    }

    info!(
        machine_authorized = parsed.machine_authorized,
        node_key_expired = parsed.node_key_expired,
        "control.register.ok"
    );

    Ok(RegistrationOutcome {
        machine_authorized: parsed.machine_authorized,
        node_key_expired: parsed.node_key_expired,
        pending_auth_url: None,
    })
}

#[derive(Serialize)]
struct RegisterRequestWire {
    #[serde(rename = "Version")]
    version: u32,
    #[serde(rename = "NodeKey")]
    node_key: String,
    #[serde(rename = "NLKey")]
    nl_key: String,
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    auth: Option<RegisterAuthWire>,
    #[serde(rename = "Followup", skip_serializing_if = "Option::is_none")]
    followup: Option<String>,
    #[serde(rename = "Hostinfo")]
    hostinfo: HostinfoWire,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "Ephemeral", skip_serializing_if = "std::ops::Not::not")]
    ephemeral: bool,
}

#[derive(Serialize)]
struct RegisterAuthWire {
    #[serde(rename = "AuthKey")]
    auth_key: String,
}

#[derive(Serialize)]
struct HostinfoWire {
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "App")]
    app: String,
    #[serde(rename = "IPNVersion")]
    ipn_version: String,
    #[serde(rename = "OS", skip_serializing_if = "String::is_empty")]
    os: String,
    #[serde(rename = "OSVersion", skip_serializing_if = "String::is_empty")]
    os_version: String,
    #[serde(rename = "BackendLogID", skip_serializing_if = "String::is_empty")]
    backend_log_id: String,
}

#[derive(Deserialize, Default)]
struct RegisterResponseWire {
    #[serde(rename = "MachineAuthorized", default)]
    machine_authorized: bool,
    #[serde(rename = "AuthURL", default)]
    auth_url: String,
    #[serde(rename = "NodeKeyExpired", default)]
    node_key_expired: bool,
    #[serde(rename = "Error", default)]
    error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hostinfo() -> HostinfoWire {
        HostinfoWire {
            hostname: "vita".into(),
            app: "tailscale-vita/0.1.0".into(),
            ipn_version: "tailscale-vita/0.1.0".into(),
            os: String::new(),
            os_version: String::new(),
            backend_log_id: "test-blog-id".into(),
        }
    }

    fn sample_request(auth_key: &str, followup: Option<&str>) -> RegisterRequestWire {
        let node_pub = NodePublic([0x11u8; 32]);
        let nl_pub = NLPublic([0x33u8; 32]);
        RegisterRequestWire {
            version: 90,
            node_key: node_pub.to_nodekey_string(),
            nl_key: nl_pub.to_nlkey_string(),
            auth: auth_field(auth_key),
            followup: followup.map(str::to_string),
            hostinfo: sample_hostinfo(),
            timestamp: "2026-05-04T00:00:00Z".into(),
            ephemeral: true,
        }
    }

    #[test]
    fn request_serializes_with_expected_fields() {
        let node_pub = NodePublic([0x11u8; 32]);
        let nl_pub = NLPublic([0x33u8; 32]);
        let req = RegisterRequestWire {
            version: 90,
            node_key: node_pub.to_nodekey_string(),
            nl_key: nl_pub.to_nlkey_string(),
            auth: Some(RegisterAuthWire {
                auth_key: "abcd1234".into(),
            }),
            followup: None,
            hostinfo: HostinfoWire {
                hostname: "vita".into(),
                app: "tailscale-vita/0.1.0".into(),
                ipn_version: "tailscale-vita/0.1.0".into(),
                // OS / OSVersion left empty exactly as `register()` builds
                // them — the skip_serializing_if must then drop them
                // (the DiscoKey-commit workaround; see module docs).
                os: String::new(),
                os_version: String::new(),
                backend_log_id: "test-blog-id".into(),
            },
            timestamp: "2026-05-04T00:00:00Z".into(),
            ephemeral: true,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Version"], 90);
        assert!(v["NodeKey"].as_str().unwrap().starts_with("nodekey:"));
        assert!(v["NLKey"].as_str().unwrap().starts_with("nlpub:"));
        assert_eq!(v["Auth"]["AuthKey"], "abcd1234");
        assert_eq!(v["Hostinfo"]["Hostname"], "vita");
        assert_eq!(v["Hostinfo"]["IPNVersion"], "tailscale-vita/0.1.0");
        assert_eq!(v["Hostinfo"]["App"], "tailscale-vita/0.1.0");
        // Timestamp + BackendLogID ARE sent (kept after M12 showed the
        // real DiscoKey-zero fix was the NetInfo MapRequest, not stripping
        // these). Present in the wire body.
        assert_eq!(v["Timestamp"], "2026-05-04T00:00:00Z");
        assert_eq!(v["Hostinfo"]["BackendLogID"], "test-blog-id");
        // OS / OSVersion empty -> skipped; NetInfo is not part of the request.
        assert!(v["Hostinfo"].get("OS").is_none());
        assert!(v["Hostinfo"].get("OSVersion").is_none());
        assert!(v["Hostinfo"].get("NetInfo").is_none());
        assert_eq!(v["Ephemeral"], true);
    }

    #[test]
    fn response_parses_minimal_authorized() {
        let body = br#"{"MachineAuthorized":true,"AuthURL":"","Error":""}"#;
        let parsed: RegisterResponseWire = serde_json::from_slice(body).unwrap();
        assert!(parsed.machine_authorized);
        assert!(parsed.auth_url.is_empty());
    }

    #[test]
    fn empty_auth_key_omits_auth_object() {
        // Empty key => the whole `Auth` struct is dropped, which is what
        // triggers the server's interactive (QR) login flow.
        let req = sample_request("", None);
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(v.get("Auth").is_none(), "Auth must be omitted for empty key");
        // The rest of the request is still well-formed.
        assert_eq!(v["Version"], 90);
        assert_eq!(v["Hostinfo"]["Hostname"], "vita");
    }

    #[test]
    fn nonempty_auth_key_emits_auth_object() {
        let req = sample_request("tskey-auth-abc123", None);
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Auth"]["AuthKey"], "tskey-auth-abc123");
    }

    #[test]
    fn followup_serializes_when_set_and_omitted_when_none() {
        // Omitted on the first (trigger) request.
        let v_none: serde_json::Value =
            serde_json::to_value(&sample_request("", None)).unwrap();
        assert!(v_none.get("Followup").is_none());

        // Present on the wait-loop re-POST.
        let url = "https://login.tailscale.com/a/deadbeef";
        let v_set: serde_json::Value =
            serde_json::to_value(&sample_request("", Some(url))).unwrap();
        assert_eq!(v_set["Followup"], url);
    }

    #[test]
    fn response_with_auth_url_yields_pending_auth() {
        // No key supplied + non-empty AuthURL + not authorized => interactive
        // login: Ok with pending_auth_url set (NOT an error).
        let parsed = RegisterResponseWire {
            machine_authorized: false,
            auth_url: "https://login.tailscale.com/a/abc123".into(),
            node_key_expired: false,
            error: String::new(),
        };
        let outcome = interpret_register_response(parsed, false).unwrap();
        assert!(!outcome.machine_authorized);
        assert_eq!(
            outcome.pending_auth_url.as_deref(),
            Some("https://login.tailscale.com/a/abc123")
        );
    }

    #[test]
    fn response_with_auth_url_and_supplied_key_is_rejected() {
        // A key WAS supplied but the server still wants interactive auth =>
        // genuine rejection (hard error), not the QR path.
        let parsed = RegisterResponseWire {
            machine_authorized: false,
            auth_url: "https://login.tailscale.com/a/abc123".into(),
            ..Default::default()
        };
        let err = interpret_register_response(parsed, true).unwrap_err();
        assert!(matches!(err, ControlError::AuthRejected { .. }));
    }

    #[test]
    fn authorized_response_has_no_pending_auth() {
        let parsed = RegisterResponseWire {
            machine_authorized: true,
            node_key_expired: false,
            ..Default::default()
        };
        let outcome = interpret_register_response(parsed, false).unwrap();
        assert!(outcome.machine_authorized);
        assert!(outcome.pending_auth_url.is_none());
    }

    #[test]
    fn node_key_expired_without_url_is_non_fatal() {
        // Unauthorized, no AuthURL, but NodeKeyExpired: must surface as a
        // non-fatal Ok so the login loop can regenerate the key + retry,
        // NOT a generic transport error that loses the signal.
        let parsed = RegisterResponseWire {
            machine_authorized: false,
            auth_url: String::new(),
            node_key_expired: true,
            error: String::new(),
        };
        let outcome = interpret_register_response(parsed, false).unwrap();
        assert!(!outcome.machine_authorized);
        assert!(outcome.node_key_expired);
        assert!(outcome.pending_auth_url.is_none());
    }
}
