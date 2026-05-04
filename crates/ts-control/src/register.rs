//! POST `/machine/register` through the open Noise+HTTP/2 tunnel.
//!
//! Wire shapes mirror upstream `tailcfg.RegisterRequest` /
//! `tailcfg.RegisterResponse`. We send a deliberately minimal request:
//! only the fields Headscale 0.26 actually consumes for an auth-key
//! registration (Version, NodeKey, Auth.AuthKey, Hostinfo, Timestamp).
//! All other RegisterRequest fields are omitted; Headscale's
//! `json.Unmarshal` treats missing fields as Go zero values, which is
//! what we want — saving us from having to emit zero-prefixed
//! `nodekey:0…0` and `nlpub:0…0` placeholders.
//!
//! Hostinfo is similarly minimal: `OS="linux"` (Tailscale's enum has no
//! `vita` value — see PLAN-V1.md OQ #7), plus IPNVersion, Hostname,
//! OSVersion. Every other Hostinfo field has `json:",omitzero"` /
//! `omitempty` upstream so absent is fine.

use http::Method;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

use crate::http2::Http2Conn;
use crate::types::NodePublic;
use crate::ControlError;

const IPN_VERSION: &str = "tailscale-vita/0.1.0";
const HOSTINFO_OS: &str = "linux";
const HOSTINFO_OS_VERSION: &str = "vita-3.74";
const REGISTER_VERSION: u32 = 90;

pub struct RegistrationOutcome {
    pub machine_authorized: bool,
    pub node_key_expired: bool,
}

/// Build and send a `RegisterRequest` through `conn`, blocking on the
/// response. Hard-fails on non-200 HTTP, server-side `Error` non-empty,
/// `AuthURL` non-empty (interactive login required, v1 cannot do that),
/// or `MachineAuthorized=false`.
pub fn register(
    conn: &mut Http2Conn,
    auth_key: &str,
    node_pub: &NodePublic,
    hostname: &str,
    host_authority: &str,
) -> Result<RegistrationOutcome, ControlError> {
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| ControlError::Transport(format!("rfc3339 format: {e}")))?;

    let req = RegisterRequestWire {
        version: REGISTER_VERSION,
        node_key: node_pub.to_nodekey_string(),
        auth: RegisterAuthWire {
            auth_key: auth_key.to_string(),
        },
        hostinfo: HostinfoWire {
            ipn_version: IPN_VERSION.to_string(),
            hostname: hostname.to_string(),
            os: HOSTINFO_OS.to_string(),
            os_version: HOSTINFO_OS_VERSION.to_string(),
        },
        timestamp,
    };

    let body = serde_json::to_vec(&req)?;
    info!(
        node_key = %node_pub.to_nodekey_string(),
        hostname,
        body_len = body.len(),
        "control.register.sent"
    );

    let resp = conn.request(
        Method::POST,
        "/machine/register",
        &body,
        &[("content-type", "application/json")],
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

    if !parsed.error.is_empty() {
        warn!(server_error = %parsed.error, "control.register.fail.server");
        return Err(ControlError::Transport(format!(
            "register: server Error={}",
            parsed.error
        )));
    }
    if !parsed.auth_url.is_empty() {
        warn!(auth_url = %parsed.auth_url, "control.register.fail.auth_url");
        return Err(ControlError::AuthRejected {
            auth_url: parsed.auth_url,
        });
    }
    if !parsed.machine_authorized {
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
    })
}

#[derive(Serialize)]
struct RegisterRequestWire {
    #[serde(rename = "Version")]
    version: u32,
    #[serde(rename = "NodeKey")]
    node_key: String,
    #[serde(rename = "Auth")]
    auth: RegisterAuthWire,
    #[serde(rename = "Hostinfo")]
    hostinfo: HostinfoWire,
    #[serde(rename = "Timestamp")]
    timestamp: String,
}

#[derive(Serialize)]
struct RegisterAuthWire {
    #[serde(rename = "AuthKey")]
    auth_key: String,
}

#[derive(Serialize)]
struct HostinfoWire {
    #[serde(rename = "IPNVersion")]
    ipn_version: String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "OS")]
    os: String,
    #[serde(rename = "OSVersion")]
    os_version: String,
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

    #[test]
    fn request_serializes_with_expected_fields() {
        let node_pub = NodePublic([0x11u8; 32]);
        let req = RegisterRequestWire {
            version: 90,
            node_key: node_pub.to_nodekey_string(),
            auth: RegisterAuthWire {
                auth_key: "abcd1234".into(),
            },
            hostinfo: HostinfoWire {
                ipn_version: "tailscale-vita/0.1.0".into(),
                hostname: "vita".into(),
                os: "linux".into(),
                os_version: "vita-3.74".into(),
            },
            timestamp: "2026-05-04T00:00:00Z".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Version"], 90);
        assert!(v["NodeKey"].as_str().unwrap().starts_with("nodekey:"));
        assert_eq!(v["Auth"]["AuthKey"], "abcd1234");
        assert_eq!(v["Hostinfo"]["OS"], "linux");
        assert_eq!(v["Hostinfo"]["IPNVersion"], "tailscale-vita/0.1.0");
        assert_eq!(v["Hostinfo"]["Hostname"], "vita");
        assert_eq!(v["Timestamp"], "2026-05-04T00:00:00Z");
    }

    #[test]
    fn response_parses_minimal_authorized() {
        let body = br#"{"MachineAuthorized":true,"AuthURL":"","Error":""}"#;
        let parsed: RegisterResponseWire = serde_json::from_slice(body).unwrap();
        assert!(parsed.machine_authorized);
        assert!(parsed.auth_url.is_empty());
    }

    #[test]
    fn response_parses_with_user_login_ignored() {
        let body = br#"{
            "User": {"ID": 1, "Name": "vita"},
            "Login": {"NodeID": 1},
            "MachineAuthorized": true,
            "AuthURL": "",
            "NodeKeyExpired": false,
            "Error": ""
        }"#;
        let parsed: RegisterResponseWire = serde_json::from_slice(body).unwrap();
        assert!(parsed.machine_authorized);
    }

    #[test]
    fn response_default_safe_for_omitted_fields() {
        let body = br#"{}"#;
        let parsed: RegisterResponseWire = serde_json::from_slice(body).unwrap();
        assert!(!parsed.machine_authorized);
        assert!(parsed.auth_url.is_empty());
        assert!(parsed.error.is_empty());
    }
}
