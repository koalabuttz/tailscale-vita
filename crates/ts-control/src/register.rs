//! POST `/machine/register` through the open Noise+HTTP/2 tunnel.
//!
//! Wire shape: minimal RegisterRequest carrying just NodeKey, NLKey,
//! Auth, and a stripped-down Hostinfo (Hostname + App + IPNVersion).
//! The "full Go-canonical" RegisterRequest body — with Timestamp,
//! NetInfo, OS, OSVersion, and BackendLogID populated — empirically
//! breaks the DiscoKey-commit path on real Tailscale's coord server
//! (verified by bisection in the M14M Phase 11 debugging session).

use http::Method;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::http2::Http2Conn;
use crate::types::{NLPublic, NodePublic};
use crate::ControlError;

const IPN_VERSION: &str = "tailscale-vita/0.1.0";
const APP_NAME: &str = "tailscale-vita/0.1.0";
const HOSTINFO_OS: &str = "linux";
const HOSTINFO_OS_VERSION: &str = "vita-3.74";
const REGISTER_VERSION: u32 = crate::CAPVER as u32;

pub struct RegistrationOutcome {
    pub machine_authorized: bool,
    pub node_key_expired: bool,
}

pub fn register(
    conn: &mut Http2Conn,
    auth_key: &str,
    node_pub: &NodePublic,
    nl_pub: &NLPublic,
    backend_log_id: &str,
    hostname: &str,
    host_authority: &str,
) -> Result<RegistrationOutcome, ControlError> {
    let req = RegisterRequestWire {
        version: REGISTER_VERSION,
        node_key: node_pub.to_nodekey_string(),
        nl_key: nl_pub.to_nlkey_string(),
        auth: RegisterAuthWire {
            auth_key: auth_key.to_string(),
        },
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
    #[serde(rename = "NLKey")]
    nl_key: String,
    #[serde(rename = "Auth")]
    auth: RegisterAuthWire,
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

    #[test]
    fn request_serializes_with_expected_fields() {
        let node_pub = NodePublic([0x11u8; 32]);
        let nl_pub = NLPublic([0x33u8; 32]);
        let req = RegisterRequestWire {
            version: 90,
            node_key: node_pub.to_nodekey_string(),
            nl_key: nl_pub.to_nlkey_string(),
            auth: RegisterAuthWire {
                auth_key: "abcd1234".into(),
            },
            hostinfo: HostinfoWire {
                hostname: "vita".into(),
                app: "tailscale-vita/0.1.0".into(),
                ipn_version: "tailscale-vita/0.1.0".into(),
                os: "linux".into(),
                os_version: "vita-3.74".into(),
                backend_log_id: "test-blog-id".into(),
            },
            timestamp: "2026-05-04T00:00:00Z".into(),
            ephemeral: true,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["Version"], 90);
        assert!(v["NodeKey"].as_str().unwrap().starts_with("nodekey:"));
        assert_eq!(v["Auth"]["AuthKey"], "abcd1234");
        assert_eq!(v["Hostinfo"]["Hostname"], "vita");
        assert_eq!(v["Hostinfo"]["IPNVersion"], "tailscale-vita/0.1.0");
        assert_eq!(v["Hostinfo"]["App"], "tailscale-vita/0.1.0");
        assert!(v["NLKey"].as_str().unwrap().starts_with("nlpub:"));
        assert!(v.get("Timestamp").is_none());
        assert!(v["Hostinfo"].get("BackendLogID").is_none());
        assert!(v["Hostinfo"].get("OS").is_none());
        assert!(v["Hostinfo"].get("NetInfo").is_none());
    }

    #[test]
    fn response_parses_minimal_authorized() {
        let body = br#"{"MachineAuthorized":true,"AuthURL":"","Error":""}"#;
        let parsed: RegisterResponseWire = serde_json::from_slice(body).unwrap();
        assert!(parsed.machine_authorized);
        assert!(parsed.auth_url.is_empty());
    }
}
