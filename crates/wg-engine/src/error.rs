use thiserror::Error;

#[derive(Error, Debug)]
pub enum WgError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("unknown peer pubkey")]
    UnknownPeer,
    #[error("packet too short ({0} B)")]
    ShortPacket(usize),
    #[error("non-ipv4 packet (version byte {0:#x})")]
    NonIpv4(u8),
    #[error("tunn panic caught: {0}")]
    TunnPanic(String),
    #[error("transport closed")]
    TransportClosed,
    #[error("base64 decode {field}: {reason}")]
    Base64 { field: &'static str, reason: String },
    #[error("invalid socket address: {0}")]
    BadSocketAddr(String),
    #[error("invalid CIDR: {0}")]
    BadCidr(String),
    #[error("expected exactly one peer, got {0}")]
    BadPeerCount(usize),
}
