use thiserror::Error;

#[derive(Error, Debug)]
pub enum DerpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("httparse: {0}")]
    HttpParse(String),

    #[error("upgrade: {0}")]
    Upgrade(String),

    #[error("bad magic: expected DERP-prefix, got first 8 bytes = {first8:02x?}")]
    BadMagic { first8: [u8; 8] },

    #[error("bad frame type: 0x{byte:02x}")]
    BadFrameType { byte: u8 },

    #[error("frame too large: {len} bytes (cap {cap})")]
    FrameTooLarge { len: usize, cap: usize },

    #[error("frame too short: {ty:?} payload {len} bytes (need {need})")]
    FrameTooShort {
        ty: &'static str,
        len: usize,
        need: usize,
    },

    #[error("nacl box: {0}")]
    NaclBox(String),

    #[error("json: {0}")]
    Json(String),

    #[error("server info version {server_version} != expected {expected}")]
    UnsupportedServerVersion { server_version: u32, expected: u32 },

    #[error("no reachable DERP region (probed {probed} of {total})")]
    NoReachableRegion { probed: usize, total: usize },

    #[error("region {region} not in DERP map")]
    UnknownRegion { region: u16 },

    #[error("derp map not yet set on transport")]
    DerpMapNotSet,

    #[error("conn cap exceeded ({cap}); refusing to evict home region {home}")]
    CapExceededHome { cap: usize, home: u16 },

    #[error("conn died: {0}")]
    ConnDied(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl From<httparse::Error> for DerpError {
    fn from(e: httparse::Error) -> Self {
        DerpError::HttpParse(e.to_string())
    }
}

impl From<rustls::Error> for DerpError {
    fn from(e: rustls::Error) -> Self {
        DerpError::Tls(e.to_string())
    }
}

impl From<serde_json::Error> for DerpError {
    fn from(e: serde_json::Error) -> Self {
        DerpError::Json(e.to_string())
    }
}
