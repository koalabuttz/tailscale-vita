use thiserror::Error;

#[derive(Error, Debug)]
pub enum ControlError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: status={status} body={body}")]
    Http { status: u16, body: String },
    #[error("transport: {0}")]
    Transport(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid server key: {reason}")]
    BadServerKey { reason: &'static str },
    #[error("server Noise key changed (security gate; remove server-key.bin to accept)")]
    ServerKeyChanged,
    #[error("url: {0}")]
    Url(&'static str),
    #[error("httparse: {0}")]
    HttpParse(String),
    #[error("auth rejected; AuthURL={auth_url}")]
    AuthRejected { auth_url: String },
    #[error("map watchdog: no frame in {idle_secs}s")]
    MapWatchdog { idle_secs: u64 },
    #[error("map frame too large: {len} bytes (cap {cap})")]
    MapFrameTooLarge { len: usize, cap: usize },
    #[error("map decode: {0}")]
    MapDecode(String),
    #[error("map connection lost: {0}")]
    MapConnectionLost(String),
    #[error("tls: {0}")]
    Tls(String),
}

impl From<ureq::Error> for ControlError {
    fn from(e: ureq::Error) -> Self {
        ControlError::Transport(e.to_string())
    }
}

impl From<httparse::Error> for ControlError {
    fn from(e: httparse::Error) -> Self {
        ControlError::HttpParse(e.to_string())
    }
}
