use thiserror::Error;

#[derive(Error, Debug)]
pub enum MagicError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("disco wire: {0}")]
    Disco(#[from] ts_disco::Error),
    #[error("send to non-UDP transport addr (e.g. Derp) is not supported here")]
    TransportMismatch,
    #[error("unknown peer; upsert_peer first")]
    UnknownPeer,
}
