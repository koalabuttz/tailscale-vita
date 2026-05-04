use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetstackError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("smoltcp: {0}")]
    Smoltcp(String),
    #[error("listener pool exhausted (cap = {0})")]
    PoolExhausted(usize),
    #[error("socket closed")]
    Closed,
    #[error("would block")]
    WouldBlock,
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("stack already shut down")]
    Shutdown,
}

impl From<NetstackError> for io::Error {
    fn from(e: NetstackError) -> Self {
        match e {
            NetstackError::Io(io) => io,
            NetstackError::Closed => io::Error::new(io::ErrorKind::NotConnected, "socket closed"),
            NetstackError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "would block")
            }
            NetstackError::Shutdown => {
                io::Error::new(io::ErrorKind::BrokenPipe, "stack shut down")
            }
            other => io::Error::other(other.to_string()),
        }
    }
}
