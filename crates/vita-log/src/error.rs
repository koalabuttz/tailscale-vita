use thiserror::Error;

#[derive(Error, Debug)]
pub enum LogError {
    #[error("vita-log already initialized")]
    AlreadyInitialized,
    #[error("could not open log file: {0}")]
    Open(#[from] std::io::Error),
    #[error("invalid TS_VITA_LOG filter: {0}")]
    InvalidFilter(String),
    #[error("subscriber registration failed: {0}")]
    Subscriber(String),
}
