//! Errors that may be encountered during disco message processing.
//! Manually implemented `Display` (no thiserror dep) so the crate can
//! stay `no_std`-compatible.

use core::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    /// Encryption or decryption failed.
    CryptoFailed,
    /// Message had the wrong magic bytes.
    WrongMagic,
    /// Decrypted message version was not 0.
    UnknownVersion,
    /// Message was too short to decode.
    TooShort,
    /// Misaligned body while decoding.
    Alignment,
    /// Validity issue while decoding.
    Validity,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::CryptoFailed => "crypto operation failed",
            Error::WrongMagic => "wrong magic bytes sequence",
            Error::UnknownVersion => "disco version other than 0",
            Error::TooShort => "message was too short",
            Error::Alignment => "misaligned body while decoding",
            Error::Validity => "invalid value",
        };
        f.write_str(s)
    }
}

/// `core::error::Error` is stable since Rust 1.81 — no std needed.
impl core::error::Error for Error {}

impl<A, S, V> From<zerocopy::ConvertError<A, S, V>> for Error {
    fn from(value: zerocopy::ConvertError<A, S, V>) -> Self {
        match value {
            zerocopy::ConvertError::Size(..) => Error::TooShort,
            zerocopy::ConvertError::Alignment(..) => Error::Alignment,
            zerocopy::ConvertError::Validity(..) => Error::Validity,
        }
    }
}
