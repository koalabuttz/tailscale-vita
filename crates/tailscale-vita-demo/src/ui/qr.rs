#![allow(dead_code)] // consumed by the vita-only Login renderer (a later stage)

//! QR-code encoding for the interactive-login AuthURL (M18 / PLAN-M18.md).
//!
//! Pure (no vita2d) so it host-tests: `encode` turns the control server's
//! AuthURL into a square module matrix; the vita-only `render.rs` draws it.
//! Uses `qrcodegen` (zero-dep, `forbid(unsafe)`) at ECC Low — the URL is
//! short and the screen is small, so we favour the smallest version that
//! fits over redundancy.

use qrcodegen::{QrCode, QrCodeEcc};

/// A finished QR code as a row-major boolean matrix.
///
/// `dark[y * size + x]` is `true` when the module at `(x, y)` is dark
/// (drawn as a filled square). `size` is the side length in modules and
/// is always one of 21, 25, 29, … (`4 * version + 17`).
pub struct Qr {
    pub size: usize,
    pub dark: Vec<bool>,
}

/// Encode `text` (the AuthURL) as a QR code, or `None` on empty input or
/// an encode error (text too long for any version at ECC Low).
pub fn encode(text: &str) -> Option<Qr> {
    if text.is_empty() {
        return None;
    }
    let code = QrCode::encode_text(text, QrCodeEcc::Low).ok()?;
    let size = code.size() as usize;
    let mut dark = Vec::with_capacity(size * size);
    for y in 0..size as i32 {
        for x in 0..size as i32 {
            dark.push(code.get_module(x, y));
        }
    }
    Some(Qr { size, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_known_short_url() {
        let qr = encode("https://login.tailscale.com/a/0123456789abcdef")
            .expect("short URL must encode");
        // Sizes are 4*version+17 => 21, 25, 29, … — always odd and >= 21.
        assert!(qr.size >= 21, "size {} below minimum version 1", qr.size);
        assert_eq!((qr.size - 17) % 4, 0, "size {} is not 4*v+17", qr.size);
        assert_eq!(qr.size % 2, 1, "QR side length is always odd");
        // Deterministic: encode_text picks the smallest fitting version and
        // an automatic mask, so this input always yields the same side.
        assert_eq!(qr.size, 29);
        // Row-major matrix is fully populated.
        assert_eq!(qr.dark.len(), qr.size * qr.size);
        // A real code has both dark and light modules (finder patterns +
        // data), so neither is uniform.
        assert!(qr.dark.iter().any(|&d| d), "must contain dark modules");
        assert!(qr.dark.iter().any(|&d| !d), "must contain light modules");
    }

    #[test]
    fn empty_text_is_none() {
        assert!(encode("").is_none());
    }
}
