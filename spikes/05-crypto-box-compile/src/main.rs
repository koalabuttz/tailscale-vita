//! M8 Day-0 spike: verify `crypto_box 0.9` (XSalsa20-Poly1305 NaCl box)
//! cross-compiles to `armv7-sony-vita-newlibeabihf` and produces correct
//! AEAD output on hardware.
//!
//! Tailscale's DERP relay handshake requires a NaCl box exchange:
//! `client_pub(32B) || nonce(24B) || box_seal(server_pub, client_priv, JSON)`
//! and the symmetric reverse for ServerInfo. Phase 0 verified
//! ChaCha20-Poly1305 (the AEAD used by Noise IK), but XSalsa20-Poly1305
//! (NaCl box) uses a different cipher family — needs its own validation.
//!
//! What this spike does on hardware:
//!   1. Hardcoded test vectors from RFC / NaCl reference (deterministic).
//!   2. SalsaBox::new(&peer_pub, &our_priv).encrypt(&nonce, plaintext)
//!      → assert ciphertext.len() == plaintext.len() + 16 (Poly1305 tag).
//!   3. Round-trip decrypt — assert plaintext recovered.
//!   4. Cross-check: x25519-dalek's PublicKey::from(StaticSecret::from(b))
//!      equals crypto_box's PublicKey from the same priv bytes. (We use
//!      the same `node.priv` bytes for both KeyStore identity AND the
//!      DERP NaCl box, so this MUST agree.)

use crypto_box::aead::generic_array::GenericArray;
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey as CbPublic, SalsaBox, SecretKey as CbSecret};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

mod logger;

macro_rules! log {
    ($($arg:tt)*) => { logger::log_line(&format!($($arg)*)) };
}

fn main() {
    logger::init("ux0:/data/spike-5.log");
    log!("crypto_box compile spike: starting");

    // ---- Hardcoded keys (NaCl test vector — deterministic) ----
    let alice_priv_bytes: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x31, 0x8a, 0x57, 0xd3, 0xc1, 0x6c, 0x17, 0x25, 0x1b,
        0x26, 0x64, 0x5d, 0xf4, 0xc2, 0xf8, 0x7e, 0xbc, 0x09, 0x92, 0xab, 0x17, 0x73, 0x91,
        0xa6, 0xa6, 0x7d, 0xeb,
    ];
    let bob_pub_bytes: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
        0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
        0x6f, 0x88, 0x2b, 0x4f,
    ];

    // ---- Build keys with crypto_box's API ----
    let alice_secret = CbSecret::from(alice_priv_bytes);
    let bob_pub = CbPublic::from(bob_pub_bytes);
    log!(
        "alice_priv loaded ({} B), bob_pub loaded ({} B)",
        alice_priv_bytes.len(),
        bob_pub_bytes.len()
    );

    // ---- Cross-check: x25519-dalek and crypto_box derive the same pub from the same priv.
    let xsecret = XSecret::from(alice_priv_bytes);
    let xpub: XPublic = (&xsecret).into();
    let cb_alice_pub = alice_secret.public_key();
    if xpub.to_bytes() == *cb_alice_pub.as_bytes() {
        log!("OK: x25519-dalek and crypto_box agree on PublicKey-from-bytes");
    } else {
        log!(
            "FAIL: pubkey mismatch — x25519: {:02x?}, crypto_box: {:02x?}",
            xpub.to_bytes(),
            cb_alice_pub.as_bytes()
        );
    }

    // ---- SalsaBox encrypt ----
    let nonce_bytes: [u8; 24] = [
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc,
        0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
    ];
    let nonce: GenericArray<u8, <SalsaBox as AeadCore>::NonceSize> = nonce_bytes.into();
    let plaintext = b"hello vita derp";

    let salsa_box = SalsaBox::new(&bob_pub, &alice_secret);
    let ciphertext = match salsa_box.encrypt(&nonce, &plaintext[..]) {
        Ok(c) => c,
        Err(e) => {
            log!("FAIL: encrypt error: {:?}", e);
            stall();
            return;
        }
    };
    log!(
        "encrypt OK: {} B plaintext -> {} B ciphertext (overhead {} B)",
        plaintext.len(),
        ciphertext.len(),
        ciphertext.len() - plaintext.len()
    );
    if ciphertext.len() != plaintext.len() + 16 {
        log!(
            "FAIL: tag overhead expected 16, got {}",
            ciphertext.len() - plaintext.len()
        );
        stall();
        return;
    }
    log!("ciphertext (first 32 B): {:02x?}", &ciphertext[..ciphertext.len().min(32)]);

    // ---- Round-trip: decrypt with reverse-roles box ----
    // In a real DERP exchange, Bob would decrypt with his own private key
    // and Alice's public key. Since we don't have Bob's private key in this
    // test vector, we just decrypt with Alice's box (same pair) — the box is
    // commutative: SalsaBox::new(&pub, &priv) is symmetric, so encrypt
    // followed by decrypt with the SAME box round-trips.
    match salsa_box.decrypt(&nonce, ciphertext.as_slice()) {
        Ok(decrypted) => {
            if decrypted == plaintext {
                log!("decrypt OK: round-trip recovered plaintext");
            } else {
                log!(
                    "FAIL: plaintext mismatch — expected {:?}, got {:?}",
                    plaintext,
                    decrypted
                );
            }
        }
        Err(e) => {
            log!("FAIL: decrypt error: {:?}", e);
        }
    }

    log!("crypto_box compile spike: done");
    stall();
}

fn stall() {
    // Hold the screen so the user sees the LiveArea bubble didn't crash.
    std::thread::sleep(std::time::Duration::from_secs(5));
}
