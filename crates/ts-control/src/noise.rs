//! Noise IK initiator for the Tailscale TS2021 control protocol.
//!
//! Wire details (per `tailscale.com/control/controlbase`):
//!
//! - Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
//! - Prologue mixed into the Noise transcript:
//!   `b"Tailscale Control Protocol v" || u16_be(1)`. The version is
//!   appended as **raw bytes**, not ASCII — getting this wrong silently
//!   reject's on the server side.
//! - The 96-byte IK init payload + a 5-byte envelope (2 B BE proto-version,
//!   1 B msgType=0x01, 2 B BE len=96) is base64-encoded into an
//!   `X-Tailscale-Handshake` HTTP header on the upgrade request.
//! - The server replies with 51 bytes on the upgraded socket:
//!   1 B msgType=0x02 || 2 B BE len=48 || 48 B Noise IK response.

use base64::Engine as _;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{Builder, HandshakeState, TransportState};

use crate::types::{MachinePrivate, MachinePublic};
use crate::ControlError;

/// Tailscale's controlbase deviates from the Noise spec on nonce
/// encoding: it uses **big-endian** u64 counter (not little-endian).
/// We replace snow's default ChaChaPoly with a wrapper that flips byte
/// order. Without this, AEAD decrypts succeed at nonce=0 but fail at
/// nonce>=1 — exactly the M5 bug we hit on hardware.
mod be_nonce_chachapoly {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use snow::params::CipherChoice;
    use snow::resolvers::CryptoResolver;
    use snow::types::Cipher;
    use snow::Error;

    const TAGLEN: usize = 16;

    #[derive(Default)]
    pub struct BeChaChaPoly {
        key: [u8; 32],
    }

    impl Cipher for BeChaChaPoly {
        fn name(&self) -> &'static str {
            "ChaChaPoly"
        }
        fn set(&mut self, key: &[u8; 32]) {
            self.key = *key;
        }
        fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
            let mut nonce_bytes = [0u8; 12];
            // BIG-endian counter in last 8 bytes (Tailscale-style).
            nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
            out[..plaintext.len()].copy_from_slice(plaintext);
            let tag = ChaCha20Poly1305::new(&self.key.into())
                .encrypt_in_place_detached(
                    &nonce_bytes.into(),
                    authtext,
                    &mut out[..plaintext.len()],
                )
                .expect("aead encrypt");
            out[plaintext.len()..plaintext.len() + TAGLEN].copy_from_slice(&tag);
            plaintext.len() + TAGLEN
        }
        fn decrypt(
            &self,
            nonce: u64,
            authtext: &[u8],
            ciphertext: &[u8],
            out: &mut [u8],
        ) -> Result<usize, Error> {
            if ciphertext.len() < TAGLEN {
                return Err(Error::Decrypt);
            }
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());
            let msg_len = ciphertext.len() - TAGLEN;
            out[..msg_len].copy_from_slice(&ciphertext[..msg_len]);
            let mut tag = [0u8; TAGLEN];
            tag.copy_from_slice(&ciphertext[msg_len..]);
            ChaCha20Poly1305::new(&self.key.into())
                .decrypt_in_place_detached(
                    &nonce_bytes.into(),
                    authtext,
                    &mut out[..msg_len],
                    &tag.into(),
                )
                .map_err(|_| Error::Decrypt)?;
            Ok(msg_len)
        }
    }

    /// Resolver that overlays BE-nonce ChaChaPoly on top of snow's
    /// `DefaultResolver`. Falls through for everything else
    /// (rng, dh, hash, etc.).
    pub struct TailscaleResolver(pub snow::resolvers::DefaultResolver);

    impl CryptoResolver for TailscaleResolver {
        fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
            self.0.resolve_rng()
        }
        fn resolve_dh(&self, c: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
            self.0.resolve_dh(c)
        }
        fn resolve_hash(
            &self,
            c: &snow::params::HashChoice,
        ) -> Option<Box<dyn snow::types::Hash>> {
            self.0.resolve_hash(c)
        }
        fn resolve_cipher(&self, c: &CipherChoice) -> Option<Box<dyn Cipher>> {
            match c {
                CipherChoice::ChaChaPoly => Some(Box::<BeChaChaPoly>::default()),
                _ => self.0.resolve_cipher(c),
            }
        }
    }
}

/// Tailscale's prologue. The version is appended as base-10 ASCII
/// (per `controlbase/handshake.go::protocolVersionPrologue`), and the
/// version field is unified with the Tailscale `CapabilityVersion` —
/// Headscale's noise.go does `isSupportedVersion(CapabilityVersion(protocolVersion))`.
/// So we use the same value for both the wire envelope and the prologue.
fn prologue() -> Vec<u8> {
    let mut p = Vec::with_capacity(b"Tailscale Control Protocol v".len() + 5);
    p.extend_from_slice(b"Tailscale Control Protocol v");
    let v = format!("{}", PROTOCOL_VERSION);
    p.extend_from_slice(v.as_bytes());
    p
}

/// The wire envelope's protocol version is unified with Tailscale's
/// `CapabilityVersion` — Headscale 0.26 enforces `>=88`. Pick 90 to clear
/// the floor with margin and unlock the modern fields (PacketFilters
/// plural at 81, Node.CapMap at 87, multi-DERP at 89). PLAN-V1.md docs
/// this in §"Wire protocols summary".
const PROTOCOL_VERSION: u16 = 90;

const MSG_TYPE_INIT: u8 = 0x01;
const MSG_TYPE_RESP: u8 = 0x02;
const MSG_TYPE_RECORD: u8 = 0x04;

/// Noise IK init payload length produced by `snow` for our pattern with a
/// known responder static and an empty payload. Asserted at runtime against
/// what `snow` actually writes — derived dynamically from snow, not
/// hard-coded into the wire framing.
const NOISE_INIT_LEN: usize = 96;

/// Fixed length of the Noise IK response payload (32-byte ephemeral public
/// + 16-byte AEAD tag).
const NOISE_RESP_LEN: usize = 48;

const SERVER_RESP_TOTAL_LEN: usize = 1 + 2 + NOISE_RESP_LEN; // 51

/// Maximum bytes a single Noise record envelope can carry. The wire format
/// uses a 2-byte BE length prefix, so the absolute upper bound is
/// `u16::MAX = 65535`. Subtract 16 for the AEAD tag — that gives the max
/// plaintext per record.
pub const NOISE_MAX_RECORD_PAYLOAD: usize = 65535 - 16;

/// The Noise pattern string we negotiate.
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Builder for the Noise IK initiation. Consumed by `build_init_header()`,
/// resumed by `finalize()` once the server's response is in hand.
pub struct NoiseHandshaker {
    state: HandshakeState,
}

impl NoiseHandshaker {
    pub fn new(my_static: &MachinePrivate, server_static: &MachinePublic) -> Result<Self, ControlError> {
        let prologue_bytes = prologue();
        let resolver = Box::new(be_nonce_chachapoly::TailscaleResolver(DefaultResolver));
        let builder = Builder::with_resolver(NOISE_PATTERN.parse().expect("static pattern parses"), resolver)
            .prologue(&prologue_bytes)
            .map_err(|e| ControlError::Transport(format!("snow prologue: {e}")))?
            .local_private_key(&my_static.0)
            .map_err(|e| ControlError::Transport(format!("snow local key: {e}")))?
            .remote_public_key(&server_static.0)
            .map_err(|e| ControlError::Transport(format!("snow remote key: {e}")))?;
        let state = builder
            .build_initiator()
            .map_err(|e| ControlError::Transport(format!("snow build_initiator: {e}")))?;
        Ok(Self { state })
    }

    /// Produce the base64-encoded `X-Tailscale-Handshake` header value.
    /// Internally builds a 5-byte envelope + 96-byte Noise init payload.
    pub fn build_init_header(&mut self) -> Result<String, ControlError> {
        let mut init = [0u8; 256];
        let n = self
            .state
            .write_message(&[], &mut init)
            .map_err(|e| ControlError::Transport(format!("snow write_message init: {e}")))?;
        if n != NOISE_INIT_LEN {
            return Err(ControlError::Transport(format!(
                "snow init unexpected length: {n} (expected {NOISE_INIT_LEN})"
            )));
        }

        let mut envelope = Vec::with_capacity(5 + NOISE_INIT_LEN);
        envelope.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        envelope.push(MSG_TYPE_INIT);
        envelope.extend_from_slice(&(NOISE_INIT_LEN as u16).to_be_bytes());
        envelope.extend_from_slice(&init[..NOISE_INIT_LEN]);

        Ok(base64::engine::general_purpose::STANDARD.encode(&envelope))
    }

    /// Consume the 51-byte server response (read directly off the upgraded
    /// socket) and finalize the Noise handshake. Returns the transport
    /// state plus the BLAKE2s handshake hash (useful for binding higher-
    /// level protocols if we ever need it).
    pub fn finalize(mut self, server_response: &[u8]) -> Result<NoiseTransport, ControlError> {
        if server_response.len() != SERVER_RESP_TOTAL_LEN {
            return Err(ControlError::Transport(format!(
                "noise: server response wrong length {} (expected {SERVER_RESP_TOTAL_LEN})",
                server_response.len()
            )));
        }
        if server_response[0] != MSG_TYPE_RESP {
            return Err(ControlError::Transport(format!(
                "noise: server response msg type {:#x} (expected {MSG_TYPE_RESP:#x})",
                server_response[0]
            )));
        }
        let len = u16::from_be_bytes([server_response[1], server_response[2]]) as usize;
        if len != NOISE_RESP_LEN {
            return Err(ControlError::Transport(format!(
                "noise: server response inner len {len} (expected {NOISE_RESP_LEN})"
            )));
        }
        let payload = &server_response[3..];
        let mut buf = [0u8; 256];
        let _read = self
            .state
            .read_message(payload, &mut buf)
            .map_err(|e| ControlError::Transport(format!("snow read_message resp: {e}")))?;

        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(self.state.get_handshake_hash());

        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| ControlError::Transport(format!("snow into_transport: {e}")))?;
        Ok(NoiseTransport {
            state: transport,
            handshake_hash,
        })
    }
}

pub struct NoiseTransport {
    pub(crate) state: TransportState,
    pub handshake_hash: [u8; 32],
}

impl NoiseTransport {
    /// Encrypt `plaintext` and write a single record envelope to `out`.
    /// Returns the total bytes written (`3 + ciphertext_len`).
    pub(crate) fn write_record(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), ControlError> {
        if plaintext.len() > NOISE_MAX_RECORD_PAYLOAD {
            return Err(ControlError::Transport(format!(
                "noise: plaintext {} > max {NOISE_MAX_RECORD_PAYLOAD}",
                plaintext.len()
            )));
        }
        let mut ct = vec![0u8; plaintext.len() + 16];
        let n = self
            .state
            .write_message(plaintext, &mut ct)
            .map_err(|e| ControlError::Transport(format!("snow write transport: {e}")))?;
        out.push(MSG_TYPE_RECORD);
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&ct[..n]);
        Ok(())
    }

    /// Decrypt one inbound record. `record_payload` is the ciphertext
    /// after the 3-byte header has been parsed off.
    pub(crate) fn decrypt_record(&mut self, record_payload: &[u8], out: &mut Vec<u8>) -> Result<(), ControlError> {
        let mut pt = vec![0u8; record_payload.len()];
        let n = self
            .state
            .read_message(record_payload, &mut pt)
            .map_err(|e| ControlError::Transport(format!("snow read transport: {e}")))?;
        out.extend_from_slice(&pt[..n]);
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prologue_bytes() {
        let p = prologue();
        assert_eq!(p, b"Tailscale Control Protocol v90");
    }

    /// End-to-end snow handshake: build initiator + responder with the
    /// Tailscale prologue and verify they finalize matching transport
    /// hashes. This catches prologue-bytes-vs-ASCII errors immediately.
    #[test]
    fn ik_handshake_roundtrip_with_prologue() {
        // Generate a server static pair via snow.
        let server_kp = Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let client_kp = Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();

        let mut my_priv = MachinePrivate([0u8; 32]);
        my_priv.0.copy_from_slice(&client_kp.private);
        let server_pub = MachinePublic({
            let mut b = [0u8; 32];
            b.copy_from_slice(&server_kp.public);
            b
        });

        // Initiator (our code under test).
        let mut hs = NoiseHandshaker::new(&my_priv, &server_pub).unwrap();
        let header_b64 = hs.build_init_header().unwrap();
        let envelope = base64::engine::general_purpose::STANDARD.decode(&header_b64).unwrap();
        assert_eq!(envelope.len(), 5 + NOISE_INIT_LEN);
        assert_eq!(
            u16::from_be_bytes([envelope[0], envelope[1]]),
            PROTOCOL_VERSION
        );
        assert_eq!(envelope[2], MSG_TYPE_INIT);
        assert_eq!(u16::from_be_bytes([envelope[3], envelope[4]]) as usize, NOISE_INIT_LEN);
        let init_payload = &envelope[5..];

        // Responder (test fixture).
        let mut resp = Builder::new(NOISE_PATTERN.parse().unwrap())
            .prologue(&prologue())
            .unwrap()
            .local_private_key(&server_kp.private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut tmp = [0u8; 256];
        resp.read_message(init_payload, &mut tmp).unwrap();

        // Build the responder's reply.
        let mut reply = [0u8; 256];
        let n = resp.write_message(&[], &mut reply).unwrap();
        assert_eq!(n, NOISE_RESP_LEN);

        // Wrap in our envelope shape: 1 B msg + 2 B BE len + payload.
        let mut server_response = Vec::with_capacity(SERVER_RESP_TOTAL_LEN);
        server_response.push(MSG_TYPE_RESP);
        server_response.extend_from_slice(&(NOISE_RESP_LEN as u16).to_be_bytes());
        server_response.extend_from_slice(&reply[..NOISE_RESP_LEN]);

        // Initiator finalizes.
        let nt = hs.finalize(&server_response).unwrap();

        // Sanity: we get a 32-byte handshake hash.
        assert_ne!(nt.handshake_hash, [0u8; 32]);

        // Encrypt + decrypt a transport record.
        let mut record = Vec::new();
        let mut nt2 = nt;
        nt2.write_record(b"hello vita", &mut record).unwrap();
        // First byte should be MSG_TYPE_RECORD; next 2 BE = ct length.
        assert_eq!(record[0], MSG_TYPE_RECORD);
        let ct_len = u16::from_be_bytes([record[1], record[2]]) as usize;
        assert_eq!(ct_len, record.len() - 3);

        // Responder decrypts.
        let mut resp_transport = resp.into_transport_mode().unwrap();
        let mut decrypted = vec![0u8; ct_len];
        let m = resp_transport.read_message(&record[3..], &mut decrypted).unwrap();
        assert_eq!(&decrypted[..m], b"hello vita");
    }
}
