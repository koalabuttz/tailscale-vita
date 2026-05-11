//! `DualTransport` — `wg_engine::Transport` adapter that multiplexes
//! direct UDP (via `ts-magicsock`) and DERP (via `ts-derp`) for the
//! engine pump's send/recv calls.
//!
//! Send: pattern-match the `TransportAddr` variant. `Udp(addr)` →
//! `MagicSocketCtl::send_to`; `Derp{..}` → delegate to the inner
//! `DerpTransport`.
//!
//! Recv: prefer non-Disco packets queued by the magic socket
//! (try_recv non-blocking) before blocking on the DERP receiver. This
//! gives direct-path bytes priority once they're available, but
//! doesn't starve DERP — the magic queue empties to `None` quickly,
//! and the Derp recv consumes the full timeout when it does.
//!
//! Stage 4 — Disco-over-DERP: when DERP delivers a frame whose first
//! 6 bytes are the Disco magic (`TS💬`), the bytes are a CallMeMaybe
//! relayed by another peer (UDP doesn't work yet, that's the whole
//! point). We route it into `MagicSocketCtl::handle_disco_from_derp`
//! and return `None` so wg-engine doesn't try to decap it as a
//! WireGuard packet. The engine's pump iterates again immediately.

use std::time::Duration;

use crossbeam_channel::Receiver;
use tracing::{debug, trace};
use ts_derp::DerpTransport;
use ts_magicsock::{MagicSocketCtl, NonDiscoPacket};
use wg_engine::{Transport, TransportAddr, WgError};

pub struct DualTransport {
    magic: MagicSocketCtl,
    magic_rx: Receiver<NonDiscoPacket>,
    derp: DerpTransport,
}

impl DualTransport {
    pub fn new(
        magic: MagicSocketCtl,
        magic_rx: Receiver<NonDiscoPacket>,
        derp: DerpTransport,
    ) -> Self {
        Self {
            magic,
            magic_rx,
            derp,
        }
    }
}

impl Transport for DualTransport {
    fn send(&self, addr: TransportAddr, datagram: &[u8]) -> Result<(), WgError> {
        match addr {
            TransportAddr::Udp(sa) => self
                .magic
                .send_to(sa, datagram)
                .map(|_| ())
                .map_err(WgError::Io),
            TransportAddr::Derp { .. } => self.derp.send(addr, datagram),
        }
    }

    fn recv_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(TransportAddr, Vec<u8>)>, WgError> {
        // Magic first (non-blocking). If something's queued, return it.
        if let Ok((src, bytes)) = self.magic_rx.try_recv() {
            trace!(%src, n = bytes.len(), "dual.rx.udp");
            return Ok(Some((TransportAddr::Udp(src), bytes)));
        }
        // Otherwise block on Derp for the full timeout. Magic packets
        // that arrive during the wait stay queued (the magic_rx
        // channel is unbounded) and get picked up next tick.
        match self.derp.recv_with_timeout(timeout)? {
            Some((addr, bytes)) => {
                // Stage 4: if a DERP-relayed frame is actually a Disco
                // message (CallMeMaybe), hand it to magicsock and
                // swallow it from wg-engine's view.
                if ts_disco::is_disco_message(&bytes) {
                    if let TransportAddr::Derp { region, peer_pubkey } = addr {
                        debug!(
                            region,
                            peer = ?&peer_pubkey[..4],
                            n = bytes.len(),
                            "dual.rx.derp.disco"
                        );
                    }
                    self.magic.handle_disco_from_derp(&bytes);
                    Ok(None)
                } else {
                    Ok(Some((addr, bytes)))
                }
            }
            None => Ok(None),
        }
    }
}
