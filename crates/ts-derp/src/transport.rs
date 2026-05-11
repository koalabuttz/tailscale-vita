//! `wg_engine::Transport` adapter for the DERP mux.
//!
//! `wg-engine`'s pump calls `transport.send(addr, datagram)` and
//! `transport.recv_with_timeout(d)`. We translate:
//!
//! - `TransportAddr::Derp { region, peer_pubkey }` → look up region's
//!   conn (lazy-dial), push `DerpTx::SendPacket{dst_pubkey, wg_bytes}`.
//! - `recv_with_timeout(d)` → drain the shared inbound channel (filled
//!   by every region's I/O thread); return `(TransportAddr::Derp{region,
//!   peer_pubkey: src_pubkey}, wg_bytes)` on each frame.
//!
//! Until the demo calls `DerpTransportCtl::set_derp_map(...)` (which
//! happens after the first `MapResponse`), `send` drops with a TRACE
//! log — BoringTun retransmits. Once set, lazy-dial kicks in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;
use tracing::trace;

use wg_engine::{Transport, TransportAddr, WgError};

use crate::conn::DerpRx;
use crate::mux::DerpMux;
use crate::probe::{HomeProbe, HomeProbeCache};
use crate::{DerpError, DerpMap, NodeKeyBytes};

pub struct DerpTransport {
    mux: DerpMux,
    rx: Receiver<(u16, DerpRx)>,
    derp_map_set: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct DerpTransportCtl {
    mux: DerpMux,
    derp_map_set: Arc<AtomicBool>,
    probe: Arc<HomeProbe>,
}

impl DerpTransport {
    /// Create a new transport + caller-side controller.
    ///
    /// The transport implements `wg_engine::Transport` and is consumed
    /// by `Engine::start`. The controller stays in the demo's hands so
    /// it can wire the DerpMap from `MapResponse` and pick a home
    /// region.
    pub fn new(
        our_priv: NodeKeyBytes,
        our_pub: NodeKeyBytes,
        cap: usize,
    ) -> (Self, DerpTransportCtl) {
        let (tx_sink, rx) = crossbeam_channel::unbounded::<(u16, DerpRx)>();
        let mux = DerpMux::new(our_priv, our_pub, cap, tx_sink);
        let derp_map_set = Arc::new(AtomicBool::new(false));
        let transport = DerpTransport {
            mux: mux.clone(),
            rx,
            derp_map_set: Arc::clone(&derp_map_set),
        };
        let ctl = DerpTransportCtl {
            mux,
            derp_map_set,
            probe: Arc::new(HomeProbe::new()),
        };
        (transport, ctl)
    }
}

impl Transport for DerpTransport {
    fn send(&self, addr: TransportAddr, datagram: &[u8]) -> Result<(), WgError> {
        let (region, peer_pubkey) = match addr {
            TransportAddr::Derp {
                region,
                peer_pubkey,
            } => (region, peer_pubkey),
            TransportAddr::Udp(_) => return Err(WgError::TransportMismatch),
        };
        if !self.derp_map_set.load(Ordering::Acquire) {
            trace!(region, "derp.tx.dropped reason=no_derp_map");
            return Ok(());
        }
        self.mux
            .send(region, peer_pubkey, datagram)
            .map_err(|e| WgError::Transport(format!("derp send: {e}")))
    }

    fn recv_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(TransportAddr, Vec<u8>)>, WgError> {
        match self.rx.recv_timeout(timeout) {
            Ok((region, rx)) => Ok(Some((
                TransportAddr::Derp {
                    region,
                    peer_pubkey: rx.src_pubkey,
                },
                rx.wg_bytes,
            ))),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => Ok(None),
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                Err(WgError::Transport("derp rx disconnect".into()))
            }
        }
    }
}

impl DerpTransportCtl {
    /// Wire the DerpMap from the first `MapResponse` carrying
    /// `DERPMap`. After this, `send` no longer drops.
    pub fn set_derp_map(&self, map: DerpMap) {
        self.mux.set_derp_map(map);
        self.derp_map_set.store(true, Ordering::Release);
    }

    /// Send an opaque datagram to `peer_pubkey` via DERP `region`.
    ///
    /// Mirrors `DerpTransport::send` but exposed on the controller so
    /// non-engine code paths (Stage 4 CallMeMaybe dispatch in
    /// `Runtime::run_event_loop`) can route Disco frames over DERP
    /// without going through the wg-engine pump. Dropped (with TRACE
    /// log) if no DerpMap has been set yet.
    pub fn send(
        &self,
        region: u16,
        peer_pubkey: NodeKeyBytes,
        datagram: &[u8],
    ) -> Result<(), DerpError> {
        if !self.derp_map_set.load(Ordering::Acquire) {
            trace!(region, "derp.tx.dropped reason=no_derp_map");
            return Ok(());
        }
        self.mux.send(region, peer_pubkey, datagram)
    }

    /// Probe regions in parallel, pick the lowest RTT, and mark it as
    /// home (sends `NotePreferred(true)` to that region).
    pub fn pick_and_set_home(&self, map: &DerpMap) -> Result<u16, DerpError> {
        let region = self.probe.pick_home(map)?;
        self.mux.set_home(region)?;
        Ok(region)
    }

    pub fn home_region(&self) -> u16 {
        self.mux.home_region()
    }

    pub fn alive_regions(&self) -> Vec<u16> {
        self.mux.alive_regions()
    }

    pub fn cached_probe(&self) -> Option<HomeProbeCache> {
        self.probe.cached()
    }

    /// Tear down all conns. Used on graceful demo exit.
    pub fn shutdown(&self) {
        self.mux.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn send_dropped_before_derp_map_set() {
        let (transport, _ctl) = DerpTransport::new([0u8; 32], [0u8; 32], 4);
        let r = transport.send(
            TransportAddr::Derp {
                region: 1,
                peer_pubkey: [0u8; 32],
            },
            b"wg",
        );
        assert!(r.is_ok()); // dropped, not errored
    }

    #[test]
    fn send_rejects_udp_addr() {
        let (transport, _ctl) = DerpTransport::new([0u8; 32], [0u8; 32], 4);
        let udp_addr = TransportAddr::Udp("127.0.0.1:51820".parse().unwrap());
        let r = transport.send(udp_addr, b"wg");
        assert!(matches!(r, Err(WgError::TransportMismatch)));
    }

    #[test]
    fn recv_returns_none_on_timeout() {
        let (transport, _ctl) = DerpTransport::new([0u8; 32], [0u8; 32], 4);
        let r = transport
            .recv_with_timeout(Duration::from_millis(10))
            .unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn ctl_home_default_zero() {
        let (_t, ctl) = DerpTransport::new([0u8; 32], [0u8; 32], 4);
        assert_eq!(ctl.home_region(), 0);
    }
}
