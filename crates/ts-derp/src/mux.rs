//! Multi-region DERP connection pool.
//!
//! - Cap of 8 concurrent conns per PLAN-V1 §M8.
//! - LRU eviction; **never evicts the home region**.
//! - Lazy dial: `send(region, ...)` opens a conn the first time we
//!   need to talk to that region.
//! - Inbound: every `DerpConn` pushes `(region, DerpRx)` onto the same
//!   `rx_sink`. The transport drains.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use vita_chan::Sender;
use vita_sync::Mutex;
use vita_log::{debug, info};

use crate::conn::{DerpConn, DerpRx, DerpTx};
use crate::magic::DEFAULT_MAX_CONNS;
use crate::{DerpError, DerpMap, NodeKeyBytes};

pub struct DerpMux {
    inner: Arc<MuxInner>,
}

struct MuxInner {
    /// Currently-alive conns keyed by region_id.
    conns: Mutex<HashMap<u16, Arc<DerpConn>>>,
    /// DERPMap from MapResponse. Set by the demo via
    /// `DerpTransportCtl::set_derp_map`.
    derp_map: ArcSwap<DerpMap>,
    /// `0` = unset; once the demo picks a home it's recorded here.
    home: AtomicU16,
    our_priv: NodeKeyBytes,
    our_pub: NodeKeyBytes,
    cap: usize,
    rx_sink: Sender<(u16, DerpRx)>,
}

impl DerpMux {
    pub fn new(
        our_priv: NodeKeyBytes,
        our_pub: NodeKeyBytes,
        cap: usize,
        rx_sink: Sender<(u16, DerpRx)>,
    ) -> Self {
        let cap = if cap == 0 { DEFAULT_MAX_CONNS } else { cap };
        Self {
            inner: Arc::new(MuxInner {
                conns: Mutex::new(HashMap::with_capacity(cap)),
                derp_map: ArcSwap::from_pointee(DerpMap::default()),
                home: AtomicU16::new(0),
                our_priv,
                our_pub,
                cap,
                rx_sink,
            }),
        }
    }

    pub fn set_derp_map(&self, map: DerpMap) {
        self.inner.derp_map.store(Arc::new(map));
    }

    pub fn home_region(&self) -> u16 {
        self.inner.home.load(Ordering::Relaxed)
    }

    pub fn set_home(&self, region: u16) -> Result<(), DerpError> {
        let prev = self.inner.home.swap(region, Ordering::Relaxed);
        if prev == region {
            return Ok(());
        }
        // Eagerly dial the new home so we send NotePreferred(true)
        // immediately. Conn::dial_and_spawn does that internally when
        // is_home=true.
        self.ensure_region(region, true)?;
        // Un-mark prev home if it's still alive.
        if prev != 0 {
            if let Some(c) = self.inner.conns.lock().get(&prev).cloned() {
                let _ = c.set_home(false);
            }
        }
        info!(prev, new = region, "derp.home.changed");
        Ok(())
    }

    pub fn ensure_region(&self, region: u16, is_home: bool) -> Result<Arc<DerpConn>, DerpError> {
        // Fast path: already connected and alive.
        {
            let conns = self.inner.conns.lock();
            if let Some(c) = conns.get(&region) {
                if c.is_alive() {
                    return Ok(Arc::clone(c));
                }
            }
        }

        // Slow path: dial a new conn. Look up the region in the DerpMap.
        let derp_map = self.inner.derp_map.load_full();
        let nodes = derp_map
            .regions
            .get(&region)
            .cloned()
            .ok_or(DerpError::UnknownRegion { region })?;

        // LRU evict if at cap, never the home.
        {
            let mut conns = self.inner.conns.lock();
            // Reap dead conns first.
            conns.retain(|r, c| {
                let alive = c.is_alive();
                if !alive {
                    debug!(region = *r, "derp.mux.reaped_dead_conn");
                }
                alive
            });
            if conns.len() >= self.inner.cap {
                let home = self.home_region();
                let evict_target: Option<(u16, Instant)> = conns
                    .iter()
                    .filter(|(r, _)| **r != home)
                    .map(|(r, c)| (*r, c.last_used()))
                    .min_by_key(|(_, t)| *t);
                match evict_target {
                    Some((evict_region, _)) => {
                        if let Some(c) = conns.remove(&evict_region) {
                            info!(
                                evict_region,
                                cap = self.inner.cap,
                                "derp.mux.lru_evict"
                            );
                            // Clone the Arc so we can shutdown without holding `conns`.
                            drop(c);
                        }
                    }
                    None => {
                        return Err(DerpError::CapExceededHome {
                            cap: self.inner.cap,
                            home,
                        });
                    }
                }
            }
        }

        let conn = DerpConn::dial_and_spawn(
            region,
            nodes,
            self.inner.our_priv,
            self.inner.our_pub,
            self.inner.rx_sink.clone(),
            is_home,
        )?;
        let conn = Arc::new(conn);
        self.inner.conns.lock().insert(region, Arc::clone(&conn));
        Ok(conn)
    }

    pub fn send(
        &self,
        region: u16,
        dst_pubkey: NodeKeyBytes,
        wg_bytes: &[u8],
    ) -> Result<(), DerpError> {
        let is_home = region == self.home_region();
        let conn = self.ensure_region(region, is_home)?;
        match conn.send(DerpTx::SendPacket {
            dst_pubkey,
            wg_bytes: wg_bytes.to_vec(),
        }) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Conn died between the alive-check and the send; drop it
                // from the map so the next caller dials fresh.
                self.inner.conns.lock().remove(&region);
                Err(e)
            }
        }
    }

    pub fn alive_regions(&self) -> Vec<u16> {
        self.inner
            .conns
            .lock()
            .iter()
            .filter(|(_, c)| c.is_alive())
            .map(|(r, _)| *r)
            .collect()
    }

    pub fn shutdown(&self) {
        let mut conns = self.inner.conns.lock();
        let drained: Vec<Arc<DerpConn>> = conns.drain().map(|(_, c)| c).collect();
        drop(conns);
        for c in drained {
            // Arc<DerpConn>::Drop sets shutdown flag and joins.
            drop(c);
        }
    }
}

impl Clone for DerpMux {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_mux() -> (DerpMux, vita_chan::Receiver<(u16, DerpRx)>) {
        let (tx, rx) = vita_chan::unbounded::<(u16, DerpRx)>();
        let mux = DerpMux::new([0u8; 32], [0u8; 32], 8, tx);
        (mux, rx)
    }

    #[test]
    fn ensure_region_unknown() {
        let (mux, _rx) = empty_mux();
        // No DerpMap set; any region lookup is unknown.
        let r = mux.ensure_region(99, false);
        assert!(matches!(r, Err(DerpError::UnknownRegion { region: 99 })));
    }

    #[test]
    fn home_default_zero() {
        let (mux, _rx) = empty_mux();
        assert_eq!(mux.home_region(), 0);
    }

    #[test]
    fn alive_regions_empty_initially() {
        let (mux, _rx) = empty_mux();
        assert!(mux.alive_regions().is_empty());
    }
}
