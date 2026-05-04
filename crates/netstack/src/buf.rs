use smoltcp::socket::{tcp, udp};

/// Default per-TCP-socket rx/tx buffer size.
pub const DEFAULT_TCP_RX_BUF: usize = 16 * 1024;
pub const DEFAULT_TCP_TX_BUF: usize = 16 * 1024;

/// Default per-UDP-socket rx/tx buffer slots and per-slot bytes.
pub const DEFAULT_UDP_PKT_SLOTS: usize = 8;
pub const DEFAULT_UDP_PKT_BYTES: usize = 4 * 1024;

pub fn make_tcp_buffers(rx_size: usize, tx_size: usize) -> (tcp::SocketBuffer<'static>, tcp::SocketBuffer<'static>) {
    let rx = tcp::SocketBuffer::new(vec![0u8; rx_size]);
    let tx = tcp::SocketBuffer::new(vec![0u8; tx_size]);
    (rx, tx)
}

pub fn make_udp_buffers(
    slots: usize,
    bytes_per_slot: usize,
) -> (udp::PacketBuffer<'static>, udp::PacketBuffer<'static>) {
    let rx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; slots],
        vec![0u8; slots * bytes_per_slot],
    );
    let tx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; slots],
        vec![0u8; slots * bytes_per_slot],
    );
    (rx, tx)
}
