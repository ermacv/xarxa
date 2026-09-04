//! Packet buffer shape shared by every explicitly sized
//! [`PacketPool`](crate::PacketPool). Pool capacity and memory placement are
//! selected per pool rather than by global crate configuration.

/// Alignment of the buffer in a [`PacketBuf`](crate::PacketBuf), in bytes.
///
/// DMA engines often require the buffers they write to be aligned. Raising this
/// also rounds [`PACKET_BUF_SIZE`] up to a multiple of it, since such engines
/// write whole bus words past the end of the frame.
///
/// Can only be set with cargo features, not with an environment variable. If
/// several are enabled, the highest wins.
///
/// Supported values: 1, 2, 4, 8, 16, 32.
///
/// Default: 1.
pub const PACKET_BUF_ALIGN: usize = cfg_select! {
    feature = "packet-buf-align-32" => 32,
    feature = "packet-buf-align-16" => 16,
    feature = "packet-buf-align-8" => 8,
    feature = "packet-buf-align-4" => 4,
    feature = "packet-buf-align-2" => 2,
    _ => 1,
};

/// Size of the buffer in a [`PacketBuf`](crate::PacketBuf), in bytes.
///
/// This is the largest frame that can be sent or received, headers included.
///
/// Not configurable yet: it is 1514 (the largest Ethernet frame without the FCS)
/// rounded up to a multiple of [`PACKET_BUF_ALIGN`].
// TODO: make configurable
pub const PACKET_BUF_SIZE: usize = 1514usize.next_multiple_of(PACKET_BUF_ALIGN);
