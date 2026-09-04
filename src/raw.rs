//! Raw sockets.
//!
//! A raw socket sends and receives whole packets, headers included.
//!
//! Raw sockets can be bound in two modes:
//!
//! - **Ethernet mode** ([`RawMode::Ethernet`]): whole Ethernet frames on one interface.
//!   The socket is bound to that interface, and optionally to an ethertype.
//! - **IP mode** ([`RawMode::Ip`]): whole IP packets on all interfaces. The socket may be
//!   bound to an IP version and/or an IP protocol, both optional.

use crate::config::RAW_RX_QUEUE_COUNT;
use crate::storage::BoundedDeque;
use core::fmt;

use crate::driver::PacketBuf;
use crate::driver::PacketMeta;
#[cfg(feature = "medium-ethernet")]
use crate::iface::IfaceHandle;
#[cfg(feature = "medium-ethernet")]
use crate::iface::Medium;
use crate::stack::{Stack, TxContext};
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
#[cfg(feature = "ipv4")]
use crate::wire::Ipv4Packet;
#[cfg(feature = "ipv6")]
use crate::wire::Ipv6Packet;
#[cfg(feature = "medium-ethernet")]
use crate::wire::{EthernetFrame, EthernetProtocol};
use crate::wire::{IpAddress, IpProtocol, IpVersion, LINK_HEADER_LEN};

define_handle! {
    /// A handle to a raw socket added to a [`Stack`].
    ///
    /// [`Stack`]: crate::Stack
    RawHandle(crate::config::raw_index)
}

/// The mode of a raw socket, set by [`RawSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMode {
    /// Send and receive whole Ethernet frames on one interface.
    #[cfg(feature = "medium-ethernet")]
    Ethernet {
        /// The interface the socket sends and receives on. Its medium must be
        /// [`Medium::Ethernet`].
        iface: IfaceHandle,
        /// If set, only frames with this ethertype are received, and only frames
        /// with this ethertype may be sent.
        ethertype: Option<EthernetProtocol>,
    },
    /// Send and receive whole IP packets, on all interfaces.
    Ip {
        /// If set, only packets of this IP version are received, and only packets
        /// of this version may be sent.
        version: Option<IpVersion>,
        /// If set, only packets with this IP protocol are received, and only
        /// packets with this protocol may be sent.
        protocol: Option<IpProtocol>,
    },
}

/// Error returned by [`RawSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    /// The socket is already bound.
    InvalidState,
    /// The interface of an Ethernet-mode bind is not an Ethernet-medium interface.
    #[cfg(feature = "medium-ethernet")]
    InvalidMedium,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            #[cfg(feature = "medium-ethernet")]
            BindError::InvalidMedium => write!(f, "invalid medium"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`RawSocket::send_slice`] and [`RawSocket::send_with`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    /// The socket is not bound.
    InvalidState,
    /// (IP mode) There is no route to the packet's destination.
    Unaddressable,
    /// The packet does not fit in a packet buffer.
    BufferFull,
    /// No packet buffer is free. Wait for one to be freed, then retry.
    NoBuffer,
    /// The interface the packet would go out of has no room for it right now.
    DeviceBusy,
    /// The packet fails basic validation (too short for an Ethernet header in
    /// Ethernet mode, malformed IP header in IP mode), or does not match the
    /// socket's bind filters.
    Malformed,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::InvalidState => write!(f, "invalid state"),
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
            SendError::NoBuffer => write!(f, "no buffer"),
            SendError::DeviceBusy => write!(f, "device busy"),
            SendError::Malformed => write!(f, "malformed"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`RawSocket::recv`] and the peek methods.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    /// The socket is not bound.
    InvalidState,
    /// The RX queue is empty.
    Exhausted,
    /// The provided slice is smaller than the packet. (The packet is dropped by
    /// `recv_slice`, but not by `peek_slice`.)
    Truncated,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// Raw socket state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct RawSocketState {
    mode: Option<RawMode>,
    rx_queue: BoundedDeque<PacketBuf, RAW_RX_QUEUE_COUNT>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl RawSocketState {
    /// Wake the task waiting to send, if any.
    #[cfg(feature = "async")]
    pub(crate) fn wake_tx(&mut self) {
        self.tx_waker.wake();
    }

    /// Create an unbound raw socket.
    pub(crate) fn new() -> RawSocketState {
        RawSocketState {
            mode: None,
            rx_queue: BoundedDeque::new(),
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    /// Queue an ingress packet. `buf` must be a whole Ethernet frame or IP packet,
    /// headers included, matching the socket's mode.
    pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
        if self.rx_queue.push_back(buf).is_err() {
            trace!("raw: rx queue full, dropping packet");
            return;
        }
        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }
}

/// Copy a packet into a freshly allocated buffer. Used when both a raw socket and
/// the stack's own protocol handlers want an ingress packet. `None` if the pool
/// is empty: the socket misses the packet, the stack still processes it.
fn copy_packet(allocator: crate::driver::PacketBufAllocator, buf: &PacketBuf) -> Option<PacketBuf> {
    let Some(mut copy) = allocator.try_alloc() else {
        trace!("raw: no packet buffer for a copy, socket misses the packet");
        return None;
    };
    copy.set_len(buf.len());
    copy.copy_from_slice(buf);
    // The copy is the same packet: it carries the same metadata (arrival timestamp,
    // driver-assigned id).
    copy.set_meta(buf.meta());
    Some(copy)
}

/// Parse the destination address and protocol out of an outgoing IP packet,
/// verifying that the IP header is well-formed. Returns `None` if it is not.
fn parse_ip_headers(buf: &mut [u8]) -> Option<(IpAddress, IpProtocol)> {
    if buf.is_empty() {
        return None;
    }
    match IpVersion::of_packet(buf).ok()? {
        #[cfg(feature = "ipv4")]
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(buf).ok()?;
            Some((packet.dst_addr().into(), packet.next_header()))
        }
        #[cfg(feature = "ipv6")]
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(buf).ok()?;
            Some((packet.dst_addr().into(), packet.next_header()))
        }
    }
}

/// A raw socket borrowed from a [`Stack`], returned by [`Stack::raw_socket`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::raw_socket`]: crate::Stack::raw_socket
pub struct RawSocket<'a, 'd> {
    pub(crate) state: &'a mut RawSocketState,
    pub(crate) tx: TxContext<'a, 'd>,
}

impl RawSocket<'_, '_> {
    /// Return the mode the socket is bound to, or `None` if it is unbound.
    #[inline]
    pub fn mode(&self) -> Option<RawMode> {
        self.state.mode
    }

    /// Bind the socket to the given mode.
    ///
    /// Returns `Err(BindError::InvalidState)` if the socket is already bound (see
    /// [is_open](#method.is_open)), and `Err(BindError::InvalidMedium)` if an
    /// Ethernet-mode bind names an interface whose medium is not
    /// [`Medium::Ethernet`].
    ///
    /// # Panics
    /// Panics if an Ethernet-mode bind names a stale interface handle.
    pub fn bind(&mut self, mode: RawMode) -> Result<(), BindError> {
        if self.is_open() {
            return Err(BindError::InvalidState);
        }
        #[cfg(feature = "medium-ethernet")]
        if let RawMode::Ethernet { iface, .. } = mode
            && self.tx.ifaces.get(iface.index()).medium() != Medium::Ethernet
        {
            return Err(BindError::InvalidMedium);
        }
        self.state.mode = Some(mode);
        // Sends are possible now, and receives can start failing differently.
        #[cfg(feature = "async")]
        {
            self.state.rx_waker.wake();
            self.state.tx_waker.wake();
        }
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        self.state.mode = None;
        self.state.rx_queue.clear();
        // Wake the tasks waiting, so they can notice the socket is closed.
        #[cfg(feature = "async")]
        {
            self.state.rx_waker.wake();
            self.state.tx_waker.wake();
        }
    }

    /// Check whether the socket is open (bound to a mode).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.state.mode.is_some()
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `recv` calls, such as receiving a packet, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   incoming data may wake it again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &core::task::Waker) {
        self.state.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `send` calls, such as the socket being bound or closed.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   it may be woken again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &core::task::Waker) {
        self.state.tx_waker.register(waker)
    }

    /// Check whether the RX queue is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.state.rx_queue.is_empty()
    }

    /// Dequeue a received packet.
    ///
    /// The buffer holds the whole Ethernet frame (Ethernet mode) or IP packet (IP
    /// mode), headers included, exactly as received. This is zero-copy: the
    /// returned value is the buffer the packet arrived in, and dropping it frees it.
    ///
    /// Returns `Err(RecvError::InvalidState)` if the socket is not bound, and
    /// `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn recv(&mut self) -> Result<PacketBuf, RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        self.state.rx_queue.pop_front().ok_or(RecvError::Exhausted)
    }

    /// Dequeue a received packet, copying it into the given slice, and return the
    /// number of octets copied.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of
    /// the packet, the packet is dropped and `Err(RecvError::Truncated)` is
    /// returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let packet = self.recv()?;
        if data.len() < packet.len() {
            return Err(RecvError::Truncated);
        }
        data[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    /// Peek at the next received packet without dequeueing it, as a borrow into the
    /// queue.
    ///
    /// Returns `Err(RecvError::InvalidState)` if the socket is not bound, and
    /// `Err(RecvError::Exhausted)` if the RX queue is empty.
    pub fn peek(&self) -> Result<&[u8], RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        match self.state.rx_queue.front() {
            Some(buf) => Ok(buf),
            None => Err(RecvError::Exhausted),
        }
    }

    /// Peek at the next received packet without dequeueing it, copying it into the
    /// given slice.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of
    /// the packet, no data is copied and `Err(RecvError::Truncated)` is returned.
    /// The packet stays in the queue.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&self, data: &mut [u8]) -> Result<usize, RecvError> {
        let packet = self.peek()?;
        if data.len() < packet.len() {
            return Err(RecvError::Truncated);
        }
        data[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }

    /// Send a packet, copying it from a slice.
    ///
    /// See [send_with](#method.send_with).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send_slice_with_meta(data, PacketMeta::default())
    }

    /// Send a packet with the given [`PacketMeta`] attached, copying it from a slice.
    ///
    /// See [send_with_meta](#method.send_with_meta).
    pub fn send_slice_with_meta(&mut self, data: &[u8], meta: PacketMeta) -> Result<(), SendError> {
        self.send_with_meta(data.len(), meta, |buf| {
            buf.copy_from_slice(data);
            data.len()
        })
    }

    /// Send a packet, building it in place.
    ///
    /// The closure gets a `max_size`-byte slice inside a freshly allocated packet
    /// buffer, and returns how many bytes it wrote. The packet is then sent
    /// immediately.
    ///
    /// The packet must be complete, headers included: a whole Ethernet frame (at
    /// most 1514 octets) in Ethernet mode, a whole IP packet (at most 1500 octets,
    /// or the full 1514 in a build without `medium-ethernet`, which reserves no
    /// link-layer headroom) in IP mode. It is emitted exactly as written, so the
    /// user is responsible for every header field, including the IPv4 header
    /// checksum.
    ///
    /// In Ethernet mode the frame is transmitted on the bound interface as-is. In IP
    /// mode the destination address is read from the IP header, and the packet is
    /// routed like any other egress packet. If the destination's neighbor is
    /// unresolved, the packet is queued inside the stack and sent when resolution
    /// completes. This still counts as a successful send.
    ///
    /// Returns `Err(SendError::InvalidState)` if the socket is not bound.
    /// Returns `Err(SendError::Unaddressable)` if (IP mode) there is no route to
    /// the packet's destination.
    /// Returns `Err(SendError::Malformed)` if the packet fails basic validation (too
    /// short for an Ethernet header in Ethernet mode, malformed IP header in IP
    /// mode), or does not match the socket's bind filters.
    /// Returns `Err(SendError::BufferFull)` if the packet cannot fit in a packet
    /// buffer.
    /// Returns `Err(SendError::NoBuffer)` if every packet buffer is in use.
    ///
    /// # Panics
    /// Panics if the socket is bound (Ethernet mode) to an interface that has been
    /// removed.
    pub fn send_with(&mut self, max_size: usize, f: impl FnOnce(&mut [u8]) -> usize) -> Result<(), SendError> {
        self.send_with_meta(max_size, PacketMeta::default(), f)
    }

    /// Send a packet with the given [`PacketMeta`] attached, building it in place.
    ///
    /// The metadata is handed to the driver along with the frame. This is how a
    /// packet is tagged with an id, or a transmit timestamp is requested for it (see
    /// [`Iface::poll_tx_timestamp`](crate::iface::Iface::poll_tx_timestamp)). Everything else
    /// is exactly [`send_with`](Self::send_with).
    pub fn send_with_meta(
        &mut self,
        max_size: usize,
        meta: PacketMeta,
        f: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SendError> {
        let Some(mode) = self.state.mode else {
            return Err(SendError::InvalidState);
        };

        // Ethernet frames go out as-is. IP packets get an Ethernet header prepended
        // on Ethernet mediums, so they need headroom for it.
        let headroom = match mode {
            #[cfg(feature = "medium-ethernet")]
            RawMode::Ethernet { .. } => 0,
            RawMode::Ip { .. } => LINK_HEADER_LEN,
        };

        // An Ethernet-mode socket knows its interface up front, so it can ask for
        // room before building. An IP-mode packet names its destination inside,
        // so it is built first and routed after.
        #[cfg(feature = "medium-ethernet")]
        if let RawMode::Ethernet { iface, .. } = mode
            && !self.tx.can_transmit(iface)
        {
            self.tx.inner.set_tx_starved();
            return Err(SendError::DeviceBusy);
        }

        let Some(mut buf) = self.tx.alloc_packet() else {
            self.tx.inner.set_tx_starved();
            return Err(SendError::NoBuffer);
        };
        if max_size > buf.capacity() - headroom {
            return Err(SendError::BufferFull);
        }
        buf.set_meta(meta);
        buf.reserve(headroom);
        buf.set_len(max_size);
        let size = f(&mut buf);
        assert!(size <= max_size);
        buf.set_len(size);

        match mode {
            #[cfg(feature = "medium-ethernet")]
            RawMode::Ethernet { iface, ethertype } => {
                {
                    let Ok(frame) = EthernetFrame::new_checked(&mut buf) else {
                        return Err(SendError::Malformed);
                    };
                    if ethertype.is_some_and(|t| t != frame.ethertype()) {
                        return Err(SendError::Malformed);
                    }
                }
                trace!("raw: sending {} octet frame", buf.len());
                self.tx.transmit_ethernet(iface, buf);
                Ok(())
            }
            RawMode::Ip { version, protocol } => {
                let Some((dst_addr, next_header)) = parse_ip_headers(&mut buf) else {
                    return Err(SendError::Malformed);
                };
                if version.is_some_and(|v| v != dst_addr.version()) || protocol.is_some_and(|p| p != next_header) {
                    return Err(SendError::Malformed);
                }
                let route = self.tx.route(&dst_addr).ok_or(SendError::Unaddressable)?;
                if !self.tx.can_transmit(route.iface) {
                    self.tx.inner.set_tx_starved();
                    return Err(SendError::DeviceBusy);
                }
                trace!("raw: sending {} octets to {}", buf.len(), dst_addr);
                self.tx.transmit_raw_ip(&route, buf, dst_addr);
                Ok(())
            }
        }
    }
}

impl Stack<'_> {
    /// Offer an ingress Ethernet frame to the raw sockets. `buf` is the whole
    /// frame, Ethernet header included.
    ///
    /// The first socket bound to the frame's interface (and to its ethertype, if
    /// the socket has an ethertype filter) receives it. If `stack_wants` is set
    /// (the stack itself processes this ethertype), the socket receives a copy and
    /// the original is returned for further processing. Otherwise the socket takes
    /// the buffer zero-copy and `None` is returned.
    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn process_raw_ethernet(
        &mut self,
        iface: IfaceHandle,
        ethertype: EthernetProtocol,
        stack_wants: bool,
        buf: PacketBuf,
    ) -> Option<PacketBuf> {
        for (_, socket) in self.sockets.raw.iter_mut() {
            let Some(RawMode::Ethernet {
                iface: bound_iface,
                ethertype: bound_ethertype,
            }) = socket.mode
            else {
                continue;
            };
            #[allow(unreachable_patterns)]
            if bound_iface != iface {
                continue;
            }
            if bound_ethertype.is_some_and(|t| t != ethertype) {
                continue;
            }

            trace!("raw: receiving {} octet frame (ethertype {})", buf.len(), ethertype);
            if stack_wants {
                if let Some(copy) = copy_packet(self.inner.packet_allocator, &buf) {
                    socket.rx_enqueue(copy);
                }
                return Some(buf);
            } else {
                socket.rx_enqueue(buf);
                return None;
            }
        }
        Some(buf)
    }

    /// Offer an ingress IP packet to the raw sockets. `buf` is the whole packet,
    /// IP header included, already trimmed of link-layer padding.
    ///
    /// The first socket whose version/protocol filters match receives it. If
    /// `stack_wants` is set (the stack itself processes this protocol), the socket
    /// receives a copy and the original is returned for further processing.
    /// Otherwise the socket takes the buffer zero-copy and `None` is returned.
    ///
    /// The returned flag records whether a socket received (a copy of) the packet.
    /// The stack suppresses its own error replies (ICMP port unreachable) for
    /// packets an application is handling through a raw socket.
    pub(crate) fn process_raw_ip(
        &mut self,
        version: IpVersion,
        protocol: IpProtocol,
        stack_wants: bool,
        buf: PacketBuf,
    ) -> Option<(PacketBuf, bool)> {
        for (_, socket) in self.sockets.raw.iter_mut() {
            let Some(RawMode::Ip {
                version: bound_version,
                protocol: bound_protocol,
            }) = socket.mode
            else {
                continue;
            };
            if bound_version.is_some_and(|v| v != version) {
                continue;
            }
            if bound_protocol.is_some_and(|p| p != protocol) {
                continue;
            }

            trace!("raw: receiving {} octets ({} {})", buf.len(), version, protocol);
            if stack_wants {
                if let Some(copy) = copy_packet(self.inner.packet_allocator, &buf) {
                    socket.rx_enqueue(copy);
                }
                return Some((buf, true));
            } else {
                socket.rx_enqueue(buf);
                return None;
            }
        }
        Some((buf, false))
    }
}

/// Iterator over the raw sockets of a [`Stack`], returned by [`Stack::raw_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.raw_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.can_recv());
/// }
/// # }
/// ```
pub struct RawSocketIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> RawSocketIter<'_, 'd> {
    /// Get the next raw socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(RawHandle, RawSocket<'_, 'd>)> {
        let index = self.stack.sockets.raw.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = RawHandle::new(index);
        Some((handle, self.stack.raw_socket(handle)))
    }
}

#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "ipv6"
))]
mod test {

    use super::*;
    use crate::stack::Stack;
    use crate::test_device::{Sent, TestDevice};
    use crate::wire::{
        ETHERNET_HEADER_LEN, EthernetAddress, HardwareAddress, IPV4_HEADER_LEN, IPV6_HEADER_LEN, IpCidr, Ipv4Address,
        Ipv6Address,
    };

    fn add_test_iface(stack: &mut Stack, medium: Medium, ip_addrs: Vec<IpCidr>) -> (IfaceHandle, Sent) {
        let driver = TestDevice::new(medium);
        let tx = driver.tx.clone();
        let handle = driver.install(
            stack,
            match medium {
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01])),
                Medium::Ip => HardwareAddress::Ip,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => unreachable!(),
            },
        );
        stack.iface(handle).set_ip_addrs(ip_addrs).unwrap();
        (handle, tx)
    }

    const IP_PROTO: IpProtocol = IpProtocol(63);
    const ETHERTYPE_CUSTOM: EthernetProtocol = EthernetProtocol(0x88b5);

    /// A whole IPv4 packet with an arbitrary protocol. The header checksum is left
    /// zero, so tests double as proof that nothing rewrites the header.
    fn ipv4_packet(protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV4_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + payload.len()) as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(Ipv4Address::new(192, 168, 69, 1));
            ip.set_dst_addr(Ipv4Address::new(192, 168, 69, 2));
        }
        bytes[IPV4_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn ipv6_packet(protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV6_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len(payload.len() as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1));
            ip.set_dst_addr(Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2));
        }
        bytes[IPV6_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn eth_frame(ethertype: EthernetProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; ETHERNET_HEADER_LEN + payload.len()];
        {
            let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
            frame.set_dst_addr(EthernetAddress([0x02, 0, 0, 0, 0, 0x01]));
            frame.set_src_addr(EthernetAddress([0x02, 0, 0, 0, 0, 0x02]));
            frame.set_ethertype(ethertype);
        }
        bytes[ETHERNET_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn buf_from(bytes: &[u8]) -> PacketBuf {
        let mut buf = crate::test_device::packet_allocator().try_alloc().unwrap();
        buf.set_len(bytes.len());
        buf.copy_from_slice(bytes);
        buf
    }

    #[test]
    fn test_bind_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        assert!(!socket.is_open());
        assert_eq!(socket.mode(), None);

        let mode = RawMode::Ip {
            version: Some(IpVersion::Ipv4),
            protocol: Some(IpProtocol::Icmp),
        };
        assert_eq!(socket.bind(mode), Ok(()));
        assert!(socket.is_open());
        assert_eq!(socket.mode(), Some(mode));
        assert_eq!(
            socket.bind(RawMode::Ip {
                version: None,
                protocol: None
            }),
            Err(BindError::InvalidState)
        );

        socket.close();
        assert!(!socket.is_open());
        assert_eq!(
            socket.bind(RawMode::Ip {
                version: None,
                protocol: None
            }),
            Ok(())
        );
    }

    #[test]
    fn test_bind_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let (eth_iface, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (ip_iface, _) = add_test_iface(&mut stack, Medium::Ip, vec![]);

        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        assert_eq!(
            socket.bind(RawMode::Ethernet {
                iface: ip_iface,
                ethertype: None
            }),
            Err(BindError::InvalidMedium)
        );
        assert!(!socket.is_open());
        assert_eq!(
            socket.bind(RawMode::Ethernet {
                iface: eth_iface,
                ethertype: Some(ETHERTYPE_CUSTOM)
            }),
            Ok(())
        );
        assert!(socket.is_open());
    }

    #[test]
    fn test_recv() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);

        // Not bound yet.
        assert_eq!(socket.recv().err(), Some(RecvError::InvalidState));
        assert_eq!(socket.peek().err(), Some(RecvError::InvalidState));

        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        assert!(!socket.can_recv());
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));
        assert_eq!(socket.peek().err(), Some(RecvError::Exhausted));

        let packet = ipv4_packet(IP_PROTO, b"abcdef");
        socket.state.rx_enqueue(buf_from(&packet));
        assert!(socket.can_recv());

        // The whole packet, header included, byte for byte.
        assert_eq!(socket.peek().unwrap(), &packet[..]);
        assert_eq!(&*socket.recv().unwrap(), &packet[..]);
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_peek_and_recv_slice() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        let packet = ipv4_packet(IP_PROTO, b"abcdef");
        socket.state.rx_enqueue(buf_from(&packet));

        let mut slice = [0; 64];
        // Peeking does not dequeue.
        assert_eq!(socket.peek_slice(&mut slice).unwrap(), packet.len());
        assert_eq!(&slice[..packet.len()], &packet[..]);

        let len = socket.recv_slice(&mut slice).unwrap();
        assert_eq!(&slice[..len], &packet[..]);
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Exhausted));
    }

    #[test]
    fn test_recv_slice_truncated() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();
        socket.state.rx_enqueue(buf_from(&ipv4_packet(IP_PROTO, b"abcdef")));

        let mut slice = [0; 4];
        // peek_slice keeps the packet...
        assert_eq!(socket.peek_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(socket.can_recv());
        // ...recv_slice drops it.
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_demux_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let h_icmp = stack.add_raw_socket().unwrap();
        let h_any = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(h_icmp)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol::Icmp),
            })
            .unwrap();
        stack
            .raw_socket(h_any)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        // Not a stack protocol: the first matching socket takes the buffer.
        let packet = ipv4_packet(IP_PROTO, b"abcd");
        let res = stack.process_raw_ip(IpVersion::Ipv4, IP_PROTO, false, buf_from(&packet));
        assert!(res.is_none());
        assert!(!stack.raw_socket(h_icmp).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &packet[..]);

        // A stack-handled protocol: the matching socket gets a copy, the original
        // is handed back for further processing.
        let packet = ipv4_packet(IpProtocol::Icmp, b"ping");
        let res = stack.process_raw_ip(IpVersion::Ipv4, IpProtocol::Icmp, true, buf_from(&packet));
        let (res_buf, handled) = res.unwrap();
        assert_eq!(&*res_buf, &packet[..]);
        assert!(handled);
        assert_eq!(&*stack.raw_socket(h_icmp).recv().unwrap(), &packet[..]);
        assert!(!stack.raw_socket(h_any).can_recv());

        // Version filter: an IPv6 packet skips the IPv4-bound socket.
        let packet = ipv6_packet(IpProtocol::Icmp, b"six");
        let res = stack.process_raw_ip(IpVersion::Ipv6, IpProtocol::Icmp, false, buf_from(&packet));
        assert!(res.is_none());
        assert!(!stack.raw_socket(h_icmp).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &packet[..]);

        // No socket matches: the buffer is handed back.
        stack.raw_socket(h_any).close();
        let packet = ipv4_packet(IP_PROTO, b"nobody");
        let res = stack.process_raw_ip(IpVersion::Ipv4, IP_PROTO, false, buf_from(&packet));
        let (res_buf, handled) = res.unwrap();
        assert_eq!(&*res_buf, &packet[..]);
        assert!(!handled);
    }

    /// Packet metadata reaches a raw socket on the zero-copy ingress path *and* on
    /// the copy the socket gets when the stack also wants the packet, and rides back
    /// out to the device on send.
    #[cfg(feature = "packetmeta-id")]
    #[test]
    fn test_packet_meta() {
        let driver = TestDevice::new(Medium::Ethernet);
        let sent = driver.tx_meta.clone();
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let iface = driver.install(
            &mut stack,
            HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01])),
        );

        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet { iface, ethertype: None })
            .unwrap();

        // Zero-copy ingress: the socket takes the very buffer the driver filled.
        let mut buf = buf_from(&eth_frame(ETHERTYPE_CUSTOM, b"abcd"));
        buf.meta_mut().id = 0x1111;
        let res = stack.process_raw_ethernet(iface, ETHERTYPE_CUSTOM, false, buf);
        assert!(res.is_none());
        assert_eq!(stack.raw_socket(handle).recv().unwrap().meta().id, 0x1111);

        // Copied ingress (the stack wants the ethertype too): the copy is the same
        // packet, so it carries the same metadata.
        let mut buf = buf_from(&eth_frame(EthernetProtocol::Arp, b"abcd"));
        buf.meta_mut().id = 0x2222;
        let res = stack.process_raw_ethernet(iface, EthernetProtocol::Arp, true, buf);
        assert_eq!(res.unwrap().meta().id, 0x2222);
        assert_eq!(stack.raw_socket(handle).recv().unwrap().meta().id, 0x2222);

        // Egress: the metadata handed to send reaches the device, and a plain send
        // carries the default.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"out");
        let mut meta = PacketMeta::default();
        meta.id = 0x3333;
        stack.raw_socket(handle).send_slice_with_meta(&frame, meta).unwrap();
        stack.raw_socket(handle).send_slice(&frame).unwrap();
        assert_eq!(&*sent.borrow(), &[meta, PacketMeta::default()]);
    }

    #[test]
    fn test_demux_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let (iface_a, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (iface_b, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);

        let h_custom = stack.add_raw_socket().unwrap();
        let h_any = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(h_custom)
            .bind(RawMode::Ethernet {
                iface: iface_a,
                ethertype: Some(ETHERTYPE_CUSTOM),
            })
            .unwrap();
        stack
            .raw_socket(h_any)
            .bind(RawMode::Ethernet {
                iface: iface_a,
                ethertype: None,
            })
            .unwrap();

        // Frame on another interface: no socket matches.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        let res = stack.process_raw_ethernet(iface_b, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert_eq!(&*res.unwrap(), &frame[..]);
        assert!(!stack.raw_socket(h_custom).can_recv());
        assert!(!stack.raw_socket(h_any).can_recv());

        // Frame on the bound interface: the first matching socket takes it.
        let res = stack.process_raw_ethernet(iface_a, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert!(res.is_none());
        assert_eq!(&*stack.raw_socket(h_custom).recv().unwrap(), &frame[..]);
        assert!(!stack.raw_socket(h_any).can_recv());

        // A stack-handled ethertype skips the filtered socket, and the wildcard
        // socket gets a copy while the original is handed back.
        let frame = eth_frame(EthernetProtocol::Arp, b"arp?");
        let res = stack.process_raw_ethernet(iface_a, EthernetProtocol::Arp, true, buf_from(&frame));
        assert_eq!(&*res.unwrap(), &frame[..]);
        assert!(!stack.raw_socket(h_custom).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &frame[..]);
    }

    #[test]
    fn test_send_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let (iface, tx) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let handle = stack.add_raw_socket().unwrap();

        // Not bound yet.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&frame),
            Err(SendError::InvalidState)
        );

        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet {
                iface,
                ethertype: Some(ETHERTYPE_CUSTOM),
            })
            .unwrap();

        assert_eq!(stack.raw_socket(handle).send_slice(&frame), Ok(()));
        assert_eq!(*tx.borrow(), vec![frame.clone()]);

        // Shorter than an Ethernet header.
        assert_eq!(stack.raw_socket(handle).send_slice(&[0; 10]), Err(SendError::Malformed));
        // Ethertype filter mismatch.
        let wrong = eth_frame(EthernetProtocol::Ipv4, b"hello");
        assert_eq!(stack.raw_socket(handle).send_slice(&wrong), Err(SendError::Malformed));
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_send_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: None,
            })
            .unwrap();

        // No interface: no route to the destination.
        let packet = ipv4_packet(IP_PROTO, b"abcd");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet),
            Err(SendError::Unaddressable)
        );

        // An IP-medium interface with the destination on-link. The packet goes out
        // byte for byte, the zeroed header checksum proves nothing rewrites it.
        let (_iface, tx) = add_test_iface(
            &mut stack,
            Medium::Ip,
            vec![IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)],
        );
        assert_eq!(stack.raw_socket(handle).send_slice(&packet), Ok(()));
        assert_eq!(*tx.borrow(), vec![packet.clone()]);

        // Malformed: empty, bogus version nibble, truncated header.
        assert_eq!(stack.raw_socket(handle).send_slice(&[]), Err(SendError::Malformed));
        assert_eq!(
            stack.raw_socket(handle).send_slice(&[0xf0; 40]),
            Err(SendError::Malformed)
        );
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet[..10]),
            Err(SendError::Malformed)
        );
        // Version filter mismatch: an IPv6 packet on an IPv4-bound socket.
        let v6 = ipv6_packet(IP_PROTO, b"abcd");
        assert_eq!(stack.raw_socket(handle).send_slice(&v6), Err(SendError::Malformed));
        // Too big for a packet buffer (IP mode leaves room for the Ethernet header).
        assert_eq!(
            stack.raw_socket(handle).send_with(1503, |_| unreachable!()),
            Err(SendError::BufferFull)
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_send_ip_protocol_filter() {
        let mut stack = Stack::new(0x1234_5678_dead_beef, crate::test_device::packet_allocator());
        let (_iface, tx) = add_test_iface(
            &mut stack,
            Medium::Ip,
            vec![IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)],
        );
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: Some(IP_PROTO),
            })
            .unwrap();

        assert_eq!(
            stack
                .raw_socket(handle)
                .send_slice(&ipv4_packet(IpProtocol::Tcp, b"nope")),
            Err(SendError::Malformed)
        );
        assert_eq!(
            stack.raw_socket(handle).send_slice(&ipv4_packet(IP_PROTO, b"yep")),
            Ok(())
        );
        assert_eq!(tx.borrow().len(), 1);
    }
}
