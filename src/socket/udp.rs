use core::cmp::min;
#[cfg(feature = "tx-egress-metadata")]
use core::num::NonZeroU16;
#[cfg(feature = "async")]
use core::task::Waker;

#[cfg(feature = "tx-egress-metadata")]
use super::{KeyedDispatchError, KeyedEmitError};
use crate::iface::Context;
#[cfg(feature = "tx-egress-metadata")]
use crate::iface::EgressDemandHandle;
use crate::phy::PacketMeta;
#[cfg(feature = "tx-egress-metadata")]
use crate::phy::{Device, EgressKey};
use crate::socket::PollAt;
#[cfg(feature = "async")]
use crate::socket::WakerRegistration;
use crate::storage::{Empty, PacketHandle};
use crate::wire::{IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpRepr, UdpRepr};

/// Metadata for a sent or received UDP packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UdpMetadata {
    /// The IP endpoint from which an incoming datagram was received, or to which an outgoing
    /// datagram will be sent.
    pub endpoint: IpEndpoint,
    /// The IP address to which an incoming datagram was sent, or from which an outgoing datagram
    /// will be sent. Incoming datagrams always have this set. On outgoing datagrams, if it is not
    /// set, and the socket is not bound to a single address anyway, a suitable address will be
    /// determined using the algorithms of RFC 6724 (candidate source address selection) or some
    /// heuristic (for IPv4).
    pub local_address: Option<IpAddress>,
    pub meta: PacketMeta,
}

impl<T: Into<IpEndpoint>> From<T> for UdpMetadata {
    fn from(value: T) -> Self {
        Self {
            endpoint: value.into(),
            local_address: None,
            meta: PacketMeta::default(),
        }
    }
}

impl core::fmt::Display for UdpMetadata {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "packetmeta-id")]
        return write!(f, "{}, PacketID: {:?}", self.endpoint, self.meta);

        #[cfg(not(feature = "packetmeta-id"))]
        write!(f, "{}", self.endpoint)
    }
}

/// A UDP packet metadata.
pub type PacketMetadata = crate::storage::PacketMetadata<UdpMetadata>;

/// A UDP packet ring buffer.
pub type PacketBuffer<'a> = crate::storage::PacketBuffer<'a, UdpMetadata>;

/// Error returned by [`Socket::bind`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BindError {
    InvalidState,
    Unaddressable,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            BindError::Unaddressable => write!(f, "unaddressable"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`Socket::send`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendError {
    Unaddressable,
    BufferFull,
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecvError {
    Exhausted,
    Truncated,
}

impl core::fmt::Display for RecvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// A User Datagram Protocol socket.
///
/// A UDP socket is bound to a specific endpoint, and owns transmit and receive
/// packet buffers.
// One key for every supported S31 SoftAP peer plus one group/broadcast key.
// This bounds hot scheduler metadata; packet capacity remains independently
// configured by the socket's PSRAM-backed packet arena.
const EGRESS_QUEUE_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy)]
struct EgressQueue {
    destination: IpAddress,
    head: PacketHandle,
    tail: PacketHandle,
    ready_units: usize,
}

/// Queue identity used before final device backing is requested.
///
/// Resolved routes are canonicalized by the device because a link destination
/// is not necessarily a physical peer. The IP fallback preserves progress for
/// packets which still need neighbour discovery.
#[cfg(feature = "tx-egress-metadata")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceEgressQueueKey {
    Classified(EgressKey),
    Unresolved(IpAddress),
}

#[derive(Debug)]
pub struct Socket<'a> {
    endpoint: IpListenEndpoint,
    rx_buffer: PacketBuffer<'a>,
    tx_buffer: PacketBuffer<'a>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    tx_egress_index_enabled: bool,
    tx_egress_index_blocked: bool,
    tx_egress_queues: [Option<EgressQueue>; EGRESS_QUEUE_CAPACITY],
    #[cfg(feature = "tx-egress-metadata")]
    tx_egress_demand_handles: [Option<EgressDemandHandle>; EGRESS_QUEUE_CAPACITY],
    tx_egress_current: Option<u8>,
    #[cfg(feature = "tx-egress-metadata")]
    tx_device_egress_current: Option<DeviceEgressQueueKey>,
    #[cfg(feature = "tx-egress-metadata")]
    tx_egress_epoch: u32,
    tx_egress_cursor: u8,
    tx_burst_remaining: u8,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    tx_waker: WakerRegistration,
}

impl<'a> Socket<'a> {
    /// Create an UDP socket with the given buffers.
    pub fn new(rx_buffer: PacketBuffer<'a>, tx_buffer: PacketBuffer<'a>) -> Socket<'a> {
        Socket {
            endpoint: IpListenEndpoint::default(),
            rx_buffer,
            tx_buffer,
            hop_limit: None,
            // A keyed build records every enqueue from the start. This avoids
            // reconstructing provider queues from packet payload ownership
            // before the first scheduling observation.
            tx_egress_index_enabled: cfg!(feature = "tx-egress-metadata"),
            tx_egress_index_blocked: false,
            tx_egress_queues: [None; EGRESS_QUEUE_CAPACITY],
            #[cfg(feature = "tx-egress-metadata")]
            tx_egress_demand_handles: [None; EGRESS_QUEUE_CAPACITY],
            tx_egress_current: None,
            #[cfg(feature = "tx-egress-metadata")]
            tx_device_egress_current: None,
            #[cfg(feature = "tx-egress-metadata")]
            tx_egress_epoch: 0,
            tx_egress_cursor: 0,
            tx_burst_remaining: 0,
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
        }
    }

    fn egress_queue_index(&self, destination: IpAddress) -> Option<usize> {
        self.tx_egress_queues
            .iter()
            .position(|queue| queue.is_some_and(|queue| queue.destination == destination))
    }

    fn record_linked_egress_packet(
        queues: &mut [Option<EgressQueue>; EGRESS_QUEUE_CAPACITY],
        index: usize,
        destination: IpAddress,
        handle: PacketHandle,
    ) {
        queues[index] = Some(if let Some(queue) = queues[index] {
            EgressQueue {
                tail: handle,
                ready_units: queue
                    .ready_units
                    .checked_add(1)
                    .expect("packet arena bounds UDP egress queue length"),
                ..queue
            }
        } else {
            EgressQueue {
                destination,
                head: handle,
                tail: handle,
                ready_units: 1,
            }
        });
    }

    fn disable_egress_index(&mut self, blocked: bool) {
        if self.tx_egress_index_enabled {
            self.tx_buffer.clear_egress_links();
        }
        self.tx_egress_index_enabled = false;
        self.tx_egress_index_blocked = blocked;
        self.tx_egress_queues = [None; EGRESS_QUEUE_CAPACITY];
        #[cfg(feature = "tx-egress-metadata")]
        {
            self.tx_egress_demand_handles = [None; EGRESS_QUEUE_CAPACITY];
        }
        self.tx_egress_current = None;
        #[cfg(feature = "tx-egress-metadata")]
        {
            self.tx_device_egress_current = None;
        }
        self.tx_burst_remaining = 0;
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn begin_device_egress_epoch(&mut self, epoch: u32) {
        if self.tx_egress_epoch != epoch {
            // Rebuild all intrusive links from live packet metadata on the
            // next selection. Packet owners and per-destination FIFO order
            // survive; only the obsolete scheduler phase is discarded.
            self.disable_egress_index(false);
            self.tx_egress_cursor = 0;
            self.tx_egress_epoch = epoch;
        }
    }

    /// Synchronize queue-local scheduler state before interface observation.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn prepare_egress_demand_epoch(&mut self, epoch: u32) {
        self.begin_device_egress_epoch(epoch);
    }

    fn enable_egress_index(&mut self) -> bool {
        if self.tx_egress_index_enabled {
            return true;
        }
        if self.tx_egress_index_blocked {
            return false;
        }

        // First prove that the complete live set fits. This keeps activation
        // transactional: an over-capacity generic socket falls back to FIFO
        // without leaving a partially linked arena behind.
        let mut destinations = [None; EGRESS_QUEUE_CAPACITY];
        let mut overflow = false;
        self.tx_buffer.for_each_packet(|_, metadata| {
            if destinations.contains(&Some(metadata.endpoint.addr)) {
                return;
            }
            match destinations
                .iter_mut()
                .find(|destination| destination.is_none())
            {
                Some(free) => *free = Some(metadata.endpoint.addr),
                None => overflow = true,
            }
        });
        if overflow {
            self.tx_egress_index_blocked = true;
            return false;
        }

        self.tx_egress_queues = [None; EGRESS_QUEUE_CAPACITY];
        let queues = &mut self.tx_egress_queues;
        self.tx_buffer.rebuild_egress_links(|handle, metadata| {
            let index = queues
                .iter()
                .position(|queue| {
                    queue.is_some_and(|queue| queue.destination == metadata.endpoint.addr)
                })
                .or_else(|| queues.iter().position(Option::is_none))
                .expect("the transactional preflight covered every destination");
            let previous = queues[index].map(|queue| queue.tail);
            Self::record_linked_egress_packet(queues, index, metadata.endpoint.addr, handle);
            previous
        });
        self.tx_egress_index_enabled = true;
        true
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn device_queue_key<D: Device + ?Sized>(
        cx: &Context,
        device: &mut D,
        queue: EgressQueue,
    ) -> DeviceEgressQueueKey {
        cx.resolved_egress_route(&queue.destination)
            .map(|route| DeviceEgressQueueKey::Classified(device.egress_key(route)))
            .unwrap_or(DeviceEgressQueueKey::Unresolved(queue.destination))
    }

    /// Select one packet by its device-classified scheduling domain.
    ///
    /// Resolution is performed only when a burst starts or crosses from one
    /// IP FIFO to another. The common one-IP-per-peer case therefore does not
    /// add a neighbour-cache lookup for every packet in a full aggregate.
    #[cfg(feature = "tx-egress-metadata")]
    fn select_device_egress_packet<D: Device + ?Sized>(
        &mut self,
        cx: &Context,
        device: &mut D,
        max_packets: u8,
    ) -> Option<(usize, PacketHandle)> {
        if !self.enable_egress_index() {
            return None;
        }

        if self.tx_burst_remaining != 0 {
            if let Some(index) = self.tx_egress_current.map(usize::from)
                && let Some(queue) = self.tx_egress_queues[index]
            {
                return Some((index, queue.head));
            }

            if let Some(current_key) = self.tx_device_egress_current {
                for offset in 0..EGRESS_QUEUE_CAPACITY {
                    let index =
                        (usize::from(self.tx_egress_cursor) + offset) % EGRESS_QUEUE_CAPACITY;
                    let Some(queue) = self.tx_egress_queues[index] else {
                        continue;
                    };
                    if Self::device_queue_key(cx, device, queue) == current_key {
                        self.tx_egress_current = Some(index as u8);
                        self.tx_egress_cursor = ((index + 1) % EGRESS_QUEUE_CAPACITY) as u8;
                        return Some((index, queue.head));
                    }
                }
            }
        }

        self.tx_egress_current = None;
        self.tx_device_egress_current = None;
        self.tx_burst_remaining = 0;
        for offset in 0..EGRESS_QUEUE_CAPACITY {
            let index = (usize::from(self.tx_egress_cursor) + offset) % EGRESS_QUEUE_CAPACITY;
            if let Some(queue) = self.tx_egress_queues[index] {
                self.tx_egress_current = Some(index as u8);
                self.tx_device_egress_current = Some(Self::device_queue_key(cx, device, queue));
                self.tx_egress_cursor = ((index + 1) % EGRESS_QUEUE_CAPACITY) as u8;
                self.tx_burst_remaining = max_packets;
                return Some((index, queue.head));
            }
        }
        None
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn complete_device_egress_packet(
        &mut self,
        queue_index: usize,
        handle: PacketHandle,
        next: Option<PacketHandle>,
    ) -> bool {
        let queue = self.tx_egress_queues[queue_index]
            .expect("a selected device egress queue remains active");
        assert_eq!(
            queue.head, handle,
            "device egress scheduling preserves IP FIFO order"
        );
        let queue_emptied = if let Some(next) = next {
            debug_assert!(queue.ready_units > 1);
            self.tx_egress_queues[queue_index] = Some(EgressQueue {
                head: next,
                ready_units: queue.ready_units - 1,
                ..queue
            });
            false
        } else {
            self.tx_egress_queues[queue_index] = None;
            self.tx_egress_current = None;
            true
        };

        self.tx_burst_remaining -= 1;
        let burst_completed = self.tx_burst_remaining == 0;
        if burst_completed {
            self.tx_egress_current = None;
            self.tx_device_egress_current = None;
        }

        // As with the IP selector, wake a full producer only at a scheduling
        // boundary. Emptying one IP FIFO is not such a boundary when another
        // IP FIFO resolves to the same radio key and the burst has credit.
        burst_completed || queue_emptied
    }

    /// Visit bounded queue metadata used by the interface demand catalog.
    ///
    /// Payload bytes are never inspected. The affine handle remains in its
    /// queue slot across an empty interval so one interface observation can
    /// terminate the old lifetime before a later activation reuses the slot.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn for_each_egress_demand_provider(
        &mut self,
        mut visit: impl FnMut(&mut Option<EgressDemandHandle>, IpAddress, NonZeroU16),
    ) {
        if !self.enable_egress_index() {
            return;
        }

        for index in 0..EGRESS_QUEUE_CAPACITY {
            let Some(queue) = self.tx_egress_queues[index] else {
                continue;
            };
            let ready_units = NonZeroU16::new(queue.ready_units.min(usize::from(u16::MAX)) as u16)
                .expect("a live egress queue is nonempty");
            visit(
                &mut self.tx_egress_demand_handles[index],
                queue.destination,
                ready_units,
            );
        }
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &Waker) {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &Waker) {
        self.tx_waker.register(waker)
    }

    /// Return the bound endpoint.
    #[inline]
    pub fn endpoint(&self) -> IpListenEndpoint {
        self.endpoint
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Bind the socket to the given endpoint.
    ///
    /// This function returns `Err(Error::Illegal)` if the socket was open
    /// (see [is_open](#method.is_open)), and `Err(Error::Unaddressable)`
    /// if the port in the given endpoint is zero.
    pub fn bind<T: Into<IpListenEndpoint>>(&mut self, endpoint: T) -> Result<(), BindError> {
        let endpoint = endpoint.into();
        if endpoint.port == 0 {
            return Err(BindError::Unaddressable);
        }

        if self.is_open() {
            return Err(BindError::InvalidState);
        }

        self.endpoint = endpoint;

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }

        Ok(())
    }

    /// Close the socket.
    pub fn close(&mut self) {
        // Clear the bound endpoint of the socket.
        self.endpoint = IpListenEndpoint::default();

        // Reset the RX and TX buffers of the socket.
        self.tx_buffer.reset();
        self.rx_buffer.reset();

        #[cfg(feature = "async")]
        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Check whether the socket is open.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.endpoint.port != 0
    }

    /// Check whether the transmit buffer is full.
    #[inline]
    pub fn can_send(&self) -> bool {
        !self.tx_buffer.is_full()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Return the maximum number packets the socket can receive.
    #[inline]
    pub fn packet_recv_capacity(&self) -> usize {
        self.rx_buffer.packet_capacity()
    }

    /// Return the maximum number packets the socket can transmit.
    #[inline]
    pub fn packet_send_capacity(&self) -> usize {
        self.tx_buffer.packet_capacity()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn payload_recv_capacity(&self) -> usize {
        self.rx_buffer.payload_capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn payload_send_capacity(&self) -> usize {
        self.tx_buffer.payload_capacity()
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and return a pointer
    /// to its payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the transmit buffer is full,
    /// `Err(Error::Unaddressable)` if local or remote port, or remote address are unspecified,
    /// and `Err(Error::Truncated)` if there is not enough transmit buffer capacity
    /// to ever send this packet.
    pub fn send(
        &mut self,
        size: usize,
        meta: impl Into<UdpMetadata>,
    ) -> Result<&mut [u8], SendError> {
        let meta = meta.into();
        if self.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        let queue_index = if self.tx_egress_index_enabled {
            match self
                .egress_queue_index(meta.endpoint.addr)
                .or_else(|| self.tx_egress_queues.iter().position(Option::is_none))
            {
                Some(index) => Some(index),
                None => {
                    // Queue cardinality is a scheduling limit, not packet
                    // capacity. Preserve the packet API by falling back to
                    // FIFO until this live backlog drains.
                    self.disable_egress_index(true);
                    None
                }
            }
        } else {
            None
        };
        let previous = queue_index
            .and_then(|index| self.tx_egress_queues[index])
            .map(|queue| queue.tail);
        let (handle, payload_buf) = self
            .tx_buffer
            .enqueue_tracked_linked(size, meta, previous)
            .map_err(|_| SendError::BufferFull)?;
        if let Some(index) = queue_index {
            Self::record_linked_egress_packet(
                &mut self.tx_egress_queues,
                index,
                meta.endpoint.addr,
                handle,
            );
        }

        net_trace!(
            "udp:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );
        Ok(payload_buf)
    }

    /// Enqueue a packet to be send to a given remote endpoint and pass the buffer
    /// to the provided closure. The closure then returns the size of the data written
    /// into the buffer.
    ///
    /// Also see [send](#method.send).
    pub fn send_with<F>(
        &mut self,
        max_size: usize,
        meta: impl Into<UdpMetadata>,
        f: F,
    ) -> Result<usize, SendError>
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let meta = meta.into();
        if self.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.addr.is_unspecified() {
            return Err(SendError::Unaddressable);
        }
        if meta.endpoint.port == 0 {
            return Err(SendError::Unaddressable);
        }

        let queue_index = if self.tx_egress_index_enabled {
            match self
                .egress_queue_index(meta.endpoint.addr)
                .or_else(|| self.tx_egress_queues.iter().position(Option::is_none))
            {
                Some(index) => Some(index),
                None => {
                    self.disable_egress_index(true);
                    None
                }
            }
        } else {
            None
        };
        let previous = queue_index
            .and_then(|index| self.tx_egress_queues[index])
            .map(|queue| queue.tail);
        let (size, handle) = self
            .tx_buffer
            .enqueue_with_infallible_tracked_linked(max_size, meta, previous, f)
            .map_err(|_| SendError::BufferFull)?;
        if let Some(index) = queue_index {
            Self::record_linked_egress_packet(
                &mut self.tx_egress_queues,
                index,
                meta.endpoint.addr,
                handle,
            );
        }

        net_trace!(
            "udp:{}:{}: buffer to send {} octets",
            self.endpoint,
            meta.endpoint,
            size
        );
        Ok(size)
    }

    /// Enqueue a packet to be sent to a given remote endpoint, and fill it from a slice.
    ///
    /// See also [send](#method.send).
    pub fn send_slice(
        &mut self,
        data: &[u8],
        meta: impl Into<UdpMetadata>,
    ) -> Result<(), SendError> {
        self.send(data.len(), meta)?.copy_from_slice(data);
        Ok(())
    }

    /// Dequeue a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload.
    ///
    /// This function returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn recv(&mut self) -> Result<(&[u8], UdpMetadata), RecvError> {
        let (remote_endpoint, payload_buf) =
            self.rx_buffer.dequeue().map_err(|_| RecvError::Exhausted)?;

        net_trace!(
            "udp:{}:{}: receive {} buffered octets",
            self.endpoint,
            remote_endpoint.endpoint,
            payload_buf.len()
        );
        Ok((payload_buf, remote_endpoint))
    }

    /// Dequeue a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint.
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// the packet is dropped and a `RecvError::Truncated` error is returned.
    ///
    /// See also [recv](#method.recv).
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<(usize, UdpMetadata), RecvError> {
        let (buffer, endpoint) = self.recv().map_err(|_| RecvError::Exhausted)?;

        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Peek at a packet received from a remote endpoint, and return the endpoint as well
    /// as a pointer to the payload without removing the packet from the receive buffer.
    /// This function otherwise behaves identically to [recv](#method.recv).
    ///
    /// It returns `Err(Error::Exhausted)` if the receive buffer is empty.
    pub fn peek(&mut self) -> Result<(&[u8], &UdpMetadata), RecvError> {
        let endpoint = self.endpoint;
        self.rx_buffer.peek().map_err(|_| RecvError::Exhausted).map(
            |(remote_endpoint, payload_buf)| {
                net_trace!(
                    "udp:{}:{}: peek {} buffered octets",
                    endpoint,
                    remote_endpoint.endpoint,
                    payload_buf.len()
                );
                (payload_buf, remote_endpoint)
            },
        )
    }

    /// Peek at a packet received from a remote endpoint, copy the payload into the given slice,
    /// and return the amount of octets copied as well as the endpoint without removing the
    /// packet from the receive buffer.
    /// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
    ///
    /// **Note**: when the size of the provided buffer is smaller than the size of the payload,
    /// no data is copied into the provided buffer and a `RecvError::Truncated` error is returned.
    ///
    /// See also [peek](#method.peek).
    pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<(usize, &UdpMetadata), RecvError> {
        let (buffer, endpoint) = self.peek()?;

        if data.len() < buffer.len() {
            return Err(RecvError::Truncated);
        }

        let length = min(data.len(), buffer.len());
        data[..length].copy_from_slice(&buffer[..length]);
        Ok((length, endpoint))
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx_buffer.payload_bytes_count()
    }

    /// Return the amount of octets queued in the receive buffer. This value can be larger than
    /// the slice read by the next `recv` or `peek` call because it includes all queued octets,
    /// and not only the octets that may be returned as a contiguous slice.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn recv_queue(&self) -> usize {
        self.rx_buffer.payload_bytes_count()
    }

    pub(crate) fn accepts(&self, cx: &mut Context, ip_repr: &IpRepr, repr: &UdpRepr) -> bool {
        if self.endpoint.port != repr.dst_port {
            return false;
        }
        if self.endpoint.addr.is_some()
            && self.endpoint.addr != Some(ip_repr.dst_addr())
            && !cx.is_broadcast(&ip_repr.dst_addr())
            && !ip_repr.dst_addr().is_multicast()
        {
            return false;
        }

        true
    }

    pub(crate) fn process(
        &mut self,
        cx: &mut Context,
        meta: PacketMeta,
        ip_repr: &IpRepr,
        repr: &UdpRepr,
        payload: &[u8],
    ) {
        debug_assert!(self.accepts(cx, ip_repr, repr));

        let size = payload.len();

        let remote_endpoint = IpEndpoint {
            addr: ip_repr.src_addr(),
            port: repr.src_port,
        };

        net_trace!(
            "udp:{}:{}: receiving {} octets",
            self.endpoint,
            remote_endpoint,
            size
        );

        let metadata = UdpMetadata {
            endpoint: remote_endpoint,
            local_address: Some(ip_repr.dst_addr()),
            meta,
        };

        match self.rx_buffer.enqueue(size, metadata) {
            Ok(buf) => buf.copy_from_slice(payload),
            Err(_) => net_trace!(
                "udp:{}:{}: buffer full, dropped incoming packet",
                self.endpoint,
                remote_endpoint
            ),
        }

        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }

    pub(crate) fn dispatch<F, E>(&mut self, cx: &mut Context, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, PacketMeta, (IpRepr, UdpRepr, &[u8])) -> Result<(), E>,
    {
        let endpoint = self.endpoint;
        let hop_limit = self.hop_limit.unwrap_or(64);

        let res = self.tx_buffer.dequeue_with(|packet_meta, payload_buf| {
            let src_addr = if let Some(s) = packet_meta.local_address {
                s
            } else {
                match endpoint.addr {
                    Some(addr) => addr,
                    None => match cx.get_source_address(&packet_meta.endpoint.addr) {
                        Some(addr) => addr,
                        None => {
                            net_trace!(
                                "udp:{}:{}: cannot find suitable source address, dropping.",
                                endpoint,
                                packet_meta.endpoint
                            );
                            return Ok(());
                        }
                    },
                }
            };

            net_trace!(
                "udp:{}:{}: sending {} octets",
                endpoint,
                packet_meta.endpoint,
                payload_buf.len()
            );

            let repr = UdpRepr {
                src_port: endpoint.port,
                dst_port: packet_meta.endpoint.port,
            };
            let ip_repr = IpRepr::new(
                src_addr,
                packet_meta.endpoint.addr,
                IpProtocol::Udp,
                repr.header_len() + payload_buf.len(),
                hop_limit,
            );

            emit(cx, packet_meta.meta, (ip_repr, repr, payload_buf))
        });
        match res {
            Err(Empty) => Ok(()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => {
                #[cfg(feature = "async")]
                self.tx_waker.wake();
                Ok(())
            }
        }
    }

    /// Dispatch one bounded run selected by the resolved interface egress key.
    ///
    /// `None` preserves ordinary FIFO dispatch. A configured schedule owns
    /// both non-zero quanta, so the hot loop has no compatibility or zero-value
    /// branches.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn dispatch_keyed<D, F, E>(
        &mut self,
        cx: &mut Context,
        device: &mut D,
        schedule: Option<crate::phy::EgressSchedule>,
        mut emit: F,
    ) -> Result<(), KeyedDispatchError<E>>
    where
        D: Device + ?Sized,
        F: FnMut(
            &mut Context,
            &mut D,
            PacketMeta,
            (IpRepr, UdpRepr, &[u8]),
        ) -> Result<(), KeyedEmitError<E>>,
    {
        let Some(schedule) = schedule else {
            self.disable_egress_index(false);
            return self
                .dispatch(cx, |cx, meta, packet| emit(cx, device, meta, packet))
                .map_err(|error| match error {
                    KeyedEmitError::KeyDeferred => KeyedDispatchError::AllKeysDeferred,
                    KeyedEmitError::Global(error) => KeyedDispatchError::Global(error),
                });
        };

        self.begin_device_egress_epoch(schedule.epoch());
        let max_packets = schedule.max_packets_per_key().get();
        let dispatch_quantum = schedule.dispatch_quantum().get();
        let endpoint = self.endpoint;
        let hop_limit = self.hop_limit.unwrap_or(64);
        let mut deferred = 0;
        let mut emitted = 0_u8;
        loop {
            let selected = self.select_device_egress_packet(cx, device, max_packets);
            let Some((queue_index, handle)) = selected else {
                let result = self.dispatch(cx, |cx, meta, packet| emit(cx, device, meta, packet));
                if self.tx_buffer.is_empty() {
                    self.tx_egress_index_blocked = false;
                }
                return result.map_err(|error| match error {
                    KeyedEmitError::KeyDeferred => KeyedDispatchError::AllKeysDeferred,
                    KeyedEmitError::Global(error) => KeyedDispatchError::Global(error),
                });
            };

            let dispatch_packet = |packet_meta: &mut UdpMetadata, payload_buf: &mut [u8]| {
                let src_addr = if let Some(s) = packet_meta.local_address {
                    s
                } else {
                    match endpoint.addr {
                        Some(addr) => addr,
                        None => match cx.get_source_address(&packet_meta.endpoint.addr) {
                            Some(addr) => addr,
                            None => {
                                net_trace!(
                                    "udp:{}:{}: cannot find suitable source address, dropping.",
                                    endpoint,
                                    packet_meta.endpoint
                                );
                                return Ok(());
                            }
                        },
                    }
                };

                net_trace!(
                    "udp:{}:{}: sending {} octets",
                    endpoint,
                    packet_meta.endpoint,
                    payload_buf.len()
                );

                let repr = UdpRepr {
                    src_port: endpoint.port,
                    dst_port: packet_meta.endpoint.port,
                };
                let ip_repr = IpRepr::new(
                    src_addr,
                    packet_meta.endpoint.addr,
                    IpProtocol::Udp,
                    repr.header_len() + payload_buf.len(),
                    hop_limit,
                );

                emit(cx, device, packet_meta.meta, (ip_repr, repr, payload_buf))
            };
            let (result, next) = self.tx_buffer.dequeue_handle_with(handle, dispatch_packet);
            match result {
                Ok(()) => {
                    let _wake_producer =
                        self.complete_device_egress_packet(queue_index, handle, next);
                    #[cfg(feature = "async")]
                    if _wake_producer {
                        self.tx_waker.wake();
                    }
                    deferred = 0;
                    emitted = emitted.saturating_add(1);
                    if emitted >= dispatch_quantum {
                        return Ok(());
                    }
                }
                Err(KeyedEmitError::Global(error)) => {
                    return Err(KeyedDispatchError::Global(error));
                }
                Err(KeyedEmitError::KeyDeferred) => {
                    // Retain the exact queue head, but do not interpret a
                    // key-specific scheduler decision as global pressure.
                    self.tx_egress_current = None;
                    self.tx_device_egress_current = None;
                    self.tx_burst_remaining = 0;
                    deferred += 1;
                    let active = self
                        .tx_egress_queues
                        .iter()
                        .filter(|queue| queue.is_some())
                        .count();
                    if deferred >= active {
                        return Err(KeyedDispatchError::AllKeysDeferred);
                    }
                }
            }
        }
    }

    pub(crate) fn poll_at(&self, _cx: &mut Context) -> PollAt {
        if self.tx_buffer.is_empty() {
            PollAt::Ingress
        } else {
            PollAt::Now
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::{IpRepr, UdpRepr};

    use crate::phy::Medium;
    use crate::tests::setup;
    use rstest::*;

    fn buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new(
            (0..packets)
                .map(|_| PacketMetadata::EMPTY)
                .collect::<Vec<_>>(),
            vec![0; 16 * packets],
        )
    }

    fn indexed_buffer(packets: usize) -> PacketBuffer<'static> {
        PacketBuffer::new_indexed_slots(
            (0..packets)
                .map(|_| PacketMetadata::EMPTY)
                .collect::<Vec<_>>(),
            vec![0; 16 * packets],
        )
    }

    fn socket(
        rx_buffer: PacketBuffer<'static>,
        tx_buffer: PacketBuffer<'static>,
    ) -> Socket<'static> {
        Socket::new(rx_buffer, tx_buffer)
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn egress_schedule(
        max_packets_per_key: u8,
        dispatch_quantum: u8,
        epoch: u32,
    ) -> crate::phy::EgressSchedule {
        crate::phy::EgressSchedule::new(
            core::num::NonZeroU8::new(max_packets_per_key).unwrap(),
            core::num::NonZeroU8::new(dispatch_quantum).unwrap(),
            epoch,
            crate::phy::EgressGrantMode::StackSelected,
        )
    }

    const LOCAL_PORT: u16 = 53;
    const REMOTE_PORT: u16 = 49500;

    cfg_if::cfg_if! {
        if #[cfg(feature = "proto-ipv4")] {
            use crate::wire::Ipv4Address as IpvXAddress;
            use crate::wire::Ipv4Repr as IpvXRepr;
            use IpRepr::Ipv4 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv4(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        } else {
            use crate::wire::Ipv6Address as IpvXAddress;
            use crate::wire::Ipv6Repr as IpvXRepr;
            use IpRepr::Ipv6 as IpReprIpvX;

            const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
            const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
            const OTHER_ADDR: IpvXAddress = IpvXAddress::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);

            const LOCAL_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(LOCAL_ADDR),
                port: LOCAL_PORT,
            };
            const REMOTE_END: IpEndpoint = IpEndpoint {
                addr: IpAddress::Ipv6(REMOTE_ADDR),
                port: REMOTE_PORT,
            };
        }
    }

    fn remote_metadata_with_local() -> UdpMetadata {
        // Would be great as a const once we have const `.into()`.
        UdpMetadata {
            local_address: Some(LOCAL_ADDR.into()),
            ..REMOTE_END.into()
        }
    }

    pub const LOCAL_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const REMOTE_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    pub const BAD_IP_REPR: IpRepr = IpReprIpvX(IpvXRepr {
        src_addr: REMOTE_ADDR,
        dst_addr: OTHER_ADDR,
        next_header: IpProtocol::Udp,
        payload_len: 8 + 6,
        hop_limit: 64,
    });

    const LOCAL_UDP_REPR: UdpRepr = UdpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
    };

    const REMOTE_UDP_REPR: UdpRepr = UdpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
    };

    const PAYLOAD: &[u8] = b"abcdef";

    #[test]
    fn test_bind_unaddressable() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(0), Err(BindError::Unaddressable));
    }

    #[test]
    fn test_bind_twice() {
        let mut socket = socket(buffer(0), buffer(0));
        assert_eq!(socket.bind(1), Ok(()));
        assert_eq!(socket.bind(2), Err(BindError::InvalidState));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket(buffer(0), buffer(1));
        s.set_hop_limit(Some(0));
    }

    #[test]
    fn test_send_unaddressable() {
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(
            socket.send_slice(b"abcdef", REMOTE_END),
            Err(SendError::Unaddressable)
        );
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    addr: IpvXAddress::UNSPECIFIED.into(),
                    ..REMOTE_END
                }
            ),
            Err(SendError::Unaddressable)
        );
        assert_eq!(
            socket.send_slice(
                b"abcdef",
                IpEndpoint {
                    port: 0,
                    ..REMOTE_END
                }
            ),
            Err(SendError::Unaddressable)
        );
        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
    }

    #[test]
    fn test_send_with_source() {
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));
        assert_eq!(
            socket.send_slice(b"abcdef", remote_metadata_with_local()),
            Ok(())
        );
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_send_dispatch(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(1));

        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        assert!(socket.can_send());
        assert_eq!(
            socket.dispatch(cx, |_, _, _| unreachable!()),
            Ok::<_, ()>(())
        );

        assert_eq!(socket.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(
            socket.send_slice(b"123456", REMOTE_END),
            Err(SendError::BufferFull)
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(cx, |_, _, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Err(())
            }),
            Err(())
        );
        assert!(!socket.can_send());

        assert_eq!(
            socket.dispatch(cx, |_, _, (ip_repr, udp_repr, payload)| {
                assert_eq!(ip_repr, LOCAL_IP_REPR);
                assert_eq!(udp_repr, LOCAL_UDP_REPR);
                assert_eq!(payload, PAYLOAD);
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert!(socket.can_send());
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_destination_burst_dispatch_preserves_per_destination_fifo() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(8));
        let other = IpEndpoint {
            addr: OTHER_ADDR.into(),
            port: REMOTE_PORT,
        };

        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        for (payload, destination) in [
            (b"a0" as &[u8], REMOTE_END),
            (b"b0", other),
            (b"a1", REMOTE_END),
            (b"b1", other),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }

        let mut observed = Vec::new();
        for _ in 0..4 {
            assert_eq!(
                socket.dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(2, 1, 0)),
                    |_, _, _, (ip, _, payload)| {
                        observed.push((ip.dst_addr(), payload.to_vec()));
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                ),
                Ok(())
            );
        }

        assert_eq!(
            observed,
            vec![
                (REMOTE_ADDR.into(), b"a0".to_vec()),
                (REMOTE_ADDR.into(), b"a1".to_vec()),
                (OTHER_ADDR.into(), b"b0".to_vec()),
                (OTHER_ADDR.into(), b"b1".to_vec()),
            ]
        );
        assert!(socket.can_send());
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn device_key_coalesces_distinct_link_routes_into_one_scheduling_run() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        device.set_egress_key_override(Some(crate::phy::EgressKey::from_words([7, 11, 13, 17])));
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(12));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        // The three IPv4 routes resolve to two distinct multicast MACs, but
        // the device maps them to one physical scheduling domain. This models
        // an infrastructure STA sending several bridged destinations through
        // one BSSID.
        let same_link_a = IpEndpoint {
            addr: crate::wire::Ipv4Address::new(224, 1, 2, 3).into(),
            port: REMOTE_PORT,
        };
        let same_link_b = IpEndpoint {
            addr: crate::wire::Ipv4Address::new(225, 1, 2, 3).into(),
            port: REMOTE_PORT,
        };
        let other_link = IpEndpoint {
            addr: crate::wire::Ipv4Address::new(224, 1, 2, 4).into(),
            port: REMOTE_PORT,
        };
        for (payload, destination) in [
            (b"a0" as &[u8], same_link_a),
            (b"c0", other_link),
            (b"b0", same_link_b),
            (b"a1", same_link_a),
            (b"c1", other_link),
            (b"b1", same_link_b),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }

        let mut observed = Vec::new();
        for _ in 0..6 {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(4, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        observed.push(payload.to_vec());
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }

        assert_eq!(
            observed,
            [
                b"a0".to_vec(),
                b"a1".to_vec(),
                b"c0".to_vec(),
                b"c1".to_vec(),
                b"b0".to_vec(),
                b"b1".to_vec(),
            ]
        );
        assert!(socket.can_send());
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn resolved_dispatch_quantum_emits_one_bounded_contiguous_run() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(8));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        let first = IpEndpoint {
            addr: crate::wire::Ipv4Address::new(224, 0, 0, 1).into(),
            port: REMOTE_PORT,
        };
        let second = IpEndpoint {
            addr: crate::wire::Ipv4Address::new(224, 0, 0, 2).into(),
            port: REMOTE_PORT,
        };
        for sequence in 0..4_u8 {
            assert_eq!(socket.send_slice(&[0, sequence], first), Ok(()));
            assert_eq!(socket.send_slice(&[1, sequence], second), Ok(()));
        }

        let mut observed = Vec::new();
        socket
            .dispatch_keyed(
                cx,
                &mut device,
                Some(egress_schedule(4, 4, 0)),
                |_, _, _, (_, _, payload)| {
                    observed.push(payload.to_vec());
                    Result::<(), KeyedEmitError<()>>::Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            observed,
            vec![vec![0, 0], vec![0, 1], vec![0, 2], vec![0, 3]]
        );
        assert!(!socket.tx_buffer.is_empty());

        socket
            .dispatch_keyed(
                cx,
                &mut device,
                Some(egress_schedule(4, 4, 0)),
                |_, _, _, (_, _, payload)| {
                    observed.push(payload.to_vec());
                    Result::<(), KeyedEmitError<()>>::Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            &observed[4..],
            [vec![1, 0], vec![1, 1], vec![1, 2], vec![1, 3]]
        );
        assert!(socket.tx_buffer.is_empty());
        assert!(socket.can_send());
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_destination_index_retains_failed_head_and_links_new_packets() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(8));
        let other = IpEndpoint {
            addr: OTHER_ADDR.into(),
            port: REMOTE_PORT,
        };
        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        assert_eq!(socket.send_slice(b"a0", REMOTE_END), Ok(()));
        assert_eq!(socket.send_slice(b"b0", other), Ok(()));
        assert_eq!(
            socket.dispatch_keyed(
                cx,
                &mut device,
                Some(egress_schedule(3, 1, 0)),
                |_, _, _, (_, _, payload)| {
                    assert_eq!(payload, b"a0");
                    Result::<(), KeyedEmitError<()>>::Err(KeyedEmitError::Global(()))
                },
            ),
            Err(KeyedDispatchError::Global(()))
        );

        // The index is now active. Newly enqueued packets must append to the
        // existing destination chain without rescanning the packet arena.
        assert_eq!(socket.send_slice(b"a1", REMOTE_END), Ok(()));
        assert_eq!(socket.send_slice(b"b1", other), Ok(()));

        let mut observed = Vec::new();
        for _ in 0..4 {
            assert_eq!(
                socket.dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(3, 1, 0)),
                    |_, _, _, (ip, _, payload)| {
                        observed.push((ip.dst_addr(), payload.to_vec()));
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                ),
                Ok(())
            );
        }
        assert_eq!(
            observed,
            vec![
                (REMOTE_ADDR.into(), b"a0".to_vec()),
                (REMOTE_ADDR.into(), b"a1".to_vec()),
                (OTHER_ADDR.into(), b"b0".to_vec()),
                (OTHER_ADDR.into(), b"b1".to_vec()),
            ]
        );
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_key_defer_rotates_but_global_error_retains_current_burst() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(8));
        let other = IpEndpoint {
            addr: OTHER_ADDR.into(),
            port: REMOTE_PORT,
        };
        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        for (payload, destination) in [
            (b"a0" as &[u8], REMOTE_END),
            (b"b0", other),
            (b"a1", REMOTE_END),
            (b"b1", other),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }

        let mut observed = Vec::new();
        for _ in 0..2 {
            assert!(
                socket
                    .dispatch_keyed(
                        cx,
                        &mut device,
                        Some(egress_schedule(2, 1, 0)),
                        |_, _, _, (ip, _, payload)| {
                            if ip.dst_addr() == REMOTE_ADDR.into() {
                                Err(KeyedEmitError::<()>::KeyDeferred)
                            } else {
                                observed.push(payload.to_vec());
                                Ok(())
                            }
                        },
                    )
                    .is_ok()
            );
        }
        assert_eq!(observed, [b"b0".to_vec(), b"b1".to_vec()]);

        assert!(matches!(
            socket.dispatch_keyed(
                cx,
                &mut device,
                Some(egress_schedule(2, 1, 0)),
                |_, _, _, _| Err(KeyedEmitError::<()>::KeyDeferred),
            ),
            Err(KeyedDispatchError::AllKeysDeferred)
        ));

        // Neither defer consumed nor reordered A's head. A global error also
        // retains that exact head instead of rotating the burst.
        assert!(matches!(
            socket.dispatch_keyed(
                cx,
                &mut device,
                Some(egress_schedule(2, 1, 0)),
                |_, _, _, (_, _, payload)| {
                    assert_eq!(payload, b"a0");
                    Err(KeyedEmitError::Global(()))
                },
            ),
            Err(KeyedDispatchError::Global(()))
        ));

        for expected in [b"a0" as &[u8], b"a1"] {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(2, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        assert_eq!(payload, expected);
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }
        assert!(socket.can_send());
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn test_destination_burst_dispatch_scales_to_fifteen_interleaved_destinations() {
        const PEERS: usize = 15;
        const PACKETS_PER_PEER: usize = 4;

        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(PEERS * PACKETS_PER_PEER));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        for sequence in 0..PACKETS_PER_PEER as u8 {
            for peer in 0..PEERS as u8 {
                let endpoint = IpEndpoint {
                    addr: crate::wire::Ipv4Address::new(10, 0, 0, peer + 1).into(),
                    port: REMOTE_PORT,
                };
                assert_eq!(socket.send_slice(&[peer, sequence], endpoint), Ok(()));
            }
        }

        let mut observed = Vec::new();
        for _ in 0..PEERS * PACKETS_PER_PEER {
            assert_eq!(
                socket.dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(PACKETS_PER_PEER as u8, 1, 0)),
                    |_, _, _, (ip, _, payload)| {
                        observed.push((ip.dst_addr(), payload.to_vec()));
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                ),
                Ok(())
            );
        }

        for (peer, burst) in observed.chunks_exact(PACKETS_PER_PEER).enumerate() {
            let expected_address = crate::wire::Ipv4Address::new(10, 0, 0, peer as u8 + 1).into();
            for (sequence, (address, payload)) in burst.iter().enumerate() {
                assert_eq!(*address, expected_address);
                assert_eq!(payload.as_slice(), &[peer as u8, sequence as u8]);
            }
        }
        assert_eq!(observed.len(), PEERS * PACKETS_PER_PEER);
        assert!(socket.can_send());
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn test_resolved_egress_burst_scales_to_fifteen_full_ba32_queues() {
        const PEERS: usize = 15;
        const PACKETS_PER_PEER: usize = 32;

        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(PEERS * PACKETS_PER_PEER));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        // Use distinct IPv4 multicast destinations so every queue has a
        // resolved Ethernet key without coupling this selector test to the
        // separately tested neighbor-cache capacity. Producer order is fully
        // interleaved across all fifteen peers.
        for sequence in 0..PACKETS_PER_PEER as u8 {
            for peer in 0..PEERS as u8 {
                let endpoint = IpEndpoint {
                    addr: crate::wire::Ipv4Address::new(224, 0, 0, peer + 1).into(),
                    port: REMOTE_PORT,
                };
                assert_eq!(socket.send_slice(&[peer, sequence], endpoint), Ok(()));
            }
        }

        let mut observed = Vec::new();
        for _ in 0..PEERS * PACKETS_PER_PEER {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(PACKETS_PER_PEER as u8, 1, 0)),
                    |_, _, _, (ip, _, payload)| {
                        observed.push((ip.dst_addr(), payload.to_vec()));
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }

        for (peer, burst) in observed.chunks_exact(PACKETS_PER_PEER).enumerate() {
            let expected_address = crate::wire::Ipv4Address::new(224, 0, 0, peer as u8 + 1).into();
            for (sequence, (address, payload)) in burst.iter().enumerate() {
                assert_eq!(*address, expected_address);
                assert_eq!(payload.as_slice(), &[peer as u8, sequence as u8]);
            }
        }
        assert_eq!(observed.len(), PEERS * PACKETS_PER_PEER);
        assert!(socket.can_send());
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn test_128_packet_backlog_cannot_prefill_ba32_for_fifteen_peers() {
        const PEERS: usize = 15;
        const BACKLOG: usize = 128;

        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(BACKLOG));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        for packet in 0..BACKLOG {
            let peer = (packet % PEERS) as u8;
            let endpoint = IpEndpoint {
                addr: crate::wire::Ipv4Address::new(224, 0, 0, peer + 1).into(),
                port: REMOTE_PORT,
            };
            assert_eq!(socket.send_slice(&[peer], endpoint), Ok(()));
        }

        let mut observed = Vec::new();
        for _ in 0..10 {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(32, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        observed.push(payload[0]);
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }

        // Eight complete producer rounds fit, followed by eight entries from
        // the ninth round. Peer zero therefore owns only nine packets and the
        // selector must rotate before BA32. This is software-backlog geometry,
        // not a reason to grow the DMA-visible SRAM working set.
        assert_eq!(&observed[..9], &[0; 9]);
        assert_eq!(observed[9], 1);
    }

    #[cfg(all(feature = "tx-egress-metadata", feature = "proto-ipv4"))]
    #[test]
    fn test_destination_index_overflow_falls_back_without_rejecting_packets() {
        const PEERS: usize = EGRESS_QUEUE_CAPACITY + 1;

        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(PEERS));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        for peer in 0..PEERS as u8 {
            let endpoint = IpEndpoint {
                addr: crate::wire::Ipv4Address::new(10, 0, 1, peer + 1).into(),
                port: REMOTE_PORT,
            };
            assert_eq!(socket.send_slice(&[peer], endpoint), Ok(()));
        }

        let mut observed = Vec::new();
        for _ in 0..PEERS {
            assert_eq!(
                socket.dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(4, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        observed.push(payload[0]);
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                ),
                Ok(())
            );
        }
        assert_eq!(observed, (0..PEERS as u8).collect::<Vec<_>>());
        assert!(socket.can_send());

        // Draining the over-capacity live set permits a later bounded set to
        // activate the index normally.
        for (payload, destination) in [
            (b"a0" as &[u8], REMOTE_END),
            (
                b"b0",
                IpEndpoint {
                    addr: OTHER_ADDR.into(),
                    port: REMOTE_PORT,
                },
            ),
            (b"a1", REMOTE_END),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }
        observed.clear();
        for _ in 0..3 {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(4, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        observed.push(payload[1]);
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }
        assert_eq!(observed, b"010");
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_switching_back_to_fifo_clears_intrusive_index_links() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), buffer(6));
        let other = IpEndpoint {
            addr: OTHER_ADDR.into(),
            port: REMOTE_PORT,
        };
        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        for (payload, destination) in [
            (b"a0" as &[u8], REMOTE_END),
            (b"b0", other),
            (b"a1", REMOTE_END),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }

        // Activate the index, then fail emission so ownership remains queued.
        assert!(
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(2, 1, 0)),
                    |_, _, _, (_, _, _)| Result::<(), KeyedEmitError<()>>::Err(
                        KeyedEmitError::Global(()),
                    ),
                )
                .is_err()
        );

        let mut observed = Vec::new();
        for _ in 0..3 {
            socket
                .dispatch_keyed(cx, &mut device, None, |_, _, _, (_, _, payload)| {
                    observed.push(payload.to_vec());
                    Result::<(), KeyedEmitError<()>>::Ok(())
                })
                .unwrap();
        }
        assert_eq!(observed, [b"a0".to_vec(), b"b0".to_vec(), b"a1".to_vec()]);
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn indexed_slot_reuse_preserves_global_fifo_fallback() {
        let (mut iface, _, mut device) = setup(Medium::Ethernet);
        let cx = iface.context();
        let mut socket = socket(buffer(0), indexed_buffer(4));
        let other = IpEndpoint {
            addr: OTHER_ADDR.into(),
            port: REMOTE_PORT,
        };
        assert_eq!(socket.bind(LOCAL_END), Ok(()));
        for (payload, destination) in [
            (b"a0" as &[u8], REMOTE_END),
            (b"b0", other),
            (b"a1", REMOTE_END),
            (b"b1", other),
        ] {
            assert_eq!(socket.send_slice(payload, destination), Ok(()));
        }

        let mut selected = Vec::new();
        for _ in 0..2 {
            socket
                .dispatch_keyed(
                    cx,
                    &mut device,
                    Some(egress_schedule(2, 1, 0)),
                    |_, _, _, (_, _, payload)| {
                        selected.push(payload.to_vec());
                        Result::<(), KeyedEmitError<()>>::Ok(())
                    },
                )
                .unwrap();
        }
        assert_eq!(selected, [b"a0".to_vec(), b"a1".to_vec()]);

        assert_eq!(socket.send_slice(b"c0", REMOTE_END), Ok(()));
        assert_eq!(socket.send_slice(b"c1", REMOTE_END), Ok(()));
        let mut fifo = Vec::new();
        for _ in 0..4 {
            socket
                .dispatch_keyed(cx, &mut device, None, |_, _, _, (_, _, payload)| {
                    fifo.push(payload.to_vec());
                    Result::<(), KeyedEmitError<()>>::Ok(())
                })
                .unwrap();
        }
        assert_eq!(
            fifo,
            [
                b"b0".to_vec(),
                b"b1".to_vec(),
                b"c0".to_vec(),
                b"c1".to_vec(),
            ]
        );
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_recv_process(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(!socket.can_recv());
        assert_eq!(socket.recv(), Err(RecvError::Exhausted));

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );
        assert!(socket.can_recv());

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        assert_eq!(
            socket.recv(),
            Ok((&b"abcdef"[..], remote_metadata_with_local()))
        );
        assert!(!socket.can_recv());
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_peek_process(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert_eq!(socket.peek(), Err(RecvError::Exhausted));

        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );
        assert_eq!(
            socket.peek(),
            Ok((&b"abcdef"[..], &remote_metadata_with_local(),))
        );
        assert_eq!(
            socket.recv(),
            Ok((&b"abcdef"[..], remote_metadata_with_local(),))
        );
        assert_eq!(socket.peek(), Err(RecvError::Exhausted));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_recv_truncated_slice(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &REMOTE_UDP_REPR));
        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        let mut slice = [0; 4];
        assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_peek_truncated_slice(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        socket.process(
            cx,
            PacketMeta::default(),
            &REMOTE_IP_REPR,
            &REMOTE_UDP_REPR,
            PAYLOAD,
        );

        let mut slice = [0; 4];
        assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Truncated));
        assert_eq!(socket.recv_slice(&mut slice[..]), Err(RecvError::Truncated));
        assert_eq!(socket.peek_slice(&mut slice[..]), Err(RecvError::Exhausted));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_set_hop_limit(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut s = socket(buffer(0), buffer(1));

        assert_eq!(s.bind(LOCAL_END), Ok(()));

        s.set_hop_limit(Some(0x2a));
        assert_eq!(s.send_slice(b"abcdef", REMOTE_END), Ok(()));
        assert_eq!(
            s.dispatch(cx, |_, _, (ip_repr, _, _)| {
                assert_eq!(
                    ip_repr,
                    IpReprIpvX(IpvXRepr {
                        src_addr: LOCAL_ADDR,
                        dst_addr: REMOTE_ADDR,
                        next_header: IpProtocol::Udp,
                        payload_len: 8 + 6,
                        hop_limit: 0x2a,
                    })
                );
                Ok::<_, ()>(())
            }),
            Ok(())
        );
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_doesnt_accept_wrong_port(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut socket = socket(buffer(1), buffer(0));

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let mut udp_repr = REMOTE_UDP_REPR;
        assert!(socket.accepts(cx, &REMOTE_IP_REPR, &udp_repr));
        udp_repr.dst_port += 1;
        assert!(!socket.accepts(cx, &REMOTE_IP_REPR, &udp_repr));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_doesnt_accept_wrong_ip(#[case] medium: Medium) {
        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        let mut port_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(port_bound_socket.bind(LOCAL_PORT), Ok(()));
        assert!(port_bound_socket.accepts(cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));

        let mut ip_bound_socket = socket(buffer(1), buffer(0));
        assert_eq!(ip_bound_socket.bind(LOCAL_END), Ok(()));
        assert!(!ip_bound_socket.accepts(cx, &BAD_IP_REPR, &REMOTE_UDP_REPR));
    }

    #[test]
    fn test_send_large_packet() {
        // buffer(4) creates a payload buffer of size 16*4
        let mut socket = socket(buffer(0), buffer(4));
        assert_eq!(socket.bind(LOCAL_END), Ok(()));

        let too_large = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefx";
        assert_eq!(
            socket.send_slice(too_large, REMOTE_END),
            Err(SendError::BufferFull)
        );
        assert_eq!(socket.send_slice(&too_large[..16 * 4], REMOTE_END), Ok(()));
    }

    #[rstest]
    #[case::ip(Medium::Ip)]
    #[cfg(feature = "medium-ip")]
    #[case::ethernet(Medium::Ethernet)]
    #[cfg(feature = "medium-ethernet")]
    #[case::ieee802154(Medium::Ieee802154)]
    #[cfg(feature = "medium-ieee802154")]
    fn test_process_empty_payload(#[case] medium: Medium) {
        let meta = Box::leak(Box::new([PacketMetadata::EMPTY]));
        let recv_buffer = PacketBuffer::new(&mut meta[..], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));

        let (mut iface, _, _) = setup(medium);
        let cx = iface.context();

        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        let repr = UdpRepr {
            src_port: REMOTE_PORT,
            dst_port: LOCAL_PORT,
        };
        socket.process(cx, PacketMeta::default(), &REMOTE_IP_REPR, &repr, &[]);
        assert_eq!(socket.recv(), Ok((&[][..], remote_metadata_with_local())));
    }

    #[test]
    fn test_closing() {
        let meta = Box::leak(Box::new([PacketMetadata::EMPTY]));
        let recv_buffer = PacketBuffer::new(&mut meta[..], vec![]);
        let mut socket = socket(recv_buffer, buffer(0));
        assert_eq!(socket.bind(LOCAL_PORT), Ok(()));

        assert!(socket.is_open());
        socket.close();
        assert!(!socket.is_open());
    }
}
