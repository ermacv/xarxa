use managed::ManagedSlice;

use crate::storage::{Full, RingBuffer};

use super::Empty;

/// Size and header of a packet.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PacketMetadata<H> {
    size: usize,
    header: Option<H>,
    #[cfg(feature = "tx-egress-metadata")]
    payload_sequence: u32,
    #[cfg(feature = "tx-egress-metadata")]
    next_egress: Option<PacketHandle>,
    #[cfg(feature = "tx-egress-metadata")]
    next_slot: Option<u16>,
    #[cfg(feature = "tx-egress-metadata")]
    previous_slot: Option<u16>,
}

impl<H> PacketMetadata<H> {
    /// Empty packet description.
    pub const EMPTY: PacketMetadata<H> = PacketMetadata {
        size: 0,
        header: None,
        #[cfg(feature = "tx-egress-metadata")]
        payload_sequence: 0,
        #[cfg(feature = "tx-egress-metadata")]
        next_egress: None,
        #[cfg(feature = "tx-egress-metadata")]
        next_slot: None,
        #[cfg(feature = "tx-egress-metadata")]
        previous_slot: None,
    };

    #[cfg(not(feature = "tx-egress-metadata"))]
    fn padding(size: usize) -> PacketMetadata<H> {
        PacketMetadata { size, header: None }
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn padding(size: usize, payload_sequence: u32) -> PacketMetadata<H> {
        PacketMetadata {
            size: size,
            header: None,
            payload_sequence,
            next_egress: None,
            next_slot: None,
            previous_slot: None,
        }
    }

    #[cfg(not(feature = "tx-egress-metadata"))]
    fn packet(size: usize, header: H) -> PacketMetadata<H> {
        PacketMetadata {
            size,
            header: Some(header),
        }
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn packet(size: usize, header: H, payload_sequence: u32) -> PacketMetadata<H> {
        PacketMetadata {
            size: size,
            header: Some(header),
            payload_sequence,
            next_egress: None,
            next_slot: None,
            previous_slot: None,
        }
    }

    fn is_padding(&self) -> bool {
        self.header.is_none()
    }
}

/// An UDP packet ring buffer.
#[derive(Debug)]
pub struct PacketBuffer<'a, H: 'a> {
    metadata_ring: RingBuffer<'a, PacketMetadata<H>>,
    payload_ring: RingBuffer<'a, u8>,
    #[cfg(feature = "tx-egress-metadata")]
    storage: PacketStorage,
    #[cfg(feature = "tx-egress-metadata")]
    metadata_base_sequence: u32,
    #[cfg(feature = "tx-egress-metadata")]
    next_sequence: u32,
    #[cfg(feature = "tx-egress-metadata")]
    next_payload_sequence: u32,
    #[cfg(feature = "tx-egress-metadata")]
    payload_base_sequence: u32,
}

/// Packet payload ownership policy.
///
/// The ordinary ring is compact for FIFO traffic. Indexed slots trade unused
/// tail bytes in short packets for O(1), out-of-order reclamation: a stalled
/// destination cannot pin payload or metadata capacity owned by another key.
#[derive(Debug)]
#[cfg(feature = "tx-egress-metadata")]
enum PacketStorage {
    Ring,
    IndexedSlots {
        free_head: Option<u16>,
        fifo_head: Option<u16>,
        fifo_tail: Option<u16>,
        live: usize,
        payload_bytes: usize,
        slot_size: usize,
        next_generation: u16,
    },
}

/// Stable identity of one allocated packet while it remains in the bounded
/// packet arena. Handles survive out-of-order removal of older packets; they
/// never expose an address and are invalid after their packet is reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "tx-egress-metadata")]
pub(crate) struct PacketHandle(u32);

/// Ephemeral location of one packet selected while the buffer is exclusively
/// borrowed. It cannot outlive or mutate the packet ring on its own.
#[derive(Debug, Clone, Copy)]
#[cfg(feature = "tx-egress-metadata")]
pub(crate) struct PacketSelection {
    metadata_offset: usize,
    payload_offset: usize,
    payload_size: usize,
}

/// Position from which a bounded selector resumes scanning. Keeping both ring
/// offsets avoids walking the payload metadata prefix again for every packet
/// in a burst.
#[derive(Debug, Clone, Copy, Default)]
#[cfg(feature = "tx-egress-metadata")]
pub(crate) struct PacketCursor {
    metadata_offset: usize,
    payload_offset: usize,
}

impl<'a, H> PacketBuffer<'a, H> {
    /// Create a new packet buffer with the provided metadata and payload storage.
    ///
    /// Metadata storage limits the maximum _number_ of packets in the buffer and payload
    /// storage limits the maximum _total size_ of packets.
    pub fn new<MS, PS>(metadata_storage: MS, payload_storage: PS) -> PacketBuffer<'a, H>
    where
        MS: Into<ManagedSlice<'a, PacketMetadata<H>>>,
        PS: Into<ManagedSlice<'a, u8>>,
    {
        PacketBuffer {
            metadata_ring: RingBuffer::new(metadata_storage),
            payload_ring: RingBuffer::new(payload_storage),
            #[cfg(feature = "tx-egress-metadata")]
            storage: PacketStorage::Ring,
            #[cfg(feature = "tx-egress-metadata")]
            metadata_base_sequence: 0,
            #[cfg(feature = "tx-egress-metadata")]
            next_sequence: 0,
            #[cfg(feature = "tx-egress-metadata")]
            next_payload_sequence: 0,
            #[cfg(feature = "tx-egress-metadata")]
            payload_base_sequence: 0,
        }
    }

    /// Create a packet pool whose metadata and payload slots are independently
    /// reclaimable. Each metadata entry owns one equal-sized payload slot.
    ///
    /// This layout is intended for keyed egress queues. It avoids the global
    /// FIFO reclaim dependency of [`Self::new`] without allocating or copying
    /// packet payloads. `payload_storage.len() / metadata_storage.len()` is the
    /// maximum packet size; any remainder stays unused.
    #[cfg(feature = "tx-egress-metadata")]
    pub fn new_indexed_slots<MS, PS>(
        metadata_storage: MS,
        payload_storage: PS,
    ) -> PacketBuffer<'a, H>
    where
        MS: Into<ManagedSlice<'a, PacketMetadata<H>>>,
        PS: Into<ManagedSlice<'a, u8>>,
    {
        let mut metadata_ring = RingBuffer::new(metadata_storage);
        let payload_ring = RingBuffer::new(payload_storage);
        let capacity = metadata_ring.capacity();
        assert!(
            capacity <= usize::from(u16::MAX),
            "indexed packet slot count fits u16"
        );
        let slot_size = if capacity == 0 {
            0
        } else {
            payload_ring.capacity() / capacity
        };
        for index in 0..capacity {
            let metadata = metadata_ring
                .storage_mut(index)
                .expect("indexed packet metadata storage remains addressable");
            *metadata = PacketMetadata::EMPTY;
            metadata.next_slot = (index + 1 < capacity)
                .then(|| u16::try_from(index + 1).expect("indexed packet slot fits u16"));
        }
        PacketBuffer {
            metadata_ring,
            payload_ring,
            storage: PacketStorage::IndexedSlots {
                free_head: (capacity != 0).then_some(0),
                fifo_head: None,
                fifo_tail: None,
                live: 0,
                payload_bytes: 0,
                slot_size,
                next_generation: 1,
            },
            metadata_base_sequence: 0,
            next_sequence: 0,
            next_payload_sequence: 0,
            payload_base_sequence: 0,
        }
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn indexed_slot_from_handle(handle: PacketHandle) -> usize {
        usize::from((handle.0 & u32::from(u16::MAX)) as u16)
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn indexed_metadata(&self, index: usize) -> &PacketMetadata<H> {
        self.metadata_ring
            .storage(index)
            .expect("indexed packet metadata remains addressable")
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn indexed_metadata_mut(&mut self, index: usize) -> &mut PacketMetadata<H> {
        self.metadata_ring
            .storage_mut(index)
            .expect("indexed packet metadata remains addressable")
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn indexed_live_slot(&self, handle: PacketHandle) -> Option<usize> {
        let index = Self::indexed_slot_from_handle(handle);
        let metadata = self.metadata_ring.storage(index)?;
        (metadata.header.is_some() && metadata.payload_sequence == handle.0).then_some(index)
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn enqueue_indexed_slot(
        &mut self,
        size: usize,
        header: H,
        previous: Option<PacketHandle>,
    ) -> Result<(PacketHandle, &mut [u8]), Full> {
        let PacketBuffer {
            metadata_ring,
            payload_ring,
            storage,
            ..
        } = self;
        let PacketStorage::IndexedSlots {
            free_head,
            fifo_head,
            fifo_tail,
            live,
            payload_bytes,
            slot_size,
            next_generation,
        } = storage
        else {
            unreachable!("indexed enqueue requires indexed packet storage")
        };
        if size > *slot_size {
            return Err(Full);
        }
        let index = usize::from(free_head.ok_or(Full)?);
        let old = metadata_ring
            .storage(index)
            .expect("free indexed packet slot remains addressable");
        *free_head = old.next_slot;

        let generation = *next_generation;
        *next_generation = next_generation.wrapping_add(1).max(1);
        let index_u16 = u16::try_from(index).expect("indexed packet slot fits u16");
        let handle = PacketHandle((u32::from(generation) << 16) | u32::from(index_u16));
        let previous_fifo = *fifo_tail;
        *metadata_ring
            .storage_mut(index)
            .expect("claimed indexed packet slot remains addressable") = PacketMetadata {
            size,
            header: Some(header),
            payload_sequence: handle.0,
            next_egress: None,
            next_slot: None,
            previous_slot: previous_fifo,
        };
        if let Some(tail) = previous_fifo {
            metadata_ring
                .storage_mut(usize::from(tail))
                .expect("indexed FIFO tail remains addressable")
                .next_slot = Some(index_u16);
        } else {
            *fifo_head = Some(index_u16);
        }
        *fifo_tail = Some(index_u16);
        *live += 1;
        *payload_bytes += size;

        if let Some(previous) = previous {
            let previous_index = Self::indexed_slot_from_handle(previous);
            let previous_metadata = metadata_ring
                .storage_mut(previous_index)
                .filter(|metadata| {
                    metadata.header.is_some() && metadata.payload_sequence == previous.0
                })
                .expect("an indexed egress tail handle remains allocated");
            assert!(
                previous_metadata.next_egress.replace(handle).is_none(),
                "an indexed egress tail is linked exactly once"
            );
        }

        let offset = index * *slot_size;
        let payload = payload_ring
            .storage_range_mut(offset, *slot_size)
            .expect("indexed packet payload slot remains addressable");
        assert_eq!(payload.len(), *slot_size);
        Ok((handle, &mut payload[..size]))
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn release_indexed_slot(&mut self, index: usize) {
        let PacketBuffer {
            metadata_ring,
            storage,
            ..
        } = self;
        let PacketStorage::IndexedSlots {
            free_head,
            fifo_head,
            fifo_tail,
            live,
            payload_bytes,
            ..
        } = storage
        else {
            unreachable!("indexed release requires indexed packet storage")
        };
        let (previous_slot, next_slot, size) = {
            let metadata = metadata_ring
                .storage(index)
                .expect("live indexed packet slot remains addressable");
            (metadata.previous_slot, metadata.next_slot, metadata.size)
        };
        let index_u16 = u16::try_from(index).expect("indexed packet slot fits u16");
        if let Some(previous) = previous_slot {
            metadata_ring
                .storage_mut(usize::from(previous))
                .expect("indexed FIFO predecessor remains addressable")
                .next_slot = next_slot;
        } else {
            *fifo_head = next_slot;
        }
        if let Some(next) = next_slot {
            metadata_ring
                .storage_mut(usize::from(next))
                .expect("indexed FIFO successor remains addressable")
                .previous_slot = previous_slot;
        } else {
            *fifo_tail = previous_slot;
        }
        let slot = metadata_ring
            .storage_mut(index)
            .expect("released indexed packet slot remains addressable");
        *slot = PacketMetadata::EMPTY;
        slot.next_slot = *free_head;
        *free_head = Some(index_u16);
        *live -= 1;
        *payload_bytes -= size;
    }

    /// Query whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            self.metadata_ring.is_empty()
        }
        #[cfg(feature = "tx-egress-metadata")]
        match self.storage {
            PacketStorage::Ring => self.metadata_ring.is_empty(),
            PacketStorage::IndexedSlots { live, .. } => live == 0,
        }
    }

    /// Query whether the buffer is full.
    pub fn is_full(&self) -> bool {
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            self.metadata_ring.is_full()
        }
        #[cfg(feature = "tx-egress-metadata")]
        match self.storage {
            PacketStorage::Ring => self.metadata_ring.is_full(),
            PacketStorage::IndexedSlots { free_head, .. } => free_head.is_none(),
        }
    }

    // There is currently no enqueue_with() because of the complexity of managing padding
    // in case of failure.

    /// Enqueue a single packet with the given header into the buffer, and
    /// return a reference to its payload, or return `Err(Full)`
    /// if the buffer is full.
    pub fn enqueue(&mut self, size: usize, header: H) -> Result<&mut [u8], Full> {
        #[cfg(feature = "tx-egress-metadata")]
        {
            self
                .enqueue_tracked(size, header)
                .map(|(_, payload)| payload)
        }
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            if self.payload_ring.capacity() < size || self.metadata_ring.is_full() {
                return Err(Full);
            }

            if self.payload_ring.is_empty() {
                self.payload_ring.clear();
            }

            let window = self.payload_ring.window();
            let contig_window = self.payload_ring.contiguous_window();
            if window < size {
                return Err(Full);
            } else if contig_window < size {
                if window - contig_window < size {
                    return Err(Full);
                }
                *self.metadata_ring.enqueue_one()? = PacketMetadata::padding(contig_window);
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }

            *self.metadata_ring.enqueue_one()? = PacketMetadata::packet(size, header);
            let payload_buf = self.payload_ring.enqueue_many(size);
            debug_assert_eq!(payload_buf.len(), size);
            Ok(payload_buf)
        }
    }

    /// Enqueue a packet and return its stable arena handle together with the
    /// payload storage. The handle is used only by bounded egress indexes; it
    /// does not transfer or expose storage ownership.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn enqueue_tracked(
        &mut self,
        size: usize,
        header: H,
    ) -> Result<(PacketHandle, &mut [u8]), Full> {
        self.enqueue_tracked_linked(size, header, None)
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn enqueue_tracked_linked(
        &mut self,
        size: usize,
        header: H,
        previous: Option<PacketHandle>,
    ) -> Result<(PacketHandle, &mut [u8]), Full> {
        if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            return self.enqueue_indexed_slot(size, header, previous);
        }
        if self.payload_ring.capacity() < size || self.metadata_ring.is_full() {
            return Err(Full);
        }

        // Ring is currently empty.  Clear it (resetting `read_at`) to maximize
        // for contiguous space.
        if self.payload_ring.is_empty() {
            self.payload_ring.clear();
            self.payload_base_sequence = self.next_payload_sequence;
        }

        let window = self.payload_ring.window();
        let contig_window = self.payload_ring.contiguous_window();

        if window < size {
            return Err(Full);
        } else if contig_window < size {
            if window - contig_window < size {
                // The buffer length is larger than the current contiguous window
                // and is larger than the contiguous window will be after adding
                // the padding necessary to circle around to the beginning of the
                // ring buffer.
                return Err(Full);
            } else {
                // Add padding to the end of the ring buffer so that the
                // contiguous window is at the beginning of the ring buffer.
                *self.metadata_ring.enqueue_one()? =
                    PacketMetadata::padding(contig_window, self.next_payload_sequence);
                self.next_sequence = self.next_sequence.wrapping_add(1);
                self.next_payload_sequence = self
                    .next_payload_sequence
                    .wrapping_add(contig_window as u32);
                // note(discard): function does not write to the result
                // enqueued padding buffer location
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }
        }

        let handle = PacketHandle(self.next_sequence);
        *self.metadata_ring.enqueue_one()? =
            PacketMetadata::packet(size, header, self.next_payload_sequence);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.next_payload_sequence = self.next_payload_sequence.wrapping_add(size as u32);

        if let Some(previous) = previous {
            let offset = self
                .handle_offset(previous)
                .expect("an egress tail handle remains allocated");
            let metadata = self
                .metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("an allocated egress tail remains addressable");
            assert!(
                metadata.header.is_some(),
                "an egress tail is not a tombstone"
            );
            assert!(
                metadata.next_egress.replace(handle).is_none(),
                "an egress tail is linked exactly once"
            );
        }

        let payload_buf = self.payload_ring.enqueue_many(size);
        debug_assert!(payload_buf.len() == size);
        Ok((handle, payload_buf))
    }

    /// Call `f` with a packet from the buffer large enough to fit `max_size` bytes. The packet
    /// is shrunk to the size returned from `f` and enqueued into the buffer.
    pub fn enqueue_with_infallible<F>(
        &mut self,
        max_size: usize,
        header: H,
        f: F,
    ) -> Result<usize, Full>
    where
        F: for<'b> FnOnce(&'b mut [u8]) -> usize,
    {
        #[cfg(feature = "tx-egress-metadata")]
        {
            self
                .enqueue_with_infallible_tracked(max_size, header, f)
                .map(|(size, _)| size)
        }
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            if self.payload_ring.capacity() < max_size || self.metadata_ring.is_full() {
                return Err(Full);
            }

            let window = self.payload_ring.window();
            let contig_window = self.payload_ring.contiguous_window();
            if window < max_size {
                return Err(Full);
            } else if contig_window < max_size {
                if window - contig_window < max_size {
                    return Err(Full);
                }
                *self.metadata_ring.enqueue_one()? = PacketMetadata::padding(contig_window);
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }

            let metadata_slot = self.metadata_ring.enqueue_one()?;
            let (size, _) = self
                .payload_ring
                .enqueue_many_with(|data| (f(&mut data[..max_size]), ()));
            *metadata_slot = PacketMetadata::packet(size, header);
            Ok(size)
        }
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn enqueue_with_infallible_tracked<F>(
        &mut self,
        max_size: usize,
        header: H,
        f: F,
    ) -> Result<(usize, PacketHandle), Full>
    where
        F: for<'b> FnOnce(&'b mut [u8]) -> usize,
    {
        self.enqueue_with_infallible_tracked_linked(max_size, header, None, f)
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn enqueue_with_infallible_tracked_linked<F>(
        &mut self,
        max_size: usize,
        header: H,
        previous: Option<PacketHandle>,
        f: F,
    ) -> Result<(usize, PacketHandle), Full>
    where
        F: for<'b> FnOnce(&'b mut [u8]) -> usize,
    {
        if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            let (handle, payload) = self.enqueue_indexed_slot(max_size, header, previous)?;
            let size = f(payload);
            assert!(size <= max_size);
            let index = Self::indexed_slot_from_handle(handle);
            let removed = max_size - size;
            self.indexed_metadata_mut(index).size = size;
            let PacketStorage::IndexedSlots { payload_bytes, .. } = &mut self.storage else {
                unreachable!()
            };
            *payload_bytes -= removed;
            return Ok((size, handle));
        }
        if self.payload_ring.capacity() < max_size || self.metadata_ring.is_full() {
            return Err(Full);
        }

        if self.payload_ring.is_empty() {
            self.payload_ring.clear();
            self.payload_base_sequence = self.next_payload_sequence;
        }

        let window = self.payload_ring.window();
        let contig_window = self.payload_ring.contiguous_window();

        if window < max_size {
            return Err(Full);
        } else if contig_window < max_size {
            if window - contig_window < max_size {
                // The buffer length is larger than the current contiguous window
                // and is larger than the contiguous window will be after adding
                // the padding necessary to circle around to the beginning of the
                // ring buffer.
                return Err(Full);
            } else {
                // Add padding to the end of the ring buffer so that the
                // contiguous window is at the beginning of the ring buffer.
                *self.metadata_ring.enqueue_one()? =
                    PacketMetadata::padding(contig_window, self.next_payload_sequence);
                self.next_sequence = self.next_sequence.wrapping_add(1);
                self.next_payload_sequence = self
                    .next_payload_sequence
                    .wrapping_add(contig_window as u32);
                // note(discard): function does not write to the result
                // enqueued padding buffer location
                let _buf_enqueued = self.payload_ring.enqueue_many(contig_window);
            }
        }

        let handle = PacketHandle(self.next_sequence);
        if let Some(previous) = previous {
            let offset = self
                .handle_offset(previous)
                .expect("an egress tail handle remains allocated");
            let metadata = self
                .metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("an allocated egress tail remains addressable");
            assert!(
                metadata.header.is_some(),
                "an egress tail is not a tombstone"
            );
            assert!(
                metadata.next_egress.replace(handle).is_none(),
                "an egress tail is linked exactly once"
            );
        }
        let metadata_slot = self.metadata_ring.enqueue_one()?;

        // Only call f once we know that we will succeed
        let (size, _) = self
            .payload_ring
            .enqueue_many_with(|data| (f(&mut data[..max_size]), ()));

        *metadata_slot = PacketMetadata::packet(size, header, self.next_payload_sequence);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.next_payload_sequence = self.next_payload_sequence.wrapping_add(size as u32);

        Ok((size, handle))
    }

    #[cfg(not(feature = "tx-egress-metadata"))]
    fn dequeue_padding(&mut self) {
        let _ = self.metadata_ring.dequeue_one_with(|metadata| {
            if metadata.is_padding() {
                let _buf_dequeued = self.payload_ring.dequeue_many(metadata.size);
                Ok(())
            } else {
                Err(())
            }
        });
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn dequeue_padding(&mut self) -> PacketCursor {
        if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            return PacketCursor::default();
        }
        // A packet selected out of global FIFO order becomes a tombstone until
        // every older packet has completed. Reclaim the complete contiguous
        // tombstone/padding prefix so arbitrary selection never leaves payload
        // capacity permanently stranded.
        let mut reclaimed = PacketCursor::default();
        loop {
            let mut payload_size = 0;
            let outcome = self.metadata_ring.dequeue_one_with(|metadata| {
                if metadata.is_padding() {
                    payload_size = metadata.size;
                    // note(discard): function does not use value of dequeued padding bytes
                    let _buf_dequeued = self.payload_ring.dequeue_many(metadata.size);
                    Ok(()) // dequeue metadata
                } else {
                    Err(()) // don't dequeue metadata
                }
            });
            if !matches!(outcome, Ok(Ok(()))) {
                break;
            }
            reclaimed.metadata_offset += 1;
            reclaimed.payload_offset += payload_size;
            self.payload_base_sequence =
                self.payload_base_sequence.wrapping_add(payload_size as u32);
            self.metadata_base_sequence = self.metadata_base_sequence.wrapping_add(1);
        }
        reclaimed
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn handle_offset(&self, handle: PacketHandle) -> Option<usize> {
        if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            return self.indexed_live_slot(handle);
        }
        let offset = handle.0.wrapping_sub(self.metadata_base_sequence) as usize;
        (offset < self.metadata_ring.len()).then_some(offset)
    }

    /// Inspect one live packet and its current intrusive egress successor.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn egress_entry(&self, handle: PacketHandle) -> (H, Option<PacketHandle>)
    where
        H: Copy,
    {
        let offset = self
            .handle_offset(handle)
            .expect("an egress packet handle remains allocated");
        let metadata = if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            self.metadata_ring
                .storage(offset)
                .expect("an indexed egress packet remains addressable")
        } else {
            self.metadata_ring
                .get_allocated(offset, 1)
                .first()
                .expect("an allocated egress packet remains addressable")
        };
        (
            metadata
                .header
                .expect("an egress packet is not a tombstone"),
            metadata.next_egress,
        )
    }

    /// Detach one live packet from its current intrusive egress successor.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn take_egress_next(&mut self, handle: PacketHandle) -> Option<PacketHandle> {
        let offset = self
            .handle_offset(handle)
            .expect("an egress packet handle remains allocated");
        let metadata = if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            self.metadata_ring
                .storage_mut(offset)
                .expect("an indexed egress packet remains addressable")
        } else {
            self.metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("an allocated egress packet remains addressable")
        };
        metadata.next_egress.take()
    }

    /// Link two live packets in one intrusive egress FIFO.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn link_egress(&mut self, tail: PacketHandle, next: PacketHandle) {
        let offset = self
            .handle_offset(tail)
            .expect("an egress tail handle remains allocated");
        let metadata = if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            self.metadata_ring
                .storage_mut(offset)
                .expect("an indexed egress tail remains addressable")
        } else {
            self.metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("an allocated egress tail remains addressable")
        };
        assert!(
            metadata.header.is_some(),
            "an egress tail is not a tombstone"
        );
        assert!(
            metadata.next_egress.replace(next).is_none(),
            "an egress tail is linked exactly once"
        );
    }

    /// Remove every intrusive egress link without changing packet ownership or
    /// FIFO order. This is used when a device changes queue policy or advances
    /// the classification epoch.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn clear_egress_links(&mut self) {
        if let PacketStorage::IndexedSlots { fifo_head, .. } = self.storage {
            let mut current = fifo_head;
            while let Some(index) = current {
                let metadata = self
                    .metadata_ring
                    .storage_mut(usize::from(index))
                    .expect("indexed FIFO packet remains addressable");
                current = metadata.next_slot;
                metadata.next_egress = None;
            }
            return;
        }
        let length = self.metadata_ring.len();
        for offset in 0..length {
            let metadata = self.metadata_ring.get_allocated_mut(offset, 1).first_mut();
            if let Some(metadata) = metadata {
                metadata.next_egress = None;
            }
        }
    }

    /// Rebuild intrusive egress links in one FIFO traversal. `predecessor`
    /// updates the external queue index and returns the prior tail for the
    /// current packet's key.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn rebuild_egress_links<F>(&mut self, mut predecessor: F)
    where
        H: Copy,
        F: FnMut(PacketHandle, H) -> Option<PacketHandle>,
    {
        self.clear_egress_links();
        if let PacketStorage::IndexedSlots { fifo_head, .. } = self.storage {
            let mut current = fifo_head;
            while let Some(index) = current {
                let (handle, header, next) = {
                    let metadata = self
                        .metadata_ring
                        .storage(usize::from(index))
                        .expect("indexed FIFO packet remains addressable");
                    (
                        PacketHandle(metadata.payload_sequence),
                        metadata
                            .header
                            .expect("indexed FIFO contains only live packets"),
                        metadata.next_slot,
                    )
                };
                if let Some(previous) = predecessor(handle, header) {
                    self.link_egress(previous, handle);
                }
                current = next;
            }
            return;
        }

        let length = self.metadata_ring.len();
        for offset in 0..length {
            let Some(header) = self
                .metadata_ring
                .get_allocated(offset, 1)
                .first()
                .and_then(|metadata| metadata.header)
            else {
                continue;
            };
            let handle = PacketHandle(self.metadata_base_sequence.wrapping_add(offset as u32));
            if let Some(previous) = predecessor(handle, header) {
                self.link_egress(previous, handle);
            }
        }
    }

    /// Complete a packet selected through an intrusive egress handle.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn dequeue_handle_with<R, E, F>(
        &mut self,
        handle: PacketHandle,
        f: F,
    ) -> (Result<R, E>, Option<PacketHandle>)
    where
        F: for<'b> FnOnce(&mut H, &'b mut [u8]) -> Result<R, E>,
    {
        if let PacketStorage::IndexedSlots { slot_size, .. } = self.storage {
            let index = self
                .indexed_live_slot(handle)
                .expect("a selected indexed packet handle remains allocated");
            let (size, next) = {
                let metadata = self.indexed_metadata(index);
                (metadata.size, metadata.next_egress)
            };
            let result = {
                let PacketBuffer {
                    metadata_ring,
                    payload_ring,
                    ..
                } = self;
                let metadata = metadata_ring
                    .storage_mut(index)
                    .expect("a selected indexed packet remains addressable");
                let payload = payload_ring
                    .storage_range_mut(index * slot_size, slot_size)
                    .expect("a selected indexed payload remains addressable");
                f(
                    metadata
                        .header
                        .as_mut()
                        .expect("a selected indexed packet remains live"),
                    &mut payload[..size],
                )
            };
            if result.is_ok() {
                self.release_indexed_slot(index);
            }
            return (result, next);
        }
        let offset = self
            .handle_offset(handle)
            .expect("a selected packet handle remains allocated");
        let (payload_offset, payload_size, next) = {
            let metadata = self
                .metadata_ring
                .get_allocated(offset, 1)
                .first()
                .expect("a selected packet remains addressable");
            let payload_offset = metadata
                .payload_sequence
                .wrapping_sub(self.payload_base_sequence) as usize;
            assert!(
                payload_offset <= self.payload_ring.len(),
                "a live payload remains inside the allocated ring window"
            );
            (payload_offset, metadata.size, metadata.next_egress)
        };
        let result = {
            let metadata = self
                .metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("a selected packet remains addressable");
            let payload = self
                .payload_ring
                .get_allocated_mut(payload_offset, payload_size);
            assert_eq!(
                payload.len(),
                payload_size,
                "packet enqueue padding keeps every payload contiguous"
            );
            f(
                metadata
                    .header
                    .as_mut()
                    .expect("a selected packet is not a tombstone"),
                payload,
            )
        };
        if result.is_ok() {
            self.metadata_ring
                .get_allocated_mut(offset, 1)
                .first_mut()
                .expect("a completed packet remains addressable")
                .header = None;
            self.dequeue_padding();
        }
        (result, next)
    }

    /// Return the first packet header matching `predicate` without removing
    /// that packet.
    ///
    /// Tombstones and ring-wrap padding are skipped. This is intended for a
    /// bounded queue selector which chooses a key before allocating final
    /// device backing.
    #[cfg(feature = "tx-egress-metadata")]
    pub fn first_header_matching<P>(&self, mut predicate: P) -> Option<H>
    where
        H: Copy,
        P: FnMut(&H) -> bool,
    {
        self.first_header_matching_from(PacketCursor::default(), |header| predicate(header))
            .map(|(_, header)| header)
    }

    /// Select the first matching packet at or after `cursor` and
    /// return both its copied header and an ephemeral removal token.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn first_header_matching_from<P>(
        &self,
        cursor: PacketCursor,
        mut predicate: P,
    ) -> Option<(PacketSelection, H)>
    where
        H: Copy,
        P: FnMut(&H) -> bool,
    {
        if let PacketStorage::IndexedSlots {
            fifo_head,
            slot_size,
            ..
        } = self.storage
        {
            let mut current = fifo_head;
            while let Some(index) = current {
                let index = usize::from(index);
                let metadata = self.indexed_metadata(index);
                if let Some(header) = metadata.header.as_ref()
                    && predicate(header)
                {
                    return Some((
                        PacketSelection {
                            metadata_offset: index,
                            payload_offset: index * slot_size,
                            payload_size: metadata.size,
                        },
                        *header,
                    ));
                }
                current = metadata.next_slot;
            }
            return None;
        }
        let mut payload_offset = cursor.payload_offset;
        for offset in cursor.metadata_offset..self.metadata_ring.len() {
            let metadata = self
                .metadata_ring
                .get_allocated(offset, 1)
                .first()
                .expect("an allocated metadata offset remains addressable");
            if let Some(header) = metadata.header.as_ref()
                && predicate(header)
            {
                return Some((
                    PacketSelection {
                        metadata_offset: offset,
                        payload_offset,
                        payload_size: metadata.size,
                    },
                    *header,
                ));
            }
            payload_offset += metadata.size;
        }
        None
    }

    /// Complete a packet chosen by [`Self::first_header_matching_from`].
    ///
    /// The returned cursor points at the first metadata and payload entries
    /// which followed the selected packet after reclaiming any newly
    /// contiguous tombstones.
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn dequeue_selection_with<R, E, F>(
        &mut self,
        selection: PacketSelection,
        f: F,
    ) -> (Result<R, E>, PacketCursor)
    where
        F: for<'b> FnOnce(&mut H, &'b mut [u8]) -> Result<R, E>,
    {
        if let PacketStorage::IndexedSlots { slot_size, .. } = self.storage {
            let index = selection.metadata_offset;
            let result = {
                let PacketBuffer {
                    metadata_ring,
                    payload_ring,
                    ..
                } = self;
                let metadata = metadata_ring
                    .storage_mut(index)
                    .filter(|metadata| metadata.header.is_some())
                    .expect("the selected indexed packet remains allocated");
                let payload = payload_ring
                    .storage_range_mut(index * slot_size, slot_size)
                    .expect("the selected indexed payload remains addressable");
                f(
                    metadata
                        .header
                        .as_mut()
                        .expect("the selected indexed packet remains live"),
                    &mut payload[..selection.payload_size],
                )
            };
            if result.is_ok() {
                self.release_indexed_slot(index);
            }
            return (result, PacketCursor::default());
        }
        let result = {
            let metadata = self
                .metadata_ring
                .get_allocated_mut(selection.metadata_offset, 1)
                .first_mut()
                .expect("the selected metadata remains allocated");
            let payload = self
                .payload_ring
                .get_allocated_mut(selection.payload_offset, selection.payload_size);
            assert_eq!(
                payload.len(),
                selection.payload_size,
                "packet enqueue padding keeps every payload contiguous"
            );
            f(
                metadata
                    .header
                    .as_mut()
                    .expect("the selected packet is not a tombstone"),
                payload,
            )
        };

        if result.is_err() {
            return (
                result,
                PacketCursor {
                    metadata_offset: selection.metadata_offset,
                    payload_offset: selection.payload_offset,
                },
            );
        }
        self.metadata_ring
            .get_allocated_mut(selection.metadata_offset, 1)
            .first_mut()
            .expect("the completed metadata remains allocated")
            .header = None;
        let reclaimed = self.dequeue_padding();
        let next = PacketCursor {
            metadata_offset: selection
                .metadata_offset
                .saturating_add(1)
                .saturating_sub(reclaimed.metadata_offset)
                .min(self.metadata_ring.len()),
            payload_offset: selection
                .payload_offset
                .saturating_add(selection.payload_size)
                .saturating_sub(reclaimed.payload_offset)
                .min(self.payload_ring.len()),
        };
        (result, next)
    }

    /// Call `f` with the oldest packet whose header matches `predicate`.
    ///
    /// Successful completion preserves FIFO order among packets with the same
    /// key while allowing independent keys to be scheduled out of global FIFO
    /// order. An out-of-order packet is tombstoned and its storage is reclaimed
    /// once every older packet has completed. If `f` fails, neither metadata nor
    /// payload ownership changes.
    #[cfg(feature = "tx-egress-metadata")]
    pub fn dequeue_matching_with<R, E, P, F>(
        &mut self,
        mut predicate: P,
        f: F,
    ) -> Result<Result<R, E>, Empty>
    where
        H: Copy,
        P: FnMut(&H) -> bool,
        F: for<'b> FnOnce(&mut H, &'b mut [u8]) -> Result<R, E>,
    {
        self.dequeue_padding();
        let (selection, _) = self
            .first_header_matching_from(PacketCursor::default(), |header| predicate(header))
            .ok_or(Empty)?;
        Ok(self.dequeue_selection_with(selection, f).0)
    }

    /// Call `f` with a single packet from the buffer, and dequeue the packet if `f`
    /// returns successfully, or return `Err(EmptyError)` if the buffer is empty.
    pub fn dequeue_with<R, E, F>(&mut self, f: F) -> Result<Result<R, E>, Empty>
    where
        F: for<'c> FnOnce(&mut H, &'c mut [u8]) -> Result<R, E>,
    {
        #[cfg(feature = "tx-egress-metadata")]
        if let PacketStorage::IndexedSlots {
            fifo_head,
            slot_size,
            ..
        } = self.storage
        {
            let index = usize::from(fifo_head.ok_or(Empty)?);
            let size = self.indexed_metadata(index).size;
            let result = {
                let PacketBuffer {
                    metadata_ring,
                    payload_ring,
                    ..
                } = self;
                let metadata = metadata_ring
                    .storage_mut(index)
                    .expect("indexed FIFO head remains addressable");
                let payload = payload_ring
                    .storage_range_mut(index * slot_size, slot_size)
                    .expect("indexed FIFO payload remains addressable");
                f(
                    metadata
                        .header
                        .as_mut()
                        .expect("indexed FIFO head remains live"),
                    &mut payload[..size],
                )
            };
            if result.is_ok() {
                self.release_indexed_slot(index);
            }
            return Ok(result);
        }
        self.dequeue_padding();

        #[cfg(feature = "tx-egress-metadata")]
        {
            let payload_base_sequence = &mut self.payload_base_sequence;
            let metadata_base_sequence = &mut self.metadata_base_sequence;
            self.metadata_ring.dequeue_one_with(|metadata| {
                self.payload_ring
                    .dequeue_many_with(|payload_buf| {
                        debug_assert!(payload_buf.len() >= metadata.size);

                        match f(
                            metadata.header.as_mut().unwrap(),
                            &mut payload_buf[..metadata.size],
                        ) {
                            Ok(val) => {
                                *payload_base_sequence =
                                    payload_base_sequence.wrapping_add(metadata.size as u32);
                                *metadata_base_sequence = metadata_base_sequence.wrapping_add(1);
                                (metadata.size, Ok(val))
                            }
                            Err(err) => (0, Err(err)),
                        }
                    })
                    .1
            })
        }
        #[cfg(not(feature = "tx-egress-metadata"))]
        self.metadata_ring.dequeue_one_with(|metadata| {
            self.payload_ring
                .dequeue_many_with(|payload_buf| {
                    debug_assert!(payload_buf.len() >= metadata.size);
                    match f(
                        metadata.header.as_mut().unwrap(),
                        &mut payload_buf[..metadata.size],
                    ) {
                        Ok(value) => (metadata.size, Ok(value)),
                        Err(error) => (0, Err(error)),
                    }
                })
                .1
        })
    }

    /// Dequeue a single packet from the buffer, and return a reference to its payload
    /// as well as its header, or return `Err(Error::Exhausted)` if the buffer is empty.
    pub fn dequeue(&mut self) -> Result<(H, &mut [u8]), Empty> {
        #[cfg(feature = "tx-egress-metadata")]
        if let PacketStorage::IndexedSlots {
            fifo_head,
            slot_size,
            ..
        } = self.storage
        {
            let index = usize::from(fifo_head.ok_or(Empty)?);
            let (header, size) = {
                let metadata = self.indexed_metadata_mut(index);
                (
                    metadata
                        .header
                        .take()
                        .expect("indexed FIFO head remains live"),
                    metadata.size,
                )
            };
            self.release_indexed_slot(index);
            let payload = self
                .payload_ring
                .storage_range_mut(index * slot_size, slot_size)
                .expect("indexed FIFO payload remains addressable");
            return Ok((header, &mut payload[..size]));
        }
        self.dequeue_padding();

        let meta = self.metadata_ring.dequeue_one()?;

        let payload_buf = self.payload_ring.dequeue_many(meta.size);
        #[cfg(feature = "tx-egress-metadata")]
        {
            self.payload_base_sequence = self.payload_base_sequence.wrapping_add(meta.size as u32);
            self.metadata_base_sequence = self.metadata_base_sequence.wrapping_add(1);
        }
        debug_assert!(payload_buf.len() == meta.size);
        Ok((meta.header.take().unwrap(), payload_buf))
    }

    /// Peek at a single packet from the buffer without removing it, and return a reference to
    /// its payload as well as its header, or return `Err(Error:Exhausted)` if the buffer is empty.
    ///
    /// This function otherwise behaves identically to [dequeue](#method.dequeue).
    pub fn peek(&mut self) -> Result<(&H, &[u8]), Empty> {
        #[cfg(feature = "tx-egress-metadata")]
        if let PacketStorage::IndexedSlots {
            fifo_head,
            slot_size,
            ..
        } = self.storage
        {
            let index = usize::from(fifo_head.ok_or(Empty)?);
            let PacketBuffer {
                metadata_ring,
                payload_ring,
                ..
            } = self;
            let metadata = metadata_ring
                .storage(index)
                .expect("indexed FIFO head remains addressable");
            let payload = payload_ring
                .storage_range(index * slot_size, metadata.size)
                .ok_or(Empty)?;
            return Ok((
                metadata
                    .header
                    .as_ref()
                    .expect("indexed FIFO head remains live"),
                payload,
            ));
        }
        self.dequeue_padding();

        if let Some(metadata) = self.metadata_ring.get_allocated(0, 1).first() {
            Ok((
                metadata.header.as_ref().unwrap(),
                self.payload_ring.get_allocated(0, metadata.size),
            ))
        } else {
            Err(Empty)
        }
    }

    /// Return the maximum number packets that can be stored.
    pub fn packet_capacity(&self) -> usize {
        self.metadata_ring.capacity()
    }

    /// Return the maximum number of bytes in the payload ring buffer.
    pub fn payload_capacity(&self) -> usize {
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            self.payload_ring.capacity()
        }
        #[cfg(feature = "tx-egress-metadata")]
        match self.storage {
            PacketStorage::Ring => self.payload_ring.capacity(),
            PacketStorage::IndexedSlots { slot_size, .. } => {
                slot_size * self.metadata_ring.capacity()
            }
        }
    }

    /// Return the current number of bytes in the payload ring buffer.
    pub fn payload_bytes_count(&self) -> usize {
        #[cfg(not(feature = "tx-egress-metadata"))]
        {
            self.payload_ring.len()
        }
        #[cfg(feature = "tx-egress-metadata")]
        match self.storage {
            PacketStorage::Ring => self.payload_ring.len(),
            PacketStorage::IndexedSlots { payload_bytes, .. } => payload_bytes,
        }
    }

    /// Reset the packet buffer and clear any staged.
    #[allow(unused)]
    pub(crate) fn reset(&mut self) {
        #[cfg(feature = "tx-egress-metadata")]
        if matches!(self.storage, PacketStorage::IndexedSlots { .. }) {
            let capacity = self.metadata_ring.capacity();
            for index in 0..capacity {
                let metadata = self
                    .metadata_ring
                    .storage_mut(index)
                    .expect("indexed packet metadata remains addressable");
                *metadata = PacketMetadata::EMPTY;
                metadata.next_slot = (index + 1 < capacity)
                    .then(|| u16::try_from(index + 1).expect("indexed packet slot fits u16"));
            }
            let PacketStorage::IndexedSlots {
                free_head,
                fifo_head,
                fifo_tail,
                live,
                payload_bytes,
                ..
            } = &mut self.storage
            else {
                unreachable!()
            };
            *free_head = (capacity != 0).then_some(0);
            *fifo_head = None;
            *fifo_tail = None;
            *live = 0;
            *payload_bytes = 0;
            return;
        }
        self.payload_ring.clear();
        self.metadata_ring.clear();
        #[cfg(feature = "tx-egress-metadata")]
        {
            self.metadata_base_sequence = self.next_sequence;
            self.payload_base_sequence = self.next_payload_sequence;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn buffer() -> PacketBuffer<'static, ()> {
        PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; 16])
    }

    #[test]
    fn test_simple() {
        let mut buffer = buffer();
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.enqueue(16, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue(), Err(Empty));
    }

    #[test]
    fn test_peek() {
        let mut buffer = buffer();
        assert_eq!(buffer.peek(), Err(Empty));
        buffer.enqueue(6, ()).unwrap().copy_from_slice(b"abcdef");
        assert_eq!(buffer.metadata_ring.len(), 1);
        assert_eq!(buffer.peek().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.dequeue().unwrap().1, &b"abcdef"[..]);
        assert_eq!(buffer.peek(), Err(Empty));
    }

    #[test]
    fn test_padding() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert_eq!(buffer.dequeue().unwrap().1, &b"abcd"[..]);
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[test]
    fn test_padding_with_large_payload() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(12, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer
            .enqueue(12, ())
            .unwrap()
            .copy_from_slice(b"abcdefghijkl");
    }

    #[test]
    fn test_dequeue_with() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(6, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        buffer.enqueue(4, ()).unwrap().copy_from_slice(b"abcd");
        assert_eq!(buffer.metadata_ring.len(), 3);
        assert!(buffer.dequeue().is_ok());

        assert!(matches!(
            buffer.dequeue_with(|_, _| Result::<(), u32>::Err(123)),
            Ok(Err(_))
        ));
        assert_eq!(buffer.metadata_ring.len(), 1);

        assert!(
            buffer
                .dequeue_with(|&mut (), payload| {
                    assert_eq!(payload, &b"abcd"[..]);
                    Result::<(), ()>::Ok(())
                })
                .is_ok()
        );
        assert_eq!(buffer.metadata_ring.len(), 0);
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_dequeue_matching_preserves_each_key_fifo_and_reclaims_tombstones() {
        let mut buffer = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0u8; 32]);
        for (key, payload) in [(1, b"a0" as &[u8]), (2, b"b0"), (1, b"a1"), (2, b"b1")] {
            buffer
                .enqueue(payload.len(), key)
                .unwrap()
                .copy_from_slice(payload);
        }

        let mut observed = Vec::new();
        for key in [1, 1, 2, 2] {
            buffer
                .dequeue_matching_with(
                    |header| *header == key,
                    |header, payload| {
                        observed.push((*header, payload.to_vec()));
                        Result::<(), ()>::Ok(())
                    },
                )
                .unwrap()
                .unwrap();
        }

        assert_eq!(
            observed,
            vec![
                (1, b"a0".to_vec()),
                (1, b"a1".to_vec()),
                (2, b"b0".to_vec()),
                (2, b"b1".to_vec()),
            ]
        );
        assert!(buffer.is_empty());
        assert_eq!(buffer.payload_bytes_count(), 0);
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn test_failed_matching_dequeue_retains_the_exact_packet() {
        let mut buffer = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; 16]);
        buffer.enqueue(2, 7u8).unwrap().copy_from_slice(b"ok");

        assert_eq!(
            buffer.dequeue_matching_with(|header| *header == 7, |_, _| Result::<(), u8>::Err(9),),
            Ok(Err(9))
        );
        let (header, payload) = buffer.dequeue().unwrap();
        assert_eq!(header, 7);
        assert_eq!(payload, b"ok");
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn indexed_slots_reclaim_out_of_order_payload_and_metadata_immediately() {
        let mut buffer =
            PacketBuffer::new_indexed_slots(vec![PacketMetadata::EMPTY; 4], vec![0u8; 16]);
        let (blocked, payload) = buffer.enqueue_tracked(4, 1u8).unwrap();
        payload.copy_from_slice(b"b000");
        let (first, payload) = buffer.enqueue_tracked(4, 2u8).unwrap();
        payload.copy_from_slice(b"a000");
        let (second, payload) = buffer.enqueue_tracked(4, 2u8).unwrap();
        payload.copy_from_slice(b"a001");
        let (third, payload) = buffer.enqueue_tracked(4, 2u8).unwrap();
        payload.copy_from_slice(b"a002");
        assert!(buffer.is_full());

        for (handle, expected) in [(first, b"a000"), (second, b"a001"), (third, b"a002")] {
            let (result, _) = buffer.dequeue_handle_with(handle, |header, payload| {
                assert_eq!(*header, 2);
                assert_eq!(payload, expected);
                Result::<(), ()>::Ok(())
            });
            result.unwrap();
        }
        assert_eq!(buffer.payload_bytes_count(), 4);
        assert!(!buffer.is_full());

        for value in [b"n000", b"n001", b"n002"] {
            buffer.enqueue(4, 3u8).unwrap().copy_from_slice(value);
        }
        assert!(buffer.is_full());

        let (result, _) = buffer.dequeue_handle_with(blocked, |header, payload| {
            assert_eq!(*header, 1);
            assert_eq!(payload, b"b000");
            Result::<(), ()>::Ok(())
        });
        result.unwrap();
        for expected in [b"n000", b"n001", b"n002"] {
            let (header, payload) = buffer.dequeue().unwrap();
            assert_eq!(header, 3);
            assert_eq!(payload, expected);
        }
        assert!(buffer.is_empty());
        assert_eq!(buffer.payload_bytes_count(), 0);
    }

    #[cfg(feature = "tx-egress-metadata")]
    #[test]
    fn indexed_slots_failed_handle_consume_retains_exact_owner() {
        let mut buffer =
            PacketBuffer::new_indexed_slots(vec![PacketMetadata::EMPTY; 2], vec![0u8; 8]);
        let (handle, payload) = buffer.enqueue_tracked(4, 7u8).unwrap();
        payload.copy_from_slice(b"keep");

        let (result, _) = buffer.dequeue_handle_with(handle, |_, _| Result::<(), u8>::Err(9));
        assert_eq!(result, Err(9));
        assert_eq!(buffer.payload_bytes_count(), 4);

        let (result, _) = buffer.dequeue_handle_with(handle, |header, payload| {
            assert_eq!(*header, 7);
            assert_eq!(payload, b"keep");
            Result::<(), ()>::Ok(())
        });
        result.unwrap();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_metadata_full_empty() {
        let mut buffer = buffer();
        assert!(buffer.is_empty());
        assert!(!buffer.is_full());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(!buffer.is_empty());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(!buffer.is_full());
        assert!(!buffer.is_empty());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.is_full());
        assert!(!buffer.is_empty());
        assert_eq!(buffer.metadata_ring.len(), 4);
        assert_eq!(buffer.enqueue(1, ()), Err(Full));
    }

    #[test]
    fn test_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(16, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_contiguous_window_too_small() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.enqueue(8, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert_eq!(buffer.enqueue(8, ()), Err(Full));
        assert_eq!(buffer.metadata_ring.len(), 1);
    }

    #[test]
    fn test_contiguous_window_wrap() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(15, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert!(buffer.enqueue(16, ()).is_ok());
    }

    #[test]
    fn test_capacity_too_small() {
        let mut buffer = buffer();
        assert_eq!(buffer.enqueue(32, ()), Err(Full));
    }

    #[test]
    fn test_contig_window_prioritized() {
        let mut buffer = buffer();
        assert!(buffer.enqueue(4, ()).is_ok());
        assert!(buffer.dequeue().is_ok());
        assert!(buffer.enqueue(5, ()).is_ok());
    }

    #[test]
    fn test_enqueue_fallible_full_metadata_fn_not_called() {
        // Fill the metadata buffer except 1 byte and then make room at the start
        let mut buffer = PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; 16]);

        assert!(buffer.enqueue(12, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        assert!(buffer.enqueue(1, ()).is_ok());
        let dequeued_buf = buffer.dequeue().unwrap();
        assert_eq!(dequeued_buf.1.len(), 12);

        // At this point there is room at the start of the payload storage
        // and 1 byte at the end of the payload storage
        // but only one metadata slot.
        assert!(
            buffer
                .enqueue_with_infallible(5, (), |_| {
                    panic!("This enqueue should fail and this closure should not be called")
                })
                .is_err()
        );
    }

    #[test]
    fn clear() {
        let mut buffer = buffer();

        // Ensure enqueuing data in the buffer fills it somewhat.
        assert!(buffer.is_empty());
        assert!(buffer.enqueue(6, ()).is_ok());

        // Ensure that resetting the buffer causes it to be empty.
        assert!(!buffer.is_empty());
        buffer.reset();
        assert!(buffer.is_empty());
    }
}
