//! Owned packet buffers.
//!
//! Every packet in the stack is a [`PacketBuf`]: one fixed-size buffer, owned by
//! whoever holds it (the driver, the stack, a socket, the application).
//!
//! Buffers are allocated from explicit static pools. [`PacketPool`] and
//! [`PacketPoolStorage`] let a system independently place multiple pools
//! without changing the packet type passed through drivers and the stack.

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
#[cfg(feature = "async")]
use core::task::Waker;

#[cfg(feature = "async")]
use atomic_waker::AtomicWaker;
#[cfg(feature = "async")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU32, Ordering};

// Explicit pools claim and release slots with atomic read-modify-write on the
// bitmap from any core; targets without it (e.g. thumbv6m) are not supported.
#[cfg(not(target_has_atomic = "32"))]
compile_error!("explicit packet pools need 32-bit atomic read-modify-write");

use crate::config::PACKET_BUF_SIZE;
use crate::meta::PacketMeta;

const MAX_PACKET_POOL_COUNT: usize = 1024;
const MAX_BITMAP_WORDS: usize = MAX_PACKET_POOL_COUNT.div_ceil(32);

cfg_select! {
    feature = "packet-buf-align-32" => { #[repr(C, align(32))] struct Data([u8; PACKET_BUF_SIZE]); }
    feature = "packet-buf-align-16" => { #[repr(C, align(16))] struct Data([u8; PACKET_BUF_SIZE]); }
    feature = "packet-buf-align-8" => { #[repr(C, align(8))] struct Data([u8; PACKET_BUF_SIZE]); }
    feature = "packet-buf-align-4" => { #[repr(C, align(4))] struct Data([u8; PACKET_BUF_SIZE]); }
    feature = "packet-buf-align-2" => { #[repr(C, align(2))] struct Data([u8; PACKET_BUF_SIZE]); }
    _ => { #[repr(C, align(1))] struct Data([u8; PACKET_BUF_SIZE]); }
}

impl Deref for Data {
    type Target = [u8; PACKET_BUF_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct PacketBufInner {
    /// Pool control which must receive this slot when the packet is dropped.
    origin: NonNull<PacketPoolHeader>,
    /// Slot within the originating pool.
    slot: usize,
    /// Offset of the first valid byte within `data`.
    headroom: u16,
    /// Number of valid bytes.
    len: u16,
    // invariant: headroom + len <= PACKET_BUF_SIZE
    /// Per-packet metadata. Zero-sized unless a `packetmeta-*` feature is enabled.
    meta: PacketMeta,
    /// Independently placed payload storage owned by this control slot.
    data: NonNull<Data>,
}

/// All fields read by the non-generic ownership operations precede the
/// variable-length control array in both kinds of origin.
#[repr(C)]
struct PacketPoolHeader {
    count: usize,
    kind: PacketOriginKind,
    used: [AtomicU32; MAX_BITMAP_WORDS],
    #[cfg(feature = "async")]
    waiter_claimed: AtomicBool,
    #[cfg(feature = "async")]
    waiter: AtomicWaker,
}

#[derive(Clone, Copy)]
enum PacketOriginKind {
    Pool {
        storage: *const UnsafeCell<MaybeUninit<Data>>,
    },
    #[cfg(feature = "external-origin")]
    External { drop_owner: ExternalOwnerDrop },
}

impl PacketPoolHeader {
    const fn new(count: usize, kind: PacketOriginKind) -> Self {
        Self {
            count,
            kind,
            used: [const { AtomicU32::new(0) }; MAX_BITMAP_WORDS],
            #[cfg(feature = "async")]
            waiter_claimed: AtomicBool::new(false),
            #[cfg(feature = "async")]
            waiter: AtomicWaker::new(),
        }
    }

    /// Claim the first free slot using the compact atomic bitmap protocol.
    fn alloc_slot(&self) -> Option<usize> {
        for (word_index, word) in self.used[..self.count.div_ceil(32)].iter().enumerate() {
            let mut current = word.load(Ordering::Relaxed);
            loop {
                let bit = current.trailing_ones() as usize;
                if bit >= 32 {
                    break;
                }
                let index = word_index * 32 + bit;
                if index >= self.count {
                    return None;
                }
                // Acquire pairs with release_slot's Release: the preceding
                // owner has finished with the control and payload slots.
                match word.compare_exchange_weak(current, current | (1 << bit), Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => return Some(index),
                    Err(actual) => current = actual,
                }
            }
        }
        None
    }

    #[cfg(feature = "async")]
    #[inline(never)]
    fn has_available(&self) -> bool {
        #[cfg(feature = "external-origin")]
        if !matches!(self.kind, PacketOriginKind::Pool { .. }) {
            return false;
        }
        self.used[..self.count.div_ceil(32)]
            .iter()
            .enumerate()
            .any(|(word_index, word)| {
                let used = word.load(Ordering::Acquire);
                let valid = (self.count - word_index * 32).min(32);
                used.count_ones() < valid as u32
            })
    }
}

/// A small, copyable capability for allocating owned packet buffers.
///
/// Allocators are created by [`PacketPool::allocator`]. They carry no memory
/// policy themselves: each one remains permanently bound to the pool whose
/// payload placement and capacity the system selected.
#[derive(Clone, Copy)]
pub struct PacketBufAllocator {
    origin: NonNull<PacketPoolHeader>,
}

// SAFETY: an allocator is a shared reference in erased form to a static
// `PacketPool`, whose allocation and release protocol is thread-safe.
unsafe impl Send for PacketBufAllocator {}
// SAFETY: see `Send`; allocating through shared copies is synchronized by the
// originating pool's atomic bitmap.
unsafe impl Sync for PacketBufAllocator {}

impl PacketBufAllocator {
    /// Allocate one empty packet from the bound pool.
    ///
    /// The packet has zero headroom and length and default metadata. Its storage
    /// retains unspecified bytes from the preceding owner.
    pub fn try_alloc(self) -> Option<PacketBuf> {
        // SAFETY: only a stable static pool constructs this capability.
        unsafe { allocate_from_pool(self.origin) }
    }

    /// Whether `buf` originated from this allocator's pool.
    pub fn owns(self, buf: &PacketBuf) -> bool {
        self.origin == buf.inner().origin
    }

    /// Whether at least one packet slot can currently be allocated.
    ///
    /// This is only a level-state observation: another owner may claim the
    /// slot before a later [`try_alloc`](Self::try_alloc). Async users combine
    /// it with [`PacketPoolWaiter::register`] using register-then-recheck.
    #[cfg(feature = "async")]
    pub fn has_available(self) -> bool {
        let header = unsafe { self.origin.as_ref() };
        header.has_available()
    }

    /// Claim the pool's unique asynchronous availability waiter.
    ///
    /// A single async stack may wait on one pool. Synchronous allocation and
    /// any number of packet owners remain unrestricted. Requiring a unique
    /// waiter makes sharing one pool between independent executor tasks an
    /// explicit composition error instead of silently losing one task's
    /// registration.
    #[cfg(feature = "async")]
    pub fn try_claim_waiter(self) -> Option<PacketPoolWaiter> {
        let header = unsafe { self.origin.as_ref() };
        header
            .waiter_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PacketPoolWaiter { origin: self.origin })
    }
}

/// Unique async notification capability for one packet pool.
///
/// The stack registers it only after allocation failed. A release racing
/// before, during, or after registration is observed through a register-then-
/// recheck protocol.
#[cfg(feature = "async")]
pub struct PacketPoolWaiter {
    origin: NonNull<PacketPoolHeader>,
}

#[cfg(feature = "async")]
unsafe impl Send for PacketPoolWaiter {}
#[cfg(feature = "async")]
unsafe impl Sync for PacketPoolWaiter {}

#[cfg(feature = "async")]
impl PacketPoolWaiter {
    /// Register the task waiting for the pool to become nonempty.
    pub fn register(&self, waker: &Waker) {
        let header = unsafe { self.origin.as_ref() };
        register_pool_waker(&header.waiter, waker);
        let available = header.has_available();
        if available {
            header.waiter.wake();
        }
    }
}

#[cfg(feature = "async")]
// Keep registration separate from the availability recheck and its wake:
// merging both erases Waker call scopes needed by stack analysis.
#[inline(never)]
fn register_pool_waker(waiter: &AtomicWaker, waker: &Waker) {
    waiter.register(waker);
}

#[cfg(feature = "async")]
impl Drop for PacketPoolWaiter {
    fn drop(&mut self) {
        let header = unsafe { self.origin.as_ref() };
        drop(header.waiter.take());
        let claimed = header.waiter_claimed.swap(false, Ordering::AcqRel);
        debug_assert!(claimed, "packet-pool waiter was released twice");
    }
}

impl fmt::Debug for PacketBufAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBufAllocator").finish_non_exhaustive()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketBufAllocator {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "PacketBufAllocator {{ .. }}")
    }
}

/// Payload storage for one statically allocated packet pool.
///
/// This value contains only packet bytes, so a system may place it in a memory
/// section independently from the pool's hot ownership and metadata control.
/// Bind it exactly once with [`PacketPool::new`]. The unique `&'static mut`
/// accepted there makes sharing one storage object between safe pools
/// impossible.
pub struct PacketPoolStorage<const COUNT: usize> {
    data: [UnsafeCell<MaybeUninit<Data>>; COUNT],
}

impl<const COUNT: usize> PacketPoolStorage<COUNT> {
    /// Create unclaimed static packet storage.
    pub const fn new() -> Self {
        Self {
            data: [const { UnsafeCell::new(MaybeUninit::zeroed()) }; COUNT],
        }
    }
}

impl<const COUNT: usize> Default for PacketPoolStorage<COUNT> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: storage has no public access path. `PacketPool::new` consumes a
// unique static borrow, and the bound pool exposes a slot only after its one
// atomic ownership transition has succeeded.
unsafe impl<const COUNT: usize> Sync for PacketPoolStorage<COUNT> {}

/// Hot ownership and metadata control for a static packet pool.
///
/// The pool and its [`PacketPoolStorage`] may be placed separately. This keeps
/// atomic ownership state and packet metadata in fast memory while allowing
/// the packet bytes themselves to live in a larger memory class.
#[repr(C)]
pub struct PacketPool<const COUNT: usize> {
    // The header and controls' offset are independent of COUNT.
    header: PacketPoolHeader,
    controls: [UnsafeCell<MaybeUninit<PacketBufInner>>; COUNT],
}

// SAFETY: every control and payload slot is published only to the one
// `PacketBuf` whose compare-exchange changed `used[index]` from false to true.
// Drop releases that same slot with Release ordering.
unsafe impl<const COUNT: usize> Sync for PacketPool<COUNT> {}

impl<const COUNT: usize> PacketPool<COUNT> {
    /// Bind hot pool control to uniquely owned static payload storage.
    ///
    /// The returned control value must itself be placed at a stable address
    /// before allocation. [`try_alloc`](Self::try_alloc) requires `&'static
    /// self`, enforcing that requirement in safe code.
    ///
    /// # Panics
    ///
    /// Panics unless `COUNT` is in `1..=1024`.
    pub fn new(storage: &'static mut PacketPoolStorage<COUNT>) -> Self {
        Self::from_storage(storage)
    }

    fn from_storage(storage: &'static PacketPoolStorage<COUNT>) -> Self {
        assert!(COUNT > 0, "a packet pool must contain at least one slot");
        assert!(
            COUNT <= MAX_PACKET_POOL_COUNT,
            "a packet pool cannot contain more than 1024 slots"
        );
        Self {
            header: PacketPoolHeader::new(
                COUNT,
                PacketOriginKind::Pool {
                    storage: storage.data.as_ptr(),
                },
            ),
            controls: [const { UnsafeCell::new(MaybeUninit::zeroed()) }; COUNT],
        }
    }

    /// Number of packet slots owned by this pool.
    pub const fn capacity(&self) -> usize {
        COUNT
    }

    /// Create a copyable allocation capability bound to this pool.
    pub fn allocator(&'static self) -> PacketBufAllocator {
        PacketBufAllocator {
            origin: NonNull::from(self).cast(),
        }
    }

    /// Whether `buf` originated from this pool.
    pub fn owns(&self, buf: &PacketBuf) -> bool {
        core::ptr::eq(buf.inner().origin.as_ptr(), &self.header)
    }

    /// Allocate one empty packet from this pool.
    pub fn try_alloc(&'static self) -> Option<PacketBuf> {
        self.allocator().try_alloc()
    }
}

/// Allocate through the fixed prefix of a stable static pool.
///
/// # Safety
/// `origin` must point at the first field of a static PacketPool or
/// ExternalPacketSlots initialized by its constructor.
unsafe fn allocate_from_pool(origin: NonNull<PacketPoolHeader>) -> Option<PacketBuf> {
    // SAFETY: the caller guarantees the header's lifetime and provenance.
    let header = unsafe { origin.as_ref() };
    let storage = match header.kind {
        PacketOriginKind::Pool { storage } => storage,
        #[cfg(feature = "external-origin")]
        PacketOriginKind::External { .. } => return None,
    };
    let index = header.alloc_slot()?;
    // SAFETY: PacketPool is repr(C), with its only COUNT-dependent field last.
    // Its controls offset is therefore the same even for COUNT = 0. The
    // actual allocation contains header.count slots, and the CAS above has
    // exclusively claimed index < header.count. No reference to the dummy
    // zero-length pool or an uninitialized control is formed.
    let ptr = unsafe {
        origin
            .as_ptr()
            .byte_add(core::mem::offset_of!(PacketPool<0>, controls))
            .cast::<UnsafeCell<MaybeUninit<PacketBufInner>>>()
            .add(index)
    };
    let ptr = unsafe { (*ptr).get().cast::<PacketBufInner>() };
    // SAFETY: the constructor bound a unique static payload array of count
    // slots; the successful CAS claimed this payload with its control.
    let data = unsafe { (*storage.add(index)).get().cast::<Data>() };
    // SAFETY: both pointers are aligned static slots uniquely owned here.
    // Every field read by PacketBuf is initialized before publication.
    unsafe {
        (&raw mut (*ptr).origin).write(origin);
        (&raw mut (*ptr).slot).write(index);
        (&raw mut (*ptr).headroom).write(0);
        (&raw mut (*ptr).len).write(0);
        (&raw mut (*ptr).meta).write(PacketMeta::default());
        (&raw mut (*ptr).data).write(NonNull::new_unchecked(data));
        #[cfg(test)]
        (*data).fill(0xa5);
    }
    Some(PacketBuf {
        // SAFETY: a pointer into static control storage is non-null.
        inner: unsafe { NonNull::new_unchecked(ptr) },
    })
}

/// Return an exclusively owned slot to its stable static origin.
#[inline(never)]
unsafe fn release_slot(origin: NonNull<PacketPoolHeader>, index: usize) {
    // SAFETY: PacketBuf carries the header and index initialized by allocation
    // or adoption; its lifetime is contained in that of its static origin.
    let header = unsafe { origin.as_ref() };
    debug_assert!(index < header.count);
    let bit = 1 << (index % 32);
    match header.kind {
        PacketOriginKind::Pool { .. } => {
            let previous = header.used[index / 32].fetch_and(!bit, Ordering::Release);
            debug_assert_ne!(previous & bit, 0, "a packet pool slot was released twice");
            #[cfg(feature = "async")]
            header.waiter.wake();
        }
        #[cfg(feature = "external-origin")]
        PacketOriginKind::External { drop_owner } => {
            let held = header.used[index / 32].load(Ordering::Acquire);
            debug_assert_ne!(held & bit, 0, "a packet pool slot was released twice");
            // SAFETY: the packet no longer accesses its control or payload;
            // its slot still holds the owner adoption placed there. The owner
            // is dropped before the slot is offered to a new adoption.
            unsafe { drop_owner(origin, index) };
            header.used[index / 32].fetch_and(!bit, Ordering::Release);
        }
    }
}

/// Drops the owner of one adopted slot: `(origin header, slot)`.
#[cfg(feature = "external-origin")]
type ExternalOwnerDrop = unsafe fn(NonNull<PacketPoolHeader>, usize);

/// Storage another owner lends to one adopted [`PacketBuf`].
///
/// [`ExternalPacketSlots::adopt`] moves the owner into its slot and only then
/// asks it for its bytes, so storage held inline by the owner is already at
/// its final address. The packet exposes the first `PACKET_BUF_SIZE` of these
/// bytes; the owner is not touched again until the packet's final drop drops
/// it, which is where the owner returns its storage. The packet may be sent
/// to and dropped in any context, so the owner is `Send`.
#[cfg(feature = "external-origin")]
pub trait ExternalPacketStorage: Send + 'static {
    /// The bytes the packet may use, starting at the packet's storage start.
    fn storage_mut(&mut self) -> &mut [u8];
}

/// Why [`ExternalPacketSlots::adopt`] refused an owner.
#[cfg(feature = "external-origin")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ExternalPacketRefusal {
    /// Every slot holds an owner.
    Full,
    /// `headroom + len` exceeds `PACKET_BUF_SIZE`.
    Range {
        /// The requested headroom.
        headroom: usize,
        /// The requested length.
        len: usize,
    },
    /// The owner's storage is shorter than `PACKET_BUF_SIZE`.
    TooShort {
        /// The bytes the owner lends.
        available: usize,
    },
    /// The owner's storage does not start at a
    /// [`PACKET_BUF_ALIGN`](crate::config::PACKET_BUF_ALIGN) boundary.
    Misaligned,
}

/// A refused adoption: the owner, returned without a packet, and why.
#[cfg(feature = "external-origin")]
#[derive(Debug)]
pub struct ExternalPacketRefused<S> {
    /// The owner; no packet refers to its storage.
    pub owner: S,
    /// Why the packet was not formed.
    pub reason: ExternalPacketRefusal,
}

/// Packets whose payload storage belongs to another owner.
///
/// A driver that already holds a received frame in stable memory, such as a
/// detached DMA buffer, adopts its owner as a [`PacketBuf`] instead of copying
/// the frame into a [`PacketPool`]. The slots never allocate, so they are not
/// an allocator for the stack.
///
/// A slot becomes free for a new owner only after the previous owner's drop
/// has returned.
#[cfg(feature = "external-origin")]
#[repr(C)]
pub struct ExternalPacketSlots<S: ExternalPacketStorage, const COUNT: usize> {
    // The header precedes everything COUNT-dependent; release finds the slots
    // from it.
    header: PacketPoolHeader,
    controls: [UnsafeCell<MaybeUninit<PacketBufInner>>; COUNT],
    owners: [UnsafeCell<MaybeUninit<S>>; COUNT],
}

// SAFETY: a control and owner slot is reached only by the one adoption whose
// bitmap claim set its bit, and then by that packet's Drop. The owner moves
// between contexts with its packet, which `S: Send` permits; no owner is
// shared.
#[cfg(feature = "external-origin")]
unsafe impl<S: ExternalPacketStorage, const COUNT: usize> Sync for ExternalPacketSlots<S, COUNT> {}

#[cfg(feature = "external-origin")]
impl<S: ExternalPacketStorage, const COUNT: usize> ExternalPacketSlots<S, COUNT> {
    const VALID_COUNT: () = {
        if COUNT == 0 {
            panic!("external packet slots must contain at least one slot");
        }
        if COUNT > MAX_PACKET_POOL_COUNT {
            panic!("external packet slots cannot contain more than 1024 slots");
        }
    };

    /// Empty slots; `const`, so that they can live in a `static`.
    ///
    /// ```compile_fail,E0080
    /// # use xarxa_driver::{ExternalPacketSlots, ExternalPacketStorage};
    /// struct Owner;
    /// impl ExternalPacketStorage for Owner {
    ///     fn storage_mut(&mut self) -> &mut [u8] { &mut [] }
    /// }
    /// static SLOTS: ExternalPacketSlots<Owner, 1025> = ExternalPacketSlots::new();
    /// ```
    pub const fn new() -> Self {
        let () = Self::VALID_COUNT;
        Self {
            header: PacketPoolHeader::new(
                COUNT,
                PacketOriginKind::External {
                    drop_owner: drop_external_owner::<S, COUNT>,
                },
            ),
            controls: [const { UnsafeCell::new(MaybeUninit::uninit()) }; COUNT],
            owners: [const { UnsafeCell::new(MaybeUninit::uninit()) }; COUNT],
        }
    }

    /// Number of owners these slots can hold at once.
    pub const fn capacity(&self) -> usize {
        COUNT
    }

    /// Whether `buf` holds an owner of these slots.
    pub fn owns(&self, buf: &PacketBuf) -> bool {
        core::ptr::eq(buf.inner().origin.as_ptr(), &self.header)
    }

    /// Adopt `owner` as a packet holding its bytes `headroom..headroom + len`.
    ///
    /// # Errors
    ///
    /// A full set of slots, a range past `PACKET_BUF_SIZE`, or storage that is
    /// shorter than `PACKET_BUF_SIZE` or misaligned returns the owner with the
    /// reason, and no packet is formed. `Full` and `Range` are refused before
    /// the owner is asked for its storage; `TooShort` and `Misaligned` after
    /// [`ExternalPacketStorage::storage_mut`], which may have changed it.
    pub fn adopt(&'static self, owner: S, headroom: usize, len: usize) -> Result<PacketBuf, ExternalPacketRefused<S>> {
        let range_fits = headroom.checked_add(len).is_some_and(|end| end <= PACKET_BUF_SIZE);
        if !range_fits {
            return Err(ExternalPacketRefused {
                owner,
                reason: ExternalPacketRefusal::Range { headroom, len },
            });
        }
        let Some(slot) = self.header.alloc_slot() else {
            return Err(ExternalPacketRefused {
                owner,
                reason: ExternalPacketRefusal::Full,
            });
        };
        let owners = self.owners[slot].get();
        // SAFETY: the bitmap claim above made this slot exclusively ours; its
        // previous owner, if any, was dropped before its bit was cleared.
        let placed = unsafe { (*owners).write(owner) };
        // The owner is at its final address before it names its bytes.
        let storage = placed.storage_mut();
        let available = storage.len();
        let refusal = if available < PACKET_BUF_SIZE {
            Some(ExternalPacketRefusal::TooShort { available })
        } else if !storage.as_ptr().addr().is_multiple_of(core::mem::align_of::<Data>()) {
            Some(ExternalPacketRefusal::Misaligned)
        } else {
            None
        };
        if let Some(reason) = refusal {
            // SAFETY: the owner was written above and no packet refers to it;
            // reading it out leaves the slot uninitialized again before the
            // claim is cleared.
            let owner = unsafe { (*owners).assume_init_read() };
            self.header.used[slot / 32].fetch_and(!(1 << (slot % 32)), Ordering::Release);
            return Err(ExternalPacketRefused { owner, reason });
        }
        // `storage` is a valid, initialized and exclusively borrowed slice of
        // at least PACKET_BUF_SIZE aligned bytes inside the placed owner.
        let data = NonNull::from(storage).cast::<Data>();
        let control = self.controls[slot].get().cast::<PacketBufInner>();
        // SAFETY: the claim made this static control slot exclusively ours.
        // The owner stays in its slot, untouched, until the packet's Drop
        // drops it, so `data` stays valid and unaliased for the packet's life.
        unsafe {
            // The origin keeps the provenance of the whole slots: release
            // reaches the owners through it.
            (&raw mut (*control).origin).write(NonNull::from(self).cast());
            (&raw mut (*control).slot).write(slot);
            // Both fit u16: `headroom + len <= PACKET_BUF_SIZE` was checked.
            (&raw mut (*control).headroom).write(headroom as u16);
            (&raw mut (*control).len).write(len as u16);
            (&raw mut (*control).meta).write(PacketMeta::default());
            (&raw mut (*control).data).write(data);
        }
        Ok(PacketBuf {
            // SAFETY: a pointer into static control storage is never null.
            inner: unsafe { NonNull::new_unchecked(control) },
        })
    }
}

#[cfg(feature = "external-origin")]
impl<S: ExternalPacketStorage, const COUNT: usize> Default for ExternalPacketSlots<S, COUNT> {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop the owner of `slot` of the slots whose header `origin` is.
///
/// # Safety
///
/// `origin` is the header of a live `ExternalPacketSlots<S, COUNT>`, whose
/// `slot` holds an owner no packet uses any more.
#[cfg(feature = "external-origin")]
unsafe fn drop_external_owner<S: ExternalPacketStorage, const COUNT: usize>(
    origin: NonNull<PacketPoolHeader>,
    slot: usize,
) {
    // SAFETY: the header is the first field of the repr(C) slots, so its
    // address is theirs; the caller guarantees they are live.
    let slots = unsafe { origin.cast::<ExternalPacketSlots<S, COUNT>>().as_ref() };
    // SAFETY: the caller guarantees the owner is initialized and unused.
    unsafe { (*slots.owners[slot].get()).assume_init_drop() };
}

/// An owned network packet buffer.
///
/// ```text
/// | headroom | data (len) | tailroom |
/// ```
pub struct PacketBuf {
    inner: NonNull<PacketBufInner>,
}

// SAFETY: a `PacketBuf` is the unique owner of its slot, like a `Box` of it.
unsafe impl Send for PacketBuf {}
unsafe impl Sync for PacketBuf {}

impl PacketBuf {
    #[inline]
    fn inner(&self) -> &PacketBufInner {
        // SAFETY: we own the slot for as long as `self` exists.
        unsafe { self.inner.as_ref() }
    }

    #[inline]
    fn inner_mut(&mut self) -> &mut PacketBufInner {
        // SAFETY: we own the slot for as long as `self` exists, and `&mut self`
        // makes this the only reference.
        unsafe { self.inner.as_mut() }
    }

    #[inline]
    fn data(&self) -> &Data {
        // SAFETY: the originating pool exclusively assigned this payload slot
        // to this PacketBuf for its entire lifetime.
        unsafe { self.inner().data.as_ref() }
    }

    #[inline]
    fn data_mut(&mut self) -> &mut Data {
        let mut data = self.inner().data;
        // SAFETY: `&mut self` proves this is the unique PacketBuf owner and the
        // pool cannot republish the slot before Drop.
        unsafe { data.as_mut() }
    }

    /// The packet's metadata.
    ///
    /// On a received packet this is what the driver attached to it. On a packet being
    /// sent it is what the application attached, and what the driver will see in
    /// [`Driver::transmit`](crate::Driver::transmit). It travels with the
    /// buffer through the whole stack, unaffected by header pushes and pulls.
    pub fn meta(&self) -> PacketMeta {
        self.inner().meta
    }

    /// Mutable reference to the packet's metadata.
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.inner_mut().meta
    }

    /// Replace the packet's metadata.
    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.inner_mut().meta = meta;
    }

    /// Total storage capacity of the buffer, in bytes.
    pub const fn capacity(&self) -> usize {
        PACKET_BUF_SIZE
    }

    /// Amount of free space in front of the payload.
    pub fn headroom(&self) -> usize {
        self.inner().headroom as usize
    }

    /// Length of the payload.
    pub fn len(&self) -> usize {
        self.inner().len as usize
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.inner().len == 0
    }

    /// Amount of free space behind the payload.
    pub fn tailroom(&self) -> usize {
        PACKET_BUF_SIZE - self.headroom() - self.len()
    }

    /// Set the headroom on an empty buffer, before writing a payload.
    ///
    /// # Panics
    /// Panics if the buffer is not empty, or if `headroom > capacity`.
    pub fn reserve(&mut self, headroom: usize) {
        assert!(self.inner().len == 0);
        assert!(headroom <= PACKET_BUF_SIZE);
        self.inner_mut().headroom = headroom as u16;
    }

    /// Grow the payload at the front by `n` bytes, taking them from the headroom.
    ///
    /// # Panics
    /// Panics if `n > headroom`.
    pub fn push_front(&mut self, n: usize) {
        assert!(n <= self.headroom());
        let inner = self.inner_mut();
        inner.headroom -= n as u16;
        inner.len += n as u16;
    }

    /// Shrink the payload at the front by `n` bytes, returning them to the headroom.
    ///
    /// # Panics
    /// Panics if `n > len`.
    pub fn pull_front(&mut self, n: usize) {
        assert!(n <= self.len());
        let inner = self.inner_mut();
        inner.headroom += n as u16;
        inner.len -= n as u16;
    }

    /// Make room for `headroom` bytes in front of the payload, moving the payload
    /// back if there isn't enough already.
    ///
    /// Returns `false` if the buffer can't fit `headroom` plus the payload, leaving
    /// it unchanged.
    pub fn ensure_headroom(&mut self, headroom: usize) -> bool {
        if self.headroom() >= headroom {
            return true;
        }
        let len = self.len();
        if headroom + len > PACKET_BUF_SIZE {
            return false;
        }
        let old = self.headroom();
        self.data_mut().copy_within(old..old + len, headroom);
        self.inner_mut().headroom = headroom as u16;
        true
    }

    /// Set the payload length, growing or shrinking it at the back.
    ///
    /// # Panics
    /// Panics if `headroom + len > capacity`.
    pub fn set_len(&mut self, len: usize) {
        assert!(self.headroom() + len <= PACKET_BUF_SIZE);
        self.inner_mut().len = len as u16;
    }

    /// The whole underlying storage, ignoring headroom and length.
    ///
    /// The returned slice is aligned to [`PACKET_BUF_ALIGN`](crate::config::PACKET_BUF_ALIGN), and its length
    /// ([`PACKET_BUF_SIZE`]) is a multiple of it.
    pub fn storage_mut(&mut self) -> &mut [u8] {
        &mut self.data_mut()[..]
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        let inner = self.inner();
        let origin = inner.origin;
        // SAFETY: allocation or adoption initialized this origin and slot;
        // PacketBuf exclusively owns them until this release.
        unsafe { release_slot(origin, inner.slot) };
    }
}

impl Deref for PacketBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        let inner = self.inner();
        let start = inner.headroom as usize;
        let end = start + inner.len as usize;
        &self.data()[start..end]
    }
}
impl DerefMut for PacketBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let inner = self.inner();
        let start = inner.headroom as usize;
        let end = start + inner.len as usize;
        &mut self.data_mut()[start..end]
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("headroom", &self.headroom())
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketBuf {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "PacketBuf {{ headroom: {}, len: {} }}", self.headroom(), self.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PACKET_BUF_ALIGN;
    use std::boxed::Box;
    #[cfg(feature = "async")]
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as StdOrdering},
    };
    #[cfg(feature = "async")]
    use std::task::{Wake, Waker};

    #[cfg(feature = "async")]
    struct CountWake(Arc<AtomicUsize>);

    #[cfg(feature = "async")]
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, StdOrdering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, StdOrdering::Relaxed);
        }
    }

    fn new_pool<const COUNT: usize>() -> &'static PacketPool<COUNT> {
        let storage = Box::leak(Box::new(PacketPoolStorage::new()));
        Box::leak(Box::new(PacketPool::new(storage)))
    }

    fn new_buffer() -> PacketBuf {
        new_pool::<1>().try_alloc().unwrap()
    }

    #[cfg(feature = "external-origin")]
    mod external {
        use super::*;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering as StdOrdering};
        use std::vec::Vec;

        macro_rules! opaque_debug {
            ($($owner:ident),*) => {$(
                impl fmt::Debug for $owner {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(stringify!($owner))
                    }
                }
            )*};
        }
        opaque_debug!(Boxed, Inline, Lent, Offset, Probe);

        fn counter() -> &'static AtomicUsize {
            Box::leak(Box::new(AtomicUsize::new(0)))
        }

        /// Lends one boxed, aligned `Data` and counts its drops.
        struct Boxed {
            bytes: Box<Data>,
            drops: &'static AtomicUsize,
        }

        impl ExternalPacketStorage for Boxed {
            fn storage_mut(&mut self) -> &mut [u8] {
                &mut self.bytes.0
            }
        }

        impl Drop for Boxed {
            fn drop(&mut self) {
                self.drops.fetch_add(1, StdOrdering::SeqCst);
            }
        }

        fn boxed(drops: &'static AtomicUsize) -> Boxed {
            Boxed {
                bytes: Box::new(Data(core::array::from_fn(|index| index as u8))),
                drops,
            }
        }

        fn slots<S: ExternalPacketStorage, const COUNT: usize>() -> &'static ExternalPacketSlots<S, COUNT> {
            Box::leak(Box::new(ExternalPacketSlots::new()))
        }

        #[test]
        fn an_adopted_packet_views_the_owner_bytes_and_drops_it_once() {
            let drops = counter();
            let slots = slots::<Boxed, 2>();
            let mut packet = slots.adopt(boxed(drops), 10, 4).unwrap();
            assert!(slots.owns(&packet));
            assert_eq!(&packet[..], &[10, 11, 12, 13]);
            assert_eq!(packet.headroom(), 10);
            // The stack may move the payload within the adopted storage.
            assert!(packet.ensure_headroom(20));
            assert_eq!(&packet[..], &[10, 11, 12, 13]);
            assert_eq!(drops.load(StdOrdering::SeqCst), 0);
            drop(packet);
            assert_eq!(drops.load(StdOrdering::SeqCst), 1);
            // The released slot takes a new owner.
            drop(slots.adopt(boxed(drops), 0, 0).unwrap());
            assert_eq!(drops.load(StdOrdering::SeqCst), 2);
        }

        /// Holds its bytes inline: they move with the owner into its slot.
        struct Inline {
            bytes: Data,
            seen: &'static Mutex<Vec<u8>>,
        }

        impl ExternalPacketStorage for Inline {
            fn storage_mut(&mut self) -> &mut [u8] {
                &mut self.bytes.0
            }
        }

        impl Drop for Inline {
            fn drop(&mut self) {
                self.seen.lock().unwrap().extend_from_slice(&self.bytes.0[..4]);
            }
        }

        #[test]
        fn inline_storage_is_lent_from_the_owner_final_place() {
            let seen: &'static Mutex<Vec<u8>> = Box::leak(Box::new(Mutex::new(Vec::new())));
            let slots = slots::<Inline, 1>();
            let owner = Inline {
                bytes: Data([0; PACKET_BUF_SIZE]),
                seen,
            };
            let mut packet = slots.adopt(owner, 0, 4).unwrap();
            packet.copy_from_slice(&[1, 2, 3, 4]);
            drop(packet);
            // The owner, dropped in its slot, holds what the packet wrote.
            assert_eq!(*seen.lock().unwrap(), [1, 2, 3, 4]);
        }

        /// Twice a packet's bytes at the largest packet alignment.
        #[repr(C, align(32))]
        struct Wide([u8; 2 * PACKET_BUF_SIZE]);

        /// Lends the first `len` of its aligned bytes and counts how often it
        /// was asked.
        struct Lent {
            bytes: Box<Wide>,
            len: usize,
            asked: &'static AtomicUsize,
            drops: &'static AtomicUsize,
        }

        impl ExternalPacketStorage for Lent {
            fn storage_mut(&mut self) -> &mut [u8] {
                self.asked.fetch_add(1, StdOrdering::SeqCst);
                &mut self.bytes.0[..self.len]
            }
        }

        fn lent(len: usize, asked: &'static AtomicUsize, drops: &'static AtomicUsize) -> Lent {
            Lent {
                bytes: Box::new(Wide([9; 2 * PACKET_BUF_SIZE])),
                len,
                asked,
                drops,
            }
        }

        impl Drop for Lent {
            fn drop(&mut self) {
                self.drops.fetch_add(1, StdOrdering::SeqCst);
            }
        }

        #[test]
        fn a_refusal_returns_the_owner_and_keeps_the_slot_free() {
            let (asked, drops) = (counter(), counter());
            let slots = slots::<Lent, 1>();
            let refused = slots.adopt(lent(PACKET_BUF_SIZE - 1, asked, drops), 0, 0).unwrap_err();
            assert_eq!(
                refused.reason,
                ExternalPacketRefusal::TooShort {
                    available: PACKET_BUF_SIZE - 1
                }
            );
            assert_eq!(refused.owner.len, PACKET_BUF_SIZE - 1);
            assert_eq!(drops.load(StdOrdering::SeqCst), 0);
            drop(refused);
            // A range past the packet is refused before the owner is asked.
            let asked_before = asked.load(StdOrdering::SeqCst);
            let refused = slots
                .adopt(lent(PACKET_BUF_SIZE, asked, drops), PACKET_BUF_SIZE, 1)
                .unwrap_err();
            assert_eq!(
                refused.reason,
                ExternalPacketRefusal::Range {
                    headroom: PACKET_BUF_SIZE,
                    len: 1
                }
            );
            assert_eq!(asked.load(StdOrdering::SeqCst), asked_before);
            // The refused adoptions left the one slot free.
            let packet = slots.adopt(refused.owner, 0, 1).unwrap();
            let refused = slots.adopt(lent(PACKET_BUF_SIZE, asked, drops), 0, 0).unwrap_err();
            assert_eq!(refused.reason, ExternalPacketRefusal::Full);
            drop(packet);
        }

        /// Lends `PACKET_BUF_SIZE` bytes starting `offset` past an aligned base.
        struct Offset {
            bytes: Box<Wide>,
            offset: usize,
        }

        impl ExternalPacketStorage for Offset {
            fn storage_mut(&mut self) -> &mut [u8] {
                &mut self.bytes.0[self.offset..self.offset + PACKET_BUF_SIZE]
            }
        }

        fn offset(offset: usize) -> Offset {
            Offset {
                bytes: Box::new(Wide([0; 2 * PACKET_BUF_SIZE])),
                offset,
            }
        }

        #[test]
        fn storage_off_the_packet_alignment_is_refused() {
            let slots = slots::<Offset, 1>();
            let align = core::mem::align_of::<Data>();
            let skewed = slots.adopt(offset(1), 0, 0);
            if align > 1 {
                let refused = skewed.unwrap_err();
                assert_eq!(refused.reason, ExternalPacketRefusal::Misaligned);
                assert_eq!(refused.owner.offset, 1);
            } else {
                drop(skewed.unwrap());
            }
            // An offset of one alignment unit is aligned, and the refused
            // adoption left the slot free.
            drop(slots.adopt(offset(align), 0, 0).unwrap());
        }

        static PROBE: ExternalPacketSlots<Probe, 1> = ExternalPacketSlots::new();
        static PROBED: Mutex<Vec<ExternalPacketRefusal>> = Mutex::new(Vec::new());

        /// While dropped from its slot, tries to take that slot again.
        struct Probe {
            bytes: Box<Data>,
            probe: bool,
        }

        impl ExternalPacketStorage for Probe {
            fn storage_mut(&mut self) -> &mut [u8] {
                &mut self.bytes.0
            }
        }

        impl Drop for Probe {
            fn drop(&mut self) {
                if self.probe {
                    let other = Probe {
                        bytes: Box::new(Data([0; PACKET_BUF_SIZE])),
                        probe: false,
                    };
                    if let Err(refused) = PROBE.adopt(other, 0, 0) {
                        PROBED.lock().unwrap().push(refused.reason);
                    }
                }
            }
        }

        #[test]
        fn a_slot_is_free_only_after_its_owner_dropped() {
            let owner = Probe {
                bytes: Box::new(Data([0; PACKET_BUF_SIZE])),
                probe: true,
            };
            drop(PROBE.adopt(owner, 0, 0).unwrap());
            assert_eq!(*PROBED.lock().unwrap(), [ExternalPacketRefusal::Full]);
            // Once that drop returned, the slot takes a new owner.
            let owner = Probe {
                bytes: Box::new(Data([0; PACKET_BUF_SIZE])),
                probe: false,
            };
            drop(PROBE.adopt(owner, 0, 0).unwrap());
        }

        #[test]
        fn an_owner_is_dropped_where_its_packet_is_dropped() {
            let drops = counter();
            let slots = slots::<Boxed, 1>();
            let packet = slots.adopt(boxed(drops), 0, 1).unwrap();
            std::thread::spawn(move || drop(packet)).join().unwrap();
            assert_eq!(drops.load(StdOrdering::SeqCst), 1);
            drop(slots.adopt(boxed(drops), 0, 1).unwrap());
        }

        #[test]
        fn external_slots_never_allocate() {
            let slots = slots::<Boxed, 1>();
            let header = NonNull::from(&slots.header);
            // SAFETY: the header belongs to live slots.
            assert!(unsafe { allocate_from_pool(header) }.is_none());
        }

        #[test]
        fn the_maximum_holds_and_returns_every_owner_once() {
            let drops = counter();
            let slots = slots::<Boxed, 1024>();
            let packets: Vec<_> = (0..1024).map(|_| slots.adopt(boxed(drops), 0, 1).unwrap()).collect();
            let refused = slots.adopt(boxed(drops), 0, 1).unwrap_err();
            assert_eq!(refused.reason, ExternalPacketRefusal::Full);
            drop(refused);
            assert_eq!(drops.load(StdOrdering::SeqCst), 1);
            drop(packets);
            assert_eq!(drops.load(StdOrdering::SeqCst), 1025);
        }

        #[cfg(debug_assertions)]
        #[test]
        fn a_double_release_does_not_drop_the_owner_twice() {
            let drops = counter();
            let slots = slots::<Boxed, 1>();
            let packet = core::mem::ManuallyDrop::new(slots.adopt(boxed(drops), 0, 0).unwrap());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: Drop is suppressed; the second release must panic
                // before it reaches the already dropped owner.
                unsafe {
                    release_slot(packet.inner().origin, packet.inner().slot);
                    release_slot(packet.inner().origin, packet.inner().slot);
                }
            }));
            assert!(result.is_err());
            assert_eq!(drops.load(StdOrdering::SeqCst), 1);
        }
    }

    #[test]
    fn packet_handle_stays_one_pointer() {
        assert_eq!(
            core::mem::size_of::<PacketBuf>(),
            core::mem::size_of::<NonNull<PacketBufInner>>()
        );
    }

    #[test]
    fn custom_pool_exhausts_and_reuses_exact_capacity() {
        let pool = new_pool::<33>();
        let mut buffers = (0..pool.capacity())
            .map(|_| pool.try_alloc().expect("every configured slot must allocate"))
            .collect::<std::vec::Vec<_>>();

        assert!(pool.try_alloc().is_none());
        assert!(buffers.iter().all(|buffer| pool.owns(buffer)));

        let mut returned = buffers.pop().unwrap();
        returned.reserve(17);
        returned.set_len(3);
        returned.copy_from_slice(&[1, 2, 3]);
        drop(returned);

        let reused = pool.try_alloc().expect("dropping must return one slot");
        assert!(pool.owns(&reused));
        assert_eq!(reused.headroom(), 0);
        assert_eq!(reused.len(), 0);
        assert_eq!(reused.meta(), PacketMeta::default());
        assert!(pool.try_alloc().is_none());
    }

    fn check_capacity<const COUNT: usize>() {
        let pool = new_pool::<COUNT>();
        let allocator = pool.allocator();
        let buffers: std::vec::Vec<_> = (0..COUNT)
            .map(|slot| {
                #[cfg(feature = "async")]
                assert!(allocator.has_available());
                let buffer = if slot % 2 == 0 {
                    pool.try_alloc()
                } else {
                    allocator.try_alloc()
                }
                .unwrap();
                assert_eq!(buffer.inner().slot, slot);
                assert!(allocator.owns(&buffer));
                buffer
            })
            .collect();
        assert!(allocator.try_alloc().is_none());
        #[cfg(feature = "async")]
        assert!(!allocator.has_available());
        drop(buffers);
        #[cfg(feature = "async")]
        assert!(allocator.has_available());
        let reused: std::vec::Vec<_> = (0..COUNT)
            .map(|slot| {
                let buffer = allocator.try_alloc().unwrap();
                assert_eq!(buffer.inner().slot, slot);
                buffer
            })
            .collect();
        assert!(allocator.try_alloc().is_none());
        drop(reused);
    }

    #[test]
    fn one_ownership_implementation_handles_different_capacities() {
        check_capacity::<1>();
        check_capacity::<31>();
        check_capacity::<32>();
        check_capacity::<33>();
    }

    #[test]
    fn maximum_pool_capacity_is_1024() {
        // Constructing the largest payload array uses a large host frame.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(check_capacity::<1024>)
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "released twice")]
    fn a_pool_double_release_is_caught() {
        let pool = new_pool::<1>();
        let buffer = core::mem::ManuallyDrop::new(pool.try_alloc().unwrap());
        // SAFETY: suppressing Drop keeps the control readable for this test;
        // no later allocation or access to payload storage occurs.
        unsafe {
            release_slot(buffer.inner().origin, buffer.inner().slot);
            release_slot(buffer.inner().origin, buffer.inner().slot);
        }
    }

    #[test]
    fn independent_pools_return_to_their_origin() {
        let first = new_pool::<1>();
        let second = new_pool::<1>();
        let first_allocator = first.allocator();
        let second_allocator = second.allocator();

        let first_buffer = first_allocator.try_alloc().unwrap();
        let second_buffer = second_allocator.try_alloc().unwrap();
        assert!(first.owns(&first_buffer));
        assert!(!second.owns(&first_buffer));
        assert!(second.owns(&second_buffer));
        assert!(!first.owns(&second_buffer));
        assert!(first_allocator.owns(&first_buffer));
        assert!(!second_allocator.owns(&first_buffer));
        assert!(first.try_alloc().is_none());
        assert!(second.try_alloc().is_none());

        drop(first_buffer);
        assert!(first.try_alloc().is_some());
        assert!(second.try_alloc().is_none());
    }

    #[cfg(feature = "async")]
    #[test]
    fn unique_pool_waiter_observes_release_on_both_sides_of_registration() {
        let pool = new_pool::<1>();
        let allocator = pool.allocator();
        let waiter = allocator.try_claim_waiter().unwrap();
        assert!(allocator.try_claim_waiter().is_none());
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));

        let held = allocator.try_alloc().unwrap();
        assert!(!allocator.has_available());
        waiter.register(&waker);
        assert_eq!(wakes.load(StdOrdering::Relaxed), 0);
        drop(held);
        assert!(allocator.has_available());
        assert_eq!(wakes.load(StdOrdering::Relaxed), 1);

        // A release before registration remains visible through the
        // register-then-recheck availability test.
        let held = allocator.try_alloc().unwrap();
        drop(held);
        waiter.register(&waker);
        assert_eq!(wakes.load(StdOrdering::Relaxed), 2);

        drop(waiter);
        assert!(allocator.try_claim_waiter().is_some());
    }

    #[test]
    fn packet_can_return_to_its_pool_from_another_thread() {
        let pool = new_pool::<1>();
        let buffer = pool.try_alloc().unwrap();
        assert!(pool.try_alloc().is_none());

        std::thread::spawn(move || drop(buffer)).join().unwrap();

        assert!(pool.try_alloc().is_some());
    }

    #[test]
    fn push_pull() {
        let mut buf = new_buffer();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.headroom(), 0);
        assert_eq!(buf.tailroom(), PACKET_BUF_SIZE);

        buf.reserve(42);
        assert_eq!(buf.headroom(), 42);
        buf.set_len(100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.tailroom(), PACKET_BUF_SIZE - 142);
        buf.fill(0xaa);

        buf.push_front(20);
        assert_eq!(buf.headroom(), 22);
        assert_eq!(buf.len(), 120);
        assert_eq!(buf[20], 0xaa);

        buf.pull_front(20);
        assert_eq!(buf.headroom(), 42);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf[0], 0xaa);
    }

    #[test]
    fn ensure_headroom() {
        let mut buf = new_buffer();
        buf.reserve(10);
        buf.set_len(4);
        buf.copy_from_slice(&[1, 2, 3, 4]);

        // Already enough: nothing moves.
        assert!(buf.ensure_headroom(4));
        assert_eq!(buf.headroom(), 10);
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // Not enough: the payload moves back, unchanged.
        assert!(buf.ensure_headroom(20));
        assert_eq!(buf.headroom(), 20);
        assert_eq!(buf.len(), 4);
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // The headroom overlapping the payload is fine, it's a move not a copy.
        assert!(buf.ensure_headroom(22));
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // Doesn't fit: the buffer is left alone.
        assert!(!buf.ensure_headroom(PACKET_BUF_SIZE - 3));
        assert_eq!(buf.headroom(), 22);
        assert_eq!(&*buf, &[1, 2, 3, 4]);
        assert!(buf.ensure_headroom(PACKET_BUF_SIZE - 4));
        assert_eq!(&*buf, &[1, 2, 3, 4]);
    }

    #[test]
    #[should_panic]
    fn push_beyond_headroom() {
        let mut buf = new_buffer();
        buf.push_front(1);
    }

    /// The storage a driver DMAs into must stay aligned to `PACKET_BUF_ALIGN` and
    /// a multiple of it long, whatever the metadata in front of it does to the
    /// layout.
    #[test]
    fn storage_is_dma_shaped() {
        let mut buf = new_buffer();
        assert!((buf.storage_mut().as_ptr() as usize).is_multiple_of(PACKET_BUF_ALIGN));
        assert!(buf.storage_mut().len().is_multiple_of(PACKET_BUF_ALIGN));
        assert!(buf.storage_mut().len() >= PACKET_BUF_SIZE);
    }

    /// A fresh buffer starts out empty with default metadata, whatever its previous
    /// owner left behind. (Pool exhaustion and reuse are covered by xarxa's
    /// `packet_pool` integration test, which has a process's pool to itself.)
    #[test]
    fn fresh_buffer_is_reset() {
        let pool = new_pool::<1>();
        let mut buf = pool.try_alloc().unwrap();
        buf.reserve(100);
        buf.set_len(200);
        buf.fill(0xff);
        drop(buf);

        let buf = pool.try_alloc().unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.headroom(), 0);
        assert_eq!(buf.meta(), PacketMeta::default());
    }

    /// Metadata rides along with the buffer, untouched by the header pushes and pulls
    /// the packet goes through on its way up or down the stack.
    #[cfg(feature = "packetmeta-id")]
    #[test]
    fn meta_travels_with_the_buffer() {
        let mut buf = new_buffer();
        assert_eq!(buf.meta(), PacketMeta::default());

        buf.meta_mut().id = 0xdead_beef;
        buf.reserve(20);
        buf.set_len(10);
        buf.push_front(20);
        buf.pull_front(4);
        assert_eq!(buf.meta().id, 0xdead_beef);

        buf.set_meta(PacketMeta::default());
        assert_eq!(buf.meta().id, 0);
    }
}
