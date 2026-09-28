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

struct PacketPoolHeader {
    allocate: unsafe fn(NonNull<PacketPoolHeader>) -> Option<PacketBuf>,
    release: unsafe fn(NonNull<PacketPoolHeader>, usize),
    #[cfg(feature = "async")]
    has_available: unsafe fn(NonNull<PacketPoolHeader>) -> bool,
    #[cfg(feature = "async")]
    waiter_claimed: AtomicBool,
    #[cfg(feature = "async")]
    waiter: AtomicWaker,
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
        let allocate = unsafe { self.origin.as_ref().allocate };
        // SAFETY: only `PacketPool::allocator` constructs this capability and
        // installs the matching monomorphized allocation function.
        unsafe { allocate(self.origin) }
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
        unsafe { (header.has_available)(self.origin) }
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
        header.waiter.register(waker);
        let available = unsafe { (header.has_available)(self.origin) };
        if available {
            header.waiter.wake();
        }
    }
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
    // Must stay first: the type-erased release function casts this address back
    // to the monomorphized pool type.
    header: PacketPoolHeader,
    used: [AtomicU32; MAX_BITMAP_WORDS],
    controls: [UnsafeCell<MaybeUninit<PacketBufInner>>; COUNT],
    storage: &'static PacketPoolStorage<COUNT>,
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
            header: PacketPoolHeader {
                allocate: allocate_from_pool::<COUNT>,
                release: release_slot::<COUNT>,
                #[cfg(feature = "async")]
                has_available: has_available_in_pool::<COUNT>,
                #[cfg(feature = "async")]
                waiter_claimed: AtomicBool::new(false),
                #[cfg(feature = "async")]
                waiter: AtomicWaker::new(),
            },
            used: [const { AtomicU32::new(0) }; MAX_BITMAP_WORDS],
            controls: [const { UnsafeCell::new(MaybeUninit::zeroed()) }; COUNT],
            storage,
        }
    }

    /// Number of packet slots owned by this pool.
    pub const fn capacity(&self) -> usize {
        COUNT
    }

    /// Create a copyable allocation capability bound to this pool.
    pub fn allocator(&'static self) -> PacketBufAllocator {
        PacketBufAllocator {
            origin: NonNull::from(&self.header),
        }
    }

    /// Whether `buf` originated from this pool.
    pub fn owns(&self, buf: &PacketBuf) -> bool {
        core::ptr::eq(buf.inner().origin.as_ptr(), &self.header)
    }

    /// Allocate one empty packet from this pool.
    pub fn try_alloc(&'static self) -> Option<PacketBuf> {
        let index = self.alloc_slot()?;
        let ptr = self.controls[index].get().cast::<PacketBufInner>();
        let data = self.storage.data[index].get().cast::<Data>();
        // SAFETY:
        // - the ownership CAS above uniquely claimed both slots at `index`;
        // - both pointers refer to statically allocated, correctly aligned
        //   `MaybeUninit` storage for their target types;
        // - every field read through PacketBuf is initialized here.
        unsafe {
            (&raw mut (*ptr).origin).write(NonNull::from(&self.header));
            (&raw mut (*ptr).slot).write(index);
            (&raw mut (*ptr).headroom).write(0);
            (&raw mut (*ptr).len).write(0);
            (&raw mut (*ptr).meta).write(PacketMeta::default());
            (&raw mut (*ptr).data).write(NonNull::new_unchecked(data));
            // Catch code that relies on fresh buffers being zeroed.
            #[cfg(test)]
            (*data).fill(0xa5);
        }
        Some(PacketBuf {
            // SAFETY: a pointer into static pool control is never null.
            inner: unsafe { NonNull::new_unchecked(ptr) },
        })
    }

    /// Claim the first free slot using the same compact bitmap protocol as the
    /// original global packet pool.
    fn alloc_slot(&self) -> Option<usize> {
        for (word_index, word) in self.used[..COUNT.div_ceil(32)].iter().enumerate() {
            let mut current = word.load(Ordering::Relaxed);
            loop {
                let bit = current.trailing_ones() as usize;
                if bit >= 32 {
                    break;
                }
                let index = word_index * 32 + bit;
                if index >= COUNT {
                    // Only the final bitmap word can contain indices outside
                    // this pool. Every real slot before this one is occupied.
                    return None;
                }
                // Acquire pairs with the Release in `release_slot`: the
                // previous owner is finished before this owner initializes the
                // reused control slot and accesses its payload.
                match word.compare_exchange_weak(current, current | (1 << bit), Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => return Some(index),
                    Err(actual) => current = actual,
                }
            }
        }
        None
    }

    #[cfg(feature = "async")]
    fn has_available(&self) -> bool {
        self.used[..COUNT.div_ceil(32)]
            .iter()
            .enumerate()
            .any(|(word_index, word)| {
                let used = word.load(Ordering::Acquire);
                let valid = (COUNT - word_index * 32).min(32);
                used.count_ones() < valid as u32
            })
    }
}

unsafe fn allocate_from_pool<const COUNT: usize>(origin: NonNull<PacketPoolHeader>) -> Option<PacketBuf> {
    // SAFETY: `origin` is produced from the first field of a stable
    // `PacketPool<COUNT>` by that same pool's `allocator` method.
    unsafe { origin.cast::<PacketPool<COUNT>>().as_ref() }.try_alloc()
}

#[cfg(feature = "async")]
unsafe fn has_available_in_pool<const COUNT: usize>(origin: NonNull<PacketPoolHeader>) -> bool {
    // SAFETY: paired with the monomorphized function stored by
    // `PacketPool::<COUNT>::from_storage`.
    unsafe { origin.cast::<PacketPool<COUNT>>().as_ref() }.has_available()
}

unsafe fn release_slot<const COUNT: usize>(origin: NonNull<PacketPoolHeader>, index: usize) {
    // SAFETY: `origin` is written only by `PacketPool<COUNT>::try_alloc` and
    // points at the first field of that stable `#[repr(C)]` pool.
    let pool = unsafe { origin.cast::<PacketPool<COUNT>>().as_ref() };
    debug_assert!(index < COUNT);
    let bit = 1 << (index % 32);
    let previous = pool.used[index / 32].fetch_and(!bit, Ordering::Release);
    debug_assert_ne!(previous & bit, 0, "a packet pool slot was released twice");
    #[cfg(feature = "async")]
    pool.header.waiter.wake();
}

/// Release callback of an [`ExternalPacketOrigin`]: `(context, slot)`.
pub type ExternalPacketRelease = unsafe fn(*const (), usize);

/// Packet buffers whose payload storage belongs to another owner.
///
/// A driver that already holds a received frame in stable memory, such as a
/// detached DMA buffer, adopts that memory as a [`PacketBuf`] instead of
/// copying it into a [`PacketPool`]. Dropping the packet returns the storage
/// by calling the owner's release function with the adopted slot index. The
/// origin never allocates, so it is not an allocator for the stack.
#[repr(C)]
pub struct ExternalPacketOrigin<const COUNT: usize> {
    // Must stay first: the type-erased release function casts this address back
    // to the monomorphized origin type.
    header: PacketPoolHeader,
    adopted: [AtomicU32; MAX_BITMAP_WORDS],
    controls: [UnsafeCell<MaybeUninit<PacketBufInner>>; COUNT],
    context: *const (),
    release: ExternalPacketRelease,
}

// SAFETY: every control slot is published only to the one `PacketBuf` whose
// adoption set its `adopted` bit, and Drop clears that bit with Release
// ordering. `context` is only passed back to the owner's release function,
// whose contract makes it callable from any core.
unsafe impl<const COUNT: usize> Sync for ExternalPacketOrigin<COUNT> {}

impl<const COUNT: usize> ExternalPacketOrigin<COUNT> {
    /// Bind the origin to the storage owner's release function.
    ///
    /// # Safety
    ///
    /// `release(context, slot)` must be sound to call from any core, at any
    /// time after the adoption of `slot`, exactly once per adoption.
    ///
    /// The packet's Drop clears the slot's adoption bit before it calls
    /// `release`, so the origin itself would accept a new adoption of `slot`
    /// while the owner is still reclaiming the old storage. The owner must
    /// adopt a slot again only after its `release` call for that slot has
    /// returned.
    ///
    /// The constructor is `const` so that an origin can live in a `static`
    /// whose own address, or that of an enclosing static, is its `context`.
    ///
    /// # Panics
    ///
    /// Panics unless `COUNT` is in `1..=1024`.
    pub const unsafe fn new(context: *const (), release: ExternalPacketRelease) -> Self {
        assert!(COUNT > 0, "an external packet origin must contain at least one slot");
        assert!(
            COUNT <= MAX_PACKET_POOL_COUNT,
            "an external packet origin cannot contain more than 1024 slots"
        );
        Self {
            header: PacketPoolHeader {
                allocate: allocate_none,
                release: release_external::<COUNT>,
                #[cfg(feature = "async")]
                has_available: has_available_none,
                #[cfg(feature = "async")]
                waiter_claimed: AtomicBool::new(false),
                #[cfg(feature = "async")]
                waiter: AtomicWaker::new(),
            },
            adopted: [const { AtomicU32::new(0) }; MAX_BITMAP_WORDS],
            controls: [const { UnsafeCell::new(MaybeUninit::zeroed()) }; COUNT],
            context,
            release,
        }
    }

    /// Number of slots this origin can adopt at once.
    pub const fn capacity(&self) -> usize {
        COUNT
    }

    /// Whether `buf` was adopted by this origin.
    pub fn owns(&self, buf: &PacketBuf) -> bool {
        core::ptr::eq(buf.inner().origin.as_ptr(), &self.header)
    }

    /// Adopt `PACKET_BUF_SIZE` bytes at `data` as a packet holding
    /// `data[headroom..headroom + len]`.
    ///
    /// # Safety
    ///
    /// `data` must point to `PACKET_BUF_SIZE` initialized bytes aligned to
    /// [`PACKET_BUF_ALIGN`](crate::config::PACKET_BUF_ALIGN). They must stay
    /// valid and be accessed only through the returned packet until its Drop
    /// calls this origin's release function with `slot`.
    ///
    /// # Panics
    ///
    /// Panics if `slot` is out of range or already adopted, or if
    /// `headroom + len` exceeds `PACKET_BUF_SIZE`.
    pub unsafe fn adopt(&'static self, slot: usize, data: NonNull<u8>, headroom: usize, len: usize) -> PacketBuf {
        assert!(slot < COUNT, "external packet slot out of range");
        assert!(headroom + len <= PACKET_BUF_SIZE, "external packet exceeds its buffer");
        let bit = 1 << (slot % 32);
        // Acquire pairs with the Release in `release_external`: the previous
        // owner of this control slot has finished with it.
        let previous = self.adopted[slot / 32].fetch_or(bit, Ordering::Acquire);
        assert_eq!(previous & bit, 0, "an external packet slot was adopted twice");
        let ptr = self.controls[slot].get().cast::<PacketBufInner>();
        // SAFETY: the adoption bit above uniquely claimed this control slot,
        // which is statically allocated and aligned for `PacketBufInner`. The
        // caller guarantees `data` is a valid, aligned, exclusively owned
        // `Data` for the packet's lifetime.
        unsafe {
            (&raw mut (*ptr).origin).write(NonNull::from(&self.header));
            (&raw mut (*ptr).slot).write(slot);
            (&raw mut (*ptr).headroom).write(headroom as u16);
            (&raw mut (*ptr).len).write(len as u16);
            (&raw mut (*ptr).meta).write(PacketMeta::default());
            (&raw mut (*ptr).data).write(data.cast::<Data>());
        }
        PacketBuf {
            // SAFETY: a pointer into static origin control is never null.
            inner: unsafe { NonNull::new_unchecked(ptr) },
        }
    }
}

unsafe fn allocate_none(_origin: NonNull<PacketPoolHeader>) -> Option<PacketBuf> {
    None
}

#[cfg(feature = "async")]
unsafe fn has_available_none(_origin: NonNull<PacketPoolHeader>) -> bool {
    false
}

unsafe fn release_external<const COUNT: usize>(origin: NonNull<PacketPoolHeader>, index: usize) {
    // SAFETY: `origin` is written only by `ExternalPacketOrigin<COUNT>::adopt`
    // and points at the first field of that stable `#[repr(C)]` origin.
    let external = unsafe { origin.cast::<ExternalPacketOrigin<COUNT>>().as_ref() };
    debug_assert!(index < COUNT);
    let bit = 1 << (index % 32);
    let previous = external.adopted[index / 32].fetch_and(!bit, Ordering::Release);
    debug_assert_ne!(previous & bit, 0, "an external packet slot was released twice");
    // SAFETY: `new`'s contract makes the owner's release callable here, once
    // per adoption; the packet no longer accesses its storage.
    unsafe { (external.release)(external.context, index) };
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
        let release = unsafe { origin.as_ref().release };
        // SAFETY: the originating pool installed this exact release function
        // and slot identity before publishing the PacketBuf.
        unsafe { release(origin, inner.slot) };
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

    struct ExternalStorage {
        bytes: std::vec::Vec<Box<Data>>,
        released: std::sync::Mutex<std::vec::Vec<usize>>,
    }

    unsafe fn record_release(context: *const (), slot: usize) {
        // SAFETY: the tests pass a leaked `ExternalStorage` as context.
        let storage = unsafe { &*context.cast::<ExternalStorage>() };
        storage.released.lock().unwrap().push(slot);
    }

    fn external<const COUNT: usize>() -> (&'static ExternalStorage, &'static ExternalPacketOrigin<COUNT>) {
        let storage: &'static ExternalStorage = Box::leak(Box::new(ExternalStorage {
            bytes: (0..COUNT)
                .map(|_| Box::new(Data(core::array::from_fn(|index| index as u8))))
                .collect(),
            released: std::sync::Mutex::new(std::vec::Vec::new()),
        }));
        // SAFETY: `record_release` only records the slot of a leaked storage.
        let origin = unsafe { ExternalPacketOrigin::new(core::ptr::from_ref(storage).cast(), record_release) };
        (storage, Box::leak(Box::new(origin)))
    }

    fn adopt<const COUNT: usize>(
        storage: &'static ExternalStorage,
        origin: &'static ExternalPacketOrigin<COUNT>,
        slot: usize,
        headroom: usize,
        len: usize,
    ) -> PacketBuf {
        let data = NonNull::from(&*storage.bytes[slot]).cast::<u8>();
        // SAFETY: each test adopts one leaked, aligned `Data` per slot and
        // does not touch it while the packet lives.
        unsafe { origin.adopt(slot, data, headroom, len) }
    }

    #[test]
    fn an_adopted_packet_views_the_external_bytes_and_returns_its_slot() {
        let (storage, origin) = external::<2>();
        let mut packet = adopt(storage, origin, 1, 10, 4);
        assert!(origin.owns(&packet));
        assert_eq!(&packet[..], &[10, 11, 12, 13]);
        assert_eq!(packet.headroom(), 10);
        // The stack may move the payload within the adopted storage.
        assert!(packet.ensure_headroom(20));
        assert_eq!(&packet[..], &[10, 11, 12, 13]);
        drop(packet);
        assert_eq!(*storage.released.lock().unwrap(), [1]);
        // The released slot can be adopted again.
        drop(adopt(storage, origin, 1, 0, 0));
        assert_eq!(*storage.released.lock().unwrap(), [1, 1]);
    }

    #[test]
    #[should_panic(expected = "adopted twice")]
    fn a_slot_cannot_be_adopted_twice() {
        let (storage, origin) = external::<1>();
        let _first = adopt(storage, origin, 0, 0, 0);
        let _second = adopt(storage, origin, 0, 0, 0);
    }

    struct StaticExternal {
        origin: ExternalPacketOrigin<1>,
        released: AtomicU32,
    }

    unsafe fn count_static_release(context: *const (), _slot: usize) {
        // SAFETY: the context is the address of `STATIC_EXTERNAL` below.
        let owner = unsafe { &*context.cast::<StaticExternal>() };
        owner.released.fetch_add(1, Ordering::Relaxed);
    }

    static STATIC_EXTERNAL: StaticExternal = StaticExternal {
        // SAFETY: `count_static_release` only increments a counter of this
        // static, which is callable from any thread at any time.
        origin: unsafe { ExternalPacketOrigin::new((&raw const STATIC_EXTERNAL).cast(), count_static_release) },
        released: AtomicU32::new(0),
    };

    #[test]
    fn a_static_origin_can_name_its_enclosing_static_as_context() {
        let data: &'static Data = Box::leak(Box::new(Data([7; PACKET_BUF_SIZE])));
        // SAFETY: the leaked `Data` is aligned, initialized and only accessed
        // through the adopted packet.
        let packet = unsafe { STATIC_EXTERNAL.origin.adopt(0, NonNull::from(data).cast(), 0, 1) };
        assert_eq!(&packet[..], &[7]);
        drop(packet);
        assert_eq!(STATIC_EXTERNAL.released.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_external_origin_never_allocates() {
        let (_, origin) = external::<1>();
        let header = NonNull::from(&origin.header);
        // SAFETY: the header belongs to a live origin.
        assert!(unsafe { (origin.header.allocate)(header) }.is_none());
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
