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

use portable_atomic::{AtomicU32, Ordering};

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
}

unsafe fn allocate_from_pool<const COUNT: usize>(origin: NonNull<PacketPoolHeader>) -> Option<PacketBuf> {
    // SAFETY: `origin` is produced from the first field of a stable
    // `PacketPool<COUNT>` by that same pool's `allocator` method.
    unsafe { origin.cast::<PacketPool<COUNT>>().as_ref() }.try_alloc()
}

unsafe fn release_slot<const COUNT: usize>(origin: NonNull<PacketPoolHeader>, index: usize) {
    // SAFETY: `origin` is written only by `PacketPool<COUNT>::try_alloc` and
    // points at the first field of that stable `#[repr(C)]` pool.
    let pool = unsafe { origin.cast::<PacketPool<COUNT>>().as_ref() };
    debug_assert!(index < COUNT);
    let bit = 1 << (index % 32);
    let previous = pool.used[index / 32].fetch_and(!bit, Ordering::Release);
    debug_assert_ne!(previous & bit, 0, "a packet pool slot was released twice");
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

    fn new_pool<const COUNT: usize>() -> &'static PacketPool<COUNT> {
        let storage = Box::leak(Box::new(PacketPoolStorage::new()));
        Box::leak(Box::new(PacketPool::new(storage)))
    }

    fn new_buffer() -> PacketBuf {
        new_pool::<1>().try_alloc().unwrap()
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
