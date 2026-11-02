use std::boxed::Box;

use xarxa::driver::{PacketBufAllocator, PacketPool, PacketPoolStorage};

/// Allocate the example's shared stack/device packet pool on the host heap.
pub fn packet_allocator() -> PacketBufAllocator {
    let storage = Box::leak(Box::new(PacketPoolStorage::<128>::new()));
    let pool = Box::leak(Box::new(PacketPool::new(storage)));
    pool.allocator()
}
