//! Readiness, routing and lifetime behavior of blocked UDP senders.
#![cfg(all(
    feature = "async",
    feature = "udp",
    feature = "ipv4",
    feature = "medium-ip",
    feature = "alloc"
))]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Wake, Waker};
use xarxa::{
    Stack,
    driver::{PacketPool, PacketPoolStorage},
    iface::Medium,
    time::Instant,
    udp::SendError,
    wire::{HardwareAddress, IpCidr, Ipv4Addr, ListenSocketAddr, SocketAddr},
};
#[path = "../src/test_device.rs"]
mod test_device;
use test_device::TestDevice;

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl Wakes {
    fn take(&self) -> usize {
        self.0.swap(0, Ordering::SeqCst)
    }
}

// Exercise the stack with its own explicit pool.
#[test]
fn device_wait_tracks_capacity_and_route_without_losing_pool_retries() {
    let storage = Box::leak(Box::new(PacketPoolStorage::<16>::new()));
    let pool = Box::leak(Box::new(PacketPool::new(storage)));
    let allocator = pool.allocator();
    let mut stack = Stack::new(1, allocator);
    let blocked = TestDevice::new(Medium::Ip);
    blocked.room.set(Some(0));
    let first = blocked.install(&mut stack, HardwareAddress::Ip);
    let address = IpCidr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 24);
    stack.iface(first).add_ip_addr(address).unwrap();
    let other = TestDevice::new(Medium::Ip);
    let second = other.install(&mut stack, HardwareAddress::Ip);
    stack
        .iface(second)
        .add_ip_addr(IpCidr::new(Ipv4Addr::new(198, 51, 100, 1).into(), 24))
        .unwrap();
    let socket = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(socket)
        .bind(1234, ListenSocketAddr::UNSPECIFIED)
        .unwrap();
    let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 1235);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    assert_eq!(
        stack.udp_socket(socket).send_slice(b"hello", peer),
        Err(SendError::DeviceBusy)
    );
    stack.udp_socket(socket).register_send_waker(&waker);
    for _ in 0..1000 {
        stack.poll(Instant::from_millis(0));
    }
    assert_eq!(wakes.take(), 0, "an idle second interface cannot wake this sender");
    blocked.room.set(Some(1));
    stack.poll(Instant::from_millis(0));
    assert_eq!(wakes.take(), 1);
    stack.udp_socket(socket).send_slice(b"hello", peer).unwrap();
    assert_eq!(blocked.tx.borrow().len(), 1);

    assert_eq!(
        stack.udp_socket(socket).send_slice(b"next", peer),
        Err(SendError::DeviceBusy)
    );
    stack.udp_socket(socket).register_send_waker(&waker);
    stack.remove_iface(first);
    stack.poll(Instant::from_millis(0));
    assert_eq!(
        wakes.take(),
        1,
        "removed route must allow the sender to observe an error"
    );
    assert_eq!(
        stack.udp_socket(socket).send_slice(b"next", peer),
        Err(SendError::Unaddressable)
    );
    stack.iface(second).add_ip_addr(address).unwrap();
    stack.udp_socket(socket).send_slice(b"rerouted", peer).unwrap();

    other.room.set(Some(0));
    assert_eq!(
        stack.udp_socket(socket).send_slice(b"close", peer),
        Err(SendError::DeviceBusy)
    );
    stack.udp_socket(socket).register_send_waker(&waker);
    stack.udp_socket(socket).close();
    assert_eq!(wakes.take(), 1);
    stack.poll(Instant::from_millis(0));
    assert_eq!(wakes.take(), 0);
    stack
        .udp_socket(socket)
        .bind(1234, ListenSocketAddr::UNSPECIFIED)
        .unwrap();
    other.room.set(None);

    let mut held = Vec::new();
    while let Some(packet) = allocator.try_alloc() {
        held.push(packet);
    }
    assert_eq!(
        stack.udp_socket(socket).send_slice(b"pool", peer),
        Err(SendError::NoBuffer)
    );
    stack.udp_socket(socket).register_send_waker(&waker);
    assert!(stack.take_packet_allocator_starved());
    stack.poll(Instant::from_millis(0));
    assert_eq!(wakes.take(), 0, "an empty pool cannot wake the sender");
    assert!(
        stack.take_packet_allocator_starved(),
        "the waiting sender keeps the pool waiter armed"
    );
    drop(held.pop());
    stack.poll(Instant::from_millis(0));
    assert_eq!(wakes.take(), 1, "a freed buffer wakes the sender");
    stack.udp_socket(socket).send_slice(b"pool", peer).unwrap();
    drop(held);
}
