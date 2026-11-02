//! Native IPv4 replies retain the RX owner across TX backpressure.
#![cfg(all(feature = "medium-ethernet", feature = "ipv4", feature = "icmp-ping-reply"))]
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use xarxa::{
    Stack,
    driver::{Capabilities, Driver, HardwareAddress, PacketBuf, PacketBufAllocator, PacketPool, PacketPoolStorage},
    time::Instant,
    wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv4Message, Icmpv4Packet, IpCidr, IpProtocol, Ipv4Addr,
        Ipv4Packet,
    },
};

#[derive(Default)]
struct State {
    rx: VecDeque<PacketBuf>,
    tx: Vec<PacketBuf>,
    credit: usize,
    attempts: usize,
    refuse: bool,
    credit_on_receive: bool,
}
struct Device(Rc<RefCell<State>>);
impl Driver for Device {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet([2, 0, 0, 0, 0, 1])
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        let mut state = self.0.borrow_mut();
        let packet = state.rx.pop_front();
        if packet.is_some() && state.credit_on_receive {
            state.credit = 1;
        }
        packet
    }
    fn can_transmit(&mut self) -> bool {
        self.0.borrow().credit != 0
    }
    fn transmit(&mut self, packet: PacketBuf) -> Result<(), PacketBuf> {
        let mut state = self.0.borrow_mut();
        state.attempts += 1;
        if state.credit == 0 || state.refuse {
            return Err(packet);
        }
        state.credit -= 1;
        state.tx.push(packet);
        Ok(())
    }
}
const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
fn allocator() -> PacketBufAllocator {
    let storage = Box::leak(Box::new(PacketPoolStorage::<32>::new()));
    Box::leak(Box::new(PacketPool::new(storage))).allocator()
}
fn configure<'d>(stack: &mut Stack<'d, Device>, device: &'d mut Device, allocator: PacketBufAllocator) {
    let state = device.0.clone();
    let iface = stack.add_iface_borrowed(device).unwrap();
    stack
        .iface(iface)
        .set_ip_addrs([IpCidr::new(LOCAL.into(), 24)])
        .unwrap();
    // Establish the real Ethernet neighbor through ARP before measuring TX.
    let mut arp = allocator.try_alloc().unwrap();
    arp.reserve(xarxa::driver::config::PACKET_BUF_DRIVER_HEADROOM);
    arp.set_len(42);
    arp.fill(0);
    arp[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    arp[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    arp[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    arp[22..28].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    arp[28..32].copy_from_slice(&[192, 0, 2, 2]);
    arp[38..42].copy_from_slice(&[192, 0, 2, 1]);
    state.borrow_mut().credit = 1;
    state.borrow_mut().rx.push_back(arp);
    stack.poll(Instant::ZERO);
    assert_eq!(state.borrow().tx.len(), 1);
    state.borrow_mut().tx.clear();
    state.borrow_mut().credit = 0;
    state.borrow_mut().attempts = 0;
}
fn request(allocator: PacketBufAllocator, sequence: u16) -> PacketBuf {
    let mut packet = allocator.try_alloc().unwrap();
    packet.reserve(xarxa::driver::config::PACKET_BUF_DRIVER_HEADROOM);
    packet.set_len(14 + 20 + 8 + 4);
    packet.fill(0);
    let mut ethernet = EthernetFrame::new_checked(&mut packet).unwrap();
    ethernet.set_src_addr(EthernetAddress([2, 0, 0, 0, 0, 2]));
    ethernet.set_dst_addr(EthernetAddress([2, 0, 0, 0, 0, 1]));
    ethernet.set_ethertype(EthernetProtocol::Ipv4);
    let mut ip = Ipv4Packet::new_unchecked(ethernet.payload_mut());
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(32);
    ip.set_next_header(IpProtocol::Icmp);
    ip.set_hop_limit(64);
    ip.set_src_addr(PEER);
    ip.set_dst_addr(LOCAL);
    ip.fill_checksum();
    let mut icmp = Icmpv4Packet::new_checked(ip.payload_mut()).unwrap();
    icmp.set_msg_type(Icmpv4Message::EchoRequest);
    icmp.set_echo_ident(17);
    icmp.set_echo_seq_no(sequence);
    icmp.data_mut().copy_from_slice(b"echo");
    icmp.fill_checksum();
    packet
}
fn sequence(packet: &mut PacketBuf) -> u16 {
    let mut ethernet = EthernetFrame::new_checked(packet).unwrap();
    let mut ip = Ipv4Packet::new_checked(ethernet.payload_mut()).unwrap();
    assert_eq!(ip.src_addr(), LOCAL);
    assert_eq!(ip.dst_addr(), PEER);
    assert!(ip.verify_checksum());
    let icmp = Icmpv4Packet::new_checked(ip.payload_mut()).unwrap();
    assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
    assert_eq!(icmp.echo_ident(), 17);
    assert_eq!(icmp.data(), b"echo");
    assert!(icmp.verify_checksum());
    icmp.echo_seq_no()
}

#[test]
fn refusal_retains_the_exact_owner_until_credit_without_pool_or_timer_retry() {
    let allocator = allocator();
    let state = Rc::new(RefCell::new(State::default()));
    let mut device = Device(state.clone());
    let mut stack = Stack::new(1, allocator);
    configure(&mut stack, &mut device, allocator);
    let before = stack.statistics().tx_frames;
    let packet = request(allocator, 7);
    let original = packet.as_ptr();
    state.borrow_mut().rx.push_back(packet);
    let mut held = Vec::new();
    while let Some(packet) = allocator.try_alloc() {
        held.push(packet);
    }
    for _ in 0..20 {
        assert!(stack.poll(Instant::ZERO) > Instant::from_millis(1));
        assert!(allocator.try_alloc().is_none());
    }
    assert_eq!(state.borrow().attempts, 1);
    assert!(state.borrow().tx.is_empty());
    assert_eq!(stack.statistics().icmpv4_echo_refused, 1);
    assert_eq!(stack.statistics().icmpv4_echo_dropped, 0);
    // Even an unexpected refusal after can_transmit(true) keeps the head slot.
    state.borrow_mut().credit = 1;
    state.borrow_mut().refuse = true;
    assert_eq!(stack.poll(Instant::ZERO), Instant::ZERO);
    assert!(allocator.try_alloc().is_none());
    state.borrow_mut().refuse = false;
    stack.poll(Instant::ZERO);
    let mut reply = state.borrow_mut().tx.pop().unwrap();
    assert_eq!(reply.as_ptr(), original);
    assert_eq!(sequence(&mut reply), 7);
    assert_eq!(stack.statistics().tx_frames - before, 3);
    assert_eq!(stack.statistics().icmpv4_echo_refused, 2);
    drop(reply);
    assert!(allocator.try_alloc().is_some());
}

#[test]
fn overflow_drops_newest_counts_once_and_preserves_fifo_across_partial_drains() {
    let allocator = allocator();
    let state = Rc::new(RefCell::new(State::default()));
    let mut device = Device(state.clone());
    let mut stack = Stack::new(1, allocator);
    configure(&mut stack, &mut device, allocator);
    for seq in 0..9 {
        state.borrow_mut().rx.push_back(request(allocator, seq));
    }
    stack.poll(Instant::ZERO);
    assert_eq!(stack.statistics().icmpv4_echo_requests, 9);
    assert_eq!(stack.statistics().icmpv4_echo_replies, 9);
    assert_eq!(stack.statistics().icmpv4_echo_refused, 1);
    assert_eq!(stack.statistics().icmpv4_echo_dropped, 1);
    assert_eq!(state.borrow().attempts, 1);
    // Only the eight retained owners remain unavailable after overflow.
    let free: Vec<_> = std::iter::from_fn(|| allocator.try_alloc()).collect();
    assert_eq!(free.len(), 24);
    drop(free);
    state.borrow_mut().credit = 2;
    stack.poll(Instant::ZERO);
    state.borrow_mut().rx.push_back(request(allocator, 9));
    stack.poll(Instant::ZERO);
    state.borrow_mut().credit = 8;
    stack.poll(Instant::ZERO);
    let mut state = state.borrow_mut();
    let sequences: Vec<_> = state.tx.iter_mut().map(sequence).collect();
    assert_eq!(sequences, [0, 1, 2, 3, 4, 5, 6, 7, 9]);
    assert_eq!(stack.statistics().icmpv4_echo_dropped, 1);
    state.tx.clear();
    assert_eq!(
        std::iter::from_fn(|| allocator.try_alloc()).collect::<Vec<_>>().len(),
        32
    );
}

#[test]
fn credit_return_during_ingress_schedules_next_turn_and_cannot_bypass_older_reply() {
    let allocator = allocator();
    let state = Rc::new(RefCell::new(State::default()));
    let mut device = Device(state.clone());
    let mut stack = Stack::new(1, allocator);
    configure(&mut stack, &mut device, allocator);
    state.borrow_mut().rx.push_back(request(allocator, 1));
    stack.poll(Instant::ZERO);
    state.borrow_mut().credit_on_receive = true;
    state.borrow_mut().rx.push_back(request(allocator, 2));
    assert_eq!(stack.poll(Instant::ZERO), Instant::ZERO);
    assert!(state.borrow().tx.is_empty());
    state.borrow_mut().credit_on_receive = false;
    stack.poll(Instant::ZERO);
    assert_eq!(sequence(&mut state.borrow_mut().tx[0]), 1);
    state.borrow_mut().credit = 1;
    stack.poll(Instant::ZERO);
    assert_eq!(sequence(&mut state.borrow_mut().tx[1]), 2);
}
