//! One process owns the shared pool, including deliberate exhaustion.
#![cfg(all(feature = "alloc", feature = "medium-ethernet", feature = "ipv4", feature = "udp"))]
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use xarxa::{
    Stack,
    driver::{Capabilities, Driver, HardwareAddress, LinkState, PacketBuf},
    time::Instant,
    udp::SendError,
    wire::{IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address},
};

#[derive(Default)]
struct State {
    rx: VecDeque<PacketBuf>,
    tx: Vec<PacketBuf>,
    credit: usize,
    refuse: bool,
    down: bool,
    attempts: usize,
}
struct Device(Rc<RefCell<State>>);
impl Driver for Device {
    fn capabilities(&self) -> Capabilities {
        Capabilities::default()
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet([2, 0, 0, 0, 0, 1])
    }
    fn link_state(&mut self) -> LinkState {
        if self.0.borrow().down {
            LinkState::Down
        } else {
            LinkState::Up
        }
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        self.0.borrow_mut().rx.pop_front()
    }
    fn can_transmit(&mut self) -> bool {
        self.0.borrow().credit != 0
    }
    fn transmit(&mut self, packet: PacketBuf) -> Result<(), PacketBuf> {
        let mut s = self.0.borrow_mut();
        s.attempts += 1;
        if s.credit == 0 || s.refuse {
            return Err(packet);
        }
        s.credit -= 1;
        s.tx.push(packet);
        Ok(())
    }
}
fn request(peer: u8) -> PacketBuf {
    let mut p = PacketBuf::try_new().unwrap();
    p.set_len(42);
    p.fill(0);
    p[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    p[6..12].copy_from_slice(&[2, 0, 0, 0, 0, peer]);
    p[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    p[22..28].copy_from_slice(&[2, 0, 0, 0, 0, peer]);
    p[28..32].copy_from_slice(&[192, 0, 2, peer]);
    p[38..42].copy_from_slice(&[192, 0, 2, 1]);
    p
}
#[test]
fn arp_retains_owner_prioritizes_credit_and_preserves_ingress() {
    let state = Rc::new(RefCell::new(State::default()));
    let mut stack = Stack::new(1);
    let iface = stack.add_iface(Box::new(Device(state.clone()))).unwrap();
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new(Ipv4Address::new(192, 0, 2, 1).into(), 24))
        .unwrap();
    let original = request(2);
    let address = original.as_ptr();
    state.borrow_mut().rx.push_back(original);
    let mut held = Vec::new();
    while let Some(p) = PacketBuf::try_new() {
        held.push(p);
    }
    assert_eq!(stack.poll(Instant::from_millis(0)), Instant::MAX);
    assert!(state.borrow().rx.is_empty());
    assert_eq!(state.borrow().attempts, 0);
    assert!(PacketBuf::try_new().is_none(), "original request owner is retained");
    for _ in 0..20 {
        assert_eq!(stack.poll(Instant::from_millis(0)), Instant::MAX);
    }
    assert_eq!(state.borrow().attempts, 0, "no busy retry against absent credit");
    state.borrow_mut().credit = 1;
    state.borrow_mut().refuse = true;
    stack.poll(Instant::from_millis(0));
    assert!(state.borrow().tx.is_empty());
    state.borrow_mut().refuse = false;
    stack.poll(Instant::from_millis(0));
    let reply = state.borrow_mut().tx.pop().unwrap();
    assert_eq!(
        reply.as_ptr(),
        address,
        "reuse exact incoming storage even with full pool"
    );
    assert_eq!(&reply[20..22], &[0, 2]);
    assert_eq!(&reply[..6], &[2, 0, 0, 0, 0, 2]);
    drop(reply);
    drop(held);

    let socket = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(socket)
        .bind(1234, IpListenEndpoint::UNSPECIFIED)
        .unwrap();
    // Duplicate requests coalesce; subsequent non-ARP RX is still consumed.
    for _ in 0..3 {
        state.borrow_mut().rx.push_back(request(2));
    }
    let mut data = PacketBuf::try_new().unwrap();
    data.set_len(46);
    data.fill(0);
    data[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    data[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    data[12..14].copy_from_slice(&[8, 0]);
    data[14] = 0x45;
    data[16..18].copy_from_slice(&32u16.to_be_bytes());
    data[22] = 64;
    data[23] = 17;
    data[26..30].copy_from_slice(&[192, 0, 2, 2]);
    data[30..34].copy_from_slice(&[192, 0, 2, 1]);
    let mut sum: u32 = data[14..34]
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    data[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    data[34..36].copy_from_slice(&1235u16.to_be_bytes());
    data[36..38].copy_from_slice(&1234u16.to_be_bytes());
    data[38..40].copy_from_slice(&12u16.to_be_bytes());
    data[42..].copy_from_slice(b"data");
    state.borrow_mut().rx.push_back(data);
    stack.poll(Instant::from_millis(1));
    assert!(state.borrow().rx.is_empty());
    let mut received = [0; 4];
    assert_eq!(stack.udp_socket(socket).recv_slice(&mut received).unwrap().0, 4);
    assert_eq!(&received, b"data", "pending ARP must not block UDP ingress");
    state.borrow_mut().credit = 1;
    assert_eq!(
        stack
            .udp_socket(socket)
            .send_slice(b"data", IpEndpoint::new(Ipv4Address::new(192, 0, 2, 2).into(), 1235)),
        Err(SendError::DeviceBusy)
    );
    assert_eq!(
        state.borrow().tx.len(),
        1,
        "response takes returned credit before socket data"
    );
    state.borrow_mut().tx.clear();
    state.borrow_mut().credit = 1;
    stack.poll(Instant::from_millis(1));
    assert!(state.borrow().tx.is_empty(), "duplicates require one reply");

    state.borrow_mut().credit = 0;
    for peer in 2..7 {
        state.borrow_mut().rx.push_back(request(peer));
    }
    stack.poll(Instant::from_millis(2));
    assert!(state.borrow().rx.is_empty());
    state.borrow_mut().credit = 8;
    stack.poll(Instant::from_millis(2));
    assert_eq!(
        state.borrow().tx.len(),
        4,
        "bounded control queue; no unbounded pool retention"
    );
    for (i, p) in state.borrow().tx.iter().enumerate() {
        assert_eq!(p[5], 2 + i as u8);
    }
    state.borrow_mut().tx.clear();

    state.borrow_mut().credit = 0;
    state.borrow_mut().rx.push_back(request(2));
    stack.poll(Instant::from_millis(3));
    state.borrow_mut().down = true;
    stack.poll(Instant::from_millis(3));
    state.borrow_mut().down = false;
    state.borrow_mut().credit = 1;
    stack.poll(Instant::from_millis(4));
    assert!(state.borrow().tx.is_empty(), "link-down discards old replies");
    state.borrow_mut().credit = 0;
    state.borrow_mut().rx.push_back(request(2));
    stack.poll(Instant::from_millis(5));
    stack.iface(iface).set_ip_addrs([]).unwrap();
    state.borrow_mut().credit = 1;
    stack.poll(Instant::from_millis(5));
    assert!(
        state.borrow().tx.is_empty(),
        "removed address cannot emit a delayed reply"
    );
}
