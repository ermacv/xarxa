#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[allow(unused)]
use std::vec::Vec;

use crate::tests::setup;

use rstest::*;

use super::*;

use crate::iface::Interface;
use crate::phy::ChecksumCapabilities;
#[cfg(feature = "alloc")]
use crate::phy::Loopback;
use crate::time::Instant;

#[cfg(feature = "tx-egress-metadata")]
fn resolved_key(last_octet: u8) -> EgressKey {
    EgressKey::from_route(EgressRoute {
        destination: EgressHardwareAddress::Ethernet([2, 0, 0, 0, 0, last_octet]),
        traffic_class: 0,
    })
}

#[cfg(feature = "tx-egress-metadata")]
fn egress_schedule(max_packets_per_key: u8, dispatch_quantum: u8, epoch: u32) -> EgressSchedule {
    EgressSchedule::new(
        core::num::NonZeroU8::new(max_packets_per_key).unwrap(),
        core::num::NonZeroU8::new(dispatch_quantum).unwrap(),
        epoch,
        crate::phy::EgressGrantMode::StackSelected,
    )
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn interface_wide_resolved_burst_defers_a_second_socket_until_ba32() {
    let a = resolved_key(1);
    let b = resolved_key(2);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 1));

    for _ in 0..31 {
        assert!(burst.prepare(a));
        burst.commit(a);
        assert!(!burst.prepare(b));
        assert!(!burst.finish_round(false));
    }

    assert!(burst.prepare(a));
    burst.commit(a);
    assert!(burst.prepare(b));
    burst.commit(b);
    assert!(!burst.finish_round(false));
    assert_eq!(burst.current, Some(b));
    assert_eq!(burst.run_length, 1);
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn interface_wide_resolved_burst_rotates_when_current_socket_empties_early() {
    let a = resolved_key(1);
    let b = resolved_key(2);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 1));

    for _ in 0..3 {
        assert!(burst.prepare(a));
        burst.commit(a);
        assert!(!burst.prepare(b));
        assert!(!burst.finish_round(false));
    }

    assert!(!burst.prepare(b));
    assert!(burst.finish_round(false));
    assert_eq!(burst.current, Some(b));
    assert!(burst.prepare(b));
    burst.commit(b);
    assert!(!burst.finish_round(false));
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn uncontended_resolved_burst_has_no_empty_round_at_ba32() {
    let a = resolved_key(1);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 1));

    for _ in 0..64 {
        assert!(burst.prepare(a));
        burst.commit(a);
        assert!(!burst.finish_round(false));
    }

    assert_eq!(burst.current, Some(a));
    assert_eq!(burst.run_length, 32);
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn global_exhaustion_does_not_rotate_the_resolved_burst() {
    let a = resolved_key(1);
    let b = resolved_key(2);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 1));

    assert!(burst.prepare(a));
    burst.commit(a);
    assert!(!burst.prepare(b));
    assert!(!burst.finish_round(true));

    assert_eq!(burst.current, Some(a));
    assert_eq!(burst.run_length, 1);
    assert!(burst.contended);
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn resolved_burst_epoch_discards_the_previous_lifecycle_phase() {
    let a = resolved_key(1);
    let b = resolved_key(2);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 7));

    for _ in 0..17 {
        assert!(burst.prepare(a));
        burst.commit(a);
        assert!(!burst.prepare(b));
        assert!(!burst.finish_round(false));
    }
    assert_eq!(burst.current, Some(a));
    assert_eq!(burst.run_length, 17);

    burst.configure(egress_schedule(32, 1, 8));
    assert_eq!(burst.current, None);
    assert_eq!(burst.run_length, 0);
    assert!(!burst.contended);
    assert!(burst.prepare(b));
}

#[cfg(all(
    feature = "tx-egress-metadata",
    feature = "socket-udp",
    feature = "proto-ipv4",
    feature = "medium-ethernet"
))]
#[test]
fn udp_providers_from_two_sockets_share_one_demand_lifetime() {
    use crate::socket::udp;

    fn udp_socket(packet_capacity: usize) -> udp::Socket<'static> {
        udp::Socket::new(
            udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 1]),
            udp::PacketBuffer::new_indexed_slots(
                vec![udp::PacketMetadata::EMPTY; packet_capacity],
                vec![0; 8 * packet_capacity],
            ),
        )
    }

    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let destination_a = Ipv4Address::new(192, 168, 1, 10);
    let destination_b = Ipv4Address::new(192, 168, 1, 11);
    for (destination, suffix) in [(destination_a, 10), (destination_b, 11)] {
        iface.inner.neighbor_cache.fill(
            IpAddress::Ipv4(destination),
            HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, suffix])),
            Instant::ZERO,
        );
    }

    let shared_key = resolved_key(42);
    device.set_egress_key_override(Some(shared_key));
    device.set_egress_schedule(Some(egress_schedule(32, 1, 7)));

    let socket_a = sockets.add(udp_socket(20));
    let socket_b = sockets.add(udp_socket(12));
    for (handle, destination, count) in [
        (socket_a, destination_a, 20_usize),
        (socket_b, destination_b, 12_usize),
    ] {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        socket.bind(1234).unwrap();
        for _ in 0..count {
            socket
                .send_slice(&[0x5a; 8], (IpAddress::Ipv4(destination), 4321))
                .unwrap();
        }
    }

    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);

    assert_eq!(device.egress_demand_updates.len(), 2);
    assert_eq!(
        device.egress_demand_updates[0],
        crate::phy::EgressDemandUpdate::Reset { schedule_epoch: 7 }
    );
    let crate::phy::EgressDemandUpdate::Active(demand) = device.egress_demand_updates[1] else {
        panic!("both providers must publish one aggregate demand");
    };
    assert_eq!(demand.key(), shared_key);
    assert_eq!(demand.level().ready_units().get(), 32);
    assert!(demand.level().horizon_ready());

    sockets.remove(socket_a);
    sockets.remove(socket_b);
    iface.poll_egress(Instant::ZERO, &mut device, &mut sockets);
    assert_eq!(
        device.egress_demand_updates.last(),
        Some(&crate::phy::EgressDemandUpdate::Inactive {
            id: demand.id(),
            key: shared_key,
        })
    );
}

#[cfg(all(
    feature = "tx-egress-metadata",
    feature = "socket-dhcpv4",
    feature = "socket-udp",
    feature = "proto-ipv4",
    feature = "medium-ethernet"
))]
#[test]
fn authoritative_udp_schedule_does_not_gate_uncatalogued_dhcp_control() {
    use crate::socket::{dhcpv4, udp};

    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let destination = Ipv4Address::new(192, 168, 1, 10);
    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv4(destination),
        HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 10])),
        Instant::ZERO,
    );
    device.set_egress_schedule(Some(EgressSchedule::new(
        core::num::NonZeroU8::new(32).unwrap(),
        core::num::NonZeroU8::new(4).unwrap(),
        7,
        crate::phy::EgressGrantMode::Authoritative,
    )));
    let udp_handle = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 1]),
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 8]),
    ));
    let udp = sockets.get_mut::<udp::Socket>(udp_handle);
    udp.bind(1234).unwrap();
    udp.send_slice(&[0x5a; 8], (IpAddress::Ipv4(destination), 4321))
        .unwrap();
    sockets.add(dhcpv4::Socket::new());
    let transmitted_before = device.tx_queue.len();

    assert_eq!(
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert!(
        device.tx_queue.len() > transmitted_before,
        "DHCP DISCOVER must bypass a UDP data grant"
    );
    assert!(device.egress_grants.is_empty());
    assert!(device.egress_grant_completions.is_empty());
    assert_eq!(device.control_transmit_calls, 1);
    assert_eq!(sockets.get::<udp::Socket>(udp_handle).send_queue(), 8);
    assert_eq!(device.egress_demand_updates.len(), 2);
    assert_eq!(
        device.egress_demand_updates[0],
        crate::phy::EgressDemandUpdate::Reset { schedule_epoch: 7 }
    );
    assert!(matches!(
        device.egress_demand_updates[1],
        crate::phy::EgressDemandUpdate::Active(_)
    ));
}

#[cfg(all(
    feature = "tx-egress-metadata",
    feature = "socket-udp",
    feature = "proto-ipv4",
    feature = "medium-ethernet"
))]
#[test]
fn authoritative_current_and_standby_grants_drain_without_an_external_wake() {
    use crate::socket::udp;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let destination = Ipv4Address::new(192, 168, 1, 10);
    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv4(destination),
        HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 10])),
        Instant::ZERO,
    );
    let selected = resolved_key(42);
    device.set_egress_key_override(Some(selected));
    device.set_egress_schedule(Some(EgressSchedule::new(
        core::num::NonZeroU8::new(32).unwrap(),
        core::num::NonZeroU8::MIN,
        7,
        crate::phy::EgressGrantMode::Authoritative,
    )));

    let socket = udp::Socket::new(
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 1]),
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY; 2], vec![0; 16]),
    );
    let handle = sockets.add(socket);
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket.bind(1234).unwrap();
    for byte in [0x5a, 0x5b] {
        socket
            .send_slice(&[byte; 8], (IpAddress::Ipv4(destination), 4321))
            .unwrap();
    }

    assert_eq!(
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets),
        PollResult::None
    );
    let crate::phy::EgressDemandUpdate::Active(initial) = device.egress_demand_updates[1] else {
        panic!("the first egress pass must publish its active demand");
    };
    let tx_before_grants = device.tx_queue.len();
    let standby_demand = crate::phy::EgressDemand::new(
        initial.id(),
        initial.key(),
        crate::phy::EgressDemandLevel::new(core::num::NonZeroU16::MIN, false),
    );
    for (serial, demand) in [(1, initial), (2, standby_demand)] {
        device.push_egress_grant(crate::phy::EgressBurstGrant::new(
            core::num::NonZeroU32::new(serial).unwrap(),
            demand,
            core::num::NonZeroU8::MIN,
            core::num::NonZeroU32::new(1_000).unwrap(),
        ));
    }

    assert_eq!(
        iface.poll(Instant::ZERO, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len() - tx_before_grants, 2);
    assert_eq!(
        device
            .granted_transmit_serials
            .iter()
            .map(|serial| serial.get())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(device.egress_grants.is_empty());
    assert_eq!(device.egress_grant_completions.len(), 2);
    assert_eq!(
        device
            .egress_grant_completions
            .iter()
            .map(|completion| (completion.serial().get(), completion.used_frames()))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 1)]
    );
}

#[cfg(all(
    feature = "tx-egress-metadata",
    feature = "socket-udp",
    feature = "proto-ipv4",
    feature = "medium-ethernet"
))]
#[test]
fn stale_current_grant_yields_to_a_valid_standby_without_sleeping() {
    use crate::socket::udp;

    let (mut iface, mut sockets, mut device) = setup(Medium::Ethernet);
    let destination = Ipv4Address::new(192, 168, 1, 10);
    iface.inner.neighbor_cache.fill(
        IpAddress::Ipv4(destination),
        HardwareAddress::Ethernet(EthernetAddress([2, 0, 0, 0, 0, 10])),
        Instant::ZERO,
    );
    let selected = resolved_key(42);
    device.set_egress_key_override(Some(selected));
    device.set_egress_schedule(Some(EgressSchedule::new(
        core::num::NonZeroU8::new(32).unwrap(),
        core::num::NonZeroU8::MIN,
        7,
        crate::phy::EgressGrantMode::Authoritative,
    )));
    let socket = udp::Socket::new(
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 1]),
        udp::PacketBuffer::new_indexed_slots(vec![udp::PacketMetadata::EMPTY], vec![0; 8]),
    );
    let handle = sockets.add(socket);
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket.bind(1234).unwrap();
    socket
        .send_slice(&[0x5a; 8], (IpAddress::Ipv4(destination), 4321))
        .unwrap();

    assert_eq!(
        iface.poll_egress(Instant::ZERO, &mut device, &mut sockets),
        PollResult::None
    );
    let crate::phy::EgressDemandUpdate::Active(demand) = device.egress_demand_updates[1] else {
        panic!("the first egress pass must publish its active demand");
    };
    let stale = crate::phy::EgressDemand::new(
        crate::phy::EgressDemandId::new(
            demand.id().schedule_epoch(),
            core::num::NonZeroU32::new(demand.id().activation().get() + 1).unwrap(),
        ),
        demand.key(),
        demand.level(),
    );
    for (serial, candidate) in [(1, stale), (2, demand)] {
        device.push_egress_grant(crate::phy::EgressBurstGrant::new(
            core::num::NonZeroU32::new(serial).unwrap(),
            candidate,
            core::num::NonZeroU8::MIN,
            core::num::NonZeroU32::new(1_000).unwrap(),
        ));
    }
    let tx_before_grants = device.tx_queue.len();

    assert_eq!(
        iface.poll(Instant::ZERO, &mut device, &mut sockets),
        PollResult::SocketStateChanged
    );
    assert_eq!(device.tx_queue.len() - tx_before_grants, 1);
    assert_eq!(
        device.granted_transmit_serials,
        [core::num::NonZeroU32::new(2).unwrap()]
    );
    assert!(device.egress_grants.is_empty());
    assert_eq!(
        device
            .egress_grant_completions
            .iter()
            .map(|completion| (completion.serial().get(), completion.used_frames()))
            .collect::<Vec<_>>(),
        vec![(1, 0), (2, 1)]
    );
}

#[cfg(feature = "tx-egress-metadata")]
#[test]
fn sparse_peer_sends_a_partial_run_without_waiting_for_ba32() {
    let saturated = resolved_key(1);
    let sparse = resolved_key(2);
    let mut burst = EgressBurstState::default();
    burst.configure(egress_schedule(32, 1, 1));

    // The sparse peer becomes contended during the saturated peer's current
    // bounded service quantum.
    for _ in 0..31 {
        assert!(burst.prepare(saturated));
        burst.commit(saturated);
        assert!(!burst.prepare(sparse));
        assert!(!burst.finish_round(false));
    }
    assert!(burst.prepare(saturated));
    burst.commit(saturated);

    // It owns only two packets. Both are admitted immediately; BA32 is the
    // maximum run, never a minimum fill threshold.
    for _ in 0..2 {
        assert!(burst.prepare(sparse));
        burst.commit(sparse);
        assert!(!burst.prepare(saturated));
        assert!(!burst.finish_round(false));
    }

    // Once the sparse queue is empty, one complete interface scan changes
    // ownership back to the still-backlogged peer and asks for an immediate
    // retry. No timer or additional packet is required.
    assert!(!burst.prepare(saturated));
    assert!(burst.finish_round(false));
    assert_eq!(burst.current, Some(saturated));
    assert!(burst.prepare(saturated));
}

#[allow(unused)]
fn fill_slice(s: &mut [u8], val: u8) {
    for x in s.iter_mut() {
        *x = val
    }
}

#[allow(unused)]
fn recv_all(device: &mut crate::tests::TestingDevice, timestamp: Instant) -> Vec<Vec<u8>> {
    let mut pkts = Vec::new();
    while let Some(pkt) = device.tx_queue.pop_front() {
        pkts.push(pkt)
    }
    pkts
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MockTxToken;

impl TxToken for MockTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut junk = [0; 1536];
        f(&mut junk[..len])
    }
}

#[test]
#[should_panic(expected = "The hardware address does not match the medium of the interface.")]
#[cfg(all(feature = "medium-ip", feature = "medium-ethernet", feature = "alloc"))]
fn test_new_panic() {
    let mut device = Loopback::new(Medium::Ethernet.to_driver());
    let config = Config::new(HardwareAddress::Ip);
    Interface::new(config, &mut device, Instant::ZERO);
}

#[cfg(feature = "socket-udp")]
#[rstest]
#[case::ip(Medium::Ip)]
#[cfg(feature = "medium-ip")]
#[case::ethernet(Medium::Ethernet)]
#[cfg(feature = "medium-ethernet")]
#[case::ieee802154(Medium::Ieee802154)]
#[cfg(feature = "medium-ieee802154")]
fn test_handle_udp_broadcast(#[case] medium: Medium) {
    use crate::socket::udp;
    use crate::wire::IpEndpoint;

    static UDP_PAYLOAD: [u8; 5] = [0x48, 0x65, 0x6c, 0x6c, 0x6f];

    let (mut iface, mut sockets, _device) = setup(medium);

    let rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);
    let tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY], vec![0; 15]);

    let udp_socket = udp::Socket::new(rx_buffer, tx_buffer);

    let mut udp_bytes = vec![0u8; 13];
    let mut packet = UdpPacket::new_unchecked(&mut udp_bytes);

    let socket_handle = sockets.add(udp_socket);

    #[cfg(feature = "proto-ipv6")]
    let src_ip = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let src_ip = Ipv4Address::new(0x7f, 0x00, 0x00, 0x02);

    let udp_repr = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };

    #[cfg(feature = "proto-ipv6")]
    let ip_repr = IpRepr::Ipv6(Ipv6Repr {
        src_addr: src_ip,
        dst_addr: IPV6_LINK_LOCAL_ALL_NODES,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    #[cfg(all(not(feature = "proto-ipv6"), feature = "proto-ipv4"))]
    let ip_repr = IpRepr::Ipv4(Ipv4Repr {
        src_addr: src_ip,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len: udp_repr.header_len() + UDP_PAYLOAD.len(),
        hop_limit: 0x40,
    });
    let dst_addr = ip_repr.dst_addr();

    // Bind the socket to port 68
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert_eq!(socket.bind(68), Ok(()));
    assert!(!socket.can_recv());
    assert!(socket.can_send());

    udp_repr.emit(
        &mut packet,
        &ip_repr.src_addr(),
        &ip_repr.dst_addr(),
        UDP_PAYLOAD.len(),
        |buf| buf.copy_from_slice(&UDP_PAYLOAD),
        &ChecksumCapabilities::default(),
    );

    // Packet should be handled by bound UDP socket
    assert_eq!(
        iface.inner.process_udp(
            &mut sockets,
            PacketMeta::default(),
            false,
            ip_repr,
            packet.into_inner(),
        ),
        None
    );

    // Make sure the payload to the UDP packet processed by process_udp is
    // appended to the bound sockets rx_buffer
    let socket = sockets.get_mut::<udp::Socket>(socket_handle);
    assert!(socket.can_recv());
    assert_eq!(
        socket.recv(),
        Ok((
            &UDP_PAYLOAD[..],
            udp::UdpMetadata {
                local_address: Some(dst_addr),
                ..IpEndpoint::new(src_ip.into(), 67).into()
            }
        ))
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv6"))]
pub fn tcp_not_accepted() {
    let (mut iface, mut sockets, _) = setup(Medium::Ip);
    let tcp = TcpRepr {
        src_port: 4242,
        dst_port: 4243,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(-10001),
        ack_number: None,
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];

    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        Some(Packet::new_ipv6(
            Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                dst_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            },
            IpPayload::Tcp(TcpRepr {
                src_port: 4243,
                dst_port: 4242,
                control: TcpControl::Rst,
                seq_number: TcpSeqNumber(0),
                ack_number: Some(TcpSeqNumber(-10000)),
                window_len: 0,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None, None, None],
                timestamp: None,
                payload: &[],
            })
        ))
    );
    // Unspecified destination address.
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2).into(),
        &Ipv6Address::UNSPECIFIED.into(),
        &ChecksumCapabilities::default(),
    );

    assert_eq!(
        iface.inner.process_tcp(
            &mut sockets,
            false,
            IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                dst_addr: Ipv6Address::UNSPECIFIED,
                next_header: IpProtocol::Tcp,
                payload_len: tcp.buffer_len(),
                hop_limit: 64,
            }),
            &tcp_bytes,
        ),
        None,
    );
}

#[test]
#[cfg(all(feature = "medium-ip", feature = "socket-tcp", feature = "proto-ipv4"))]
pub fn tcp_listen_drops_unspecified_src() {
    use crate::socket::tcp;

    let (mut iface, mut sockets, _) = setup(Medium::Ip);

    let tcp_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64]),
        tcp::SocketBuffer::new(vec![0; 64]),
    );
    let handle = sockets.add(tcp_socket);
    sockets.get_mut::<tcp::Socket>(handle).listen(1234).unwrap();

    let tcp = TcpRepr {
        src_port: 65000,
        dst_port: 1234,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut tcp_bytes = vec![0u8; tcp.buffer_len()];
    tcp.emit(
        &mut TcpPacket::new_unchecked(&mut tcp_bytes),
        &Ipv4Address::UNSPECIFIED.into(),
        &Ipv4Address::new(127, 0, 0, 1).into(),
        &ChecksumCapabilities::default(),
    );

    let reply = iface.inner.process_tcp(
        &mut sockets,
        false,
        IpRepr::Ipv4(Ipv4Repr {
            src_addr: Ipv4Address::UNSPECIFIED,
            dst_addr: Ipv4Address::new(127, 0, 0, 1),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        }),
        &tcp_bytes,
    );

    assert_eq!(reply, None);
    assert!(sockets.get_mut::<tcp::Socket>(handle).is_listening());
}
