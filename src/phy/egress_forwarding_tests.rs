use core::num::{NonZeroU16, NonZeroU32};

use super::{
    Device, EgressDemand, EgressDemandId, EgressDemandLevel, EgressDemandUpdate, EgressKey,
    FaultInjector, FuzzInjector, Fuzzer, Medium, PcapMode, PcapWriter, Tracer,
};
use crate::tests::TestingDevice;
use crate::time::Instant;

fn update() -> EgressDemandUpdate {
    EgressDemandUpdate::Active(EgressDemand::new(
        EgressDemandId::new(7, NonZeroU32::new(11).unwrap()),
        EgressKey::from_words([2, 3, 5, 7]),
        EgressDemandLevel::new(NonZeroU16::new(13).unwrap(), true),
    ))
}

fn assert_forwarded(device: &TestingDevice) {
    assert_eq!(device.egress_demand_updates, vec![update()]);
}

#[test]
fn mutable_reference_forwards_egress_demand() {
    let mut device = TestingDevice::new(Medium::Ethernet);
    let mut borrowed = &mut device;
    <&mut TestingDevice as Device>::update_egress_demand(&mut borrowed, update());
    assert_forwarded(&device);
}

#[test]
fn tracer_forwards_egress_demand() {
    let mut device = Tracer::new(TestingDevice::new(Medium::Ethernet), |_| {});
    device.update_egress_demand(update());
    assert_forwarded(device.get_ref());
}

struct NoopFuzzer;

impl Fuzzer for NoopFuzzer {
    fn fuzz_packet(&mut self, _packet_data: &mut [u8]) {}
}

#[test]
fn fuzz_injector_forwards_egress_demand() {
    let mut device =
        FuzzInjector::new(TestingDevice::new(Medium::Ethernet), NoopFuzzer, NoopFuzzer);
    device.update_egress_demand(update());
    assert_forwarded(&device.into_inner());
}

fn now() -> Instant {
    Instant::ZERO
}

#[test]
fn fault_injector_forwards_egress_demand() {
    let mut device = FaultInjector::new(TestingDevice::new(Medium::Ethernet), 1, now);
    device.update_egress_demand(update());
    assert_forwarded(&device.into_inner());
}

#[test]
fn pcap_writer_forwards_egress_demand() {
    let mut device = PcapWriter::new(
        TestingDevice::new(Medium::Ethernet),
        Vec::<u8>::new(),
        PcapMode::Both,
        now,
    );
    device.update_egress_demand(update());
    assert_forwarded(device.get_ref());
}
