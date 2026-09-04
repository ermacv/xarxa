use std::collections::VecDeque;

use crate::iface::*;
use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;
use crate::wire::*;

pub(crate) fn setup<'a>(medium: Medium) -> (Interface, SocketSet<'a>, TestingDevice) {
    let mut device = TestingDevice::new(medium);

    let config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => {
            HardwareAddress::Ethernet(EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]))
        }
        #[cfg(feature = "medium-ip")]
        Medium::Ip => HardwareAddress::Ip,
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::Extended([
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ])),
    });

    let mut iface = Interface::new(config, &mut device, Instant::ZERO);

    #[cfg(feature = "proto-ipv4")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
    }

    #[cfg(feature = "proto-ipv6")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
        });
    }

    (iface, SocketSet::new(vec![]), device)
}

/// A testing device.
#[derive(Debug)]
pub struct TestingDevice {
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
    pub(crate) rx_queue: VecDeque<Vec<u8>>,
    max_transmission_unit: usize,
    medium: Medium,
    #[cfg(feature = "tx-egress-metadata")]
    egress_key_override: Option<phy::EgressKey>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) egress_key_calls: usize,
    #[cfg(feature = "tx-egress-metadata")]
    egress_schedule: Option<phy::EgressSchedule>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) egress_demand_updates: Vec<phy::EgressDemandUpdate>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) egress_grants: VecDeque<phy::EgressBurstGrant>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) egress_grant_completions: Vec<phy::EgressGrantCompletion>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) granted_transmit_serials: Vec<core::num::NonZeroU32>,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) ordinary_transmit_calls: usize,
    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) control_transmit_calls: usize,
}

#[allow(clippy::new_without_default)]
impl TestingDevice {
    /// Creates a testing device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    /// The medium of this device.
    pub(crate) fn medium(&self) -> Medium {
        self.medium
    }

    pub fn new(medium: Medium) -> Self {
        TestingDevice {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            max_transmission_unit: match medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => 1514,
                #[cfg(feature = "medium-ip")]
                Medium::Ip => 1500,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => 1500,
            },
            medium,
            #[cfg(feature = "tx-egress-metadata")]
            egress_key_override: None,
            #[cfg(feature = "tx-egress-metadata")]
            egress_key_calls: 0,
            #[cfg(feature = "tx-egress-metadata")]
            egress_schedule: None,
            #[cfg(feature = "tx-egress-metadata")]
            egress_demand_updates: Vec::new(),
            #[cfg(feature = "tx-egress-metadata")]
            egress_grants: VecDeque::new(),
            #[cfg(feature = "tx-egress-metadata")]
            egress_grant_completions: Vec::new(),
            #[cfg(feature = "tx-egress-metadata")]
            granted_transmit_serials: Vec::new(),
            #[cfg(feature = "tx-egress-metadata")]
            ordinary_transmit_calls: 0,
            #[cfg(feature = "tx-egress-metadata")]
            control_transmit_calls: 0,
        }
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn set_egress_key_override(&mut self, key: Option<phy::EgressKey>) {
        self.egress_key_override = key;
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn set_egress_schedule(&mut self, schedule: Option<phy::EgressSchedule>) {
        self.egress_schedule = schedule;
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn push_egress_grant(&mut self, grant: phy::EgressBurstGrant) {
        self.egress_grants.push_back(grant);
    }
}

impl Device for TestingDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = self.medium.to_driver();
        caps.max_transmission_unit = self.max_transmission_unit;
        caps
    }

    fn receive(&mut self) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.tx_queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self) -> Option<Self::TxToken<'_>> {
        #[cfg(feature = "tx-egress-metadata")]
        {
            self.ordinary_transmit_calls = self.ordinary_transmit_calls.saturating_add(1);
        }
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn transmit_control(&mut self) -> Option<Self::TxToken<'_>> {
        self.control_transmit_calls = self.control_transmit_calls.saturating_add(1);
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn transmit_granted(
        &mut self,
        grant_serial: core::num::NonZeroU32,
    ) -> phy::EgressAdmission<Self::TxToken<'_>> {
        self.ordinary_transmit_calls = self.ordinary_transmit_calls.saturating_add(1);
        self.granted_transmit_serials.push(grant_serial);
        phy::EgressAdmission::Granted(TxToken {
            queue: &mut self.tx_queue,
        })
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn egress_key(&mut self, route: phy::EgressRoute) -> phy::EgressKey {
        self.egress_key_calls = self.egress_key_calls.saturating_add(1);
        self.egress_key_override
            .unwrap_or_else(|| phy::EgressKey::from_route(route))
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn egress_schedule(&mut self) -> Option<phy::EgressSchedule> {
        self.egress_schedule
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn update_egress_demand(&mut self, update: phy::EgressDemandUpdate) {
        self.egress_demand_updates.push(update);
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn poll_egress_grant(&mut self) -> Option<phy::EgressBurstGrant> {
        self.egress_grants.pop_front()
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn finish_egress_grant(&mut self, completion: phy::EgressGrantCompletion) {
        self.egress_grant_completions.push(completion);
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
