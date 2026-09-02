/*! Access to networking hardware.

The `phy` module deals with the *network devices*. The [Driver] trait, and the types
appearing in its signature, live in the separate [`xarxa-driver`](xarxa_driver) crate,
and are re-exported here. Driver crates should depend on `xarxa-driver` rather than on
`xarxa`, so that they don't need to be updated for every breaking change in `xarxa`

This module provides implementations of [Driver]:

  * the [_loopback_](struct.Loopback.html), for zero dependency testing;
  * _middleware_ [Tracer](struct.Tracer.html) and
    [FaultInjector](struct.FaultInjector.html), to facilitate debugging;
  * _adapters_ [RawSocket](struct.RawSocket.html) and
    [TunTapInterface](struct.TunTapInterface.html), to transmit and receive frames
    on the host OS.
*/

#[cfg(feature = "packetmeta-timestamp")]
pub use xarxa_driver::TxTimestamp;
pub use xarxa_driver::{
    Checksum, ChecksumCapabilities, Device, DeviceCapabilities, PacketMeta, RxToken, Timestamp,
    TxToken,
};
#[cfg(feature = "tx-egress-metadata")]
pub use xarxa_driver::{
    EgressAdmission, EgressBurstGrant, EgressDemand, EgressDemandId, EgressDemandLevel,
    EgressDemandUpdate, EgressGrantCompletion, EgressGrantMode, EgressHardwareAddress, EgressKey,
    EgressRoute, EgressSchedule,
};

/// Type of medium of a driver, as reported in [`DeviceCapabilities::medium`].
///
/// This always has all its variants, regardless of which Cargo features `xarxa` is built with,
/// because a driver crate cannot know what the stack it is used with was built for. See
/// [`Medium`] for the stack-internal counterpart.
pub use xarxa_driver::Medium as DriverMedium;

/// Type of medium of an interface.
///
/// This is the stack-internal counterpart of [`xarxa_driver::Medium`]: it only has variants for the
/// mediums the stack was built for, so that when a single `medium-*` Cargo feature is enabled
/// it becomes a zero-sized type and all the matches on it are compiled away.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Medium {
    /// See [`DriverMedium::Ethernet`].
    #[cfg(feature = "medium-ethernet")]
    Ethernet,

    /// See [`DriverMedium::Ip`].
    #[cfg(feature = "medium-ip")]
    Ip,

    /// See [`DriverMedium::Ieee802154`].
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154,
}

impl Medium {
    /// Convert from the medium reported by a driver.
    ///
    /// # Panics
    ///
    /// Panics if the corresponding `medium-*` Cargo feature is not enabled.
    pub fn from_driver(medium: DriverMedium) -> Self {
        match medium {
            #[cfg(feature = "medium-ethernet")]
            DriverMedium::Ethernet => Self::Ethernet,
            #[cfg(feature = "medium-ip")]
            DriverMedium::Ip => Self::Ip,
            #[cfg(feature = "medium-ieee802154")]
            DriverMedium::Ieee802154 => Self::Ieee802154,
            medium => panic!(
                "The driver's medium is {medium:?}, but xarxa was built without support for it. Enable the corresponding `medium-*` Cargo feature."
            ),
        }
    }

    /// Convert to the medium a driver reports.
    pub fn to_driver(self) -> DriverMedium {
        match self {
            #[cfg(feature = "medium-ethernet")]
            Self::Ethernet => DriverMedium::Ethernet,
            #[cfg(feature = "medium-ip")]
            Self::Ip => DriverMedium::Ip,
            #[cfg(feature = "medium-ieee802154")]
            Self::Ieee802154 => DriverMedium::Ieee802154,
        }
    }
}

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
mod sys;

#[cfg(all(
    test,
    feature = "std",
    feature = "alloc",
    feature = "medium-ethernet",
    feature = "tx-egress-metadata"
))]
mod egress_forwarding_tests;
mod fault_injector;
#[cfg(feature = "alloc")]
mod fuzz_injector;
#[cfg(feature = "alloc")]
mod loopback;
mod pcap_writer;
#[cfg(all(feature = "phy-raw_socket", unix))]
mod raw_socket;
mod tracer;
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
mod tuntap_interface;

#[cfg(all(
    any(feature = "phy-raw_socket", feature = "phy-tuntap_interface"),
    unix
))]
pub use self::sys::wait;

pub use self::fault_injector::FaultInjector;
#[cfg(feature = "alloc")]
pub use self::fuzz_injector::{FuzzInjector, Fuzzer};
#[cfg(feature = "alloc")]
pub use self::loopback::Loopback;
pub use self::pcap_writer::{PcapLinkType, PcapMode, PcapSink, PcapWriter};
#[cfg(all(feature = "phy-raw_socket", unix))]
pub use self::raw_socket::RawSocket;
pub use self::tracer::{Tracer, TracerDirection, TracerPacket};
#[cfg(all(
    feature = "phy-tuntap_interface",
    any(target_os = "linux", target_os = "android")
))]
pub use self::tuntap_interface::TunTapInterface;

/// The IPV4 payload fragment size must be an increment of this value.
#[cfg(feature = "proto-ipv4-fragmentation")]
pub const IPV4_FRAGMENT_PAYLOAD_ALIGNMENT: usize = 8;
