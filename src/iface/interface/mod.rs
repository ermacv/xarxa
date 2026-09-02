// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

#[cfg(test)]
mod tests;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "medium-ieee802154")]
mod ieee802154;

#[cfg(feature = "tx-egress-metadata")]
mod egress_catalog;

#[cfg(feature = "tx-egress-metadata")]
pub(crate) use egress_catalog::EgressDemandHandle;

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "multicast")]
pub(crate) mod multicast;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
mod udp;

use super::packet::*;

use core::result::Result;
use heapless::Vec;

#[cfg(feature = "_proto-fragmentation")]
use super::fragmentation::FragKey;
#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
use super::fragmentation::{Fragmenter, FragmentsBuffer};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::socket_set::SocketSet;
use crate::config::{
    IFACE_MAX_ADDR_COUNT, IFACE_MAX_PREFIX_COUNT, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT,
};
use crate::iface::Routes;
#[cfg(feature = "proto-ipv6-slaac")]
use crate::iface::Slaac;
use crate::phy::PacketMeta;
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
#[cfg(feature = "tx-egress-metadata")]
use crate::phy::{EgressAdmission, EgressHardwareAddress, EgressKey, EgressRoute, EgressSchedule};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};

use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}
use check;

/// Result returned by [`Interface::poll`].
///
/// This contains information on whether socket states might have changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollResult {
    /// Socket state is guaranteed to not have changed.
    None,
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// Result returned by [`Interface::poll_ingress_single`].
///
/// This contains information on whether a packet was processed or not,
/// and whether it might've affected socket states.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollIngressSingleResult {
    /// No packet was processed. You don't need to call [`Interface::poll_ingress_single`]
    /// again, until more packets arrive.
    ///
    /// Socket state is guaranteed to not have changed.
    None,
    /// A packet was processed.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// Socket state is guaranteed to not have changed.
    PacketProcessed,
    /// A packet was processed, which might have caused socket state to change.
    ///
    /// There may be more packets in the device's RX queue, so you should call [`Interface::poll_ingress_single`] again.
    ///
    /// You should check the state of sockets again for received data or completion of operations.
    SocketStateChanged,
}

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface {
    pub(crate) inner: InterfaceInner,
    fragments: FragmentsBuffer,
    fragmenter: Fragmenter,
    #[cfg(feature = "tx-egress-metadata")]
    egress_demands: egress_catalog::EgressDemandCatalog<EGRESS_DEMAND_CATALOG_CAPACITY>,
}

/// Bounded distinct device keys observed by one interface.
///
/// A SoftAP interface has at most fifteen unicast peers plus one group domain.
/// Provider/socket count and packet backlog consume no additional catalog
/// slots. Overflow omits excess shadow demand while synchronous `transmit_for`
/// admission remains authoritative.
#[cfg(feature = "tx-egress-metadata")]
const EGRESS_DEMAND_CATALOG_CAPACITY: usize = 16;

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    /// Medium of the device, converted once from `caps.medium`.
    medium: Medium,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: NeighborCache,
    hardware_addr: HardwareAddress,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_id: u16,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context:
        Vec<SixlowpanAddressContext, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    ip_addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    any_ip: bool,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac_enabled: bool,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac: Slaac,
    #[cfg(feature = "proto-ipv6-slaac")]
    slaac_updated: Instant,
    routes: Routes,
    #[cfg(feature = "tx-egress-metadata")]
    egress_burst: EgressBurstState,
    #[cfg(feature = "multicast")]
    multicast: multicast::State,
}

/// Interface-wide arbitration for device-classified egress keys.
///
/// A UDP socket owns its packet arena and its per-key FIFO index, but the
/// interface owns the set of sockets. Keeping the active burst here prevents
/// two independently well-ordered sockets from being admitted to the device
/// as `A, B, A, B, ...`.
#[cfg(feature = "tx-egress-metadata")]
const EGRESS_GRANT_PIPELINE_DEPTH: usize = 2;

#[cfg(feature = "tx-egress-metadata")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EgressPreparedAdmission {
    StackSelected,
    Authoritative(core::num::NonZeroU32),
}

#[cfg(feature = "tx-egress-metadata")]
#[derive(Default)]
struct EgressBurstState {
    current: Option<EgressKey>,
    run_length: u8,
    schedule: Option<EgressSchedule>,
    contended: bool,
    granted_in_round: bool,
    deferred_in_round: Option<EgressKey>,
    quota_blocked_in_round: bool,
    grant: Option<crate::phy::EgressBurstGrant>,
    grant_used: u8,
    standby_grant: Option<crate::phy::EgressBurstGrant>,
}

#[cfg(feature = "tx-egress-metadata")]
impl EgressBurstState {
    fn drain_grants(
        &mut self,
    ) -> [Option<crate::phy::EgressGrantCompletion>; EGRESS_GRANT_PIPELINE_DEPTH] {
        let completions = [
            self.take_grant_completion(None),
            self.take_grant_completion(None),
        ];
        debug_assert!(self.grant.is_none());
        debug_assert!(self.standby_grant.is_none());
        completions
    }

    fn configure(
        &mut self,
        schedule: EgressSchedule,
    ) -> [Option<crate::phy::EgressGrantCompletion>; EGRESS_GRANT_PIPELINE_DEPTH] {
        if self.schedule != Some(schedule) {
            let completions = self.drain_grants();
            *self = Self {
                schedule: Some(schedule),
                ..Self::default()
            };
            return completions;
        }
        [None; 2]
    }

    fn install_grant(
        &mut self,
        grant: crate::phy::EgressBurstGrant,
    ) -> Result<(), crate::phy::EgressGrantCompletion> {
        let schedule = self
            .schedule
            .expect("a grant requires configured keyed scheduling");
        if schedule.grant_mode() == crate::phy::EgressGrantMode::StackSelected
            || grant.demand().id().schedule_epoch() != schedule.epoch()
            || grant.frame_credits().get() > schedule.max_packets_per_key().get()
        {
            return Err(crate::phy::EgressGrantCompletion::new(
                grant.serial(),
                0,
                None,
            ));
        }
        if self.grant.is_none() {
            self.grant = Some(grant);
            self.grant_used = 0;
            return Ok(());
        }
        if self.standby_grant.is_none() {
            self.standby_grant = Some(grant);
            return Ok(());
        }
        Err(crate::phy::EgressGrantCompletion::new(
            grant.serial(),
            0,
            None,
        ))
    }

    fn needs_grant(&self) -> bool {
        self.schedule.is_some_and(|schedule| {
            schedule.grant_mode() != crate::phy::EgressGrantMode::StackSelected
        }) && self.standby_grant.is_none()
    }

    fn active_grant(&self) -> Option<crate::phy::EgressBurstGrant> {
        self.grant
    }

    fn grant_complete(&self) -> bool {
        let Some(grant) = self.grant else {
            return false;
        };
        // A burst grant is a cross-round credit lease. In particular, the
        // stack dispatch quantum may be smaller than the radio aggregation
        // horizon, so a poll boundary must not turn one radio grant into a
        // per-dispatch (and eventually per-packet) handshake.
        self.grant_used >= grant.frame_credits().get()
    }

    fn take_grant_completion(
        &mut self,
        remaining: Option<crate::phy::EgressDemandLevel>,
    ) -> Option<crate::phy::EgressGrantCompletion> {
        let grant = self.grant.take()?;
        let used = core::mem::replace(&mut self.grant_used, 0);
        self.grant = self.standby_grant.take();
        Some(crate::phy::EgressGrantCompletion::new(
            grant.serial(),
            used,
            remaining,
        ))
    }

    fn prepare_admission(&mut self, egress: EgressKey) -> Option<EgressPreparedAdmission> {
        if self
            .schedule
            .expect("configured egress scheduler")
            .grant_mode()
            == crate::phy::EgressGrantMode::Authoritative
        {
            return self.grant.and_then(|grant| {
                (grant.demand().key() == egress && self.grant_used < grant.frame_credits().get())
                    .then_some(EgressPreparedAdmission::Authoritative(grant.serial()))
            });
        }
        let max_packets = self
            .schedule
            .expect("configured egress scheduler owns a non-zero quantum")
            .max_packets_per_key()
            .get();

        let Some(current) = self.current else {
            return Some(EgressPreparedAdmission::StackSelected);
        };
        if current == egress {
            if self.run_length < max_packets || !self.contended {
                return Some(EgressPreparedAdmission::StackSelected);
            }
            self.quota_blocked_in_round = true;
            return None;
        }

        self.contended = true;
        if self.run_length >= max_packets {
            return Some(EgressPreparedAdmission::StackSelected);
        }
        if self.deferred_in_round.is_none() {
            self.deferred_in_round = Some(egress);
        }
        None
    }

    #[cfg(test)]
    fn prepare(&mut self, egress: EgressKey) -> bool {
        self.prepare_admission(egress).is_some()
    }

    fn commit(&mut self, egress: EgressKey) {
        if self
            .schedule
            .expect("configured egress scheduler")
            .grant_mode()
            == crate::phy::EgressGrantMode::Authoritative
        {
            // `commit` is reached only after `prepare` authorized this exact
            // key and the device accepted the packet. No scheduler state can
            // change inside that synchronous emission transaction. Keep the
            // invariant visible in debug builds without repeating the full
            // 128-bit key and credit checks on every production packet.
            debug_assert!(self.grant.is_some_and(|grant| {
                grant.demand().key() == egress && self.grant_used < grant.frame_credits().get()
            }));
            self.grant_used += 1;
            self.granted_in_round = true;
            return;
        }

        // A shadow grant observes stack-selected work, so unlike an
        // authoritative grant it may legitimately not match this packet.
        if let Some(grant) = self.grant
            && grant.demand().key() == egress
            && self.grant_used < grant.frame_credits().get()
        {
            self.grant_used = self.grant_used.saturating_add(1);
        }
        let max_packets = self
            .schedule
            .expect("configured egress scheduler owns a non-zero quantum")
            .max_packets_per_key()
            .get();
        if self.current != Some(egress) {
            self.current = Some(egress);
            self.run_length = 0;
            self.contended = false;
        } else if self.run_length >= max_packets && !self.contended {
            // An uncontended stream must not pay for an empty scheduler round
            // merely because it crossed an accounting quantum.
            self.run_length = 0;
        }
        self.run_length = self.run_length.saturating_add(1);
        self.granted_in_round = true;
    }

    /// End one complete scan of all socket egress queues.
    ///
    /// Returns true when the selected key changed without an emitted packet,
    /// so the caller should immediately scan the sockets once more.
    fn finish_round(&mut self, globally_exhausted: bool) -> bool {
        if self
            .schedule
            .expect("configured egress scheduler")
            .grant_mode()
            == crate::phy::EgressGrantMode::Authoritative
        {
            self.granted_in_round = false;
            self.deferred_in_round = None;
            self.quota_blocked_in_round = false;
            return false;
        }
        let mut retry = false;
        if !globally_exhausted && !self.granted_in_round {
            if let Some(deferred) = self.deferred_in_round {
                self.current = Some(deferred);
                self.run_length = 0;
                self.contended = false;
                retry = true;
            } else if self.quota_blocked_in_round {
                // A previously observed contender disappeared. Let the only
                // remaining key resume instead of retaining a stale defer.
                self.run_length = 0;
                self.contended = false;
                retry = true;
            }
        }
        self.granted_in_round = false;
        self.deferred_in_round = None;
        self.quota_blocked_in_round = false;
        retry
    }

    fn disable(
        &mut self,
    ) -> [Option<crate::phy::EgressGrantCompletion>; EGRESS_GRANT_PIPELINE_DEPTH] {
        let completions = self.drain_grants();
        *self = Self::default();
        completions
    }
}

#[cfg(all(test, feature = "tx-egress-metadata"))]
mod egress_grant_tests {
    use core::num::{NonZeroU8, NonZeroU16, NonZeroU32};

    use super::{EGRESS_GRANT_PIPELINE_DEPTH, EgressBurstState};
    use crate::phy::{
        EgressBurstGrant, EgressDemand, EgressDemandId, EgressDemandLevel, EgressGrantMode,
        EgressKey, EgressSchedule,
    };

    fn key(value: u32) -> EgressKey {
        EgressKey::from_words([value, 0, 0, 0])
    }

    fn schedule(mode: EgressGrantMode, epoch: u32) -> EgressSchedule {
        EgressSchedule::new(
            NonZeroU8::new(32).unwrap(),
            NonZeroU8::new(4).unwrap(),
            epoch,
            mode,
        )
    }

    fn grant(serial: u32, selected: EgressKey, credits: u8) -> EgressBurstGrant {
        EgressBurstGrant::new(
            NonZeroU32::new(serial).unwrap(),
            EgressDemand::new(
                EgressDemandId::new(7, NonZeroU32::new(3).unwrap()),
                selected,
                EgressDemandLevel::new(NonZeroU16::new(32).unwrap(), true),
            ),
            NonZeroU8::new(credits).unwrap(),
            NonZeroU32::new(20_000).unwrap(),
        )
    }

    #[test]
    fn shadow_grant_survives_rounds_until_its_credits_are_spent() {
        let mut state = EgressBurstState::default();
        assert_eq!(
            state.configure(schedule(EgressGrantMode::Shadow, 7)),
            [None; 2]
        );
        let grant = grant(1, key(2), 2);
        state.install_grant(grant).unwrap();

        assert!(state.prepare(key(1)));
        state.commit(key(1));
        assert!(state.prepare(key(1)));
        state.commit(key(1));
        assert!(!state.grant_complete());
        assert!(!state.finish_round(false));
        assert!(!state.grant_complete());

        assert!(!state.prepare(key(2)));
        assert!(state.finish_round(false));
        assert!(!state.grant_complete());

        assert!(state.prepare(key(2)));
        state.commit(key(2));
        assert!(!state.grant_complete());
        assert!(!state.finish_round(false));
        assert!(!state.grant_complete());

        assert!(state.prepare(key(2)));
        state.commit(key(2));
        assert!(state.grant_complete());
        assert_eq!(
            state.take_grant_completion(Some(grant.demand().level())),
            Some(crate::phy::EgressGrantCompletion::new(
                grant.serial(),
                2,
                Some(grant.demand().level()),
            ))
        );
    }

    #[test]
    fn authoritative_grant_allows_only_its_exact_bounded_prefix() {
        let mut state = EgressBurstState::default();
        let _ = state.configure(schedule(EgressGrantMode::Authoritative, 7));
        let grant = grant(4, key(2), 2);
        state.install_grant(grant).unwrap();

        assert!(!state.prepare(key(1)));
        for _ in 0..EGRESS_GRANT_PIPELINE_DEPTH {
            assert!(state.prepare(key(2)));
            state.commit(key(2));
        }
        assert!(!state.prepare(key(2)));
        assert!(state.grant_complete());
        let completion = state.take_grant_completion(None).unwrap();
        assert_eq!(completion.serial(), grant.serial());
        assert_eq!(completion.used_frames(), 2);
    }

    #[test]
    fn epoch_change_closes_but_does_not_retarget_an_old_grant() {
        let mut state = EgressBurstState::default();
        let _ = state.configure(schedule(EgressGrantMode::Authoritative, 7));
        let grant = grant(5, key(2), 4);
        state.install_grant(grant).unwrap();
        state.commit(key(2));

        let [completion, standby] = state.configure(schedule(EgressGrantMode::Authoritative, 8));
        let completion = completion.unwrap();
        assert_eq!(standby, None);
        assert_eq!(completion.serial(), grant.serial());
        assert_eq!(completion.used_frames(), 1);
        assert_eq!(completion.remaining(), None);
        assert!(state.needs_grant());
    }

    #[test]
    fn completed_current_grant_promotes_standby_without_a_poll_boundary() {
        let mut state = EgressBurstState::default();
        let _ = state.configure(schedule(EgressGrantMode::Authoritative, 7));
        let current = grant(6, key(2), 2);
        let standby = grant(7, key(3), 2);
        state.install_grant(current).unwrap();
        state.install_grant(standby).unwrap();
        assert!(!state.needs_grant());

        for _ in 0..EGRESS_GRANT_PIPELINE_DEPTH {
            assert!(state.prepare(key(2)));
            state.commit(key(2));
        }
        let completion = state.take_grant_completion(None).unwrap();
        assert_eq!(completion.serial(), current.serial());
        assert_eq!(state.active_grant(), Some(standby));
        assert_eq!(state.grant_used, 0);
        assert!(state.needs_grant());

        for _ in 0..EGRESS_GRANT_PIPELINE_DEPTH {
            assert!(state.prepare(key(3)));
            state.commit(key(3));
        }
        let completion = state.take_grant_completion(None).unwrap();
        assert_eq!(completion.serial(), standby.serial());
        assert_eq!(state.active_grant(), None);
    }

    #[test]
    fn epoch_change_returns_current_and_standby_in_issue_order() {
        let mut state = EgressBurstState::default();
        let _ = state.configure(schedule(EgressGrantMode::Authoritative, 7));
        let current = grant(8, key(2), 4);
        let standby = grant(9, key(3), 4);
        state.install_grant(current).unwrap();
        state.install_grant(standby).unwrap();
        state.commit(key(2));

        let completions = state.configure(schedule(EgressGrantMode::Authoritative, 8));
        assert_eq!(
            completions.map(|completion| completion.map(|completion| completion.serial())),
            [Some(current.serial()), Some(standby.serial())]
        );
        assert_eq!(completions[0].unwrap().used_frames(), 1);
        assert_eq!(completions[1].unwrap().used_frames(), 0);
    }
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub pan_id: Option<Ieee802154Pan>,

    /// Enable stateless address autoconfiguration on the interface.
    #[cfg(feature = "proto-ipv6")]
    pub slaac: bool,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            hardware_addr,
            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,
            #[cfg(feature = "proto-ipv6")]
            slaac: false,
        }
    }
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the [`Config::hardware_addr`] does not match
    /// the medium of the device.
    pub fn new(config: Config, device: &mut (impl Device + ?Sized), now: Instant) -> Self {
        let caps = device.capabilities();
        let medium = Medium::from_driver(caps.medium);
        assert_eq!(
            config.hardware_addr.medium(),
            medium,
            "The hardware address does not match the medium of the interface."
        );

        let mut rand = Rand::new(config.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = rand.rand_u16();
            if tag != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-ipv4")]
        let mut ipv4_id;

        #[cfg(feature = "proto-ipv4")]
        loop {
            ipv4_id = rand.rand_u16();
            if ipv4_id != 0 {
                break;
            }
        }

        Interface {
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-sixlowpan")]
                decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],

                #[cfg(feature = "_proto-fragmentation")]
                assembler: PacketAssemblerSet::new(),
                #[cfg(feature = "_proto-fragmentation")]
                reassembly_timeout: Duration::from_secs(60),
            },
            fragmenter: Fragmenter::new(),
            #[cfg(feature = "tx-egress-metadata")]
            egress_demands: egress_catalog::EgressDemandCatalog::new(),
            inner: InterfaceInner {
                now,
                caps,
                medium,
                hardware_addr: config.hardware_addr,
                ip_addrs: Vec::new(),
                any_ip: false,
                routes: Routes::new(),
                #[cfg(feature = "tx-egress-metadata")]
                egress_burst: EgressBurstState::default(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: NeighborCache::new(),
                #[cfg(feature = "multicast")]
                multicast: multicast::State::new(),
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: config.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_id,
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: Vec::new(),
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac_enabled: config.slaac,
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac: Slaac::new(),
                #[cfg(feature = "proto-ipv6-slaac")]
                slaac_updated: Instant::from_millis(0),
                rand,
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(self.inner.medium == Medium::Ethernet || self.inner.medium == Medium::Ieee802154);

        self.inner.hardware_addr
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(self.inner.medium == Medium::Ethernet || self.inner.medium == Medium::Ieee802154);

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = addr;
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.inner.ipv6_addr()
    }

    /// Get an address from the interface that could be used as source address.
    /// For IPv4, this function tries to find a registered IPv4 address in the same
    /// subnet as the destination, falling back to the first IPv4 address if none is
    /// found. For IPv6, the selection is based on RFC6724.
    pub fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.inner.get_source_address(dst_addr)
    }

    /// Get an IPv4 source address based on a destination address. This function tries
    /// to find the first IPv4 address from the interface that is in the same subnet as
    /// the destination address. If no such address is found, the first IPv4 address
    /// from the interface is returned.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        self.inner.get_source_address_ipv4(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. The selection is
    /// based on RFC6724.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        self.inner.get_source_address_ipv6(dst_addr)
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr, IFACE_MAX_ADDR_COUNT>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_neighbor_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs);

        #[cfg(all(
            feature = "proto-ipv6",
            feature = "multicast",
            feature = "medium-ethernet"
        ))]
        if self.inner.medium == Medium::Ethernet {
            self.update_solicited_node_groups();
        }
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// AnyIP allowins packets to be received
    /// locally on IP addresses other than the interface's configured [`ip_addrs`](Self::ip_addrs).
    /// When AnyIP is enabled and a route prefix in [`routes`](Self::routes) specifies one of
    /// the interface's [`ip_addrs`](Self::ip_addrs) as its gateway, the interface will accept
    /// packets addressed to that prefix.
    pub fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Get whether AnyIP is enabled.
    ///
    /// See [`set_any_ip`](Self::set_any_ip) for details on AnyIP
    pub fn any_ip(&self) -> bool {
        self.inner.any_ip
    }

    /// Get the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.reassembly_timeout
    }

    /// Set the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        if timeout > Duration::from_secs(60) {
            net_debug!(
                "RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds"
            );
        }
        self.fragments.reassembly_timeout = timeout;
    }

    /// Transmit packets queued in the sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// ## DoS warning
    ///
    /// This function processes all packets in the device's queue. This can
    /// be an unbounded amount of work if packets arrive faster than they're
    /// processed.
    ///
    /// If this is a concern for your application (i.e. your environment doesn't
    /// have preemptive scheduling, or `poll()` is called from a main loop where
    /// other important things are processed), you may use the lower-level methods
    /// [`poll_egress()`](Self::poll_egress), [`poll_maintenance()`](Self::poll_maintenance)
    /// and [`poll_ingress_single()`](Self::poll_ingress_single).
    /// This allows you to insert yields or process other events between processing
    /// individual ingress packets.
    pub fn poll(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        let mut res = PollResult::None;

        self.poll_maintenance(timestamp);

        // Process ingress while there's packets available.
        loop {
            match self.socket_ingress(device, sockets) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        // Process egress.
        loop {
            match self.poll_egress(timestamp, device, sockets) {
                PollResult::None => break,
                PollResult::SocketStateChanged => res = PollResult::SocketStateChanged,
            }
        }

        res
    }

    /// Transmit packets queued in the sockets.
    ///
    /// This function returns a value indicating whether the state of any socket
    /// might have changed.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_egress(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;

        match self.inner.medium {
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                self.sixlowpan_egress(device);
            }
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
            _ => {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                self.ipv4_egress(device);
            }
        }

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac_enabled {
            self.ndisc_rs_egress(device);
        }

        #[cfg(feature = "multicast")]
        self.multicast_egress(device);

        self.socket_egress(device, sockets)
    }

    /// Process one incoming packet queued in the device.
    ///
    /// Returns a value indicating:
    /// - whether a packet was processed, in which case you have to call this method again in case there's more packets queued.
    /// - whether the state of any socket might have changed.
    ///
    /// Since it processes at most one packet, this is guaranteed to always perform a bounded amount of work.
    pub fn poll_ingress_single(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollIngressSingleResult {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.fragments.assembler.remove_expired(timestamp);

        self.socket_ingress(device, sockets)
    }

    /// Maintain stateful processing on the device.
    ///
    /// This is guaranteed to always perform a bounded amount of work.
    pub fn poll_maintenance(&mut self, timestamp: Instant) {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.fragments.assembler.remove_expired(timestamp);

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac.sync_required(timestamp) {
            self.sync_slaac_state(timestamp)
        }
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        if !self.fragmenter.is_empty() {
            return Some(Instant::from_millis(0));
        }

        #[allow(unused_mut)]
        let mut res = sockets
            .items()
            .filter_map(|item| {
                let socket_poll_at = item.socket.poll_at(&mut self.inner);
                match item.meta.poll_at(
                    socket_poll_at,
                    |ip_addr| self.inner.has_neighbor(&ip_addr),
                    timestamp,
                ) {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
                }
            })
            .min();

        #[cfg(feature = "proto-ipv6-slaac")]
        if self.inner.slaac_enabled {
            res = res.min(self.inner.slaac.poll_at(timestamp));
        }

        res
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollIngressSingleResult {
        let Some((rx_token, tx_token)) = device.receive() else {
            return PollIngressSingleResult::None;
        };

        let rx_meta = rx_token.meta();
        rx_token.consume(|frame| {
            if frame.is_empty() {
                return PollIngressSingleResult::PacketProcessed;
            }

            match self.inner.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => {
                    if let Some(packet) =
                        self.inner
                            .process_ethernet(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) =
                            self.inner.dispatch(tx_token, packet, &mut self.fragmenter)
                    {
                        net_debug!("Failed to send response: {:?}", err);
                    }
                }
                #[cfg(feature = "medium-ip")]
                Medium::Ip => {
                    if let Some(packet) =
                        self.inner
                            .process_ip(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        )
                    {
                        net_debug!("Failed to send response: {:?}", err);
                    }
                }
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => {
                    if let Some(packet) =
                        self.inner
                            .process_ieee802154(sockets, rx_meta, frame, &mut self.fragments)
                        && let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        )
                    {
                        net_debug!("Failed to send response: {:?}", err);
                    }
                }
            }

            // TODO: Propagate the PollIngressSingleResult from deeper.
            // There's many received packets that we process but can't cause sockets
            // to change state. For example IP fragments, multicast stuff, ICMP pings
            // if they dont't match any raw socket...
            // We should return `PacketProcessed` for these to save the user from
            // doing useless socket polls.
            PollIngressSingleResult::SocketStateChanged
        })
    }

    fn socket_egress(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        let _caps = device.capabilities();
        #[cfg(feature = "tx-egress-metadata")]
        let egress_schedule = device.egress_schedule();
        #[cfg(feature = "tx-egress-metadata")]
        let mut grant_state_changed = false;
        #[cfg(feature = "tx-egress-metadata")]
        let displaced_grants = match egress_schedule {
            Some(schedule) => self.inner.egress_burst.configure(schedule),
            None => self.inner.egress_burst.disable(),
        };
        #[cfg(feature = "tx-egress-metadata")]
        for completion in displaced_grants.into_iter().flatten() {
            device.finish_egress_grant(completion);
            grant_state_changed = true;
        }
        #[cfg(feature = "tx-egress-metadata")]
        self.reconcile_egress_demands(device, sockets, egress_schedule);
        #[cfg(feature = "tx-egress-metadata")]
        for _ in 0..EGRESS_GRANT_PIPELINE_DEPTH {
            if !self.inner.egress_burst.needs_grant() {
                break;
            }
            let Some(grant) = device.poll_egress_grant() else {
                break;
            };
            if let Err(completion) = self.inner.egress_burst.install_grant(grant) {
                device.finish_egress_grant(completion);
                grant_state_changed = true;
            }
        }
        #[cfg(feature = "tx-egress-metadata")]
        for _ in 0..EGRESS_GRANT_PIPELINE_DEPTH {
            let Some(grant) = self.inner.egress_burst.active_grant() else {
                break;
            };
            if self
                .egress_demands
                .exact_demand(grant.demand().id(), grant.demand().key())
                .is_some()
            {
                break;
            }
            if let Some(completion) = self.inner.egress_burst.take_grant_completion(None) {
                device.finish_egress_grant(completion);
                grant_state_changed = true;
            }
        }

        enum EgressError {
            Exhausted,
            Dispatch,
            #[cfg(feature = "tx-egress-metadata")]
            AllKeysDeferred,
        }

        #[cfg(feature = "tx-egress-metadata")]
        #[derive(Clone, Copy, Eq, PartialEq)]
        enum EgressProviderCoverage {
            /// The provider participates in the interface demand catalogue,
            /// so an authoritative driver grant may select its final backing.
            Catalogued,
            /// The provider has no selectable queue head yet. It must not be
            /// deadlocked behind a grant which it has no way to request.
            UncataloguedBulk,
            /// Bounded network-control work which may use a driver's fixed
            /// reserve while bulk keyed queues occupy the ordinary horizon.
            Control,
        }

        #[cfg(feature = "tx-egress-metadata")]
        let mut result = if grant_state_changed {
            PollResult::SocketStateChanged
        } else {
            PollResult::None
        };
        #[cfg(not(feature = "tx-egress-metadata"))]
        let mut result = PollResult::None;
        #[cfg(feature = "tx-egress-metadata")]
        let mut globally_exhausted = false;
        for item in sockets.items_mut() {
            if !item
                .meta
                .egress_permitted(self.inner.now, |ip_addr| self.inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut respond = |inner: &mut InterfaceInner,
                               device: &mut _,
                               #[cfg(feature = "tx-egress-metadata")]
                               coverage: EgressProviderCoverage,
                               meta: PacketMeta,
                               response: Packet| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                #[cfg(feature = "tx-egress-metadata")]
                let egress_route = inner.resolved_egress_route(&response.ip_repr().dst_addr());
                #[cfg(feature = "tx-egress-metadata")]
                let egress_key = egress_route.map(|route| Device::egress_key(device, route));
                #[cfg(feature = "tx-egress-metadata")]
                let scheduled_key = match (coverage, egress_schedule) {
                    (
                        EgressProviderCoverage::UncataloguedBulk | EgressProviderCoverage::Control,
                        Some(schedule),
                    ) if schedule.grant_mode() == crate::phy::EgressGrantMode::Authoritative => {
                        None
                    }
                    _ => egress_key,
                };
                #[cfg(feature = "tx-egress-metadata")]
                let prepared_admission = match (scheduled_key, egress_schedule) {
                    (Some(egress), Some(_)) => inner
                        .egress_burst
                        .prepare_admission(egress)
                        .ok_or(KeyedEmitError::KeyDeferred)?
                        .into(),
                    _ => None,
                };
                #[cfg(feature = "tx-egress-metadata")]
                let admission = match (coverage, scheduled_key) {
                    (EgressProviderCoverage::Control, None) => {
                        match Device::transmit_control(device) {
                            Some(token) => EgressAdmission::Granted(token),
                            None => EgressAdmission::GlobalExhausted,
                        }
                    }
                    (_, Some(egress)) => match prepared_admission {
                        Some(EgressPreparedAdmission::Authoritative(serial)) => {
                            Device::transmit_granted(device, serial)
                        }
                        Some(EgressPreparedAdmission::StackSelected) => {
                            Device::transmit_for(device, egress)
                        }
                        None => unreachable!("a scheduled key has a prepared admission"),
                    },
                    (_, None) => match Device::transmit(device) {
                        Some(token) => EgressAdmission::Granted(token),
                        None => EgressAdmission::GlobalExhausted,
                    },
                };
                #[cfg(not(feature = "tx-egress-metadata"))]
                let admission = match Device::transmit(device) {
                    Some(token) => Some(token),
                    None => None,
                };

                #[cfg(feature = "tx-egress-metadata")]
                let t = match admission {
                    EgressAdmission::Granted(token) => token,
                    EgressAdmission::GlobalExhausted => {
                        net_debug!("failed to transmit IP: device globally exhausted");
                        return Err(KeyedEmitError::Global(EgressError::Exhausted));
                    }
                    EgressAdmission::KeyDeferred => return Err(KeyedEmitError::KeyDeferred),
                };
                #[cfg(not(feature = "tx-egress-metadata"))]
                let t = admission.ok_or_else(|| {
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                #[cfg(feature = "tx-egress-metadata")]
                let dispatched = match egress_route {
                    Some(route) => {
                        inner.dispatch_ip_resolved(t, meta, response, &mut self.fragmenter, route)
                    }
                    None => inner.dispatch_ip(t, meta, response, &mut self.fragmenter),
                };
                #[cfg(not(feature = "tx-egress-metadata"))]
                let dispatched = inner.dispatch_ip(t, meta, response, &mut self.fragmenter);

                dispatched.map_err(|_| {
                    #[cfg(feature = "tx-egress-metadata")]
                    {
                        KeyedEmitError::Global(EgressError::Dispatch)
                    }
                    #[cfg(not(feature = "tx-egress-metadata"))]
                    {
                        EgressError::Dispatch
                    }
                })?;

                #[cfg(feature = "tx-egress-metadata")]
                if let (Some(egress), Some(_)) = (scheduled_key, egress_schedule) {
                    inner.egress_burst.commit(egress);
                }

                result = PollResult::SocketStateChanged;

                Ok(())
            };

            macro_rules! respond_uncatalogued {
                ($coverage:expr, $inner:expr, $meta:expr, $packet:expr) => {{
                    #[cfg(feature = "tx-egress-metadata")]
                    {
                        respond($inner, device, $coverage, $meta, $packet).map_err(|error| {
                            match error {
                                KeyedEmitError::KeyDeferred => EgressError::AllKeysDeferred,
                                KeyedEmitError::Global(error) => error,
                            }
                        })
                    }
                    #[cfg(not(feature = "tx-egress-metadata"))]
                    {
                        respond($inner, device, $meta, $packet)
                    }
                }};
            }

            macro_rules! respond_bulk {
                ($inner:expr, $meta:expr, $packet:expr) => {
                    respond_uncatalogued!(
                        EgressProviderCoverage::UncataloguedBulk,
                        $inner,
                        $meta,
                        $packet
                    )
                };
            }

            macro_rules! respond_control {
                ($inner:expr, $meta:expr, $packet:expr) => {
                    respond_uncatalogued!(EgressProviderCoverage::Control, $inner, $meta, $packet)
                };
            }

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut self.inner, |inner, (ip, raw)| {
                    respond_bulk!(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Raw(raw))
                    )
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, response| match response {
                        #[cfg(feature = "proto-ipv4")]
                        (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => respond_control!(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ipv4_repr, IpPayload::Icmpv4(icmpv4_repr))
                        ),
                        #[cfg(feature = "proto-ipv6")]
                        (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => respond_control!(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmpv6_repr))
                        ),
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    })
                }
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => {
                    #[cfg(feature = "tx-egress-metadata")]
                    {
                        socket
                            .dispatch_keyed(
                                &mut self.inner,
                                device,
                                egress_schedule,
                                |inner, device, meta, (ip, udp, payload)| {
                                    respond(
                                        inner,
                                        device,
                                        EgressProviderCoverage::Catalogued,
                                        meta,
                                        Packet::new(ip, IpPayload::Udp(udp, payload)),
                                    )
                                },
                            )
                            .map_err(|error| match error {
                                KeyedDispatchError::AllKeysDeferred => EgressError::AllKeysDeferred,
                                KeyedDispatchError::Global(error) => error,
                            })
                    }
                    #[cfg(not(feature = "tx-egress-metadata"))]
                    {
                        socket.dispatch(&mut self.inner, |inner, meta, (ip, udp, payload)| {
                            respond(
                                inner,
                                device,
                                meta,
                                Packet::new(ip, IpPayload::Udp(udp, payload)),
                            )
                        })
                    }
                }
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(&mut self.inner, |inner, (ip, tcp)| {
                    respond_bulk!(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Tcp(tcp))
                    )
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => {
                    socket.dispatch(&mut self.inner, |inner, (ip, udp, dhcp)| {
                        respond_control!(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ip, IpPayload::Dhcpv4(udp, dhcp))
                        )
                    })
                }
                #[cfg(feature = "socket-dns")]
                Socket::Dns(socket) => socket.dispatch(&mut self.inner, |inner, (ip, udp, dns)| {
                    respond_control!(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Udp(udp, dns))
                    )
                }),
            };

            match result {
                Err(EgressError::Exhausted) => {
                    #[cfg(feature = "tx-egress-metadata")]
                    {
                        globally_exhausted = true;
                    }
                    break; // Driver buffer full.
                }
                Err(EgressError::Dispatch) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        self.inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                }
                #[cfg(feature = "tx-egress-metadata")]
                Err(EgressError::AllKeysDeferred) => {}
                Ok(()) => {}
            }
        }
        #[cfg(feature = "tx-egress-metadata")]
        if egress_schedule.is_some() && self.inner.egress_burst.finish_round(globally_exhausted) {
            result = PollResult::SocketStateChanged;
        }
        #[cfg(feature = "tx-egress-metadata")]
        if self.inner.egress_burst.grant_complete() {
            // Rebuild exact queue levels after the synchronous turn that
            // spent the final credit. The ordinary demand callback and this
            // completion therefore share device publication order, while no
            // per-packet level update is introduced.
            self.reconcile_egress_demands(device, sockets, egress_schedule);
            let remaining = self.inner.egress_burst.active_grant().and_then(|grant| {
                self.egress_demands
                    .exact_demand(grant.demand().id(), grant.demand().key())
                    .map(|demand| demand.level())
            });
            if let Some(completion) = self.inner.egress_burst.take_grant_completion(remaining) {
                device.finish_egress_grant(completion);
                // A locally retained standby is now the current affine grant.
                // Re-enter egress without waiting for a device or socket wake.
                result = PollResult::SocketStateChanged;
            }
        }
        result
    }

    /// Publish one coalesced shadow view of protocol-owned UDP demand.
    ///
    /// The interface resolves route and device key because UDP enqueue has
    /// neither context. Socket queues retain only an affine catalog handle;
    /// payload bytes are not scanned. This remains observational: the existing
    /// keyed dispatcher and `transmit_for` are still the only TX authority.
    #[cfg(feature = "tx-egress-metadata")]
    fn reconcile_egress_demands(
        &mut self,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
        schedule: Option<EgressSchedule>,
    ) {
        let Some(schedule) = schedule else {
            self.egress_demands
                .disable(|update| device.update_egress_demand(update));
            return;
        };

        match self.egress_demands.configure(schedule) {
            Ok(Some(update)) => device.update_egress_demand(update),
            Ok(None) => {}
            Err(error) => {
                net_debug!("invalid egress demand schedule: {:?}", error);
                self.egress_demands
                    .disable(|update| device.update_egress_demand(update));
                return;
            }
        }

        self.egress_demands.begin_observation();
        for item in sockets.items_mut() {
            #[allow(unreachable_patterns)]
            match &mut item.socket {
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => {
                    socket.prepare_egress_demand_epoch(schedule.epoch());
                    socket.for_each_egress_demand_provider(|handle, destination, ready_units| {
                        let Some(route) = self.inner.resolved_egress_route(&destination) else {
                            return;
                        };
                        let key = device.egress_key(route);
                        if let Err(error) = self.egress_demands.observe(handle, key, ready_units) {
                            net_debug!("failed to observe UDP egress demand: {:?}", error);
                        }
                    });
                }
                _ => {}
            }
        }

        self.egress_demands
            .finish_observation(|update| device.update_egress_demand(update));
    }
}

impl InterfaceInner {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        match self.medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                self.caps.max_transmission_unit - EthernetFrame::<&[u8]>::header_len()
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.caps.max_transmission_unit,
            // TODO(thvdveld): what is the MTU for Medium::Ieee802154?
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => self.caps.max_transmission_unit,
        }
    }

    /// The maximum IPv4 payload fragment size, aligned per spec.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(crate) fn max_ipv4_fragment_size(&self, ip_header_len: usize) -> usize {
        let payload_mtu = self.ip_mtu() - ip_header_len;
        payload_mtu - (payload_mtu % crate::phy::IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(|a| a.into()),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => Some(self.get_source_address_ipv6(addr).into()),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_ip_addrs(&mut self, addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>) {
        self.ip_addrs = addrs;
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    ///
    /// Always returns true if [`InterfaceInner::any_ip`].
    pub(crate) fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        // If any IP is set to true, we don't bother about checking the IP.
        if self.any_ip {
            return true;
        }

        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Check whether the interface listens to given destination multicast IP address.
    fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();

        #[cfg(feature = "multicast")]
        if self.multicast.has_multicast_group(addr) {
            return true;
        }

        match addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(key) => key == IPV4_MULTICAST_ALL_SYSTEMS,
            #[cfg(feature = "proto-rpl")]
            IpAddress::Ipv6(IPV6_LINK_LOCAL_ALL_RPL_NODES) => true,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(key) => {
                key == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(key)
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ip_payload: &'frame [u8],
        frag: &'frame mut FragmentsBuffer,
    ) -> Option<Packet<'frame>> {
        match IpVersion::of_packet(ip_payload) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(ip_payload));
                self.process_ipv4(sockets, meta, HardwareAddress::Ip, &ipv4_packet, frag)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(ip_payload));
                self.process_ipv6(sockets, meta, HardwareAddress::Ip, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| raw::Socket::downcast_mut(&mut i.socket))
        {
            if raw_socket.accepts(ip_repr) {
                raw_socket.process(self, ip_repr, ip_payload);
                handled_by_raw_socket = true;
            }
        }
        handled_by_raw_socket
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => {
                self.dispatch_ip(tx_token, PacketMeta::default(), packet, frag)
            }
        }
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        // Send directly.
        // note: no need to use `self.is_broadcast()` to check for subnet-local broadcast addrs
        //       here because `in_same_network` will already return true.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        // Route via a router.
        self.routes.lookup(addr, timestamp)
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Some(_routed_addr) => match self.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            None => false,
        }
    }

    #[cfg(feature = "tx-egress-metadata")]
    pub(crate) fn resolved_egress_route(&self, addr: &IpAddress) -> Option<EgressRoute> {
        if !matches!(self.medium, Medium::Ethernet) {
            return None;
        }
        let destination = if self.is_broadcast(addr) {
            EthernetAddress::BROADCAST
        } else if addr.is_multicast() {
            match *addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(addr) => {
                    let bytes = addr.octets();
                    EthernetAddress::from_bytes(&[
                        0x01,
                        0x00,
                        0x5e,
                        bytes[1] & 0x7f,
                        bytes[2],
                        bytes[3],
                    ])
                }
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(addr) => {
                    let bytes = addr.octets();
                    EthernetAddress::from_bytes(&[
                        0x33, 0x33, bytes[12], bytes[13], bytes[14], bytes[15],
                    ])
                }
            }
        } else {
            let routed = self.route(addr, self.now)?;
            match self.neighbor_cache.lookup(&routed, self.now) {
                NeighborAnswer::Found(HardwareAddress::Ethernet(address)) => address,
                _ => return None,
            }
        };
        Some(EgressRoute {
            destination: EgressHardwareAddress::Ethernet(destination.0),
            traffic_class: 0,
        })
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        dst_addr: &IpAddress,
        fragmenter: &mut Fragmenter,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
    where
        Tx: TxToken,
    {
        if self.is_broadcast(dst_addr) {
            let hardware_addr = match self.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(addr) => match self.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let b = addr.octets();
                        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                            0x01,
                            0x00,
                            0x5e,
                            b[1] & 0x7F,
                            b[2],
                            b[3],
                        ]))
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => unreachable!(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(addr) => match self.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => {
                        let b = addr.octets();
                        HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                            0x33, 0x33, b[12], b[13], b[14], b[15],
                        ]))
                    }
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self
            .route(dst_addr, self.now)
            .ok_or(DispatchError::NoRoute)?;

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match dst_addr {
            #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
            IpAddress::Ipv4(dst_addr) if matches!(self.medium, Medium::Ethernet) => {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: self
                        .get_source_address_ipv4(&dst_addr)
                        .ok_or(DispatchError::NoRoute)?,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                if let Err(e) =
                    self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                        frame.set_dst_addr(EthernetAddress::BROADCAST);
                        frame.set_ethertype(EthernetProtocol::Arp);

                        arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                    })
                {
                    net_debug!("Failed to dispatch ARP request: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(dst_addr) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.hardware_addr.into()),
                });

                let packet = Packet::new_ipv6(
                    Ipv6Repr {
                        src_addr: self.get_source_address_ipv6(&dst_addr),
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    IpPayload::Icmpv6(solicit),
                );

                if let Err(e) =
                    self.dispatch_ip(tx_token, PacketMeta::default(), packet, fragmenter)
                {
                    net_debug!("Failed to dispatch NDISC solicit: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[allow(unreachable_patterns)]
            _ => (),
        }

        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.limit_rate(self.now);
        Err(DispatchError::NeighborPending)
    }

    fn flush_neighbor_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        self.neighbor_cache.flush()
    }

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError> {
        self.dispatch_ip_to(tx_token, meta, packet, frag, None)
    }

    #[cfg(feature = "tx-egress-metadata")]
    fn dispatch_ip_resolved<Tx: TxToken>(
        &mut self,
        tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
        egress: EgressRoute,
    ) -> Result<(), DispatchError> {
        let destination = match egress.destination {
            #[cfg(feature = "medium-ethernet")]
            EgressHardwareAddress::Ethernet(address) => {
                Some(HardwareAddress::Ethernet(EthernetAddress(address)))
            }
            #[cfg(feature = "medium-ieee802154")]
            EgressHardwareAddress::Ieee802154(address) => Some(HardwareAddress::Ieee802154(
                Ieee802154Address::Extended(address),
            )),
            #[cfg(feature = "medium-ip")]
            EgressHardwareAddress::Ip => Some(HardwareAddress::Ip),
            _ => None,
        };
        self.dispatch_ip_to(tx_token, meta, packet, frag, destination)
    }

    fn dispatch_ip_to<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
        resolved_destination: Option<HardwareAddress>,
    ) -> Result<(), DispatchError> {
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.medium, Medium::Ieee802154) {
            let (addr, tx_token) =
                self.lookup_hardware_addr(tx_token, &ip_repr.dst_addr(), frag)?;
            let addr = addr.ieee802154_or_panic();

            self.dispatch_ieee802154(addr, tx_token, meta, packet, frag);
            return Ok(());
        }

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ipv4_id = self.next_ipv4_frag_ident();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        #[cfg(feature = "medium-ethernet")]
        let (dst_hardware_addr, mut tx_token) = match self.medium {
            Medium::Ethernet => match resolved_destination {
                Some(HardwareAddress::Ethernet(address)) => (address, tx_token),
                Some(_) => unreachable!("resolved egress medium matches the interface"),
                None => match self.lookup_hardware_addr(tx_token, &ip_repr.dst_addr(), frag)? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    (_, _) => unreachable!(),
                },
            },
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            repr.emit(&mut *tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        let total_ip_len = ip_repr.buffer_len();

        match &mut ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(repr) => {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                if total_ip_len > self.ip_mtu() {
                    #[cfg(feature = "proto-ipv4-fragmentation")]
                    {
                        net_debug!("start fragmentation");

                        // Calculate how much we will send now (including the Ethernet header).

                        let ip_header_len = repr.buffer_len();
                        let first_frag_data_len = self.max_ipv4_fragment_size(repr.buffer_len());
                        let first_frag_ip_len = first_frag_data_len + ip_header_len;
                        let mut tx_len = first_frag_ip_len;
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.medium, Medium::Ethernet) {
                            tx_len += EthernetFrame::<&[u8]>::header_len();
                        }

                        if frag.buffer.len() < total_ip_len {
                            net_debug!(
                                "Fragmentation buffer is too small, at least {} needed. Dropping",
                                total_ip_len
                            );
                            return Ok(());
                        }

                        #[cfg(feature = "medium-ethernet")]
                        {
                            frag.ipv4.dst_hardware_addr = dst_hardware_addr;
                        }

                        // Save the total packet len (without the Ethernet header, but with the first
                        // IP header).
                        frag.packet_len = total_ip_len;

                        // Save the IP header for other fragments.
                        frag.ipv4.repr = *repr;

                        // Modify the IP header
                        repr.payload_len = first_frag_data_len;

                        // Save the number of bytes we will send now.
                        frag.sent_bytes = first_frag_ip_len;

                        // Emit the IP header to the buffer.
                        emit_ip(&ip_repr, &mut frag.buffer);

                        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut frag.buffer[..]);
                        frag.ipv4.ident = ipv4_id;
                        ipv4_packet.set_ident(ipv4_id);
                        ipv4_packet.set_more_frags(true);
                        ipv4_packet.set_dont_frag(false);
                        ipv4_packet.set_frag_offset(0);

                        if caps.checksum.ipv4.tx() {
                            ipv4_packet.fill_checksum();
                        }

                        // Transmit the first packet.
                        tx_token.consume(tx_len, |mut tx_buffer| {
                            #[cfg(feature = "medium-ethernet")]
                            if matches!(self.medium, Medium::Ethernet) {
                                emit_ethernet(&ip_repr, tx_buffer);
                                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                            }

                            // Change the offset for the next packet.
                            frag.ipv4.frag_offset = (first_frag_ip_len - ip_header_len) as u16;

                            // Copy the IP header and the payload.
                            tx_buffer[..first_frag_ip_len]
                                .copy_from_slice(&frag.buffer[..first_frag_ip_len]);
                        });

                        Ok(())
                    }

                    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                    {
                        net_debug!(
                            "Enable the `proto-ipv4-fragmentation` feature for fragmentation support."
                        );
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    // No fragmentation is required.
                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer);
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                    });

                    Ok(())
                }
            }
            // We don't support IPv6 fragmentation yet.
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) => {
                // Check if we need to fragment it.
                if total_ip_len > self.ip_mtu() {
                    net_debug!("IPv6 fragmentation support is unimplemented. Dropping.");
                    Ok(())
                } else {
                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer);
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                    });
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
