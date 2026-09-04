//! Interface-owned generic egress-demand lifecycle.
//!
//! Multiple protocol providers may contribute work to the same opaque device
//! key. Provider queues retain a generation-validated lookup handle, while the
//! catalog rebuilds aggregate levels from bounded queue metadata once per
//! interface observation. It retains no per-provider entries and never scans
//! packet payload.

use core::num::{NonZeroU16, NonZeroU32};

use crate::phy::{
    EgressDemand, EgressDemandId, EgressDemandLevel, EgressDemandUpdate, EgressKey, EgressSchedule,
};

/// Cached identity of one aggregate demand slot.
///
/// This is an O(1) lookup hint, not provider ownership. Provider lifetime
/// remains in the protocol queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EgressDemandHandle {
    demand_slot: u16,
    demand_activation: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EgressDemandCatalogError {
    NotConfigured,
    Full,
    ActivationSerialExhausted,
    EpochNotAdvanced,
    InsufficientCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DemandEntry {
    key: EgressKey,
    id: EgressDemandId,
    committed_ready_units: u32,
    observed_ready_units: u32,
    horizon_ready: bool,
}

impl DemandEntry {
    fn demand(self, ready_units: u32, horizon_ready: bool) -> EgressDemand {
        let ready_units = NonZeroU16::new(ready_units.min(u32::from(u16::MAX)) as u16)
            .expect("an active demand is nonempty");
        EgressDemand::new(
            self.id,
            self.key,
            EgressDemandLevel::new(ready_units, horizon_ready),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DemandWatermarks {
    low: NonZeroU16,
    high: NonZeroU16,
}

impl DemandWatermarks {
    fn from_schedule(schedule: EgressSchedule) -> Self {
        let high = NonZeroU16::from(schedule.max_packets_per_key());
        let low = NonZeroU16::new((high.get() / 4).max(1)).unwrap();
        Self { low, high }
    }

    const fn next_horizon_ready(self, was_ready: bool, ready_units: u32) -> bool {
        if self.high.get() == 1 {
            return true;
        }
        if was_ready {
            ready_units > self.low.get() as u32
        } else {
            ready_units >= self.high.get() as u32
        }
    }
}

/// Bounded aggregate demand state for one Xarxa interface.
///
/// Capacity bounds distinct device keys, not sockets or packet backlog. A
/// provider uses its cached handle in O(1); only first activation or a stale
/// handle scans the fixed table. Recomputing aggregates makes socket removal
/// safe without provider-sized state in an async-owned interface.
pub(super) struct EgressDemandCatalog<const CAPACITY: usize> {
    schedule: Option<EgressSchedule>,
    watermarks: Option<DemandWatermarks>,
    next_demand_activation: u32,
    demands: [Option<DemandEntry>; CAPACITY],
}

impl<const CAPACITY: usize> EgressDemandCatalog<CAPACITY> {
    pub(super) const fn new() -> Self {
        assert!(CAPACITY != 0, "egress demand catalog must not be empty");
        assert!(
            CAPACITY <= u16::MAX as usize,
            "egress demand catalog handle must fit u16"
        );
        Self {
            schedule: None,
            watermarks: None,
            next_demand_activation: 1,
            demands: [None; CAPACITY],
        }
    }

    pub(super) fn configure(
        &mut self,
        schedule: EgressSchedule,
    ) -> Result<Option<EgressDemandUpdate>, EgressDemandCatalogError> {
        if usize::from(schedule.max_active_keys().get()) > CAPACITY {
            return Err(EgressDemandCatalogError::InsufficientCapacity);
        }
        if self.schedule == Some(schedule) {
            return Ok(None);
        }
        if self
            .schedule
            .is_some_and(|current| current.epoch() == schedule.epoch())
        {
            return Err(EgressDemandCatalogError::EpochNotAdvanced);
        }
        self.schedule = Some(schedule);
        self.watermarks = Some(DemandWatermarks::from_schedule(schedule));
        self.demands.fill(None);
        Ok(Some(EgressDemandUpdate::Reset {
            schedule_epoch: schedule.epoch(),
        }))
    }

    fn next_id(&mut self) -> Result<EgressDemandId, EgressDemandCatalogError> {
        let schedule = self
            .schedule
            .ok_or(EgressDemandCatalogError::NotConfigured)?;
        let activation = NonZeroU32::new(self.next_demand_activation)
            .ok_or(EgressDemandCatalogError::ActivationSerialExhausted)?;
        self.next_demand_activation = self
            .next_demand_activation
            .checked_add(1)
            .ok_or(EgressDemandCatalogError::ActivationSerialExhausted)?;
        Ok(EgressDemandId::new(schedule.epoch(), activation))
    }

    pub(super) fn begin_observation(&mut self) {
        for demand in self.demands.iter_mut().flatten() {
            demand.observed_ready_units = 0;
        }
    }

    fn handle_slot(&self, handle: EgressDemandHandle, key: EgressKey) -> Option<usize> {
        let slot = usize::from(handle.demand_slot);
        self.demands
            .get(slot)
            .copied()
            .flatten()
            .filter(|demand| {
                demand.id.activation() == handle.demand_activation && demand.key == key
            })
            .map(|_| slot)
    }

    fn demand_slot(&mut self, key: EgressKey) -> Result<usize, EgressDemandCatalogError> {
        if let Some(slot) = self
            .demands
            .iter()
            .position(|demand| demand.is_some_and(|demand| demand.key == key))
        {
            return Ok(slot);
        }
        let slot = self
            .demands
            .iter()
            .position(Option::is_none)
            .ok_or(EgressDemandCatalogError::Full)?;
        let id = self.next_id()?;
        self.demands[slot] = Some(DemandEntry {
            key,
            id,
            committed_ready_units: 0,
            observed_ready_units: 0,
            horizon_ready: false,
        });
        Ok(slot)
    }

    pub(super) fn observe(
        &mut self,
        handle: &mut Option<EgressDemandHandle>,
        key: EgressKey,
        ready_units: NonZeroU16,
    ) -> Result<(), EgressDemandCatalogError> {
        self.schedule
            .ok_or(EgressDemandCatalogError::NotConfigured)?;
        let slot = handle
            .and_then(|handle| self.handle_slot(handle, key))
            .map(Ok)
            .unwrap_or_else(|| self.demand_slot(key))?;
        let demand = self.demands[slot]
            .as_mut()
            .expect("resolved demand slot remains active");
        demand.observed_ready_units = demand
            .observed_ready_units
            .checked_add(u32::from(ready_units.get()))
            .expect("bounded queue metadata cannot overflow aggregate demand");
        *handle = Some(EgressDemandHandle {
            demand_slot: u16::try_from(slot).expect("catalog capacity was checked"),
            demand_activation: demand.id.activation(),
        });
        Ok(())
    }

    pub(super) fn finish_observation(&mut self, mut publish: impl FnMut(EgressDemandUpdate)) {
        let watermarks = self
            .watermarks
            .expect("configured demand catalog owns watermarks");
        for slot in 0..CAPACITY {
            let Some(mut demand) = self.demands[slot] else {
                continue;
            };
            let observed = demand.observed_ready_units;
            if observed == 0 {
                if demand.committed_ready_units != 0 {
                    publish(EgressDemandUpdate::Inactive {
                        id: demand.id,
                        key: demand.key,
                    });
                }
                self.demands[slot] = None;
                continue;
            }

            let horizon_ready = watermarks.next_horizon_ready(demand.horizon_ready, observed);
            if demand.committed_ready_units == 0 || horizon_ready != demand.horizon_ready {
                publish(EgressDemandUpdate::Active(
                    demand.demand(observed, horizon_ready),
                ));
            }
            demand.committed_ready_units = observed;
            demand.observed_ready_units = 0;
            demand.horizon_ready = horizon_ready;
            self.demands[slot] = Some(demand);
        }
    }

    /// Return the exact level from the most recent synchronous interface
    /// observation for one still-live demand identity.
    pub(super) fn exact_demand(&self, id: EgressDemandId, key: EgressKey) -> Option<EgressDemand> {
        self.demands
            .iter()
            .flatten()
            .copied()
            .find(|demand| {
                demand.id == id && demand.key == key && demand.committed_ready_units != 0
            })
            .map(|demand| demand.demand(demand.committed_ready_units, demand.horizon_ready))
    }

    pub(super) fn disable(&mut self, mut publish: impl FnMut(EgressDemandUpdate)) {
        for demand in self.demands.iter().flatten() {
            if demand.committed_ready_units != 0 {
                publish(EgressDemandUpdate::Inactive {
                    id: demand.id,
                    key: demand.key,
                });
            }
        }
        self.schedule = None;
        self.watermarks = None;
        self.demands.fill(None);
    }

    #[cfg(test)]
    fn active_demands(&self) -> usize {
        self.demands.iter().flatten().count()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use super::*;

    fn schedule(max_packets: u8, max_active_keys: u16, epoch: u32) -> EgressSchedule {
        EgressSchedule::new(
            NonZeroU8::new(max_packets).unwrap(),
            NonZeroU8::new(1).unwrap(),
            NonZeroU16::new(max_active_keys).unwrap(),
            epoch,
            crate::phy::EgressGrantMode::StackSelected,
        )
    }

    fn key(value: u32) -> EgressKey {
        EgressKey::from_words([value, 0, 0, 0])
    }

    fn active(update: EgressDemandUpdate) -> EgressDemand {
        match update {
            EgressDemandUpdate::Active(demand) => demand,
            _ => panic!("expected active demand update"),
        }
    }

    fn observe(
        catalog: &mut EgressDemandCatalog<4>,
        handle: &mut Option<EgressDemandHandle>,
        key: EgressKey,
        ready: u16,
    ) {
        catalog
            .observe(handle, key, NonZeroU16::new(ready).unwrap())
            .unwrap();
    }

    #[test]
    fn observation_before_configuration_fails_closed() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        assert_eq!(
            catalog.observe(&mut None, key(1), NonZeroU16::new(1).unwrap()),
            Err(EgressDemandCatalogError::NotConfigured)
        );
    }

    #[test]
    fn schedule_rejects_more_device_keys_than_compiled_catalog_capacity() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        let schedule = EgressSchedule::new(
            NonZeroU8::new(32).unwrap(),
            NonZeroU8::MIN,
            NonZeroU16::new(5).unwrap(),
            7,
            crate::phy::EgressGrantMode::Authoritative,
        );
        assert_eq!(
            catalog.configure(schedule),
            Err(EgressDemandCatalogError::InsufficientCapacity)
        );
    }

    #[test]
    fn softap_catalog_does_not_scale_with_provider_count() {
        assert!(
            core::mem::size_of::<EgressDemandCatalog<16>>() <= 1024,
            "aggregate catalog must stay out of provider-sized async frames"
        );
    }

    #[test]
    fn sparse_activation_is_immediate_and_counts_are_coalesced() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        catalog.configure(schedule(32, 4, 7)).unwrap();
        let mut handle = None;
        let mut updates = std::vec::Vec::new();

        catalog.begin_observation();
        observe(&mut catalog, &mut handle, key(1), 1);
        catalog.finish_observation(|update| updates.push(update));
        let demand = active(updates.pop().unwrap());
        assert_eq!(demand.level().ready_units().get(), 1);
        assert!(!demand.level().horizon_ready());

        for ready in 2..32 {
            catalog.begin_observation();
            observe(&mut catalog, &mut handle, key(1), ready);
            catalog.finish_observation(|update| updates.push(update));
            assert!(updates.is_empty());
        }
        catalog.begin_observation();
        observe(&mut catalog, &mut handle, key(1), 32);
        catalog.finish_observation(|update| updates.push(update));
        let demand = active(updates.pop().unwrap());
        assert_eq!(demand.level().ready_units().get(), 32);
        assert!(demand.level().horizon_ready());
    }

    #[test]
    fn multiple_providers_share_one_aggregate_observation() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        catalog.configure(schedule(8, 4, 3)).unwrap();
        let mut a = None;
        let mut b = None;
        let mut updates = std::vec::Vec::new();
        catalog.begin_observation();
        observe(&mut catalog, &mut a, key(1), 3);
        observe(&mut catalog, &mut b, key(1), 5);
        catalog.finish_observation(|update| updates.push(update));

        assert_eq!(updates.len(), 1);
        let demand = active(updates[0]);
        assert_eq!(demand.level().ready_units().get(), 8);
        assert!(demand.level().horizon_ready());
        assert_eq!(catalog.active_demands(), 1);

        catalog.begin_observation();
        observe(&mut catalog, &mut b, key(1), 5);
        catalog.finish_observation(|update| updates.push(update));
        assert_eq!(updates.len(), 1, "one provider ending is not terminal");

        catalog.begin_observation();
        catalog.finish_observation(|update| updates.push(update));
        assert!(matches!(
            updates.last(),
            Some(EgressDemandUpdate::Inactive { id, key: ended })
                if *id == demand.id() && *ended == key(1)
        ));
    }

    #[test]
    fn high_low_hysteresis_avoids_packet_frequency_publication() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        catalog.configure(schedule(32, 4, 1)).unwrap();
        let mut handle = None;
        let mut updates = std::vec::Vec::new();

        for ready in [40, 39, 9, 8, 9, 31, 32] {
            catalog.begin_observation();
            observe(&mut catalog, &mut handle, key(1), ready);
            catalog.finish_observation(|update| updates.push(update));
        }
        assert_eq!(updates.len(), 3);
        assert!(active(updates[0]).level().horizon_ready());
        assert!(!active(updates[1]).level().horizon_ready());
        assert!(active(updates[2]).level().horizon_ready());
    }

    #[test]
    fn stale_slot_handle_rebinds_to_a_later_lifetime() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 1)).unwrap();
        let mut stale = None;
        catalog.begin_observation();
        catalog
            .observe(&mut stale, key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});
        let old = stale.unwrap();
        catalog.begin_observation();
        catalog.finish_observation(|_| {});

        let mut current = None;
        catalog.begin_observation();
        catalog
            .observe(&mut current, key(2), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});
        assert_ne!(old.demand_activation, current.unwrap().demand_activation);

        catalog.begin_observation();
        catalog
            .observe(&mut stale, key(2), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});
        assert_eq!(stale, current);
    }

    #[test]
    fn epoch_reset_invalidates_cached_handles() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 11)).unwrap();
        let mut handle = None;
        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});
        let old = handle.unwrap();

        assert_eq!(
            catalog.configure(schedule(32, 1, 12)).unwrap(),
            Some(EgressDemandUpdate::Reset { schedule_epoch: 12 })
        );
        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});
        assert_ne!(old.demand_activation, handle.unwrap().demand_activation);
    }

    #[test]
    fn schedule_geometry_change_requires_an_advanced_epoch() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 5)).unwrap();
        assert_eq!(
            catalog.configure(schedule(16, 1, 5)),
            Err(EgressDemandCatalogError::EpochNotAdvanced)
        );
    }

    #[test]
    fn full_distinct_key_catalog_preserves_existing_demand() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 1)).unwrap();
        let mut a = None;
        let mut b = None;
        catalog.begin_observation();
        catalog
            .observe(&mut a, key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        assert_eq!(
            catalog.observe(&mut b, key(2), NonZeroU16::new(1).unwrap()),
            Err(EgressDemandCatalogError::Full)
        );
        catalog.finish_observation(|_| {});
        assert_eq!(catalog.active_demands(), 1);
    }

    #[test]
    fn one_unit_horizon_stays_ready_for_every_nonempty_level() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(1, 1, 1)).unwrap();
        let mut handle = None;
        let mut updates = std::vec::Vec::new();
        for ready in [1, 2, 1] {
            catalog.begin_observation();
            catalog
                .observe(&mut handle, key(1), NonZeroU16::new(ready).unwrap())
                .unwrap();
            catalog.finish_observation(|update| updates.push(update));
        }
        assert_eq!(updates.len(), 1);
        assert!(active(updates[0]).level().horizon_ready());
    }

    #[test]
    fn aggregate_publication_saturates_without_corrupting_reclamation() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 1)).unwrap();
        let mut a = None;
        let mut b = None;
        let mut updates = std::vec::Vec::new();
        catalog.begin_observation();
        catalog
            .observe(&mut a, key(1), NonZeroU16::new(u16::MAX).unwrap())
            .unwrap();
        catalog
            .observe(&mut b, key(1), NonZeroU16::new(u16::MAX).unwrap())
            .unwrap();
        catalog.finish_observation(|update| updates.push(update));
        assert_eq!(
            active(updates[0]).level().ready_units(),
            NonZeroU16::new(u16::MAX).unwrap()
        );

        catalog.begin_observation();
        catalog.finish_observation(|update| updates.push(update));
        assert!(matches!(
            updates.last(),
            Some(EgressDemandUpdate::Inactive { .. })
        ));
    }

    #[test]
    fn rekey_publishes_terminal_then_new_lifetime() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 2, 9)).unwrap();
        let mut handle = None;
        let mut updates = std::vec::Vec::new();
        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(1), NonZeroU16::new(3).unwrap())
            .unwrap();
        catalog.finish_observation(|update| updates.push(update));
        let first = active(updates.pop().unwrap());

        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(2), NonZeroU16::new(3).unwrap())
            .unwrap();
        catalog.finish_observation(|update| updates.push(update));
        assert_eq!(updates.len(), 2);
        assert!(matches!(
            updates[0],
            EgressDemandUpdate::Inactive { id, key: ended }
                if id == first.id() && ended == key(1)
        ));
        let second = active(updates[1]);
        assert_eq!(second.key(), key(2));
        assert_ne!(second.id(), first.id());
    }

    #[test]
    fn disable_publishes_terminal_lifetime_once() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1, 3)).unwrap();
        let mut handle = None;
        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        catalog.finish_observation(|_| {});

        let mut disabled = std::vec::Vec::new();
        catalog.disable(|update| disabled.push(update));
        assert!(matches!(
            disabled.as_slice(),
            [EgressDemandUpdate::Inactive { key: ended, .. }] if *ended == key(1)
        ));
        catalog.disable(|_| panic!("disabled catalog must not publish twice"));
    }
}
