//! Interface-owned generic egress-demand lifecycle.
//!
//! This is stack state, not radio policy. Multiple protocol providers may
//! contribute work to the same opaque device key. The catalog gives every
//! provider an affine handle, aggregates their queue levels into one nonempty
//! key lifetime, and coalesces packet-frequency changes through a high/low
//! watermark pair.

use core::num::{NonZeroU16, NonZeroU32};

use crate::phy::{
    EgressDemand, EgressDemandId, EgressDemandLevel, EgressDemandUpdate, EgressKey, EgressSchedule,
};

/// Affine identity of one protocol provider's active contribution.
///
/// This handle is stack-local. A radio grant names the aggregate
/// [`EgressDemandId`], never an individual provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EgressDemandHandle {
    provider_slot: u16,
    provider_activation: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EgressDemandCatalogError {
    NotConfigured,
    Full,
    StaleHandle,
    ActivationSerialExhausted,
    EpochNotAdvanced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DemandEntry {
    key: EgressKey,
    id: EgressDemandId,
    /// Exact aggregate used internally. The published observation saturates.
    ready_units: u32,
    horizon_ready: bool,
}

impl DemandEntry {
    fn demand(self) -> EgressDemand {
        let ready_units = NonZeroU16::new(self.ready_units.min(u32::from(u16::MAX)) as u16)
            .expect("an active demand is nonempty");
        EgressDemand::new(
            self.id,
            self.key,
            EgressDemandLevel::new(ready_units, self.horizon_ready),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderEntry {
    activation: NonZeroU32,
    demand_slot: u16,
    demand_id: EgressDemandId,
    ready_units: NonZeroU16,
    observed: bool,
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
        // With a one-unit horizon every nonempty demand is ready. Applying the
        // generic high/low hysteresis would otherwise alternate at count one.
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

/// Bounded generic demand owners for one Xarxa interface.
///
/// Empty-to-nonempty provider activation may scan the fixed tables once.
/// Every later provider mutation uses its affine handle and validates both
/// the provider activation and aggregate demand identity in O(1). Therefore a
/// packet-frequency update never searches all active keys. Multiple providers
/// for the same key share one aggregate nonempty lifetime.
pub(super) struct EgressDemandCatalog<const CAPACITY: usize> {
    schedule: Option<EgressSchedule>,
    watermarks: Option<DemandWatermarks>,
    next_demand_activation: u32,
    next_provider_activation: u32,
    demands: [Option<DemandEntry>; CAPACITY],
    providers: [Option<ProviderEntry>; CAPACITY],
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
            next_provider_activation: 1,
            demands: [None; CAPACITY],
            providers: [None; CAPACITY],
        }
    }

    /// Begin or replace the device-owned scheduling epoch.
    ///
    /// A schedule geometry change without an epoch advance is rejected. This
    /// keeps one unambiguous reset value at a future asynchronous boundary.
    pub(super) fn configure(
        &mut self,
        schedule: EgressSchedule,
    ) -> Result<Option<EgressDemandUpdate>, EgressDemandCatalogError> {
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
        self.providers.fill(None);
        Ok(Some(EgressDemandUpdate::Reset {
            schedule_epoch: schedule.epoch(),
        }))
    }

    fn serial(next: u32) -> Result<(NonZeroU32, u32), EgressDemandCatalogError> {
        let serial =
            NonZeroU32::new(next).ok_or(EgressDemandCatalogError::ActivationSerialExhausted)?;
        let following = next
            .checked_add(1)
            .ok_or(EgressDemandCatalogError::ActivationSerialExhausted)?;
        Ok((serial, following))
    }

    /// Activate one independently owned provider contribution.
    ///
    /// The first provider for a key starts and publishes a new demand lifetime.
    /// Further providers join that lifetime and publish only if their addition
    /// crosses the useful high watermark.
    pub(super) fn activate(
        &mut self,
        key: EgressKey,
        ready_units: NonZeroU16,
    ) -> Result<(EgressDemandHandle, Option<EgressDemandUpdate>), EgressDemandCatalogError> {
        let schedule = self
            .schedule
            .ok_or(EgressDemandCatalogError::NotConfigured)?;
        let watermarks = self
            .watermarks
            .expect("configured demand catalog owns watermarks");
        let provider_slot = self
            .providers
            .iter()
            .position(Option::is_none)
            .ok_or(EgressDemandCatalogError::Full)?;
        let demand_slot = self
            .demands
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.key == key))
            .or_else(|| self.demands.iter().position(Option::is_none))
            .ok_or(EgressDemandCatalogError::Full)?;

        let (provider_activation, next_provider_activation) =
            Self::serial(self.next_provider_activation)?;

        let update = if let Some(mut demand) = self.demands[demand_slot] {
            demand.ready_units = demand
                .ready_units
                .checked_add(u32::from(ready_units.get()))
                .expect("bounded providers cannot overflow u32 aggregate demand");
            let horizon_ready =
                watermarks.next_horizon_ready(demand.horizon_ready, demand.ready_units);
            let publish = horizon_ready != demand.horizon_ready;
            demand.horizon_ready = horizon_ready;
            self.demands[demand_slot] = Some(demand);
            publish.then(|| EgressDemandUpdate::Active(demand.demand()))
        } else {
            let (activation, next_demand_activation) = Self::serial(self.next_demand_activation)?;
            self.next_demand_activation = next_demand_activation;
            let id = EgressDemandId::new(schedule.epoch(), activation);
            let demand = DemandEntry {
                key,
                id,
                ready_units: u32::from(ready_units.get()),
                horizon_ready: watermarks.next_horizon_ready(false, u32::from(ready_units.get())),
            };
            self.demands[demand_slot] = Some(demand);
            Some(EgressDemandUpdate::Active(demand.demand()))
        };

        self.next_provider_activation = next_provider_activation;
        let demand = self.demands[demand_slot].expect("activation installed demand");
        self.providers[provider_slot] = Some(ProviderEntry {
            activation: provider_activation,
            demand_slot: u16::try_from(demand_slot).expect("catalog capacity was checked"),
            demand_id: demand.id,
            ready_units,
            observed: false,
        });
        Ok((
            EgressDemandHandle {
                provider_slot: u16::try_from(provider_slot).expect("catalog capacity was checked"),
                provider_activation,
            },
            update,
        ))
    }

    /// Update one provider and return only a useful aggregate transition.
    ///
    /// `None` coalesces packet-frequency count changes inside the current
    /// hysteresis band. Zero ends this provider contribution. Only the last
    /// provider ending publishes the terminal key lifetime.
    pub(super) fn update(
        &mut self,
        handle: EgressDemandHandle,
        ready_units: u16,
    ) -> Result<Option<EgressDemandUpdate>, EgressDemandCatalogError> {
        let provider_slot = usize::from(handle.provider_slot);
        let mut provider = self
            .providers
            .get(provider_slot)
            .copied()
            .flatten()
            .filter(|provider| provider.activation == handle.provider_activation)
            .ok_or(EgressDemandCatalogError::StaleHandle)?;
        let demand_slot = usize::from(provider.demand_slot);
        let mut demand = self
            .demands
            .get(demand_slot)
            .copied()
            .flatten()
            .filter(|demand| demand.id == provider.demand_id)
            .ok_or(EgressDemandCatalogError::StaleHandle)?;

        let previous = u32::from(provider.ready_units.get());
        if ready_units == 0 {
            self.providers[provider_slot] = None;
            demand.ready_units -= previous;
            if demand.ready_units == 0 {
                self.demands[demand_slot] = None;
                return Ok(Some(EgressDemandUpdate::Inactive {
                    id: demand.id,
                    key: demand.key,
                }));
            }
        } else {
            let ready_units = NonZeroU16::new(ready_units).unwrap();
            if ready_units == provider.ready_units {
                return Ok(None);
            }
            provider.ready_units = ready_units;
            self.providers[provider_slot] = Some(provider);
            demand.ready_units = demand.ready_units - previous + u32::from(ready_units.get());
        }

        let watermarks = self
            .watermarks
            .expect("configured demand catalog owns watermarks");
        let horizon_ready = watermarks.next_horizon_ready(demand.horizon_ready, demand.ready_units);
        let publish = horizon_ready != demand.horizon_ready;
        demand.horizon_ready = horizon_ready;
        self.demands[demand_slot] = Some(demand);
        Ok(publish.then(|| EgressDemandUpdate::Active(demand.demand())))
    }

    fn demand_for(
        &self,
        handle: EgressDemandHandle,
    ) -> Result<DemandEntry, EgressDemandCatalogError> {
        let provider = self
            .providers
            .get(usize::from(handle.provider_slot))
            .copied()
            .flatten()
            .filter(|provider| provider.activation == handle.provider_activation)
            .ok_or(EgressDemandCatalogError::StaleHandle)?;
        self.demands
            .get(usize::from(provider.demand_slot))
            .copied()
            .flatten()
            .filter(|demand| demand.id == provider.demand_id)
            .ok_or(EgressDemandCatalogError::StaleHandle)
    }

    fn mark_observed(
        &mut self,
        handle: EgressDemandHandle,
    ) -> Result<(), EgressDemandCatalogError> {
        let provider = self
            .providers
            .get_mut(usize::from(handle.provider_slot))
            .and_then(Option::as_mut)
            .filter(|provider| provider.activation == handle.provider_activation)
            .ok_or(EgressDemandCatalogError::StaleHandle)?;
        provider.observed = true;
        Ok(())
    }

    /// Begin one complete observation of protocol-owned egress providers.
    pub(super) fn begin_observation(&mut self) {
        for provider in self.providers.iter_mut().flatten() {
            provider.observed = false;
        }
    }

    /// Reconcile one live protocol provider through its affine socket-owned handle.
    ///
    /// A route-to-key change ends the old contribution before starting the new
    /// one. This is safe even when a generic device violates the stronger
    /// schedule-epoch stability recommendation.
    pub(super) fn observe(
        &mut self,
        handle: &mut Option<EgressDemandHandle>,
        key: EgressKey,
        ready_units: NonZeroU16,
        mut publish: impl FnMut(EgressDemandUpdate),
    ) -> Result<(), EgressDemandCatalogError> {
        if let Some(current) = *handle {
            match self.demand_for(current) {
                Ok(demand) if demand.key == key => {
                    if let Some(update) = self.update(current, ready_units.get())? {
                        publish(update);
                    }
                    self.mark_observed(current)?;
                    return Ok(());
                }
                Ok(_) => {
                    if let Some(update) = self.update(current, 0)? {
                        publish(update);
                    }
                    *handle = None;
                }
                Err(EgressDemandCatalogError::StaleHandle) => {
                    *handle = None;
                }
                Err(error) => return Err(error),
            }
        }

        let (new_handle, update) = self.activate(key, ready_units)?;
        self.mark_observed(new_handle)?;
        *handle = Some(new_handle);
        if let Some(update) = update {
            publish(update);
        }
        Ok(())
    }

    /// End one complete observation and reclaim every disappeared provider.
    pub(super) fn finish_observation(
        &mut self,
        mut publish: impl FnMut(EgressDemandUpdate),
    ) -> Result<(), EgressDemandCatalogError> {
        for provider_slot in 0..CAPACITY {
            let Some(provider) = self.providers[provider_slot] else {
                continue;
            };
            if provider.observed {
                continue;
            }
            let handle = EgressDemandHandle {
                provider_slot: u16::try_from(provider_slot).expect("catalog capacity was checked"),
                provider_activation: provider.activation,
            };
            if let Some(update) = self.update(handle, 0)? {
                publish(update);
            }
        }
        Ok(())
    }

    /// Disable observation and terminate every published demand lifetime.
    pub(super) fn disable(&mut self, mut publish: impl FnMut(EgressDemandUpdate)) {
        for demand in self.demands.iter().flatten() {
            publish(EgressDemandUpdate::Inactive {
                id: demand.id,
                key: demand.key,
            });
        }
        self.schedule = None;
        self.watermarks = None;
        self.demands.fill(None);
        self.providers.fill(None);
    }

    #[cfg(test)]
    fn active_demands(&self) -> usize {
        self.demands.iter().flatten().count()
    }

    #[cfg(test)]
    fn active_providers(&self) -> usize {
        self.providers.iter().flatten().count()
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use super::*;

    fn schedule(max_packets: u8, epoch: u32) -> EgressSchedule {
        EgressSchedule::new(
            NonZeroU8::new(max_packets).unwrap(),
            NonZeroU8::new(1).unwrap(),
            epoch,
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

    #[test]
    fn activation_before_configuration_fails_closed() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        assert_eq!(
            catalog.activate(key(1), NonZeroU16::new(1).unwrap()),
            Err(EgressDemandCatalogError::NotConfigured)
        );
    }

    #[test]
    fn sparse_activation_is_immediate_and_packet_count_changes_are_coalesced() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        assert_eq!(
            catalog.configure(schedule(32, 7)).unwrap(),
            Some(EgressDemandUpdate::Reset { schedule_epoch: 7 })
        );
        let (handle, update) = catalog
            .activate(key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        let demand = active(update.unwrap());
        assert_eq!(demand.level().ready_units().get(), 1);
        assert!(!demand.level().horizon_ready());

        for ready in 2..32 {
            assert_eq!(catalog.update(handle, ready).unwrap(), None);
        }
        let demand = active(catalog.update(handle, 32).unwrap().unwrap());
        assert_eq!(demand.level().ready_units().get(), 32);
        assert!(demand.level().horizon_ready());
    }

    #[test]
    fn high_low_hysteresis_avoids_one_publication_per_saturated_packet() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 1)).unwrap();
        let (handle, update) = catalog
            .activate(key(1), NonZeroU16::new(40).unwrap())
            .unwrap();
        assert!(active(update.unwrap()).level().horizon_ready());

        for ready in (9..40).rev() {
            assert_eq!(catalog.update(handle, ready).unwrap(), None);
        }
        let demand = active(catalog.update(handle, 8).unwrap().unwrap());
        assert_eq!(demand.level().ready_units().get(), 8);
        assert!(!demand.level().horizon_ready());

        for ready in 9..32 {
            assert_eq!(catalog.update(handle, ready).unwrap(), None);
        }
        assert!(
            active(catalog.update(handle, 32).unwrap().unwrap())
                .level()
                .horizon_ready()
        );
    }

    #[test]
    fn multiple_providers_share_one_key_lifetime_and_aggregate_level() {
        let mut catalog = EgressDemandCatalog::<4>::new();
        catalog.configure(schedule(8, 3)).unwrap();
        let (a, first) = catalog
            .activate(key(1), NonZeroU16::new(3).unwrap())
            .unwrap();
        let first = active(first.unwrap());
        let (b, high) = catalog
            .activate(key(1), NonZeroU16::new(5).unwrap())
            .unwrap();
        let high = active(high.unwrap());
        assert_eq!(high.id(), first.id());
        assert_eq!(high.level().ready_units().get(), 8);
        assert!(high.level().horizon_ready());
        assert_eq!(catalog.active_demands(), 1);
        assert_eq!(catalog.active_providers(), 2);

        assert_eq!(catalog.update(a, 0).unwrap(), None);
        let low = active(catalog.update(b, 2).unwrap().unwrap());
        assert_eq!(low.id(), first.id());
        assert!(!low.level().horizon_ready());
        assert_eq!(
            catalog.update(b, 0).unwrap(),
            Some(EgressDemandUpdate::Inactive {
                id: first.id(),
                key: key(1),
            })
        );
        assert_eq!(catalog.active_demands(), 0);
        assert_eq!(catalog.active_providers(), 0);
    }

    #[test]
    fn inactive_is_terminal_and_provider_slot_reuse_rejects_old_handle() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1)).unwrap();
        let (old, old_update) = catalog
            .activate(key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        let old_id = active(old_update.unwrap()).id();
        assert_eq!(
            catalog.update(old, 0).unwrap(),
            Some(EgressDemandUpdate::Inactive {
                id: old_id,
                key: key(1)
            })
        );
        let (new, _) = catalog
            .activate(key(2), NonZeroU16::new(1).unwrap())
            .unwrap();
        assert_ne!(old.provider_activation, new.provider_activation);
        assert_eq!(
            catalog.update(old, 1),
            Err(EgressDemandCatalogError::StaleHandle)
        );
        assert_eq!(catalog.active_demands(), 1);
    }

    #[test]
    fn epoch_reset_invalidates_every_affine_handle_even_without_new_demand() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 11)).unwrap();
        let (a, _) = catalog
            .activate(key(1), NonZeroU16::new(4).unwrap())
            .unwrap();
        let (b, _) = catalog
            .activate(key(2), NonZeroU16::new(4).unwrap())
            .unwrap();

        assert_eq!(
            catalog.configure(schedule(32, 12)).unwrap(),
            Some(EgressDemandUpdate::Reset { schedule_epoch: 12 })
        );
        assert_eq!(catalog.active_demands(), 0);
        assert_eq!(catalog.active_providers(), 0);
        assert_eq!(
            catalog.update(a, 1),
            Err(EgressDemandCatalogError::StaleHandle)
        );
        assert_eq!(
            catalog.update(b, 1),
            Err(EgressDemandCatalogError::StaleHandle)
        );
    }

    #[test]
    fn schedule_geometry_change_requires_an_advanced_epoch() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 5)).unwrap();
        assert_eq!(
            catalog.configure(schedule(16, 5)),
            Err(EgressDemandCatalogError::EpochNotAdvanced)
        );
    }

    #[test]
    fn full_catalog_fails_closed_without_overwriting_a_live_provider() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(32, 1)).unwrap();
        let (handle, _) = catalog
            .activate(key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        assert_eq!(
            catalog.activate(key(2), NonZeroU16::new(1).unwrap()),
            Err(EgressDemandCatalogError::Full)
        );
        assert_eq!(catalog.update(handle, 2).unwrap(), None);
        assert_eq!(catalog.active_demands(), 1);
        assert_eq!(catalog.active_providers(), 1);
    }

    #[test]
    fn one_unit_horizon_remains_ready_for_every_nonempty_level() {
        let mut catalog = EgressDemandCatalog::<1>::new();
        catalog.configure(schedule(1, 1)).unwrap();
        let (handle, update) = catalog
            .activate(key(1), NonZeroU16::new(1).unwrap())
            .unwrap();
        assert!(active(update.unwrap()).level().horizon_ready());

        assert_eq!(catalog.update(handle, 2).unwrap(), None);
        assert_eq!(catalog.update(handle, 1).unwrap(), None);
        assert!(matches!(
            catalog.update(handle, 0).unwrap(),
            Some(EgressDemandUpdate::Inactive { .. })
        ));
    }

    #[test]
    fn saturated_and_sparse_keys_have_independent_demand_lifetimes() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 1)).unwrap();
        let (saturated, saturated_update) = catalog
            .activate(key(1), NonZeroU16::new(64).unwrap())
            .unwrap();
        let (sparse, sparse_update) = catalog
            .activate(key(2), NonZeroU16::new(1).unwrap())
            .unwrap();
        assert!(active(saturated_update.unwrap()).level().horizon_ready());
        assert!(!active(sparse_update.unwrap()).level().horizon_ready());

        assert!(matches!(
            catalog.update(sparse, 0).unwrap(),
            Some(EgressDemandUpdate::Inactive { key: ended, .. }) if ended == key(2)
        ));
        assert_eq!(catalog.update(saturated, 63).unwrap(), None);
        assert_eq!(catalog.active_demands(), 1);
    }

    #[test]
    fn published_level_saturates_without_corrupting_internal_reclamation() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 1)).unwrap();
        let (a, _) = catalog
            .activate(key(1), NonZeroU16::new(u16::MAX).unwrap())
            .unwrap();
        let (b, _) = catalog
            .activate(key(1), NonZeroU16::new(1).unwrap())
            .unwrap();

        let sparse = active(catalog.update(a, 0).unwrap().unwrap());
        assert_eq!(sparse.level().ready_units().get(), 1);
        assert!(!sparse.level().horizon_ready());
        assert!(matches!(
            catalog.update(b, 0).unwrap(),
            Some(EgressDemandUpdate::Inactive { key: ended, .. }) if ended == key(1)
        ));
    }

    #[test]
    fn observation_rekeys_one_provider_with_terminal_then_new_lifetime() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 9)).unwrap();
        let mut handle = None;
        let mut updates = std::vec::Vec::new();

        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(1), NonZeroU16::new(3).unwrap(), |update| {
                updates.push(update)
            })
            .unwrap();
        catalog.finish_observation(|_| unreachable!()).unwrap();
        let first = active(updates.pop().unwrap());

        catalog.begin_observation();
        catalog
            .observe(&mut handle, key(2), NonZeroU16::new(3).unwrap(), |update| {
                updates.push(update)
            })
            .unwrap();
        catalog.finish_observation(|_| unreachable!()).unwrap();

        assert_eq!(updates.len(), 2);
        assert_eq!(
            updates[0],
            EgressDemandUpdate::Inactive {
                id: first.id(),
                key: key(1),
            }
        );
        let second = active(updates[1]);
        assert_eq!(second.key(), key(2));
        assert_ne!(second.id(), first.id());
    }

    #[test]
    fn observation_sweep_and_disable_publish_terminal_lifetimes_once() {
        let mut catalog = EgressDemandCatalog::<2>::new();
        catalog.configure(schedule(32, 3)).unwrap();
        let mut a = None;
        let mut b = None;
        catalog.begin_observation();
        catalog
            .observe(&mut a, key(1), NonZeroU16::new(1).unwrap(), |_| {})
            .unwrap();
        catalog
            .observe(&mut b, key(2), NonZeroU16::new(1).unwrap(), |_| {})
            .unwrap();
        catalog.finish_observation(|_| unreachable!()).unwrap();

        let mut swept = std::vec::Vec::new();
        catalog.begin_observation();
        catalog
            .observe(&mut a, key(1), NonZeroU16::new(1).unwrap(), |_| {})
            .unwrap();
        catalog
            .finish_observation(|update| swept.push(update))
            .unwrap();
        assert!(matches!(
            swept.as_slice(),
            [EgressDemandUpdate::Inactive { key: ended, .. }] if *ended == key(2)
        ));

        let mut disabled = std::vec::Vec::new();
        catalog.disable(|update| disabled.push(update));
        assert!(matches!(
            disabled.as_slice(),
            [EgressDemandUpdate::Inactive { key: ended, .. }] if *ended == key(1)
        ));
        catalog.disable(|_| panic!("disabled catalog must not publish twice"));
    }
}
