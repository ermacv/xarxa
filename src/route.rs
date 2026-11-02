//! IP routing.
//!
//! [`Routes`] is the routing table, accessed with [`Stack::routes`] and
//! [`Stack::routes_mut`].
//!
//! Routes are keyed by a CIDR. On lookup most specific CIDR wins. Each route contains:
//! - via
//! - outgoing interface
//! - optional expiry time.
//!
//! On-link destinations (in the same network as one of the stack's addresses) do
//! not consult the table: the next hop is the destination itself.
//!
//! [`Stack::routes`]: crate::Stack::routes
//! [`Stack::routes_mut`]: crate::Stack::routes_mut

use crate::config::ROUTE_COUNT;
use crate::error::Full;
use crate::storage::Vec;

use crate::iface::IfaceHandle;
use crate::stack::IfaceBinding;
use crate::time::{Clock, Instant};
use crate::wire::{IpAddr, IpCidr};
#[cfg(feature = "ipv4")]
use crate::wire::{Ipv4Addr, Ipv4Cidr};
#[cfg(feature = "ipv6")]
use crate::wire::{Ipv6Addr, Ipv6Cidr};

#[cfg(feature = "ipv4")]
const IPV4_DEFAULT: IpCidr = IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0));
#[cfg(feature = "ipv6")]
const IPV6_DEFAULT: IpCidr = IpCidr::V6(Ipv6Cidr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

/// Where a route came from.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteOrigin {
    /// Added by the application.
    Manual,
    /// Learned from a DHCPv4 lease.
    #[cfg(feature = "dhcpv4")]
    Dhcpv4,
    /// Learned from an IPv6 router advertisement.
    #[cfg(feature = "slaac")]
    Slaac,
}

/// A prefix of addresses that should be routed via a router, out of an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddr,
    /// The interface this route goes out of.
    pub iface: IfaceHandle,
    /// Where the route came from.
    pub origin: RouteOrigin,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever". An expired route is removed from the table at the
    /// next poll.
    pub expires_at: Option<Instant>,
}

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, out of `iface`, with no expiry.
    #[cfg(feature = "ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Addr, iface: IfaceHandle) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            iface,
            origin: RouteOrigin::Manual,
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, out of `iface`, with no expiry.
    #[cfg(feature = "ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Addr, iface: IfaceHandle) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            iface,
            origin: RouteOrigin::Manual,
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns `true` if the route is a default route for IPv4.
    #[cfg(feature = "ipv4")]
    pub fn is_ipv4_gateway(&self) -> bool {
        self.cidr == IPV4_DEFAULT
    }

    /// Returns `true` if the route is a default route for IPv6.
    #[cfg(feature = "ipv6")]
    pub fn is_ipv6_gateway(&self) -> bool {
        self.cidr == IPV6_DEFAULT
    }
}

/// Error returned by [`Routes::add`], [`Routes::add_default_ipv4_route`] and
/// [`Routes::add_default_ipv6_route`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// The router address is not unicast.
    NotUnicast,
    /// The table has no room for another route. Only possible without the
    /// `alloc` feature, where the limit is [`ROUTE_COUNT`].
    Full,
}

impl From<Full> for RouteError {
    fn from(_: Full) -> Self {
        RouteError::Full
    }
}

impl core::fmt::Display for RouteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RouteError::NotUnicast => f.write_str("router not unicast"),
            RouteError::Full => f.write_str("full"),
        }
    }
}

impl core::error::Error for RouteError {}

/// A routing table.
#[derive(Debug, Default)]
pub struct Routes {
    storage: Vec<Route, ROUTE_COUNT>,
}

impl Routes {
    /// Creates a new empty routing table.
    pub(crate) fn new() -> Self {
        Self { storage: Vec::new() }
    }

    /// Add a route.
    ///
    /// # Errors
    /// - `NotUnicast`: if `via_router` is not a unicast address.
    /// - `Full`: if the table has no room. Only possible without the `alloc`
    ///   feature, where the limit is [`ROUTE_COUNT`].
    pub fn add(&mut self, route: Route) -> Result<(), RouteError> {
        if !route.via_router.is_unicast() {
            return Err(RouteError::NotUnicast);
        }
        self.storage.push(route).map_err(|_| RouteError::Full)
    }

    /// Remove the route at `index` and return it.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> Route {
        self.storage.remove(index)
    }

    /// Keep only the routes for which `f` returns true.
    pub fn retain(&mut self, f: impl FnMut(&Route) -> bool) {
        self.storage.retain(f)
    }

    /// Remove all routes.
    pub fn clear(&mut self) {
        self.storage.clear()
    }

    /// Iterate over the routes.
    pub fn iter(&self) -> impl Iterator<Item = &Route> {
        self.storage.iter()
    }

    /// Iterate over the routes, mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route> {
        self.storage.iter_mut()
    }

    /// Number of routes.
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Whether there are no routes.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway` dev `iface`").
    ///
    /// Returns the previous default route, if any. On error the previous
    /// default route is kept.
    ///
    /// # Errors
    /// - `NotUnicast`: if `gateway` is not a unicast address.
    /// - `Full`: if the table has no room. Only possible without the `alloc`
    ///   feature, where the limit is [`ROUTE_COUNT`].
    #[cfg(feature = "ipv4")]
    pub fn add_default_ipv4_route(
        &mut self,
        gateway: Ipv4Addr,
        iface: IfaceHandle,
    ) -> Result<Option<Route>, RouteError> {
        if !IpAddr::from(gateway).is_unicast() {
            return Err(RouteError::NotUnicast);
        }
        let old = self.remove_default_ipv4_route();
        // If the table is full here, `old` was `None` and nothing was lost.
        self.add(Route::new_ipv4_gateway(gateway, iface))?;
        Ok(old)
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway` dev `iface`").
    ///
    /// Returns the previous default route, if any. On error the previous
    /// default route is kept.
    ///
    /// # Errors
    /// - `NotUnicast`: if `gateway` is not a unicast address.
    /// - `Full`: if the table has no room. Only possible without the `alloc`
    ///   feature, where the limit is [`ROUTE_COUNT`].
    #[cfg(feature = "ipv6")]
    pub fn add_default_ipv6_route(
        &mut self,
        gateway: Ipv6Addr,
        iface: IfaceHandle,
    ) -> Result<Option<Route>, RouteError> {
        if !IpAddr::from(gateway).is_unicast() {
            return Err(RouteError::NotUnicast);
        }
        let old = self.remove_default_ipv6_route();
        // If the table is full here, `old` was `None` and nothing was lost.
        self.add(Route::new_ipv6_gateway(gateway, iface))?;
        Ok(old)
    }

    /// Returns the ipv4 default route if there is one in the route table.
    #[cfg(feature = "ipv4")]
    pub fn default_ipv4_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv4_gateway()).copied()
    }

    /// Returns the ipv6 default route if there is one in the route table.
    #[cfg(feature = "ipv6")]
    pub fn default_ipv6_route(&self) -> Option<Route> {
        self.storage.iter().find(|r| r.is_ipv6_gateway()).copied()
    }

    /// Remove the default ipv4 gateway, returning it if it existed.
    #[cfg(feature = "ipv4")]
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        let index = self.storage.iter().position(|r| r.is_ipv4_gateway())?;
        Some(self.storage.remove(index))
    }

    /// Remove the default ipv6 gateway, returning it if it existed.
    #[cfg(feature = "ipv6")]
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        let index = self.storage.iter().position(|r| r.is_ipv6_gateway())?;
        Some(self.storage.remove(index))
    }

    /// Look up the route for `addr`: the most specific matching prefix that has not
    /// expired.
    ///
    /// A bound socket (`binding`) only considers routes that go out of its
    /// interface. Without the `iface-bind` feature the binding is always
    /// `Any` and the filter compiles out.
    pub(crate) fn lookup(&self, binding: IfaceBinding, addr: &IpAddr) -> Option<&Route> {
        assert!(addr.is_unicast());

        self.storage
            .iter()
            // Keep only matching routes
            .filter(|route| {
                // `add` rejects these, but `iter_mut` can still write one in. A
                // gateway that isn't unicast can't be resolved as a next hop.
                if !route.via_router.is_unicast() {
                    return false;
                }
                if let Some(iface) = binding.iface()
                    && route.iface != iface
                {
                    return false;
                }
                route.cidr.contains_addr(addr)
            })
            // pick the most specific one (highest prefix_len)
            .max_by_key(|route| route.cidr.prefix_len())
    }

    /// Remove the routes that expired, and count the expiry of the others toward
    /// the next deadline. A lookup doesn't look at expiries: the stack is polled
    /// when one is due.
    ///
    /// The poll calls this at its start, before anything in it routes, and at its
    /// end, after everything that can add or refresh a route. Only the end call's
    /// deadline counts.
    pub(crate) fn remove_expired(&mut self, clock: &mut Clock) {
        // Not `retain`: that is a new copy of the loop for every closure.
        let mut i = 0;
        while let Some(route) = self.storage.get(i) {
            if route.expires_at.is_some_and(|expires_at| clock.expired(expires_at)) {
                self.storage.remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Remove all routes that go out of the given interface.
    pub(crate) fn purge_iface(&mut self, iface: IfaceHandle) {
        self.storage.retain(|route| route.iface != iface);
    }
}

#[cfg(all(test, feature = "ipv4", feature = "ipv6"))]
mod test {
    use super::*;
    #[allow(unused_imports)]
    use std::vec::Vec;

    const IF_0: IfaceHandle = IfaceHandle::new(0);
    const IF_1: IfaceHandle = IfaceHandle::new(1);

    const ADDR_1A: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 2, 0, 0, 0, 1);
    const ADDR_1B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 2, 0, 0, 0, 13);
    const ADDR_1C: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 2, 0, 0, 0, 42);
    fn cidr_1() -> Ipv6Cidr {
        Ipv6Cidr::new(Ipv6Addr::new(0xfe80, 0, 0, 2, 0, 0, 0, 0), 64)
    }

    const ADDR_2A: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 1);
    const ADDR_2B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 21);
    fn cidr_2() -> Ipv6Cidr {
        Ipv6Cidr::new(Ipv6Addr::new(0xfe80, 0, 0, 0x3364, 0, 0, 0, 0), 64)
    }

    /// Poll the table at `at_millis`, then look up and return (via_router, iface).
    fn lookup(routes: &mut Routes, addr: Ipv6Addr, at_millis: u32) -> Option<(IpAddr, IfaceHandle)> {
        routes.remove_expired(&mut Clock::new(Instant::from_millis(at_millis)));
        routes
            .lookup(IfaceBinding::Any, &addr.into())
            .map(|route| (route.via_router, route.iface))
    }

    /// A lookup with an interface binding only considers that interface's
    /// routes.
    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_lookup_iface_bound() {
        let mut routes = Routes::new();
        // The same prefix, reachable through two interfaces via different routers.
        for (via, iface) in [(ADDR_1A, IF_0), (ADDR_1B, IF_1)] {
            routes
                .add(Route {
                    cidr: cidr_2().into(),
                    via_router: via.into(),
                    iface,
                    origin: RouteOrigin::Manual,
                    preferred_until: None,
                    expires_at: None,
                })
                .unwrap();
        }

        assert_eq!(
            routes
                .lookup(IfaceBinding::Iface(IF_0), &ADDR_2A.into())
                .map(|r| r.via_router),
            Some(ADDR_1A.into())
        );
        assert_eq!(
            routes
                .lookup(IfaceBinding::Iface(IF_1), &ADDR_2A.into())
                .map(|r| r.via_router),
            Some(ADDR_1B.into())
        );
        // No route through the bound interface: no match, even though an
        // unconstrained lookup has one.
        let mut routes2 = Routes::new();
        routes2
            .add(Route {
                cidr: cidr_2().into(),
                via_router: ADDR_1A.into(),
                iface: IF_0,
                origin: RouteOrigin::Manual,
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();
        assert!(routes2.lookup(IfaceBinding::Any, &ADDR_2A.into()).is_some());
        assert!(routes2.lookup(IfaceBinding::Iface(IF_1), &ADDR_2A.into()).is_none());
    }

    #[test]
    fn test_fill() {
        let mut routes = Routes::new();

        assert_eq!(lookup(&mut routes, ADDR_1A, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_1B, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_1C, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_2B, 0), None);

        let route = Route {
            cidr: cidr_1().into(),
            via_router: ADDR_1A.into(),
            iface: IF_0,
            origin: RouteOrigin::Manual,
            preferred_until: None,
            expires_at: None,
        };
        routes.add(route).unwrap();

        assert_eq!(lookup(&mut routes, ADDR_1A, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&mut routes, ADDR_1B, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&mut routes, ADDR_1C, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_2B, 0), None);

        let route2 = Route {
            cidr: cidr_2().into(),
            via_router: ADDR_2A.into(),
            iface: IF_1,
            origin: RouteOrigin::Manual,
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        routes.add(route2).unwrap();

        assert_eq!(lookup(&mut routes, ADDR_1A, 0), Some((ADDR_1A.into(), IF_0)));
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), Some((ADDR_2A.into(), IF_1)));
        assert_eq!(lookup(&mut routes, ADDR_2B, 0), Some((ADDR_2A.into(), IF_1)));

        // Up to the expiry timestamp the route is valid...
        assert_eq!(lookup(&mut routes, ADDR_2A, 9), Some((ADDR_2A.into(), IF_1)));
        // ...and from it on, the route is gone.
        assert_eq!(lookup(&mut routes, ADDR_2B, 10), None);
        assert_eq!(lookup(&mut routes, ADDR_1A, 10), Some((ADDR_1A.into(), IF_0)));
    }

    #[test]
    fn test_most_specific_wins() {
        let mut routes = Routes::new();

        routes.add_default_ipv6_route(ADDR_1A, IF_0).unwrap();
        routes
            .add(Route {
                cidr: cidr_2().into(),
                via_router: ADDR_2A.into(),
                iface: IF_1,
                origin: RouteOrigin::Manual,
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();

        // In cidr_2: the /64 wins over the default route.
        assert_eq!(lookup(&mut routes, ADDR_2B, 0), Some((ADDR_2A.into(), IF_1)));
        // Everything else: the default route.
        assert_eq!(lookup(&mut routes, ADDR_1B, 0), Some((ADDR_1A.into(), IF_0)));
    }

    #[test]
    fn test_default_route() {
        let mut routes = Routes::new();
        let gw1 = Ipv4Addr::new(192, 168, 1, 1);
        let gw2 = Ipv4Addr::new(192, 168, 1, 2);

        assert!(routes.default_ipv4_route().is_none());
        assert!(routes.add_default_ipv4_route(gw1, IF_0).unwrap().is_none());

        // Adding a second default route replaces the first.
        let old = routes.add_default_ipv4_route(gw2, IF_1).unwrap().unwrap();
        assert_eq!(old.via_router, gw1.into());
        let current = routes.default_ipv4_route().unwrap();
        assert_eq!(current.via_router, gw2.into());
        assert_eq!(current.iface, IF_1);

        assert!(routes.remove_default_ipv4_route().is_some());
        assert!(routes.default_ipv4_route().is_none());
    }

    /// A gateway that isn't unicast is rejected, and a default route it would
    /// have replaced stays.
    #[test]
    fn test_router_not_unicast() {
        let mut routes = Routes::new();
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        routes.add_default_ipv4_route(gw, IF_0).unwrap();

        for bad in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, Ipv4Addr::new(224, 0, 0, 1)] {
            assert_eq!(
                routes.add_default_ipv4_route(bad, IF_0).err(),
                Some(RouteError::NotUnicast)
            );
            assert_eq!(
                routes.add(Route {
                    cidr: IpCidr::new(Ipv4Addr::new(10, 0, 0, 0).into(), 8),
                    ..Route::new_ipv4_gateway(bad, IF_0)
                }),
                Err(RouteError::NotUnicast)
            );
        }
        for bad in [Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)] {
            assert_eq!(
                routes.add_default_ipv6_route(bad, IF_0).err(),
                Some(RouteError::NotUnicast)
            );
        }

        assert_eq!(routes.len(), 1);
        assert_eq!(routes.default_ipv4_route().unwrap().via_router, gw.into());
    }

    /// A route whose gateway was made non-unicast through `iter_mut` is
    /// skipped by lookups.
    #[test]
    fn test_lookup_skips_router_not_unicast() {
        let mut routes = Routes::new();
        routes.add_default_ipv6_route(ADDR_1A, IF_0).unwrap();
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), Some((ADDR_1A.into(), IF_0)));

        routes.iter_mut().next().unwrap().via_router = Ipv6Addr::UNSPECIFIED.into();
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), None);
    }

    #[test]
    fn test_purge_iface() {
        let mut routes = Routes::new();
        routes
            .add(Route {
                cidr: cidr_1().into(),
                via_router: ADDR_1A.into(),
                iface: IF_0,
                origin: RouteOrigin::Manual,
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();
        routes
            .add(Route {
                cidr: cidr_2().into(),
                via_router: ADDR_2A.into(),
                iface: IF_1,
                origin: RouteOrigin::Manual,
                preferred_until: None,
                expires_at: None,
            })
            .unwrap();

        routes.purge_iface(IF_0);
        assert_eq!(lookup(&mut routes, ADDR_1A, 0), None);
        assert_eq!(lookup(&mut routes, ADDR_2A, 0), Some((ADDR_2A.into(), IF_1)));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Routes {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Routes({=[?]})", self.storage.as_slice());
    }
}
