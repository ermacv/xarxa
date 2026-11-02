//! Error types.
//!
//! The errors of the wire layer and of the stack itself. Socket errors live in
//! their own socket's module.

use core::fmt;

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by xarxa.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed packet")
    }
}

impl core::error::Error for Malformed {}

/// Parsing a string failed.
///
/// Returned by the [`FromStr`](core::str::FromStr) implementations of the
/// address, CIDR and socket address types.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("parse error")
    }
}

impl core::error::Error for ParseError {}

/// A table, slab or queue has no room for another item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Full;

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("full")
    }
}

impl core::error::Error for Full {}

/// The hostname does not fit. The limit is 63 bytes.
///
/// Returned by [`Stack::set_hostname`](crate::Stack::set_hostname).
#[cfg(feature = "hostname")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HostnameTooLong;

#[cfg(feature = "hostname")]
impl core::fmt::Display for HostnameTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("hostname too long")
    }
}

#[cfg(feature = "hostname")]
impl core::error::Error for HostnameTooLong {}

/// A hop limit of zero was given. A packet must not be sent with one.
///
/// Returned by the `set_hop_limit` method of the UDP and TCP sockets.
#[cfg(any(feature = "udp", feature = "tcp"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidHopLimit;

#[cfg(any(feature = "udp", feature = "tcp"))]
impl core::fmt::Display for InvalidHopLimit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid hop limit")
    }
}

#[cfg(any(feature = "udp", feature = "tcp"))]
impl core::error::Error for InvalidHopLimit {}

/// An address is not unicast.
///
/// Returned by [`NeighborCache::insert`](crate::NeighborCache::insert).
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NotUnicast;

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl core::fmt::Display for NotUnicast {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not unicast")
    }
}

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
impl core::error::Error for NotUnicast {}

/// ICMP error reported against a socket.
///
/// Returned by `take_icmp_error` on UDP and TCP sockets (and by
/// [`UdpSocket::recv`](crate::udp::UdpSocket::recv)) when an ICMP error message quoting
/// one of the socket's packets arrives. Requires the `icmp-errors` cargo
/// feature.
#[cfg(feature = "icmp-errors")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IcmpError {
    /// The destination network is unreachable (`ENETUNREACH`).
    NetUnreachable,
    /// The destination host is unreachable (`EHOSTUNREACH`). Also reported when
    /// the stack's own neighbor resolution (ARP/NDISC) for the destination fails.
    HostUnreachable,
    /// The destination host does not speak this protocol (`EPROTO`).
    ProtoUnreachable,
    /// Nothing is listening on the destination port (`ECONNREFUSED`).
    PortUnreachable,
    /// The packet was too big for a link on the path and could not be fragmented
    /// (`EMSGSIZE`): ICMPv4 "fragmentation needed and DF set" / ICMPv6 packet too
    /// big.
    PacketTooBig,
    /// Any other error: time exceeded, parameter problem, source route failed, ...
    Other,
}

#[cfg(feature = "icmp-errors")]
impl core::fmt::Display for IcmpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IcmpError::NetUnreachable => write!(f, "network unreachable"),
            IcmpError::HostUnreachable => write!(f, "host unreachable"),
            IcmpError::ProtoUnreachable => write!(f, "protocol unreachable"),
            IcmpError::PortUnreachable => write!(f, "port unreachable"),
            IcmpError::PacketTooBig => write!(f, "packet too big"),
            IcmpError::Other => write!(f, "other ICMP error"),
        }
    }
}
