use core::convert::From;
use core::fmt;

use crate::error::Malformed;
#[cfg(feature = "ipv4")]
use crate::wire::{Ipv4Addr, Ipv4AddrExt, Ipv4Cidr};
#[cfg(feature = "ipv6")]
use crate::wire::{Ipv6Addr, Ipv6AddrExt, Ipv6Cidr};

/// Internet protocol version.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    #[cfg(feature = "ipv4")]
    V4,
    #[cfg(feature = "ipv6")]
    V6,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// # Errors
    /// - `Malformed`: if the version is neither 4 nor 6, or the build has no
    ///   feature for it.
    pub const fn of_packet(data: &[u8]) -> Result<Version, Malformed> {
        let first = match data {
            [first, ..] => *first,
            [] => return Err(Malformed),
        };
        match first >> 4 {
            #[cfg(feature = "ipv4")]
            4 => Ok(Version::V4),
            #[cfg(feature = "ipv6")]
            6 => Ok(Version::V6),
            _ => Err(Malformed),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Version::V4 => write!(f, "IPv4"),
            #[cfg(feature = "ipv6")]
            Version::V6 => write!(f, "IPv6"),
        }
    }
}

open_enum! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        IpSecEsp  = 0x32,
        IpSecAh   = 0x33,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

/// An internetworking address.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An IPv4 address.
    #[cfg(feature = "ipv4")]
    V4(Ipv4Addr),
    /// An IPv6 address.
    #[cfg(feature = "ipv6")]
    V6(Ipv6Addr),
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    #[cfg(feature = "ipv4")]
    pub const fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::V4(Ipv4Addr::new(a0, a1, a2, a3))
    }

    /// Create an address wrapping an IPv6 address with the given octets.
    #[cfg(feature = "ipv6")]
    #[allow(clippy::too_many_arguments)]
    pub const fn v6(a0: u16, a1: u16, a2: u16, a3: u16, a4: u16, a5: u16, a6: u16, a7: u16) -> Address {
        Address::V6(Ipv6Addr::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// Return the protocol version.
    pub const fn version(&self) -> Version {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(_) => Version::V4,
            #[cfg(feature = "ipv6")]
            Address::V6(_) => Version::V6,
        }
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.x_is_unicast(),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => addr.x_is_unicast(),
        }
    }

    /// Query whether the address is a valid multicast address.
    pub const fn is_multicast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.is_multicast(),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => addr.is_multicast(),
        }
    }

    /// The Ethernet address this multicast address maps to.
    ///
    /// IPv4 groups map per RFC 1112, IPv6 groups per RFC 2464. Both mappings
    /// drop part of the group address, so distinct groups can map to the same
    /// Ethernet address.
    ///
    /// Only with the `medium-ethernet` feature.
    ///
    /// # Panics
    /// Panics if the address is not multicast.
    #[cfg(feature = "medium-ethernet")]
    pub fn multicast_ethernet_addr(&self) -> crate::wire::EthernetAddress {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.multicast_ethernet_addr(),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => addr.multicast_ethernet_addr(),
        }
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.is_broadcast(),
            #[cfg(feature = "ipv6")]
            Address::V6(_) => false,
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.is_unspecified(),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => addr.is_unspecified(),
        }
    }

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    pub fn prefix_len(&self) -> Option<u8> {
        match self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => addr.prefix_len(),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => addr.prefix_len(),
        }
    }

    /// Is this an IPv4 address.
    #[cfg(feature = "ipv4")]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Address::V4(_))
    }

    /// Is this an IPv6 address.
    #[cfg(feature = "ipv6")]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::V6(_))
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::IpAddr> for Address {
    fn from(x: ::core::net::IpAddr) -> Address {
        match x {
            ::core::net::IpAddr::V4(ipv4) => Address::V4(ipv4),
            ::core::net::IpAddr::V6(ipv6) => Address::V6(ipv6),
        }
    }
}

impl From<Address> for ::core::net::IpAddr {
    fn from(x: Address) -> ::core::net::IpAddr {
        match x {
            #[cfg(feature = "ipv4")]
            Address::V4(ipv4) => ::core::net::IpAddr::V4(ipv4),
            #[cfg(feature = "ipv6")]
            Address::V6(ipv6) => ::core::net::IpAddr::V6(ipv6),
        }
    }
}

#[cfg(feature = "ipv4")]
impl From<Ipv4Addr> for Address {
    fn from(ipv4: Ipv4Addr) -> Address {
        Address::V4(ipv4)
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Addr> for Address {
    fn from(addr: Ipv6Addr) -> Self {
        Address::V6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => write!(f, "{addr}"),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => write!(f, "{addr}"),
        }
    }
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    #[cfg(feature = "ipv4")]
    V4(Ipv4Cidr),
    #[cfg(feature = "ipv6")]
    V6(Ipv6Cidr),
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// Return `None` if the prefix length is invalid for the given address: larger
    /// than 32 for an IPv4 address, or larger than 128 for an IPv6 one.
    pub const fn try_new(addr: Address, prefix_len: u8) -> Option<Self> {
        match addr {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => match Ipv4Cidr::try_new(addr, prefix_len) {
                Some(cidr) => Some(Cidr::V4(cidr)),
                None => None,
            },
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => match Ipv6Cidr::try_new(addr, prefix_len) {
                Some(cidr) => Some(Cidr::V6(cidr)),
                None => None,
            },
        }
    }

    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given prefix length is invalid for the given address.
    pub const fn new(addr: Address, prefix_len: u8) -> Cidr {
        Self::try_new(addr, prefix_len).unwrap()
    }

    /// Return the IP address of this CIDR block.
    pub const fn address(&self) -> Address {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::V4(cidr) => Address::V4(cidr.address()),
            #[cfg(feature = "ipv6")]
            Cidr::V6(cidr) => Address::V6(cidr.address()),
        }
    }

    /// Return the prefix length of this CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::V4(cidr) => cidr.prefix_len(),
            #[cfg(feature = "ipv6")]
            Cidr::V6(cidr) => cidr.prefix_len(),
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        match (self, addr) {
            #[cfg(feature = "ipv4")]
            (Cidr::V4(cidr), Address::V4(addr)) => cidr.contains_addr(addr),
            #[cfg(feature = "ipv6")]
            (Cidr::V6(cidr), Address::V6(addr)) => cidr.contains_addr(addr),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            #[cfg(feature = "ipv4")]
            (Cidr::V4(cidr), Cidr::V4(other)) => cidr.contains_subnet(other),
            #[cfg(feature = "ipv6")]
            (Cidr::V6(cidr), Cidr::V6(other)) => cidr.contains_subnet(other),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Is this an IPv4 address.
    #[cfg(feature = "ipv4")]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Cidr::V4(_))
    }

    /// Is this an IPv6 address.
    #[cfg(feature = "ipv6")]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Cidr::V6(_))
    }
}

#[cfg(feature = "ipv4")]
impl From<Ipv4Cidr> for Cidr {
    fn from(addr: Ipv4Cidr) -> Self {
        Cidr::V4(addr)
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Cidr> for Cidr {
    fn from(addr: Ipv6Cidr) -> Self {
        Cidr::V6(addr)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::V4(cidr) => write!(f, "{cidr}"),
            #[cfg(feature = "ipv6")]
            Cidr::V6(cidr) => write!(f, "{cidr}"),
        }
    }
}

/// An IP address and a port.
///
/// `SocketAddr` names one peer: both the address and the port are meant to be
/// specified. [`UNSPECIFIED`](Self::UNSPECIFIED) is the one exception, a
/// sentinel for "no address given" where an API defaults it from elsewhere.
/// [`UdpSocket::send_with`](crate::udp::UdpSocket::send_with) takes the socket's
/// connected remote for it.
///
/// See also [`ListenSocketAddr`], the address of a *bind*, whose address is
/// optional so that it can match more than one of our addresses.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SocketAddr {
    pub addr: Address,
    pub port: u16,
}

impl SocketAddr {
    /// The wildcard address: unspecified address, port zero. Not a destination
    /// anything can be sent to, but a sentinel for "no address given".
    #[cfg(feature = "ipv4")]
    pub const UNSPECIFIED: SocketAddr = SocketAddr {
        addr: Address::V4(Ipv4Addr::UNSPECIFIED),
        port: 0,
    };

    /// The wildcard address: unspecified address, port zero. Not a destination
    /// anything can be sent to, but a sentinel for "no address given".
    #[cfg(not(feature = "ipv4"))]
    pub const UNSPECIFIED: SocketAddr = SocketAddr {
        addr: Address::V6(Ipv6Addr::UNSPECIFIED),
        port: 0,
    };

    /// Create a socket address from an address and a port.
    pub const fn new(addr: Address, port: u16) -> SocketAddr {
        SocketAddr { addr, port }
    }

    /// Query whether both the address and the port are specified.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::SocketAddr> for SocketAddr {
    fn from(x: ::core::net::SocketAddr) -> SocketAddr {
        SocketAddr {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

impl From<SocketAddr> for ::core::net::SocketAddr {
    fn from(x: SocketAddr) -> ::core::net::SocketAddr {
        ::core::net::SocketAddr::new(x.addr.into(), x.port)
    }
}

impl<T: Into<Address>> From<(T, u16)> for SocketAddr {
    fn from((addr, port): (T, u16)) -> SocketAddr {
        SocketAddr {
            addr: addr.into(),
            port,
        }
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            #[cfg(feature = "ipv4")]
            Address::V4(addr) => write!(f, "{}:{}", addr, self.port),
            #[cfg(feature = "ipv6")]
            Address::V6(addr) => write!(f, "[{}]:{}", addr, self.port),
        }
    }
}

/// An optional IP address and a port, for binding.
///
/// In contrast with [`SocketAddr`], `ListenSocketAddr` allows leaving the address
/// unspecified, in order to listen on a given port at more than one of our
/// addresses. The address field has three states, which are exactly the three
/// ways a bind can be scoped:
///
/// - `None`: any address, of either IP version, a dual-stack bind.
/// - `Some(addr)` with an unspecified address (`0.0.0.0` / `::`): any address
///   of *that* version, and none of the other one.
/// - `Some(addr)` with a concrete address: that address alone.
///
/// It can be constructed from a port alone, in which case the address
/// is `None`, and from an (address, port) pair, in which case it is `Some`. So
/// `(Ipv4Addr::UNSPECIFIED, 80)` is the "any IPv4 address" bind, and
/// `(Ipv6Addr::UNSPECIFIED, 80)` the IPv6 one.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ListenSocketAddr {
    pub addr: Option<Address>,
    pub port: u16,
}

impl ListenSocketAddr {
    /// The fully wildcard address: any address of any version, port zero.
    pub const UNSPECIFIED: ListenSocketAddr = ListenSocketAddr { addr: None, port: 0 };

    /// The address, if it is a concrete one, neither absent nor unspecified. That
    /// is, one of our addresses rather than a filter over several.
    pub fn concrete_addr(&self) -> Option<Address> {
        self.addr.filter(|addr| !addr.is_unspecified())
    }

    /// The IP version this is restricted to, if it is restricted to one.
    pub fn version(&self) -> Option<Version> {
        self.addr.map(|addr| addr.version())
    }

    /// Query whether this names one concrete address and a nonzero port.
    pub fn is_specified(&self) -> bool {
        self.concrete_addr().is_some() && self.port != 0
    }
}

impl From<u16> for ListenSocketAddr {
    fn from(port: u16) -> ListenSocketAddr {
        ListenSocketAddr { addr: None, port }
    }
}

impl From<SocketAddr> for ListenSocketAddr {
    fn from(addr: SocketAddr) -> ListenSocketAddr {
        ListenSocketAddr {
            addr: Some(addr.addr),
            port: addr.port,
        }
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::SocketAddr> for ListenSocketAddr {
    fn from(x: ::core::net::SocketAddr) -> ListenSocketAddr {
        ListenSocketAddr {
            addr: Some(x.ip().into()),
            port: x.port(),
        }
    }
}

impl<T: Into<Address>> From<(T, u16)> for ListenSocketAddr {
    fn from((addr, port): (T, u16)) -> ListenSocketAddr {
        ListenSocketAddr {
            addr: Some(addr.into()),
            port,
        }
    }
}

impl fmt::Display for ListenSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            #[cfg(feature = "ipv4")]
            Some(Address::V4(addr)) => write!(f, "{}:{}", addr, self.port),
            #[cfg(feature = "ipv6")]
            Some(Address::V6(addr)) => write!(f, "[{}]:{}", addr, self.port),
            None => write!(f, "*:{}", self.port),
        }
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    const fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    #[inline(always)]
    fn add_with_end_around_carry(accumulator: u32, word: u32) -> u32 {
        // Accumulating modulo 2^32-1 preserves the final Internet-checksum
        // fold because 2^32 is congruent to 1 modulo 2^16-1. This avoids
        // splitting every native u32 load into two u16 addends.
        let (sum, carry) = accumulator.overflowing_add(word);
        sum + u32::from(carry)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(data: &[u8]) -> u16 {
        // This is the same aligned native-endian scheme as lwIP's
        // LWIP_CHKSUM_ALGORITHM=2: the bulk path sums native u32 loads, two
        // Internet-checksum words each. See RFC 1071 section 2(B).
        // `pod_align_to` provides the aligned u32 view without unsafe code.
        let start = data.as_ptr().addr();
        let (head, words, tail) = bytemuck::pod_align_to::<u8, u32>(data);
        let (quad_words, remaining_words) = words.as_chunks::<4>();
        let mut accum_0 = edge_sum(head, start);
        let mut accum_1 = 0u32;
        let mut accum_2 = 0u32;
        let mut accum_3 = 0u32;
        for words in quad_words {
            accum_0 = add_with_end_around_carry(accum_0, words[0]);
            accum_1 = add_with_end_around_carry(accum_1, words[1]);
            accum_2 = add_with_end_around_carry(accum_2, words[2]);
            accum_3 = add_with_end_around_carry(accum_3, words[3]);
        }
        let mut accum = add_with_end_around_carry(accum_0, accum_1);
        accum = add_with_end_around_carry(accum, accum_2);
        accum = add_with_end_around_carry(accum, accum_3);
        for &word in remaining_words {
            accum = add_with_end_around_carry(accum, word);
        }
        let tail_start = start + head.len() + words.len() * 4;
        accum = add_with_end_around_carry(accum, edge_sum(tail, tail_start));

        let mut collapsed = propagate_carries(accum);
        collapsed = propagate_carries(collapsed as u32);
        // Memory lanes pair each byte with its u16-aligned neighbour. When the
        // data starts on an odd address its checksum words straddle those
        // lanes, which RFC 1071 section 2(B) resolves by one byte swap.
        if start & 1 != 0 {
            collapsed = collapsed.swap_bytes();
        }
        collapsed.to_be()
    }

    /// Sum up to three unaligned edge bytes, each in the native u16 lane its
    /// address selects, so they line up with the bulk u32 loads.
    fn edge_sum(bytes: &[u8], address: usize) -> u32 {
        bytes.iter().enumerate().fold(0, |sum, (offset, &byte)| {
            let lane = if (address + offset) & 1 == 0 {
                [byte, 0]
            } else {
                [0, byte]
            };
            sum + u32::from(u16::from_ne_bytes(lane))
        })
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    #[cfg(feature = "ipv4")]
    pub fn pseudo_header_v4(src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr, next_header: Protocol, length: u32) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[data(&src_addr.octets()), data(&dst_addr.octets()), data(&proto_len[..])])
    }

    #[cfg(feature = "ipv6")]
    pub fn pseudo_header_v6(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr, next_header: Protocol, length: u32) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[data(&src_addr.octets()), data(&dst_addr.octets()), data(&proto_len[..])])
    }

    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address, next_header: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            #[cfg(feature = "ipv4")]
            (Address::V4(src_addr), Address::V4(dst_addr)) => pseudo_header_v4(src_addr, dst_addr, next_header, length),
            #[cfg(feature = "ipv6")]
            (Address::V6(src_addr), Address::V6(dst_addr)) => pseudo_header_v6(src_addr, dst_addr, next_header, length),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::data;

        fn reference(bytes: &[u8]) -> u16 {
            let mut accum = 0u32;
            let mut chunks = bytes.chunks_exact(2);
            for chunk in &mut chunks {
                accum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            if let Some(&last) = chunks.remainder().first() {
                accum += (last as u32) << 8;
            }
            let sum = (accum >> 16) + (accum & 0xffff);
            ((sum >> 16) + (sum & 0xffff)) as u16
        }

        #[test]
        fn aligned_native_words_match_reference() {
            let mut storage = [0u8; 264];
            for (index, byte) in storage.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
            }

            for offset in 0..8 {
                for length in 0..=255 {
                    let bytes = &storage[offset..offset + length];
                    assert_eq!(data(bytes), reference(bytes), "offset={offset} length={length}");
                }
            }
        }

        /// Deterministic xorshift bytes, so failures reproduce.
        fn random_bytes(length: usize, mut state: u32) -> Vec<u8> {
            (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect()
        }

        #[test]
        fn every_length_and_alignment_up_to_two_kilobytes_matches_reference() {
            let random = random_bytes(2048 + 4, 0x9e37_79b9);
            let saturated = vec![0xffu8; 2048 + 4];
            for storage in [&random, &saturated] {
                for offset in 0..=3 {
                    for length in 0..=2048 {
                        let bytes = &storage[offset..offset + length];
                        assert_eq!(data(bytes), reference(bytes), "offset={offset} length={length}");
                    }
                }
            }
        }

        #[test]
        fn a_saturated_maximum_datagram_folds_every_carry() {
            let storage = vec![0xffu8; 65_535 + 3];
            for offset in 0..=3 {
                for length in [65_534, 65_535] {
                    let bytes = &storage[offset..offset + length];
                    assert_eq!(data(bytes), reference(bytes), "offset={offset} length={length}");
                }
            }
        }

        #[test]
        fn maximum_ipv4_datagram_matches_reference() {
            let mut storage = vec![0xffu8; 65_542];
            for (index, byte) in storage.iter_mut().enumerate() {
                *byte ^= (index as u8).wrapping_mul(17);
            }

            for offset in 0..8 {
                let bytes = &storage[offset..offset + 65_535];
                assert_eq!(data(bytes), reference(bytes), "offset={offset}");
            }
        }
    }
}

#[cfg(all(test, feature = "ipv4", feature = "ipv6"))]
pub(crate) mod test {
    #![allow(unused)]

    use super::*;
    use crate::wire::{IpAddr, IpCidr, IpProtocol};
    use crate::wire::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn to_prefix_len_ipv4() {
        fn test_eq(prefix_len: u8, mask: impl Into<Address>) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv4Addr::new(0, 0, 0, 0));
        test_eq(1, Ipv4Addr::new(128, 0, 0, 0));
        test_eq(2, Ipv4Addr::new(192, 0, 0, 0));
        test_eq(3, Ipv4Addr::new(224, 0, 0, 0));
        test_eq(4, Ipv4Addr::new(240, 0, 0, 0));
        test_eq(5, Ipv4Addr::new(248, 0, 0, 0));
        test_eq(6, Ipv4Addr::new(252, 0, 0, 0));
        test_eq(7, Ipv4Addr::new(254, 0, 0, 0));
        test_eq(8, Ipv4Addr::new(255, 0, 0, 0));
        test_eq(9, Ipv4Addr::new(255, 128, 0, 0));
        test_eq(10, Ipv4Addr::new(255, 192, 0, 0));
        test_eq(11, Ipv4Addr::new(255, 224, 0, 0));
        test_eq(12, Ipv4Addr::new(255, 240, 0, 0));
        test_eq(13, Ipv4Addr::new(255, 248, 0, 0));
        test_eq(14, Ipv4Addr::new(255, 252, 0, 0));
        test_eq(15, Ipv4Addr::new(255, 254, 0, 0));
        test_eq(16, Ipv4Addr::new(255, 255, 0, 0));
        test_eq(17, Ipv4Addr::new(255, 255, 128, 0));
        test_eq(18, Ipv4Addr::new(255, 255, 192, 0));
        test_eq(19, Ipv4Addr::new(255, 255, 224, 0));
        test_eq(20, Ipv4Addr::new(255, 255, 240, 0));
        test_eq(21, Ipv4Addr::new(255, 255, 248, 0));
        test_eq(22, Ipv4Addr::new(255, 255, 252, 0));
        test_eq(23, Ipv4Addr::new(255, 255, 254, 0));
        test_eq(24, Ipv4Addr::new(255, 255, 255, 0));
        test_eq(25, Ipv4Addr::new(255, 255, 255, 128));
        test_eq(26, Ipv4Addr::new(255, 255, 255, 192));
        test_eq(27, Ipv4Addr::new(255, 255, 255, 224));
        test_eq(28, Ipv4Addr::new(255, 255, 255, 240));
        test_eq(29, Ipv4Addr::new(255, 255, 255, 248));
        test_eq(30, Ipv4Addr::new(255, 255, 255, 252));
        test_eq(31, Ipv4Addr::new(255, 255, 255, 254));
        test_eq(32, Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn to_prefix_len_ipv4_error() {
        assert_eq!(None, IpAddr::from(Ipv4Addr::new(255, 255, 255, 1)).prefix_len());
    }

    #[test]
    fn to_prefix_len_ipv6() {
        fn test_eq(prefix_len: u8, mask: impl Into<Address>) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        test_eq(
            128,
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
    }

    #[test]
    fn to_prefix_len_ipv6_error() {
        assert_eq!(
            None,
            IpAddr::from(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 1)).prefix_len()
        );
    }

    #[cfg(feature = "ipv4")]
    #[test]
    fn test_print_ipv4_cidr() {
        let cidr = Cidr::new(Ipv4Addr::LOCALHOST.into(), 8);
        assert_eq!("127.0.0.1/8", format!("{cidr}"));
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn test_print_ipv6_cidr() {
        let cidr = Cidr::new(Ipv6Addr::LOCALHOST.into(), 128);
        assert_eq!("::1/128", format!("{cidr}"));
    }

    /// `Version::of_packet` dispatches on the first nibble, and never panics on
    /// a short buffer.
    #[test]
    fn test_version_of_packet() {
        assert_eq!(Version::of_packet(&[]), Err(Malformed));
        assert_eq!(Version::of_packet(&[0xff]), Err(Malformed));
        assert_eq!(Version::of_packet(&[0x50]), Err(Malformed));
        assert_eq!(Version::of_packet(&[0x00]), Err(Malformed));
        #[cfg(feature = "ipv4")]
        assert_eq!(Version::of_packet(&[0x45]), Ok(Version::V4));
        #[cfg(feature = "ipv6")]
        assert_eq!(Version::of_packet(&[0x60]), Ok(Version::V6));
    }

    #[cfg(feature = "ipv4")]
    #[test]
    fn test_print_ipv4_endpoint() {
        let endpoint = SocketAddr {
            addr: Ipv4Addr::LOCALHOST.into(),
            port: 8080,
        };
        assert_eq!("127.0.0.1:8080", format!("{endpoint}"));
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn test_print_ipv6_endpoint() {
        let endpoint = SocketAddr {
            addr: Ipv6Addr::LOCALHOST.into(),
            port: 8080,
        };
        assert_eq!("[::1]:8080", format!("{endpoint}"));
    }
}
