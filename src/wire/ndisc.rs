use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use crate::time::Duration;
use crate::wire::Ipv6Addr;
use crate::wire::icmpv6::{Packet, field};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RouterFlags: u8 {
        const MANAGED = 0b10000000;
        const OTHER   = 0b01000000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct NeighborFlags: u8 {
        const ROUTER    = 0b10000000;
        const SOLICITED = 0b01000000;
        const OVERRIDE  = 0b00100000;
    }
}

/// Getters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<'a> Packet<'a> {
    /// Return the current hop limit field.
    #[inline]
    pub fn current_hop_limit(&self) -> u8 {
        self.buffer[field::CUR_HOP_LIMIT]
    }

    /// Return the Router Advertisement flags.
    #[inline]
    pub fn router_flags(&self) -> RouterFlags {
        RouterFlags::from_bits_truncate(self.buffer[field::ROUTER_FLAGS])
    }

    /// Return the router lifetime field.
    #[inline]
    pub fn router_lifetime(&self) -> Duration {
        Duration::from_secs(NetworkEndian::read_u16(&self.buffer[field::ROUTER_LT]).into())
    }

    /// Return the reachable time field.
    #[inline]
    pub fn reachable_time(&self) -> Duration {
        Duration::from_millis(NetworkEndian::read_u32(&self.buffer[field::REACHABLE_TM]))
    }

    /// Return the retransmit time field.
    #[inline]
    pub fn retrans_time(&self) -> Duration {
        Duration::from_millis(NetworkEndian::read_u32(&self.buffer[field::RETRANS_TM]))
    }
}

/// Common getters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<'a> Packet<'a> {
    /// Return the target address field.
    #[inline]
    pub fn target_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.buffer[field::TARGET_ADDR].try_into().unwrap())
    }
}

/// Getters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<'a> Packet<'a> {
    /// Return the Neighbor Solicitation flags.
    #[inline]
    pub fn neighbor_flags(&self) -> NeighborFlags {
        NeighborFlags::from_bits_truncate(self.buffer[field::NEIGH_FLAGS])
    }
}

/// Getters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<'a> Packet<'a> {
    /// Return the destination address field.
    #[inline]
    pub fn dest_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.buffer[field::DEST_ADDR].try_into().unwrap())
    }
}

/// Setters for the Router Advertisement message header.
/// See [RFC 4861 § 4.2].
///
/// [RFC 4861 § 4.2]: https://tools.ietf.org/html/rfc4861#section-4.2
impl<'a> Packet<'a> {
    /// Set the current hop limit field.
    #[inline]
    pub fn set_current_hop_limit(&mut self, value: u8) {
        self.buffer[field::CUR_HOP_LIMIT] = value;
    }

    /// Set the Router Advertisement flags.
    #[inline]
    pub fn set_router_flags(&mut self, flags: RouterFlags) {
        self.buffer[field::ROUTER_FLAGS] = flags.bits();
    }

    /// Set the router lifetime field.
    #[inline]
    pub fn set_router_lifetime(&mut self, value: Duration) {
        NetworkEndian::write_u16(&mut self.buffer[field::ROUTER_LT], value.as_secs() as u16);
    }

    /// Set the reachable time field.
    #[inline]
    pub fn set_reachable_time(&mut self, value: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::REACHABLE_TM], value.as_millis());
    }

    /// Set the retransmit time field.
    #[inline]
    pub fn set_retrans_time(&mut self, value: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::RETRANS_TM], value.as_millis());
    }
}

/// Common setters for the [Neighbor Solicitation], [Neighbor Advertisement], and
/// [Redirect] message types.
///
/// [Neighbor Solicitation]: https://tools.ietf.org/html/rfc4861#section-4.3
/// [Neighbor Advertisement]: https://tools.ietf.org/html/rfc4861#section-4.4
/// [Redirect]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<'a> Packet<'a> {
    /// Set the target address field.
    #[inline]
    pub fn set_target_addr(&mut self, value: Ipv6Addr) {
        self.buffer[field::TARGET_ADDR].copy_from_slice(&value.octets());
    }
}

/// Setters for the Neighbor Solicitation message header.
/// See [RFC 4861 § 4.3].
///
/// [RFC 4861 § 4.3]: https://tools.ietf.org/html/rfc4861#section-4.3
impl<'a> Packet<'a> {
    /// Set the Neighbor Solicitation flags.
    #[inline]
    pub fn set_neighbor_flags(&mut self, flags: NeighborFlags) {
        self.buffer[field::NEIGH_FLAGS] = flags.bits();
    }
}

/// Setters for the Redirect message header.
/// See [RFC 4861 § 4.5].
///
/// [RFC 4861 § 4.5]: https://tools.ietf.org/html/rfc4861#section-4.5
impl<'a> Packet<'a> {
    /// Set the destination address field.
    #[inline]
    pub fn set_dest_addr(&mut self, value: Ipv6Addr) {
        self.buffer[field::DEST_ADDR].copy_from_slice(&value.octets());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::icmpv6::Message;

    static ROUTER_ADVERT_BYTES: [u8; 24] = [
        0x86, 0x00, 0xa9, 0xde, 0x40, 0x80, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84, 0x01, 0x01,
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    ];
    static SOURCE_LINK_LAYER_OPT: [u8; 8] = [0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    #[test]
    fn test_router_advert_deconstruct() {
        let mut bytes = ROUTER_ADVERT_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::RouterAdvert);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.current_hop_limit(), 64);
        assert_eq!(packet.router_flags(), RouterFlags::MANAGED);
        assert_eq!(packet.router_lifetime(), Duration::from_secs(900));
        assert_eq!(packet.reachable_time(), Duration::from_millis(900));
        assert_eq!(packet.retrans_time(), Duration::from_millis(900));
        assert_eq!(packet.payload(), &SOURCE_LINK_LAYER_OPT[..]);
    }

    #[test]
    fn test_router_advert_construct() {
        use crate::wire::{Ipv6Addr, NdiscOption, NdiscOptionType, RawHardwareAddress};
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        // Into a buffer full of stale bytes: every byte of the message is written.
        let mut bytes = [0x2a; 24];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::RouterAdvert);
        packet.set_msg_code(0);
        packet.set_current_hop_limit(64);
        packet.set_router_flags(RouterFlags::MANAGED);
        packet.set_router_lifetime(Duration::from_secs(900));
        packet.set_reachable_time(Duration::from_millis(900));
        packet.set_retrans_time(Duration::from_millis(900));
        {
            let mut opt = NdiscOption::new_unchecked(packet.payload_mut());
            opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
            opt.set_data_len(1);
            opt.set_link_layer_addr(RawHardwareAddress::from_bytes(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        }
        packet.fill_checksum(&src, &dst);
        assert_eq!(&bytes[..], &ROUTER_ADVERT_BYTES[..]);

        // And it verifies, for the addresses it was built with.
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert!(packet.verify_checksum(&src, &dst));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for RouterFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "RouterFlags({=u8:#010b})", self.bits());
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NeighborFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "NeighborFlags({=u8:#010b})", self.bits());
    }
}
