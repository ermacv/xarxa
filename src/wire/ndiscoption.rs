use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::time::Duration;
use crate::wire::{Ipv6Addr, MAX_HARDWARE_ADDRESS_LEN};

use crate::wire::RawHardwareAddress;

open_enum! {
    /// NDISC Option Type
    pub enum Type(u8) {
        /// Source Link-layer Address
        SourceLinkLayerAddr = 0x1,
        /// Target Link-layer Address
        TargetLinkLayerAddr = 0x2,
        /// Prefix Information
        PrefixInformation   = 0x3,
        /// Redirected Header
        RedirectedHeader    = 0x4,
        /// MTU
        Mtu                 = 0x5
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PrefixInfoFlags: u8 {
        const ON_LINK  = 0b10000000;
        const ADDRCONF = 0b01000000;
    }
}

/// A read/write wrapper around an [NDISC Option].
///
/// [NDISC Option]: https://tools.ietf.org/html/rfc4861#section-4.6
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct NdiscOption<'a> {
    buffer: &'a mut [u8],
}

// Format of an NDISC Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~                              ...                              ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc4861#section-4.6 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. Length of the option, in units of 8 octets.
    pub const LENGTH: usize = 1;
    // Minimum length of an option.
    pub const MIN_OPT_LEN: usize = 8;
    // Variable-length field. Option-Type-specific data.
    pub const fn DATA(length: u8) -> Field {
        2..length as usize * 8
    }

    // Source/Target Link-layer Option fields.
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix Information Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Valid Lifetime                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Preferred Lifetime                      |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved2                           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +                            Prefix                             +
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix length.
    pub const PREFIX_LEN: usize = 2;
    // Flags field of prefix header.
    pub const FLAGS: usize = 3;
    // Valid lifetime.
    pub const VALID_LT: Field = 4..8;
    // Preferred lifetime.
    pub const PREF_LT: Field = 8..12;
    // Reserved bits
    pub const PREF_RESERVED: Field = 12..16;
    // Prefix
    pub const PREFIX: Field = 16..32;

    // Redirected Header Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |            Reserved           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  ~                       IP header + data                        ~
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Reserved bits.
    pub const REDIRECTED_RESERVED: Field = 2..8;
    pub const REDIR_MIN_SZ: usize = 48;

    // MTU Option fields
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |           Reserved            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              MTU                              |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  MTU
    pub const MTU_RESERVED: Field = 2..4;
    pub const MTU: Field = 4..8;
}

/// Core getter methods relevant to any type of NDISC option.
impl<'a> NdiscOption<'a> {
    /// Create a raw octet buffer with an NDISC Option structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> NdiscOption<'a> {
        NdiscOption { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<NdiscOption<'a>, Malformed> {
        let opt = Self::new_unchecked(buffer);
        opt.check_len()?;

        // A data length field of 0 is invalid.
        if opt.data_len() == 0 {
            return Err(Malformed);
        }

        Ok(opt)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// The result of this check is invalidated by calling [set_data_len].
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    ///
    /// [set_data_len]: #method.set_data_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();

        if len < field::MIN_OPT_LEN {
            Err(Malformed)
        } else {
            let data_range = field::DATA(self.buffer[field::LENGTH]);
            if len < data_range.end {
                Err(Malformed)
            } else {
                match self.option_type() {
                    Type::SourceLinkLayerAddr | Type::TargetLinkLayerAddr | Type::Mtu => Ok(()),
                    Type::PrefixInformation if data_range.end >= field::PREFIX.end => Ok(()),
                    Type::RedirectedHeader if data_range.end >= field::REDIR_MIN_SZ => Ok(()),
                    Type::PrefixInformation | Type::RedirectedHeader => Err(Malformed),
                    _ => Ok(()),
                }
            }
        }
    }

    /// Return the option type.
    #[inline]
    pub fn option_type(&self) -> Type {
        Type::from(self.buffer[field::TYPE])
    }

    /// Return the length of the data.
    #[inline]
    pub fn data_len(&self) -> u8 {
        self.buffer[field::LENGTH]
    }
}

/// Getter methods only relevant for Source/Target Link-layer Address options.
impl<'a> NdiscOption<'a> {
    /// Return the Source/Target Link-layer Address.
    #[inline]
    pub fn link_layer_addr(&self) -> RawHardwareAddress {
        let len = MAX_HARDWARE_ADDRESS_LEN.min(self.data_len() as usize * 8 - 2);
        RawHardwareAddress::from_bytes(&self.buffer[2..len + 2])
    }
}

/// Getter methods only relevant for the MTU option.
impl<'a> NdiscOption<'a> {
    /// Return the MTU value.
    #[inline]
    pub fn mtu(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::MTU])
    }
}

/// Getter methods only relevant for the Prefix Information option.
impl<'a> NdiscOption<'a> {
    /// Return the prefix length.
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.buffer[field::PREFIX_LEN]
    }

    /// Return the prefix information flags.
    #[inline]
    pub fn prefix_flags(&self) -> PrefixInfoFlags {
        PrefixInfoFlags::from_bits_truncate(self.buffer[field::FLAGS])
    }

    /// Return the valid lifetime of the prefix.
    #[inline]
    pub fn valid_lifetime(&self) -> Duration {
        Duration::from_secs(NetworkEndian::read_u32(&self.buffer[field::VALID_LT]))
    }

    /// Return the preferred lifetime of the prefix.
    #[inline]
    pub fn preferred_lifetime(&self) -> Duration {
        Duration::from_secs(NetworkEndian::read_u32(&self.buffer[field::PREF_LT]))
    }

    /// Return the prefix.
    #[inline]
    pub fn prefix(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.buffer[field::PREFIX].try_into().unwrap())
    }
}

impl<'a> NdiscOption<'a> {
    /// Return the option data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let len = self.data_len();
        &self.buffer[field::DATA(len)]
    }
}

/// Core setter methods relevant to any type of NDISC option.
impl<'a> NdiscOption<'a> {
    /// Set the option type.
    #[inline]
    pub fn set_option_type(&mut self, value: Type) {
        self.buffer[field::TYPE] = value.into();
    }

    /// Set the option data length.
    #[inline]
    pub fn set_data_len(&mut self, value: u8) {
        self.buffer[field::LENGTH] = value;
    }
}

/// Setter methods only relevant for Source/Target Link-layer Address options.
impl<'a> NdiscOption<'a> {
    /// Set the Source/Target Link-layer Address.
    #[inline]
    pub fn set_link_layer_addr(&mut self, addr: RawHardwareAddress) {
        self.buffer[2..2 + addr.len()].copy_from_slice(addr.as_bytes())
    }
}

/// Setter methods only relevant for the MTU option.
impl<'a> NdiscOption<'a> {
    /// Clear the reserved area of the MTU option.
    #[inline]
    pub fn clear_mtu_reserved(&mut self) {
        NetworkEndian::write_u16(&mut self.buffer[field::MTU_RESERVED], 0);
    }

    /// Set the MTU value.
    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::MTU], value);
    }
}

/// Setter methods only relevant for the Prefix Information option.
impl<'a> NdiscOption<'a> {
    /// Set the prefix length.
    #[inline]
    pub fn set_prefix_len(&mut self, value: u8) {
        self.buffer[field::PREFIX_LEN] = value;
    }

    /// Set the prefix information flags.
    #[inline]
    pub fn set_prefix_flags(&mut self, flags: PrefixInfoFlags) {
        self.buffer[field::FLAGS] = flags.bits();
    }

    /// Set the valid lifetime of the prefix.
    #[inline]
    pub fn set_valid_lifetime(&mut self, time: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::VALID_LT], time.as_secs());
    }

    /// Set the preferred lifetime of the prefix.
    #[inline]
    pub fn set_preferred_lifetime(&mut self, time: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::PREF_LT], time.as_secs());
    }

    /// Clear the reserved bits.
    #[inline]
    pub fn clear_prefix_reserved(&mut self) {
        NetworkEndian::write_u32(&mut self.buffer[field::PREF_RESERVED], 0);
    }

    /// Set the prefix.
    #[inline]
    pub fn set_prefix(&mut self, addr: Ipv6Addr) {
        self.buffer[field::PREFIX].copy_from_slice(&addr.octets());
    }
}

/// Setter methods only relevant for the Redirected Header option.
impl<'a> NdiscOption<'a> {
    /// Clear the reserved bits.
    #[inline]
    pub fn clear_redirected_reserved(&mut self) {
        self.buffer[field::REDIRECTED_RESERVED].fill_with(|| 0);
    }
}

impl<'a> NdiscOption<'a> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        &mut self.buffer[field::DATA(len)]
    }
}

#[cfg(test)]
mod test {
    use super::Malformed;
    use super::{NdiscOption, PrefixInfoFlags, Type};
    use crate::time::Duration;
    use crate::wire::Ipv6Addr;

    static PREFIX_OPT_BYTES: [u8; 32] = [
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PREFIX_OPT_BYTES;
        let opt = NdiscOption::new_unchecked(&mut bytes[..]);
        assert_eq!(opt.option_type(), Type::PrefixInformation);
        assert_eq!(opt.data_len(), 4);
        assert_eq!(opt.prefix_len(), 64);
        assert_eq!(opt.prefix_flags(), PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        assert_eq!(opt.valid_lifetime(), Duration::from_secs(900));
        assert_eq!(opt.preferred_lifetime(), Duration::from_secs(1000));
        assert_eq!(opt.prefix(), Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_construct() {
        // Into a buffer full of stale bytes: every byte of the option is written.
        let mut bytes = [0x2a; 32];
        let mut opt = NdiscOption::new_unchecked(&mut bytes[..]);
        opt.set_option_type(Type::PrefixInformation);
        opt.set_data_len(4);
        opt.set_prefix_len(64);
        opt.set_prefix_flags(PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        opt.set_valid_lifetime(Duration::from_secs(900));
        opt.set_preferred_lifetime(Duration::from_secs(1000));
        opt.clear_prefix_reserved();
        opt.set_prefix(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(&bytes[..], &PREFIX_OPT_BYTES[..]);
    }

    #[test]
    fn test_mtu() {
        let mut bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc];
        let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(opt.option_type(), Type::Mtu);
        assert_eq!(opt.data_len(), 1);
        assert_eq!(opt.mtu(), 1500);

        let mut built = [0x2a; 8];
        let mut opt = NdiscOption::new_unchecked(&mut built[..]);
        opt.set_option_type(Type::Mtu);
        opt.set_data_len(1);
        opt.clear_mtu_reserved();
        opt.set_mtu(1500);
        assert_eq!(built, bytes);
    }

    /// An 8-byte link-layer address option (data length 1) carries an Ethernet
    /// address, as a source or a target option alike.
    #[test]
    #[cfg(feature = "medium-ethernet")]
    fn test_link_layer_addr_ethernet() {
        use crate::iface::Medium;
        use crate::wire::{EthernetAddress, HardwareAddress};
        let mut bytes = [0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34];
        let addr = HardwareAddress::Ethernet(EthernetAddress([0x54, 0x52, 0x00, 0x12, 0x23, 0x34]));
        {
            let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(opt.option_type(), Type::SourceLinkLayerAddr);
            assert_eq!(opt.data_len(), 1);
            assert_eq!(opt.link_layer_addr().parse(Medium::Ethernet), Ok(addr));
            #[cfg(feature = "medium-ieee802154")]
            assert!(opt.link_layer_addr().parse(Medium::Ieee802154).is_err());
        }
        bytes[0] = 0x02;
        {
            let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(opt.option_type(), Type::TargetLinkLayerAddr);
            assert_eq!(opt.link_layer_addr().parse(Medium::Ethernet), Ok(addr));
        }

        // The same option, built with the setters.
        let mut built = [0x2a; 8];
        let mut opt = NdiscOption::new_unchecked(&mut built[..]);
        opt.set_option_type(Type::TargetLinkLayerAddr);
        opt.set_data_len(1);
        opt.set_link_layer_addr(addr.into());
        assert_eq!(built, bytes);
    }

    /// A 16-byte link-layer address option (data length 2) carries an
    /// extended 802.15.4 address, padded with zeros.
    #[test]
    #[cfg(feature = "medium-ieee802154")]
    fn test_link_layer_addr_ieee802154() {
        use crate::iface::Medium;
        use crate::wire::{HardwareAddress, Ieee802154Address};
        let mut bytes = [
            0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(opt.option_type(), Type::SourceLinkLayerAddr);
        assert_eq!(opt.data_len(), 2);
        let addr = Ieee802154Address::Extended([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            opt.link_layer_addr().parse(Medium::Ieee802154),
            Ok(HardwareAddress::Ieee802154(addr))
        );
        #[cfg(feature = "medium-ethernet")]
        assert!(opt.link_layer_addr().parse(Medium::Ethernet).is_err());
    }

    #[test]
    fn test_short_packet() {
        assert_eq!(NdiscOption::new_checked(&mut [0x00, 0x00]), Err(Malformed));
        let mut bytes = [0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(NdiscOption::new_checked(&mut bytes), Err(Malformed));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PrefixInfoFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "PrefixInfoFlags({=u8:#010b})", self.bits());
    }
}
