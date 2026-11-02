use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use crate::error::Malformed;

open_enum! {
    /// Ethernet protocol type.
    pub enum EtherType(u16) {
        Ipv4 = 0x0800,
        Arp  = 0x0806,
        Ipv6 = 0x86DD
    }
}

/// A six-octet Ethernet II address.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; 6]);

impl Address {
    /// The length of an Ethernet address, in octets.
    pub const SIZE: usize = 6;

    /// The broadcast address.
    pub const BROADCAST: Address = Address([0xff; 6]);

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Convert the address to a modified EUI-64 interface identifier (RFC 4291).
    pub const fn as_eui_64(&self) -> [u8; 8] {
        let m = self.0;
        [m[0] ^ 0x02, m[1], m[2], 0xFF, 0xFE, m[3], m[4], m[5]]
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

/// A read/write wrapper around an Ethernet II frame buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct Frame<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const DESTINATION: Field = 0..6;
    pub const SOURCE: Field = 6..12;
    pub const ETHERTYPE: Field = 12..14;
    pub const PAYLOAD: Rest = 14..;
}

/// The Ethernet header length
pub const HEADER_LEN: usize = field::PAYLOAD.start;

impl<'a> Frame<'a> {
    /// Imbue a raw octet buffer with Ethernet frame structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Frame<'a> {
        Frame { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Frame<'a>, Malformed> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < HEADER_LEN { Err(Malformed) } else { Ok(()) }
    }

    /// Return the length of a frame header.
    pub const fn header_len() -> usize {
        HEADER_LEN
    }

    /// Return the length of a buffer required to hold a packet with the payload
    /// of a given length.
    pub const fn buffer_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        Address::from_bytes(&self.buffer[field::DESTINATION])
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        Address::from_bytes(&self.buffer[field::SOURCE])
    }

    /// Return the EtherType field, without checking for 802.1Q.
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        let raw = NetworkEndian::read_u16(&self.buffer[field::ETHERTYPE]);
        EtherType::from(raw)
    }

    /// Return a pointer to the payload, without checking for 802.1Q.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buffer[field::PAYLOAD]
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        self.buffer[field::DESTINATION].copy_from_slice(value.as_bytes())
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        self.buffer[field::SOURCE].copy_from_slice(value.as_bytes())
    }

    /// Set the EtherType field.
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.buffer[field::ETHERTYPE], value.into())
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[field::PAYLOAD]
    }
}

impl<'a> AsRef<[u8]> for Frame<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

impl<'a> fmt::Display for Frame<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EthernetII src={} dst={} type={}",
            self.src_addr(),
            self.dst_addr(),
            self.ethertype()
        )
    }
}

#[cfg(test)]
mod test {
    // Tests that are valid with any combination of
    // "ipv4"/"ipv6" features.
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
        assert!(Address::BROADCAST.is_multicast());
        assert!(Address::BROADCAST.is_local());
    }

    /// The modified EUI-64 of a MAC: the U/L bit flipped, `ff:fe` in the middle.
    #[test]
    fn test_as_eui_64() {
        assert_eq!(
            Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).as_eui_64(),
            [0xa8, 0xbb, 0xcc, 0xff, 0xfe, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            Address([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).as_eui_64(),
            [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01]
        );
    }
}

#[cfg(test)]
mod test_ipv4 {
    // Tests that are valid only with "ipv4"
    use super::*;

    static FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x08, 0x00, 0xaa, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 50] = [
        0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_deconstruct() {
        let mut bytes = FRAME_BYTES;
        let frame = Frame::new_unchecked(&mut bytes[..]);
        assert_eq!(frame.dst_addr(), Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ethertype(), EtherType::Ipv4);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0xa5; 64];
        let mut frame = Frame::new_unchecked(&mut bytes[..]);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv4);
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&bytes[..], &FRAME_BYTES[..]);
    }
}

#[cfg(test)]
mod test_ipv6 {
    // Tests that are valid only with "ipv6"
    use super::*;

    static FRAME_BYTES: [u8; 54] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    static PAYLOAD_BYTES: [u8; 40] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let mut bytes = FRAME_BYTES;
        let frame = Frame::new_unchecked(&mut bytes[..]);
        assert_eq!(frame.dst_addr(), Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(frame.src_addr(), Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        assert_eq!(frame.ethertype(), EtherType::Ipv6);
        assert_eq!(frame.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0xa5; 54];
        let mut frame = Frame::new_unchecked(&mut bytes[..]);
        frame.set_dst_addr(Address([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        frame.set_src_addr(Address([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        frame.set_ethertype(EtherType::Ipv6);
        assert_eq!(PAYLOAD_BYTES.len(), frame.payload().len());
        frame.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(&bytes[..], &FRAME_BYTES[..]);
    }
}
