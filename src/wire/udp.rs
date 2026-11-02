use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::wire::ip::checksum;
use crate::wire::{IpAddr, IpProtocol};

/// A read/write wrapper around an User Datagram Protocol packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const LENGTH: Field = 4..6;
    pub const CHECKSUM: Field = 6..8;
}

pub const HEADER_LEN: usize = field::CHECKSUM.end;

#[allow(clippy::len_without_is_empty)]
impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with UDP packet structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>, Malformed> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// The result of this check is invalidated by calling [set_len].
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short, or the length field is smaller
    ///   than the header length or larger than the buffer.
    ///
    /// [set_len]: #method.set_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        let buffer_len = self.buffer.len();
        if buffer_len < HEADER_LEN {
            return Err(Malformed);
        }
        let field_len = self.len() as usize;
        if buffer_len < field_len || field_len < HEADER_LEN {
            return Err(Malformed);
        }
        Ok(())
    }

    /// Return the source port field.
    #[inline]
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::SRC_PORT])
    }

    /// Return the destination port field.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::DST_PORT])
    }

    /// Return the length field.
    #[inline]
    pub fn len(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::LENGTH])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Validate the packet checksum.
    ///
    /// An all-zeroes checksum field means the transmitter didn't generate one.
    /// That is accepted on UDP-over-IPv4, and rejected on UDP-over-IPv6, which
    /// requires checksums (RFC 8200 § 8.1).
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self, src_addr: &IpAddr, dst_addr: &IpAddr) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        if self.checksum() == 0 {
            #[cfg(feature = "ipv4")]
            return matches!(src_addr, IpAddr::V4(_));
            #[cfg(not(feature = "ipv4"))]
            return false;
        }

        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, self.len() as u32),
            checksum::data(&self.buffer[..self.len() as usize]),
        ]) == !0
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buffer[HEADER_LEN..self.len() as usize]
    }

    /// Set the source port field.
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::SRC_PORT], value)
    }

    /// Set the destination port field.
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::DST_PORT], value)
    }

    /// Set the length field.
    #[inline]
    pub fn set_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::LENGTH], value)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Compute and fill in the checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr) {
        self.set_checksum(0);
        let checksum = !checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, self.len() as u32),
            checksum::data(&self.buffer[..self.len() as usize]),
        ]);
        // A UDP checksum of 0 means no checksum. If the checksum really is zero, use
        // all-ones instead, which is arithmetically identical under RFC 1071.
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum })
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = self.len() as usize;
        &mut self.buffer[HEADER_LEN..len]
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(all(test, feature = "ipv4", feature = "ipv6"))]
mod test {
    use super::*;
    use crate::wire::{Ipv4Addr, Ipv6Addr};

    const SRC_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const DST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    static PACKET_BYTES: [u8; 12] = [0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff];

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PACKET_BYTES;
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 53);
        assert_eq!(packet.len(), 12);
        assert_eq!(packet.checksum(), 0x124d);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR, &DST_ADDR));
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(53);
        packet.set_len(12);
        packet.set_checksum(0xffff);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR, &DST_ADDR);
        assert_eq!(&bytes[..], &PACKET_BYTES[..]);
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_len(4);
        assert_eq!(packet.check_len(), Err(Malformed));
    }

    #[test]
    fn test_zero_checksum() {
        let mut bytes = vec![0; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(31881);
        packet.set_len(8);
        packet.fill_checksum(&SRC_ADDR, &DST_ADDR);
        assert_eq!(packet.checksum(), 0xffff);
    }

    #[test]
    fn test_no_checksum() {
        let mut bytes = vec![0; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(1);
        packet.set_dst_port(31881);
        packet.set_len(8);
        packet.set_checksum(0);
        // Omitted checksum is valid on IPv4...
        assert!(packet.verify_checksum(&SRC_ADDR, &DST_ADDR));
        // ...but not on IPv6.
        let src_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!packet.verify_checksum(&src_v6, &dst_v6));
    }
}
