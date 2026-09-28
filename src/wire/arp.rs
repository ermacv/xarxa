use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;

pub use super::EthernetProtocol as Protocol;

open_enum! {
    /// ARP hardware type.
    pub enum Hardware(u16) {
        Ethernet = 1
    }
}

open_enum! {
    /// ARP operation type.
    pub enum Operation(u16) {
        Request = 1,
        Reply = 2
    }
}

/// A read/write wrapper around an Address Resolution Protocol packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const HTYPE: Field = 0..2;
    pub const PTYPE: Field = 2..4;
    pub const HLEN: usize = 4;
    pub const PLEN: usize = 5;
    pub const OPER: Field = 6..8;

    #[inline]
    pub const fn SHA(hardware_len: u8, _protocol_len: u8) -> Field {
        let start = OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn SPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    pub const fn THA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    pub const fn TPA(hardware_len: u8, protocol_len: u8) -> Field {
        let start = THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }
}

/// The length of an Ethernet+IPv4 Address Resolution Protocol packet.
pub const BUFFER_LEN: usize = field::TPA(6, 4).end;

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with ARP packet structure.
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
    /// The result of this check is invalidated by calling [set_hardware_len] or
    /// [set_protocol_len].
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    ///
    /// [set_hardware_len]: #method.set_hardware_len
    /// [set_protocol_len]: #method.set_protocol_len
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::OPER.end {
            Err(Malformed)
        } else if len < field::TPA(self.hardware_len(), self.protocol_len()).end {
            Err(Malformed)
        } else {
            Ok(())
        }
    }

    /// Return the hardware type field.
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        let raw = NetworkEndian::read_u16(&self.buffer[field::HTYPE]);
        Hardware::from(raw)
    }

    /// Return the protocol type field.
    #[inline]
    pub fn protocol_type(&self) -> Protocol {
        let raw = NetworkEndian::read_u16(&self.buffer[field::PTYPE]);
        Protocol::from(raw)
    }

    /// Return the hardware length field.
    #[inline]
    pub fn hardware_len(&self) -> u8 {
        self.buffer[field::HLEN]
    }

    /// Return the protocol length field.
    #[inline]
    pub fn protocol_len(&self) -> u8 {
        self.buffer[field::PLEN]
    }

    /// Return the operation field.
    #[inline]
    pub fn operation(&self) -> Operation {
        let raw = NetworkEndian::read_u16(&self.buffer[field::OPER]);
        Operation::from(raw)
    }

    /// Return the source hardware address field.
    pub fn source_hardware_addr(&self) -> &[u8] {
        &self.buffer[field::SHA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the source protocol address field.
    pub fn source_protocol_addr(&self) -> &[u8] {
        &self.buffer[field::SPA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the target hardware address field.
    pub fn target_hardware_addr(&self) -> &[u8] {
        &self.buffer[field::THA(self.hardware_len(), self.protocol_len())]
    }

    /// Return the target protocol address field.
    pub fn target_protocol_addr(&self) -> &[u8] {
        &self.buffer[field::TPA(self.hardware_len(), self.protocol_len())]
    }

    /// Set the hardware type field.
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        NetworkEndian::write_u16(&mut self.buffer[field::HTYPE], value.into())
    }

    /// Set the protocol type field.
    #[inline]
    pub fn set_protocol_type(&mut self, value: Protocol) {
        NetworkEndian::write_u16(&mut self.buffer[field::PTYPE], value.into())
    }

    /// Set the hardware length field.
    #[inline]
    pub fn set_hardware_len(&mut self, value: u8) {
        self.buffer[field::HLEN] = value
    }

    /// Set the protocol length field.
    #[inline]
    pub fn set_protocol_len(&mut self, value: u8) {
        self.buffer[field::PLEN] = value
    }

    /// Set the operation field.
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        NetworkEndian::write_u16(&mut self.buffer[field::OPER], value.into())
    }

    /// Set the source hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_source_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.buffer[field::SHA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the source protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_source_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.buffer[field::SPA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target hardware address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.hardware_len()` long.
    pub fn set_target_hardware_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.buffer[field::THA(hardware_len, protocol_len)].copy_from_slice(value)
    }

    /// Set the target protocol address field.
    ///
    /// # Panics
    /// The function panics if `value` is not `self.protocol_len()` long.
    pub fn set_target_protocol_addr(&mut self, value: &[u8]) {
        let (hardware_len, protocol_len) = (self.hardware_len(), self.protocol_len());
        self.buffer[field::TPA(hardware_len, protocol_len)].copy_from_slice(value)
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static PACKET_BYTES: [u8; 28] = [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
    ];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.protocol_type(), Protocol::Ipv4);
        assert_eq!(packet.hardware_len(), 6);
        assert_eq!(packet.protocol_len(), 4);
        assert_eq!(packet.operation(), Operation::Request);
        assert_eq!(packet.source_hardware_addr(), &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        assert_eq!(packet.source_protocol_addr(), &[0x21, 0x22, 0x23, 0x24]);
        assert_eq!(packet.target_hardware_addr(), &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        assert_eq!(packet.target_protocol_addr(), &[0x41, 0x42, 0x43, 0x44]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0xa5; 28];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_hardware_type(Hardware::Ethernet);
        packet.set_protocol_type(Protocol::Ipv4);
        packet.set_hardware_len(6);
        packet.set_protocol_len(4);
        packet.set_operation(Operation::Request);
        packet.set_source_hardware_addr(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16]);
        packet.set_source_protocol_addr(&[0x21, 0x22, 0x23, 0x24]);
        packet.set_target_hardware_addr(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
        packet.set_target_protocol_addr(&[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(&bytes[..], &PACKET_BYTES[..]);
    }
}
