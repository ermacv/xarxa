use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::wire::ip::checksum;

open_enum! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Echo reply
        EchoReply      =  0,
        /// Destination unreachable
        DstUnreachable =  3,
        /// Source quench (deprecated)
        SourceQuench   =  4,
        /// Message redirect
        Redirect       =  5,
        /// Echo request
        EchoRequest    =  8,
        /// Router advertisement
        RouterAdvert   =  9,
        /// Router solicitation
        RouterSolicit  = 10,
        /// Time exceeded
        TimeExceeded   = 11,
        /// Parameter problem
        ParamProblem   = 12,
        /// Timestamp
        Timestamp      = 13,
        /// Timestamp reply
        TimestampReply = 14
    }
}

impl Message {
    /// Whether this message type is an error message.
    ///
    /// RFC 1122 §3.2.2 lists the error message types. Everything else is a query or
    /// informational message. Malformed messages must never be sent in response to
    /// another error message.
    pub fn is_error(&self) -> bool {
        matches!(
            *self,
            Message::DstUnreachable
                | Message::SourceQuench
                | Message::Redirect
                | Message::TimeExceeded
                | Message::ParamProblem
        )
    }
}

open_enum! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// Destination network unreachable
        NetUnreachable   =  0,
        /// Destination host unreachable
        HostUnreachable  =  1,
        /// Destination protocol unreachable
        ProtoUnreachable =  2,
        /// Destination port unreachable
        PortUnreachable  =  3,
        /// Fragmentation required, and DF flag set
        FragRequired     =  4,
        /// Source route failed
        SrcRouteFailed   =  5,
        /// Destination network unknown
        DstNetUnknown    =  6,
        /// Destination host unknown
        DstHostUnknown   =  7,
        /// Source host isolated
        SrcHostIsolated  =  8,
        /// Network administratively prohibited
        NetProhibited    =  9,
        /// Host administratively prohibited
        HostProhibited   = 10,
        /// Network unreachable for ToS
        NetUnreachToS    = 11,
        /// Host unreachable for ToS
        HostUnreachToS   = 12,
        /// Communication administratively prohibited
        CommProhibited   = 13,
        /// Host precedence violation
        HostPrecedViol   = 14,
        /// Precedence cutoff in effect
        PrecedCutoff     = 15
    }
}

open_enum! {
    /// Internet protocol control message subtype for type "Redirect Message".
    pub enum Redirect(u8) {
        /// Redirect Datagram for the Network
        Net     = 0,
        /// Redirect Datagram for the Host
        Host    = 1,
        /// Redirect Datagram for the ToS & network
        NetToS  = 2,
        /// Redirect Datagram for the ToS & host
        HostToS = 3
    }
}

open_enum! {
    /// Internet protocol control message subtype for type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// TTL expired in transit
        TtlExpired  = 0,
        /// Fragment reassembly time exceeded
        FragExpired = 1
    }
}

open_enum! {
    /// Internet protocol control message subtype for type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Pointer indicates the error
        AtPointer     = 0,
        /// Missing a required option
        MissingOption = 1,
        /// Bad length
        BadLength     = 2
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 4 packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;

    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;
}

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with ICMPv4 packet structure.
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
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::HEADER_END {
            Err(Malformed)
        } else {
            Ok(())
        }
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        Message::from(self.buffer[field::TYPE])
    }

    /// Return the message code field.
    #[inline]
    pub fn msg_code(&self) -> u8 {
        self.buffer[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_SEQNO])
    }

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply => field::ECHO_SEQNO.end,
            Message::DstUnreachable => field::UNUSED.end,
            _ => field::UNUSED.end, // make a conservative assumption
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        checksum::data(self.buffer) == !0
    }

    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buffer[self.header_len()..]
    }

    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.buffer[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        self.buffer[field::CODE] = value
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_SEQNO], value)
    }

    /// Zero the unused field of an error message (destination unreachable, time
    /// exceeded) header.
    #[inline]
    pub fn clear_unused(&mut self) {
        NetworkEndian::write_u32(&mut self.buffer[field::UNUSED], 0);
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(self.buffer);
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        &mut self.buffer[range]
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

    static ECHO_PACKET_BYTES: [u8; 12] = [0x08, 0x00, 0x8e, 0xfe, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff];

    static ECHO_DATA_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_echo_deconstruct() {
        let mut bytes = ECHO_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes);
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x8efe);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.data(), &ECHO_DATA_BYTES[..]);
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = [0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.data_mut().copy_from_slice(&ECHO_DATA_BYTES[..]);
        packet.fill_checksum();
        assert_eq!(bytes, ECHO_PACKET_BYTES);
    }

    #[test]
    fn test_check_len() {
        let mut bytes = [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(Packet::new_checked(&mut []), Err(Malformed));
        assert_eq!(Packet::new_checked(&mut bytes[..4]), Err(Malformed));
        assert!(Packet::new_checked(&mut bytes[..]).is_ok());
    }
}
