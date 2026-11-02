use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::time::Duration;
use crate::wire::Ipv4Addr;
use crate::wire::ip::checksum;

open_enum! {
    /// Internet Group Management Protocol v1/v2 message version/type.
    pub enum Message(u8) {
        /// Membership Query
        MembershipQuery = 0x11,
        /// Version 2 Membership Report
        MembershipReportV2 = 0x16,
        /// Leave Group
        LeaveGroup = 0x17,
        /// Version 1 Membership Report
        MembershipReportV1 = 0x12
    }
}

/// Type of IGMP membership report version
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum IgmpVersion {
    /// IGMPv1
    Version1,
    /// IGMPv2
    Version2,
}

/// A read/write wrapper around an Internet Group Management Protocol v1/v2 packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const TYPE: usize = 0;
    pub const MAX_RESP_CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;
    pub const GROUP_ADDRESS: Field = 4..8;
}

/// The length of an IGMPv1/v2 packet. Always 8 bytes.
pub const BUFFER_LEN: usize = field::GROUP_ADDRESS.end;

/// Internet Group Management Protocol v1/v2 defined in [RFC 2236].
///
/// [RFC 2236]: https://tools.ietf.org/html/rfc2236
impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with IGMPv2 packet structure.
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
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::GROUP_ADDRESS.end {
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

    /// Return the maximum response time, using the encoding specified in
    /// [RFC 3376]: 4.1.1. Max Resp Code.
    ///
    /// [RFC 3376]: https://tools.ietf.org/html/rfc3376
    #[inline]
    pub fn max_resp_code(&self) -> u8 {
        self.buffer[field::MAX_RESP_CODE]
    }

    /// Return the maximum response time, decoded from the max resp code field.
    #[inline]
    pub fn max_resp_time(&self) -> Duration {
        max_resp_code_to_duration(self.max_resp_code())
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Return the group address field.
    #[inline]
    pub fn group_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.buffer[field::GROUP_ADDRESS].try_into().unwrap())
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

    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.buffer[field::TYPE] = value.into()
    }

    /// Set the maximum response time, using the encoding specified in
    /// [RFC 3376]: 4.1.1. Max Resp Code.
    ///
    /// [RFC 3376]: https://tools.ietf.org/html/rfc3376
    #[inline]
    pub fn set_max_resp_code(&mut self, value: u8) {
        self.buffer[field::MAX_RESP_CODE] = value;
    }

    /// Set the maximum response time, encoding it into the max resp code field.
    #[inline]
    pub fn set_max_resp_time(&mut self, value: Duration) {
        self.set_max_resp_code(duration_to_max_resp_code(value))
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the group address field
    #[inline]
    pub fn set_group_address(&mut self, addr: Ipv4Addr) {
        self.buffer[field::GROUP_ADDRESS].copy_from_slice(&addr.octets());
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(self.buffer);
        self.set_checksum(checksum)
    }
}

fn max_resp_code_to_duration(value: u8) -> Duration {
    let value: u32 = value.into();
    let decisecs = if value < 128 {
        value
    } else {
        let mant = value & 0xF;
        let exp = (value >> 4) & 0x7;
        (mant | 0x10) << (exp + 3)
    };
    Duration::from_millis(decisecs * 100)
}

const fn duration_to_max_resp_code(duration: Duration) -> u8 {
    let decisecs = duration.as_millis() / 100;
    if decisecs < 128 {
        decisecs as u8
    } else if decisecs < 31744 {
        let mut mant = decisecs >> 3;
        let mut exp = 0u8;
        while mant > 0x1F && exp < 0x8 {
            mant >>= 1;
            exp += 1;
        }
        0x80 | (exp << 4) | (mant as u8 & 0xF)
    } else {
        0xFF
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static LEAVE_PACKET_BYTES: [u8; 8] = [0x17, 0x00, 0x02, 0x69, 0xe0, 0x00, 0x06, 0x96];
    static REPORT_PACKET_BYTES: [u8; 8] = [0x16, 0x00, 0x08, 0xda, 0xe1, 0x00, 0x00, 0x25];

    #[test]
    fn test_leave_group_deconstruct() {
        let mut bytes = LEAVE_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::LeaveGroup);
        assert_eq!(packet.max_resp_code(), 0);
        assert_eq!(packet.checksum(), 0x269);
        assert_eq!(packet.group_addr(), Ipv4Addr::from_octets([224, 0, 6, 150]));
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_report_deconstruct() {
        let mut bytes = REPORT_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::MembershipReportV2);
        assert_eq!(packet.max_resp_code(), 0);
        assert_eq!(packet.checksum(), 0x08da);
        assert_eq!(packet.group_addr(), Ipv4Addr::from_octets([225, 0, 0, 37]));
        assert!(packet.verify_checksum());
    }

    #[test]
    fn test_leave_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::LeaveGroup);
        packet.set_max_resp_code(0);
        packet.set_group_address(Ipv4Addr::from_octets([224, 0, 6, 150]));
        packet.fill_checksum();
        assert_eq!(&bytes[..], &LEAVE_PACKET_BYTES[..]);
    }

    #[test]
    fn test_report_construct() {
        let mut bytes = vec![0xa5; 8];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::MembershipReportV2);
        packet.set_max_resp_code(0);
        packet.set_group_address(Ipv4Addr::from_octets([225, 0, 0, 37]));
        packet.fill_checksum();
        assert_eq!(&bytes[..], &REPORT_PACKET_BYTES[..]);
    }

    #[test]
    fn max_resp_time_to_duration_and_back() {
        for i in 0..256usize {
            let time1 = i as u8;
            let duration = max_resp_code_to_duration(time1);
            let time2 = duration_to_max_resp_code(duration);
            assert!(time1 == time2);
        }
    }

    #[test]
    fn duration_to_max_resp_time_max() {
        for duration in 31744..65536 {
            let time = duration_to_max_resp_code(Duration::from_millis(duration * 100));
            assert_eq!(time, 0xFF);
        }
    }
}
