use byteorder::{ByteOrder, NetworkEndian};
use core::{cmp, fmt, ops};

use crate::error::Malformed;
use crate::wire::ip::checksum;
use crate::wire::{IpAddr, IpProtocol};

/// A TCP sequence number.
///
/// A sequence number is a monotonically advancing integer modulo 2<sup>32</sup>.
/// Sequence numbers do not have a discontiguity when compared pairwise across a signed overflow.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct SeqNumber(pub i32);

impl SeqNumber {
    pub fn max(self, rhs: Self) -> Self {
        if self > rhs { self } else { rhs }
    }

    pub fn min(self, rhs: Self) -> Self {
        if self < rhs { self } else { rhs }
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0 as u32)
    }
}

impl ops::Add<usize> for SeqNumber {
    type Output = SeqNumber;

    fn add(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to add to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_add(rhs as i32))
    }
}

impl ops::Sub<usize> for SeqNumber {
    type Output = SeqNumber;

    fn sub(self, rhs: usize) -> SeqNumber {
        if rhs > i32::MAX as usize {
            panic!("attempt to subtract to sequence number with unsigned overflow")
        }
        SeqNumber(self.0.wrapping_sub(rhs as i32))
    }
}

impl ops::AddAssign<usize> for SeqNumber {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl ops::Sub for SeqNumber {
    type Output = usize;

    fn sub(self, rhs: SeqNumber) -> usize {
        let result = self.0.wrapping_sub(rhs.0);
        if result < 0 {
            panic!("attempt to subtract sequence numbers with underflow")
        }
        result as usize
    }
}

impl cmp::PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<cmp::Ordering> {
        self.0.wrapping_sub(other.0).partial_cmp(&0)
    }
}

/// A read/write wrapper around a Transmission Control Protocol packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    pub const SRC_PORT: Field = 0..2;
    pub const DST_PORT: Field = 2..4;
    pub const SEQ_NUM: Field = 4..8;
    pub const ACK_NUM: Field = 8..12;
    pub const FLAGS: Field = 12..14;
    pub const WIN_SIZE: Field = 14..16;
    pub const CHECKSUM: Field = 16..18;
    pub const URGENT: Field = 18..20;

    pub const fn OPTIONS(length: u8) -> Field {
        URGENT.end..(length as usize)
    }

    pub const FLG_FIN: u16 = 0x001;
    pub const FLG_SYN: u16 = 0x002;
    pub const FLG_RST: u16 = 0x004;
    pub const FLG_PSH: u16 = 0x008;
    pub const FLG_ACK: u16 = 0x010;
    pub const FLG_URG: u16 = 0x020;
    pub const FLG_ECE: u16 = 0x040;
    pub const FLG_CWR: u16 = 0x080;
    pub const FLG_NS: u16 = 0x100;

    pub const OPT_END: u8 = 0x00;
    pub const OPT_NOP: u8 = 0x01;
    pub const OPT_MSS: u8 = 0x02;
    pub const OPT_WS: u8 = 0x03;
    pub const OPT_SACKPERM: u8 = 0x04;
    pub const OPT_SACKRNG: u8 = 0x05;
    #[cfg(feature = "tcp-timestamps")]
    pub const OPT_TSTAMP: u8 = 0x08;
}

pub const HEADER_LEN: usize = field::URGENT.end;

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with TCP packet structure.
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
    /// - `Malformed`: if the buffer is too short, or the header length field is
    ///   smaller than the minimal header length.
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::URGENT.end {
            Err(Malformed)
        } else {
            let header_len = self.header_len() as usize;
            if len < header_len || header_len < field::URGENT.end {
                Err(Malformed)
            } else {
                Ok(())
            }
        }
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

    /// Return the sequence number field.
    #[inline]
    pub fn seq_number(&self) -> SeqNumber {
        SeqNumber(NetworkEndian::read_i32(&self.buffer[field::SEQ_NUM]))
    }

    /// Return the acknowledgement number field.
    #[inline]
    pub fn ack_number(&self) -> SeqNumber {
        SeqNumber(NetworkEndian::read_i32(&self.buffer[field::ACK_NUM]))
    }

    /// Return the FIN flag.
    #[inline]
    pub fn fin(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_FIN != 0
    }

    /// Return the SYN flag.
    #[inline]
    pub fn syn(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_SYN != 0
    }

    /// Return the RST flag.
    #[inline]
    pub fn rst(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_RST != 0
    }

    /// Return the PSH flag.
    #[inline]
    pub fn psh(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_PSH != 0
    }

    /// Return the ACK flag.
    #[inline]
    pub fn ack(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_ACK != 0
    }

    /// Return the URG flag.
    #[inline]
    pub fn urg(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_URG != 0
    }

    /// Return the ECE flag.
    #[inline]
    pub fn ece(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_ECE != 0
    }

    /// Return the CWR flag.
    #[inline]
    pub fn cwr(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_CWR != 0
    }

    /// Return the NS flag.
    #[inline]
    pub fn ns(&self) -> bool {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        raw & field::FLG_NS != 0
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        ((raw >> 12) * 4) as u8
    }

    /// Return the window size field.
    #[inline]
    pub fn window_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::WIN_SIZE])
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Return the urgent pointer field.
    #[inline]
    pub fn urgent_at(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::URGENT])
    }

    /// Validate the packet checksum.
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

        let data = &self.buffer[..];
        checksum::combine(&[
            checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
            checksum::data(data),
        ]) == !0
    }

    /// Return a pointer to the options.
    #[inline]
    pub fn options(&self) -> &[u8] {
        let header_len = self.header_len();
        &self.buffer[field::OPTIONS(header_len)]
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        &self.buffer[header_len..]
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

    /// Set the sequence number field.
    #[inline]
    pub fn set_seq_number(&mut self, value: SeqNumber) {
        NetworkEndian::write_i32(&mut self.buffer[field::SEQ_NUM], value.0)
    }

    /// Set the acknowledgement number field.
    #[inline]
    pub fn set_ack_number(&mut self, value: SeqNumber) {
        NetworkEndian::write_i32(&mut self.buffer[field::ACK_NUM], value.0)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        let raw = raw & !0x0fff;
        NetworkEndian::write_u16(&mut self.buffer[field::FLAGS], raw)
    }

    fn set_flag(&mut self, flag: u16, value: bool) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        let raw = if value { raw | flag } else { raw & !flag };
        NetworkEndian::write_u16(&mut self.buffer[field::FLAGS], raw)
    }

    /// Set the FIN flag.
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        self.set_flag(field::FLG_FIN, value)
    }

    /// Set the SYN flag.
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        self.set_flag(field::FLG_SYN, value)
    }

    /// Set the RST flag.
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        self.set_flag(field::FLG_RST, value)
    }

    /// Set the PSH flag.
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        self.set_flag(field::FLG_PSH, value)
    }

    /// Set the ACK flag.
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        self.set_flag(field::FLG_ACK, value)
    }

    /// Set the URG flag.
    #[inline]
    pub fn set_urg(&mut self, value: bool) {
        self.set_flag(field::FLG_URG, value)
    }

    /// Set the ECE flag.
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        self.set_flag(field::FLG_ECE, value)
    }

    /// Set the CWR flag.
    #[inline]
    pub fn set_cwr(&mut self, value: bool) {
        self.set_flag(field::FLG_CWR, value)
    }

    /// Set the NS flag.
    #[inline]
    pub fn set_ns(&mut self, value: bool) {
        self.set_flag(field::FLG_NS, value)
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLAGS]);
        let raw = (raw & !0xf000) | ((value as u16) / 4) << 12;
        NetworkEndian::write_u16(&mut self.buffer[field::FLAGS], raw)
    }

    /// Set the window size field.
    #[inline]
    pub fn set_window_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::WIN_SIZE], value)
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the urgent pointer field.
    #[inline]
    pub fn set_urgent_at(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::URGENT], value)
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr) {
        self.set_checksum(0);
        let checksum = {
            let data = &self.buffer[..];
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Tcp, data.len() as u32),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the options.
    #[inline]
    pub fn options_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len();
        &mut self.buffer[field::OPTIONS(header_len)]
    }

    /// Return a mutable pointer to the payload data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        &mut self.buffer[header_len..]
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

/// A representation of a single TCP option.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption<'a> {
    EndOfList,
    NoOperation,
    MaxSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    SackRange([Option<(u32, u32)>; 3]),
    #[cfg(feature = "tcp-timestamps")]
    TimeStamp {
        tsval: u32,
        tsecr: u32,
    },
    Unknown {
        kind: u8,
        data: &'a [u8],
    },
}

impl<'a> TcpOption<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>), Malformed> {
        let (length, option);
        match *buffer.first().ok_or(Malformed)? {
            field::OPT_END => {
                length = 1;
                option = TcpOption::EndOfList;
            }
            field::OPT_NOP => {
                length = 1;
                option = TcpOption::NoOperation;
            }
            kind => {
                length = *buffer.get(1).ok_or(Malformed)? as usize;
                let data = buffer.get(2..length).ok_or(Malformed)?;
                match (kind, length) {
                    (field::OPT_END, _) | (field::OPT_NOP, _) => unreachable!(),
                    (field::OPT_MSS, 4) => option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data)),
                    (field::OPT_MSS, _) => return Err(Malformed),
                    (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
                    (field::OPT_WS, _) => return Err(Malformed),
                    (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
                    (field::OPT_SACKPERM, _) => return Err(Malformed),
                    (field::OPT_SACKRNG, n) => {
                        if n < 10 || (n - 2) % 8 != 0 {
                            return Err(Malformed);
                        }
                        if n > 26 {
                            // It's possible for a remote to send 4 SACK blocks, but extremely rare.
                            // Better to "lose" that 4th block and save the extra RAM and CPU
                            // cycles in the vastly more common case.
                            //
                            // RFC 2018: SACK option that specifies n blocks will have a length of
                            // 8*n+2 bytes, so the 40 bytes available for TCP options can specify a
                            // maximum of 4 blocks.  It is expected that SACK will often be used in
                            // conjunction with the Timestamp option used for RTTM [...] thus a
                            // maximum of 3 SACK blocks will be allowed in this case.
                            debug!("sACK with >3 blocks, truncating to 3");
                        }
                        let mut sack_ranges: [Option<(u32, u32)>; 3] = [None; 3];

                        // RFC 2018: Each contiguous block of data queued at the data receiver is
                        // defined in the SACK option by two 32-bit unsigned integers in network
                        // byte order[...]
                        sack_ranges.iter_mut().enumerate().for_each(|(i, nmut)| {
                            let left = i * 8;
                            *nmut = if left < data.len() {
                                let mid = left + 4;
                                let right = mid + 4;
                                let range_left = NetworkEndian::read_u32(&data[left..mid]);
                                let range_right = NetworkEndian::read_u32(&data[mid..right]);
                                Some((range_left, range_right))
                            } else {
                                None
                            };
                        });
                        option = TcpOption::SackRange(sack_ranges);
                    }
                    #[cfg(feature = "tcp-timestamps")]
                    (field::OPT_TSTAMP, 10) => {
                        let tsval = NetworkEndian::read_u32(&data[0..4]);
                        let tsecr = NetworkEndian::read_u32(&data[4..8]);
                        option = TcpOption::TimeStamp { tsval, tsecr };
                    }
                    (_, _) => option = TcpOption::Unknown { kind, data },
                }
            }
        }
        Ok((&buffer[length..], option))
    }

    pub fn buffer_len(&self) -> usize {
        match *self {
            TcpOption::EndOfList => 1,
            TcpOption::NoOperation => 1,
            TcpOption::MaxSegmentSize(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::SackRange(s) => s.iter().filter(|s| s.is_some()).count() * 8 + 2,
            #[cfg(feature = "tcp-timestamps")]
            TcpOption::TimeStamp { tsval: _, tsecr: _ } => 10,
            TcpOption::Unknown { data, .. } => 2 + data.len(),
        }
    }

    pub fn emit<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
        let length;
        match *self {
            TcpOption::EndOfList => {
                length = 1;
                // There may be padding space which also should be initialized.
                for p in buffer.iter_mut() {
                    *p = field::OPT_END;
                }
            }
            TcpOption::NoOperation => {
                length = 1;
                buffer[0] = field::OPT_NOP;
            }
            _ => {
                length = self.buffer_len();
                buffer[1] = length as u8;
                match self {
                    &TcpOption::EndOfList | &TcpOption::NoOperation => unreachable!(),
                    &TcpOption::MaxSegmentSize(value) => {
                        buffer[0] = field::OPT_MSS;
                        NetworkEndian::write_u16(&mut buffer[2..], value)
                    }
                    &TcpOption::WindowScale(value) => {
                        buffer[0] = field::OPT_WS;
                        buffer[2] = value;
                    }
                    &TcpOption::SackPermitted => {
                        buffer[0] = field::OPT_SACKPERM;
                    }
                    &TcpOption::SackRange(slice) => {
                        buffer[0] = field::OPT_SACKRNG;
                        slice.iter().filter(|s| s.is_some()).enumerate().for_each(|(i, s)| {
                            let (first, second) = *s.as_ref().unwrap();
                            let pos = i * 8 + 2;
                            NetworkEndian::write_u32(&mut buffer[pos..], first);
                            NetworkEndian::write_u32(&mut buffer[pos + 4..], second);
                        });
                    }
                    #[cfg(feature = "tcp-timestamps")]
                    &TcpOption::TimeStamp { tsval, tsecr } => {
                        buffer[0] = field::OPT_TSTAMP;
                        NetworkEndian::write_u32(&mut buffer[2..], tsval);
                        NetworkEndian::write_u32(&mut buffer[6..], tsecr);
                    }
                    &TcpOption::Unknown { kind, data: provided } => {
                        buffer[0] = kind;
                        buffer[2..].copy_from_slice(provided)
                    }
                }
            }
        }
        &mut buffer[length..]
    }
}

/// The possible control flags of a Transmission Control Protocol packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Control {
    None,
    Psh,
    Syn,
    Fin,
    Rst,
}

#[allow(clippy::len_without_is_empty)]
impl Control {
    /// Return the length of a control flag, in terms of sequence space.
    pub const fn len(self) -> usize {
        match self {
            Control::Syn | Control::Fin => 1,
            _ => 0,
        }
    }

    /// Turn the PSH flag into no flag, and keep the rest as-is.
    pub const fn quash_psh(self) -> Control {
        match self {
            Control::Psh => Control::None,
            _ => self,
        }
    }
}

#[cfg(all(test, feature = "ipv4"))]
mod test {
    use super::*;
    use crate::wire::Ipv4Addr;

    const SRC_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const DST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);

    static PACKET_BYTES: [u8; 28] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x60, 0x35, 0x01, 0x23, 0x01, 0xb6,
        0x02, 0x01, 0x03, 0x03, 0x0c, 0x01, 0xaa, 0x00, 0x00, 0xff,
    ];

    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.src_port(), 48896);
        assert_eq!(packet.dst_port(), 80);
        assert_eq!(packet.seq_number(), SeqNumber(0x01234567));
        assert_eq!(packet.ack_number(), SeqNumber(0x89abcdefu32 as i32));
        assert_eq!(packet.header_len(), 24);
        assert!(packet.fin());
        assert!(!packet.syn());
        assert!(packet.rst());
        assert!(!packet.psh());
        assert!(packet.ack());
        assert!(packet.urg());
        assert_eq!(packet.window_len(), 0x0123);
        assert_eq!(packet.urgent_at(), 0x0201);
        assert_eq!(packet.checksum(), 0x01b6);
        assert_eq!(packet.options(), &OPTION_BYTES[..]);
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
    }

    #[test]
    fn test_construct() {
        let mut bytes = vec![0xa5; PACKET_BYTES.len()];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_src_port(48896);
        packet.set_dst_port(80);
        packet.set_seq_number(SeqNumber(0x01234567));
        packet.set_ack_number(SeqNumber(0x89abcdefu32 as i32));
        packet.set_header_len(24);
        packet.clear_flags();
        packet.set_fin(true);
        packet.set_syn(false);
        packet.set_rst(true);
        packet.set_psh(false);
        packet.set_ack(true);
        packet.set_urg(true);
        packet.set_window_len(0x0123);
        packet.set_urgent_at(0x0201);
        packet.set_checksum(0xEEEE);
        packet.options_mut().copy_from_slice(&OPTION_BYTES[..]);
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        packet.fill_checksum(&SRC_ADDR.into(), &DST_ADDR.into());
        assert_eq!(&bytes[..], &PACKET_BYTES[..]);
    }

    #[test]
    fn test_truncated() {
        let mut bytes = PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..23]);
        assert_eq!(packet.check_len(), Err(Malformed));
    }

    #[test]
    fn test_impossible_len() {
        let mut bytes = vec![0; 20];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(10);
        assert_eq!(packet.check_len(), Err(Malformed));
    }

    macro_rules! assert_option_parses {
        ($opt:expr, $data:expr) => {{
            assert_eq!(TcpOption::parse($data), Ok((&[][..], $opt)));
            let buffer = &mut [0; 40][..$opt.buffer_len()];
            assert_eq!($opt.emit(buffer), &mut [] as &mut [u8]);
            assert_eq!(&*buffer, $data);
        }};
    }

    #[test]
    fn test_tcp_options() {
        assert_option_parses!(TcpOption::EndOfList, &[0x00]);
        assert_option_parses!(TcpOption::NoOperation, &[0x01]);
        assert_option_parses!(TcpOption::MaxSegmentSize(1500), &[0x02, 0x04, 0x05, 0xdc]);
        assert_option_parses!(TcpOption::WindowScale(12), &[0x03, 0x03, 0x0c]);
        assert_option_parses!(TcpOption::SackPermitted, &[0x4, 0x02]);
        assert_option_parses!(
            TcpOption::SackRange([Some((500, 1500)), None, None]),
            &[0x05, 0x0a, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x05, 0xdc]
        );
        assert_option_parses!(
            TcpOption::SackRange([Some((875, 1225)), Some((1500, 2500)), None]),
            &[
                0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9, 0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x09,
                0xc4
            ]
        );
        assert_option_parses!(
            TcpOption::SackRange([
                Some((875000, 1225000)),
                Some((1500000, 2500000)),
                Some((876543210, 876654320))
            ]),
            &[
                0x05, 0x1a, 0x00, 0x0d, 0x59, 0xf8, 0x00, 0x12, 0xb1, 0x28, 0x00, 0x16, 0xe3, 0x60, 0x00, 0x26, 0x25,
                0xa0, 0x34, 0x3e, 0xfc, 0xea, 0x34, 0x40, 0xae, 0xf0
            ]
        );
        #[cfg(feature = "tcp-timestamps")]
        assert_option_parses!(
            TcpOption::TimeStamp {
                tsval: 5000000,
                tsecr: 7000000
            },
            &[
                0x08, // data length
                0x0a, // type
                0x00, 0x4c, 0x4b, 0x40, //tsval
                0x00, 0x6a, 0xcf, 0xc0 //tsecr
            ]
        );
        assert_option_parses!(
            TcpOption::Unknown {
                kind: 12,
                data: &[1, 2, 3][..]
            },
            &[0x0c, 0x05, 0x01, 0x02, 0x03]
        )
    }

    #[test]
    fn test_malformed_tcp_options() {
        assert_eq!(TcpOption::parse(&[]), Err(Malformed));
        assert_eq!(TcpOption::parse(&[0xc]), Err(Malformed));
        assert_eq!(TcpOption::parse(&[0xc, 0x05, 0x01, 0x02]), Err(Malformed));
        assert_eq!(TcpOption::parse(&[0xc, 0x01]), Err(Malformed));
        assert_eq!(TcpOption::parse(&[0x2, 0x02]), Err(Malformed));
        assert_eq!(TcpOption::parse(&[0x3, 0x02]), Err(Malformed));
    }
}
