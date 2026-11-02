use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use core::iter;
use core::iter::Iterator;

use crate::error::Malformed;
#[cfg(feature = "ipv4")]
use crate::wire::Ipv4Addr;
#[cfg(feature = "ipv6")]
use crate::wire::Ipv6Addr;

open_enum! {
    /// DNS opcode.
    pub enum Opcode(u8) {
        Query  = 0x00,
        Status = 0x01,
    }
}
open_enum! {
    /// DNS response code.
    pub enum Rcode(u8) {
        NoError  = 0x00,
        FormErr  = 0x01,
        ServFail = 0x02,
        NXDomain = 0x03,
        NotImp   = 0x04,
        Refused  = 0x05,
        YXDomain = 0x06,
        YXRRSet  = 0x07,
        NXRRSet  = 0x08,
        NotAuth  = 0x09,
        NotZone  = 0x0a,
    }
}

open_enum! {
    /// DNS record type.
    pub enum Type(u16) {
        A     = 0x0001,
        Ns    = 0x0002,
        Cname = 0x0005,
        Soa   = 0x0006,
        Aaaa  = 0x001c,
    }
}

bitflags! {
    /// DNS header flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u16 {
        const RESPONSE            = 0b1000_0000_0000_0000;
        const AUTHORITATIVE       = 0b0000_0100_0000_0000;
        const TRUNCATED           = 0b0000_0010_0000_0000;
        const RECURSION_DESIRED   = 0b0000_0001_0000_0000;
        const RECURSION_AVAILABLE = 0b0000_0000_1000_0000;
        const AUTHENTIC_DATA      = 0b0000_0000_0010_0000;
        const CHECK_DISABLED      = 0b0000_0000_0001_0000;
    }
}

mod field {
    use crate::wire::field::*;

    pub const ID: Field = 0..2;
    pub const FLAGS: Field = 2..4;
    pub const QDCOUNT: Field = 4..6;
    pub const ANCOUNT: Field = 6..8;
    pub const NSCOUNT: Field = 8..10;
    pub const ARCOUNT: Field = 10..12;

    pub const HEADER_END: usize = 12;
}

#[cfg(feature = "defmt")]
impl defmt::Format for Flags {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Flags({=u16:#018b})", self.bits());
    }
}

/// Length of the DNS header.
pub const HEADER_LEN: usize = field::HEADER_END;

// DNS class IN (Internet)
const CLASS_IN: u16 = 1;

/// A read/write wrapper around a DNS packet buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with DNS packet structure.
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
    /// - `Malformed`: if the buffer is smaller than the header length.
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::HEADER_END {
            Err(Malformed)
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> &'a mut [u8] {
        self.buffer
    }

    /// The bytes after the header: questions and records.
    pub fn payload(&self) -> &[u8] {
        &self.buffer[field::HEADER_END..]
    }

    /// Return the transaction ID field.
    pub fn transaction_id(&self) -> u16 {
        let field = &self.buffer[field::ID];
        NetworkEndian::read_u16(field)
    }

    /// Return the flags field.
    pub fn flags(&self) -> Flags {
        let field = &self.buffer[field::FLAGS];
        Flags::from_bits_truncate(NetworkEndian::read_u16(field))
    }

    /// Return the opcode field.
    pub fn opcode(&self) -> Opcode {
        let field = &self.buffer[field::FLAGS];
        let flags = NetworkEndian::read_u16(field);
        Opcode::from((flags >> 11 & 0xF) as u8)
    }

    /// Return the response code field.
    pub fn rcode(&self) -> Rcode {
        let field = &self.buffer[field::FLAGS];
        let flags = NetworkEndian::read_u16(field);
        Rcode::from((flags & 0xF) as u8)
    }

    /// Return the question count field.
    pub fn question_count(&self) -> u16 {
        let field = &self.buffer[field::QDCOUNT];
        NetworkEndian::read_u16(field)
    }

    /// Return the answer record count field.
    pub fn answer_record_count(&self) -> u16 {
        let field = &self.buffer[field::ANCOUNT];
        NetworkEndian::read_u16(field)
    }

    /// Return the authority record count field.
    pub fn authority_record_count(&self) -> u16 {
        let field = &self.buffer[field::NSCOUNT];
        NetworkEndian::read_u16(field)
    }

    /// Return the additional record count field.
    pub fn additional_record_count(&self) -> u16 {
        let field = &self.buffer[field::ARCOUNT];
        NetworkEndian::read_u16(field)
    }

    /// Parse a name from `bytes`, following compression pointers into this packet.
    ///
    /// Yields one label at a time. Pointers are only allowed to point backwards, so
    /// pointer loops end the iteration with an error.
    pub fn parse_name<'b>(&'b self, mut bytes: &'b [u8]) -> impl Iterator<Item = Result<&'b [u8], Malformed>> {
        let mut packet: &'b [u8] = self.buffer;

        iter::from_fn(move || {
            loop {
                if bytes.is_empty() {
                    return Some(Err(Malformed));
                }
                match bytes[0] {
                    0x00 => return None,
                    x if x & 0xC0 == 0x00 => {
                        let len = (x & 0x3F) as usize;
                        if bytes.len() < 1 + len {
                            return Some(Err(Malformed));
                        }
                        let label = &bytes[1..1 + len];
                        bytes = &bytes[1 + len..];
                        return Some(Ok(label));
                    }
                    x if x & 0xC0 == 0xC0 => {
                        if bytes.len() < 2 {
                            return Some(Err(Malformed));
                        }
                        let y = bytes[1];
                        let ptr = ((x & 0x3F) as usize) << 8 | (y as usize);
                        if packet.len() <= ptr {
                            return Some(Err(Malformed));
                        }

                        // RFC1035 says: "In this scheme, an entire domain name or a list of labels at
                        //      the end of a domain name is replaced with a pointer to a ***prior*** occurrence
                        //      of the same name.
                        //
                        // Is it unclear if this means the pointer MUST point backwards in the packet or not. Either way,
                        // pointers that don't point backwards are never seen in the fields, so use this to check that
                        // there are no pointer loops.

                        // Split packet into parts before and after `ptr`.
                        // parse the part after, keep only the part before in `packet`. This ensure we never
                        // parse the same byte twice, therefore eliminating pointer loops.

                        bytes = &packet[ptr..];
                        packet = &packet[..ptr];
                    }
                    _ => return Some(Err(Malformed)),
                }
            }
        })
    }

    /// The bytes after the header, mutable.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[field::HEADER_END..]
    }

    /// Set the transaction ID field.
    pub fn set_transaction_id(&mut self, val: u16) {
        let field = &mut self.buffer[field::ID];
        NetworkEndian::write_u16(field, val)
    }

    /// Set the flags field. Leaves the opcode and rcode bits alone.
    pub fn set_flags(&mut self, val: Flags) {
        let field = &mut self.buffer[field::FLAGS];
        let mask = Flags::all().bits();
        let old = NetworkEndian::read_u16(field);
        NetworkEndian::write_u16(field, (old & !mask) | val.bits());
    }

    /// Set the opcode field.
    pub fn set_opcode(&mut self, val: Opcode) {
        let field = &mut self.buffer[field::FLAGS];
        let mask = 0x7800;
        let val: u8 = val.into();
        let val = (val as u16) << 11;
        let old = NetworkEndian::read_u16(field);
        NetworkEndian::write_u16(field, (old & !mask) | val);
    }

    /// Set the question count field.
    pub fn set_question_count(&mut self, val: u16) {
        let field = &mut self.buffer[field::QDCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    /// Set the answer record count field.
    pub fn set_answer_record_count(&mut self, val: u16) {
        let field = &mut self.buffer[field::ANCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    /// Set the authority record count field.
    pub fn set_authority_record_count(&mut self, val: u16) {
        let field = &mut self.buffer[field::NSCOUNT];
        NetworkEndian::write_u16(field, val)
    }
    /// Set the additional record count field.
    pub fn set_additional_record_count(&mut self, val: u16) {
        let field = &mut self.buffer[field::ARCOUNT];
        NetworkEndian::write_u16(field, val)
    }
}

/// Parse part of a name from `bytes`, not following pointers.
/// Returns the unused part of `bytes`, and the pointer offset if the sequence ends with a pointer.
fn parse_name_part<'a>(
    mut bytes: &'a [u8],
    mut f: impl FnMut(&'a [u8]),
) -> Result<(&'a [u8], Option<usize>), Malformed> {
    loop {
        let x = *bytes.first().ok_or(Malformed)?;
        bytes = &bytes[1..];
        match x {
            0x00 => return Ok((bytes, None)),
            x if x & 0xC0 == 0x00 => {
                let len = (x & 0x3F) as usize;
                let label = bytes.get(..len).ok_or(Malformed)?;
                bytes = &bytes[len..];
                f(label);
            }
            x if x & 0xC0 == 0xC0 => {
                let y = *bytes.first().ok_or(Malformed)?;
                bytes = &bytes[1..];

                let ptr = ((x & 0x3F) as usize) << 8 | (y as usize);
                return Ok((bytes, Some(ptr)));
            }
            _ => return Err(Malformed),
        }
    }
}

/// A question in a DNS packet.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Question<'a> {
    /// The name, in wire format. May contain compression pointers.
    pub name: &'a [u8],
    /// The record type asked for.
    pub type_: Type,
}

impl<'a> Question<'a> {
    /// Parse a question from the start of `buffer`.
    ///
    /// Returns the rest of the buffer and the question.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short, or the class is not IN.
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], Question<'a>), Malformed> {
        let (rest, _) = parse_name_part(buffer, |_| ())?;
        let name = &buffer[..buffer.len() - rest.len()];

        if rest.len() < 4 {
            return Err(Malformed);
        }
        let type_ = NetworkEndian::read_u16(&rest[0..2]).into();
        let class = NetworkEndian::read_u16(&rest[2..4]);
        let rest = &rest[4..];

        if class != CLASS_IN {
            return Err(Malformed);
        }

        Ok((rest, Question { name, type_ }))
    }

    /// Length of this question on the wire.
    pub const fn buffer_len(&self) -> usize {
        self.name.len() + 4
    }

    /// Write this question at the start of `packet`.
    ///
    /// Panics if `packet` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, packet: &mut [u8]) {
        packet[..self.name.len()].copy_from_slice(self.name);
        let rest = &mut packet[self.name.len()..];
        NetworkEndian::write_u16(&mut rest[0..2], self.type_.into());
        NetworkEndian::write_u16(&mut rest[2..4], CLASS_IN);
    }
}

/// A resource record in a DNS packet.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Record<'a> {
    /// The name, in wire format. May contain compression pointers.
    pub name: &'a [u8],
    /// Time to live, in seconds.
    pub ttl: u32,
    /// The record data.
    pub data: RecordData<'a>,
}

impl<'a> RecordData<'a> {
    /// Parse record data of the given type.
    pub fn parse(type_: Type, data: &'a [u8]) -> Result<RecordData<'a>, Malformed> {
        match type_ {
            #[cfg(feature = "ipv4")]
            Type::A => Ok(RecordData::A(Ipv4Addr::from(
                <[u8; 4]>::try_from(data).map_err(|_| Malformed)?,
            ))),
            #[cfg(feature = "ipv6")]
            Type::Aaaa => Ok(RecordData::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).map_err(|_| Malformed)?,
            ))),
            Type::Cname => Ok(RecordData::Cname(data)),
            x => Ok(RecordData::Other(x, data)),
        }
    }
}

/// The data of a resource record.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RecordData<'a> {
    /// An IPv4 address.
    #[cfg(feature = "ipv4")]
    A(Ipv4Addr),
    /// An IPv6 address.
    #[cfg(feature = "ipv6")]
    Aaaa(Ipv6Addr),
    /// A canonical name, in wire format. May contain compression pointers.
    Cname(&'a [u8]),
    /// Any other record type, with its raw data.
    Other(Type, &'a [u8]),
}

impl<'a> Record<'a> {
    /// Parse a record from the start of `buffer`.
    ///
    /// Returns the rest of the buffer and the record.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short, or the class is not IN.
    pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], Record<'a>), Malformed> {
        let (rest, _) = parse_name_part(buffer, |_| ())?;
        let name = &buffer[..buffer.len() - rest.len()];

        if rest.len() < 10 {
            return Err(Malformed);
        }
        let type_ = NetworkEndian::read_u16(&rest[0..2]).into();
        let class = NetworkEndian::read_u16(&rest[2..4]);
        let ttl = NetworkEndian::read_u32(&rest[4..8]);
        let len = NetworkEndian::read_u16(&rest[8..10]) as usize;
        let rest = &rest[10..];

        if class != CLASS_IN {
            return Err(Malformed);
        }

        let data = rest.get(..len).ok_or(Malformed)?;
        let rest = &rest[len..];

        Ok((
            rest,
            Record {
                name,
                ttl,
                data: RecordData::parse(type_, data)?,
            },
        ))
    }
}

#[cfg(feature = "ipv4")] // tests assume ipv4
#[cfg(test)]
mod test {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn test_parse_name() {
        let mut bytes = [
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x08, 0x66,
            0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69,
            0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ];
        let copy = bytes;
        let packet = Packet::new_unchecked(&mut bytes);
        let bytes = &copy;

        let name_vec = |bytes| {
            let mut v = Vec::new();
            packet
                .parse_name(bytes)
                .try_for_each(|label| label.map(|label| v.push(label)))
                .map(|_| v)
        };

        assert_eq!(
            name_vec(&bytes[0x0c..]),
            Ok(vec![&b"www"[..], &b"facebook"[..], &b"com"[..]])
        );
        assert_eq!(
            name_vec(&bytes[0x22..]),
            Ok(vec![&b"www"[..], &b"facebook"[..], &b"com"[..]])
        );
        assert_eq!(
            name_vec(&bytes[0x2e..]),
            Ok(vec![&b"star-mini"[..], &b"c10r"[..], &b"facebook"[..], &b"com"[..]])
        );
        assert_eq!(
            name_vec(&bytes[0x3f..]),
            Ok(vec![&b"star-mini"[..], &b"c10r"[..], &b"facebook"[..], &b"com"[..]])
        );
    }

    struct Parsed<'a> {
        packet: Packet<'a>,
        questions: Vec<Question<'a>>,
        answers: Vec<Record<'a>>,
        authorities: Vec<Record<'a>>,
        additionals: Vec<Record<'a>>,
    }

    impl<'a> Parsed<'a> {
        fn parse(bytes: &'a mut [u8]) -> Result<Self, Malformed> {
            let mut questions = Vec::new();
            let mut answers = Vec::new();
            let mut authorities = Vec::new();
            let mut additionals = Vec::new();

            // The header is all the wrapper needs here. Keep the payload as a
            // shared slice so the parsed borrows can live alongside it.
            let (header, payload) = bytes.split_at_mut(12);
            let packet = Packet::new_unchecked(header);
            let mut payload: &'a [u8] = payload;

            for _ in 0..packet.question_count() {
                let (p, r) = Question::parse(payload)?;
                questions.push(r);
                payload = p;
            }
            for _ in 0..packet.answer_record_count() {
                let (p, r) = Record::parse(payload)?;
                answers.push(r);
                payload = p;
            }
            for _ in 0..packet.authority_record_count() {
                let (p, r) = Record::parse(payload)?;
                authorities.push(r);
                payload = p;
            }
            for _ in 0..packet.additional_record_count() {
                let (p, r) = Record::parse(payload)?;
                additionals.push(r);
                payload = p;
            }

            // Check that there are no bytes left
            assert_eq!(payload.len(), 0);

            Ok(Parsed {
                packet,
                questions,
                answers,
                authorities,
                additionals,
            })
        }
    }

    #[test]
    fn test_parse_request() {
        let mut bytes = [
            0x51, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let p = Parsed::parse(&mut bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x5184);
        assert_eq!(p.packet.flags(), Flags::RECURSION_DESIRED | Flags::AUTHENTIC_DATA);
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 0);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(p.questions.len(), 1);
        assert_eq!(
            p.questions[0].name,
            &[0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        assert_eq!(p.answers.len(), 0);
        assert_eq!(p.authorities.len(), 0);
        assert_eq!(p.additionals.len(), 0);
    }

    #[test]
    fn test_parse_response() {
        let mut bytes = [
            0x51, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xca, 0x00, 0x04, 0xac, 0xd9, 0xa8, 0xae,
        ];
        let p = Parsed::parse(&mut bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x5184);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 1);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 202);
        assert_eq!(p.answers[0].data, RecordData::A(Ipv4Addr::new(0xac, 0xd9, 0xa8, 0xae)));
    }

    #[test]
    fn test_parse_response_multiple_a() {
        let mut bytes = [
            0x4b, 0x9e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72, 0x75, 0x73, 0x74, 0x2d,
            0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x35, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x28, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00,
            0x04, 0x0d, 0xe0, 0x77, 0x62,
        ];
        let p = Parsed::parse(&mut bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x4b9e);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 4);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[
                0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        for (i, last) in [0x35, 0x28, 0x43, 0x62].into_iter().enumerate() {
            assert_eq!(p.answers[i].name, &[0xc0, 0x0c]);
            assert_eq!(p.answers[i].ttl, 9);
            assert_eq!(p.answers[i].data, RecordData::A(Ipv4Addr::new(0x0d, 0xe0, 0x77, last)));
        }
    }

    #[test]
    fn test_parse_response_cname() {
        let mut bytes = [
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x08, 0x66,
            0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69,
            0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ];
        let p = Parsed::parse(&mut bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x786c);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NoError);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 2);
        assert_eq!(p.packet.authority_record_count(), 0);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(
            p.questions[0].name,
            &[
                0x03, 0x77, 0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d,
                0x00
            ]
        );
        assert_eq!(p.questions[0].type_, Type::A);

        // cname
        assert_eq!(p.answers[0].name, &[0xc0, 0x0c]);
        assert_eq!(p.answers[0].ttl, 1523);
        assert_eq!(
            p.answers[0].data,
            RecordData::Cname(&[
                0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10
            ])
        );
        // a
        assert_eq!(p.answers[1].name, &[0xc0, 0x2e]);
        assert_eq!(p.answers[1].ttl, 5);
        assert_eq!(p.answers[1].data, RecordData::A(Ipv4Addr::new(0x1f, 0x0d, 0x53, 0x24)));
    }

    #[test]
    fn test_parse_response_nxdomain() {
        let mut bytes = [
            0x63, 0xc4, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x13, 0x61, 0x68, 0x61, 0x73, 0x64,
            0x67, 0x68, 0x6c, 0x61, 0x6b, 0x73, 0x6a, 0x68, 0x62, 0x61, 0x61, 0x73, 0x6c, 0x64, 0x03, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x20, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x03, 0x83, 0x00, 0x3d, 0x01,
            0x61, 0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74,
            0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67,
            0x72, 0x73, 0xc0, 0x20, 0x5f, 0xce, 0x8b, 0x85, 0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09,
            0x3a, 0x80, 0x00, 0x01, 0x51, 0x80,
        ];
        let p = Parsed::parse(&mut bytes).unwrap();

        assert_eq!(p.packet.transaction_id(), 0x63c4);
        assert_eq!(
            p.packet.flags(),
            Flags::RESPONSE | Flags::RECURSION_DESIRED | Flags::RECURSION_AVAILABLE
        );
        assert_eq!(p.packet.opcode(), Opcode::Query);
        assert_eq!(p.packet.rcode(), Rcode::NXDomain);
        assert_eq!(p.packet.question_count(), 1);
        assert_eq!(p.packet.answer_record_count(), 0);
        assert_eq!(p.packet.authority_record_count(), 1);
        assert_eq!(p.packet.additional_record_count(), 0);

        assert_eq!(p.questions[0].type_, Type::A);

        // SOA authority
        assert_eq!(p.authorities[0].name, &[0xc0, 0x20]); // com.
        assert_eq!(p.authorities[0].ttl, 899);
        assert!(matches!(p.authorities[0].data, RecordData::Other(Type::Soa, _)));
    }

    #[test]
    fn test_emit() {
        let name = &[
            0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00,
        ];
        let question = Question { name, type_: Type::A };

        let mut buf = vec![0; HEADER_LEN + question.buffer_len()];
        let mut packet = Packet::new_unchecked(&mut buf);
        packet.set_transaction_id(0x1234);
        packet.set_flags(Flags::RECURSION_DESIRED);
        packet.set_opcode(Opcode::Query);
        packet.set_question_count(1);
        packet.set_answer_record_count(0);
        packet.set_authority_record_count(0);
        packet.set_additional_record_count(0);
        question.emit(packet.payload_mut());

        let want = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72, 0x75, 0x73, 0x74, 0x2d,
            0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(&buf, want);
    }
}
