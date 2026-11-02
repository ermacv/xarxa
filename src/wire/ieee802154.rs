//! IEEE 802.15.4 MAC frames.

use core::fmt;

use super::take;
use crate::error::Malformed;
use crate::wire::Ipv6Addr;

open_enum! {
    /// IEEE 802.15.4 frame type.
    pub enum FrameType(u8) {
        Beacon = 0b000,
        Data = 0b001,
        Acknowledgement = 0b010,
        MacCommand = 0b011,
        Multipurpose = 0b101,
        FragmentOrFrak = 0b110,
        Extended = 0b111,
    }
}

open_enum! {
    /// IEEE 802.15.4 addressing mode for destination and source addresses.
    pub enum AddressingMode(u8) {
        Absent    = 0b00,
        Short     = 0b10,
        Extended  = 0b11,
    }
}

/// An IEEE 802.15.4 PAN identifier.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Pan(pub u16);

impl Pan {
    /// The broadcast PAN identifier.
    pub const BROADCAST: Self = Self(0xffff);

    /// The PAN identifier as bytes, in little-endian.
    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

impl fmt::Display for Pan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0x}", self.0)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Pan {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{:02x}", self.0)
    }
}

/// An IEEE 802.15.4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// No address.
    Absent,
    /// A 16-bit short address.
    Short([u8; 2]),
    /// A 64-bit extended address.
    Extended([u8; 8]),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, f: defmt::Formatter) {
        match self {
            Self::Absent => defmt::write!(f, "not-present"),
            Self::Short(bytes) => defmt::write!(f, "{:02x}:{:02x}", bytes[0], bytes[1]),
            Self::Extended(bytes) => defmt::write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                bytes[4],
                bytes[5],
                bytes[6],
                bytes[7]
            ),
        }
    }
}

#[cfg(test)]
impl Default for Address {
    fn default() -> Self {
        Address::Extended([0u8; 8])
    }
}

impl Address {
    /// The broadcast address.
    pub const BROADCAST: Address = Address::Short([0xff; 2]);

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast()
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Construct an address from its bytes: 2 for a short address, 8 for an
    /// extended one.
    ///
    /// # Panics
    /// Panics if `a` is neither 2 nor 8 bytes long.
    pub fn from_bytes(a: &[u8]) -> Self {
        if a.len() == 2 {
            let mut b = [0u8; 2];
            b.copy_from_slice(a);
            Address::Short(b)
        } else if a.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(a);
            Address::Extended(b)
        } else {
            panic!("Not an IEEE802.15.4 address");
        }
    }

    /// The address as bytes. Empty for `Absent`.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Address::Absent => &[],
            Address::Short(value) => value,
            Address::Extended(value) => value,
        }
    }

    /// Convert an extended address to a modified EUI-64 interface identifier.
    ///
    /// Returns `None` for short and absent addresses.
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        match self {
            Address::Absent | Address::Short(_) => None,
            Address::Extended(value) => {
                let mut bytes = [0; 8];
                bytes.copy_from_slice(&value[..]);

                bytes[0] ^= 1 << 1;

                Some(bytes)
            }
        }
    }

    /// Convert an extended address to a link-local IPv6 address (RFC 4944 §6).
    ///
    /// Returns `None` for short and absent addresses.
    pub fn as_link_local_address(&self) -> Option<Ipv6Addr> {
        let mut bytes = [0; 16];
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        bytes[8..].copy_from_slice(&self.as_eui_64()?);

        Some(Ipv6Addr::from_octets(bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Absent => write!(f, "not-present"),
            Self::Short(bytes) => write!(f, "{:02x}:{:02x}", bytes[0], bytes[1]),
            Self::Extended(bytes) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
            ),
        }
    }
}

open_enum! {
    /// IEEE 802.15.4 frame version.
    pub enum FrameVersion(u8) {
        Ieee802154_2003 = 0b00,
        Ieee802154_2006 = 0b01,
        Ieee802154 = 0b10,
    }
}

/// The largest MAC header this crate emits: frame control, sequence number,
/// destination PAN, and two extended addresses.
pub const MAX_HEADER_LEN: usize = 3 + 2 + 8 + 8;

/// The fields of an IEEE 802.15.4 MAC header.
///
/// The layout of the header depends on its own fields (which addresses are
/// present, whether the PAN identifier is compressed), so the header is parsed
/// and emitted as a whole.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub frame_type: FrameType,
    pub security_enabled: bool,
    pub frame_pending: bool,
    pub ack_request: bool,
    pub sequence_number: Option<u8>,
    pub pan_id_compression: bool,
    pub frame_version: FrameVersion,
    pub dst_pan_id: Option<Pan>,
    pub dst_addr: Option<Address>,
    pub src_pan_id: Option<Pan>,
    pub src_addr: Option<Address>,
}

/// Which addressing fields the frame carries:
/// (destination PAN, destination address mode, source PAN, source address mode).
fn addr_present_flags(
    frame_version: FrameVersion,
    dst_addr_mode: AddressingMode,
    src_addr_mode: AddressingMode,
    pan_id_compression: bool,
) -> Option<(bool, AddressingMode, bool, AddressingMode)> {
    const ABSENT: AddressingMode = AddressingMode::Absent;
    const SHORT: AddressingMode = AddressingMode::Short;
    const EXTENDED: AddressingMode = AddressingMode::Extended;
    match frame_version {
        FrameVersion::Ieee802154_2003 | FrameVersion::Ieee802154_2006 => match (dst_addr_mode, src_addr_mode) {
            (ABSENT, src) => Some((false, ABSENT, true, src)),
            (dst, ABSENT) => Some((true, dst, false, ABSENT)),

            (dst, src) if pan_id_compression => Some((true, dst, false, src)),
            (dst, src) if !pan_id_compression => Some((true, dst, true, src)),
            _ => None,
        },
        FrameVersion::Ieee802154 => Some(match (dst_addr_mode, src_addr_mode, pan_id_compression) {
            (ABSENT, ABSENT, false) => (false, ABSENT, false, ABSENT),
            (ABSENT, ABSENT, true) => (true, ABSENT, false, ABSENT),
            (dst, ABSENT, false) if dst != ABSENT => (true, dst, false, ABSENT),
            (dst, ABSENT, true) if dst != ABSENT => (false, dst, false, ABSENT),
            (ABSENT, src, false) if src != ABSENT => (false, ABSENT, true, src),
            (ABSENT, src, true) if src != ABSENT => (false, ABSENT, true, src),
            (EXTENDED, EXTENDED, false) => (true, EXTENDED, false, EXTENDED),
            (EXTENDED, EXTENDED, true) => (false, EXTENDED, false, EXTENDED),
            (SHORT, SHORT, false) => (true, SHORT, true, SHORT),
            (SHORT, EXTENDED, false) => (true, SHORT, true, EXTENDED),
            (EXTENDED, SHORT, false) => (true, EXTENDED, true, SHORT),
            (SHORT, EXTENDED, true) => (true, SHORT, false, EXTENDED),
            (EXTENDED, SHORT, true) => (true, EXTENDED, false, SHORT),
            (SHORT, SHORT, true) => (true, SHORT, false, SHORT),
            _ => return None,
        }),
        _ => None,
    }
}

/// Read an address in little-endian byte order.
fn parse_addr(buf: &[u8], offset: &mut usize, mode: AddressingMode) -> Result<Address, Malformed> {
    match mode {
        AddressingMode::Absent => Ok(Address::Absent),
        AddressingMode::Short => {
            let raw = take(buf, offset, 2)?;
            Ok(Address::Short([raw[1], raw[0]]))
        }
        AddressingMode::Extended => {
            let raw = take(buf, offset, 8)?;
            let mut bytes: [u8; 8] = raw.try_into().unwrap();
            bytes.reverse();
            Ok(Address::Extended(bytes))
        }
        _ => Err(Malformed),
    }
}

/// Write an address in little-endian byte order. Returns the length written.
fn emit_addr(buf: &mut [u8], addr: Option<Address>) -> usize {
    match addr {
        None | Some(Address::Absent) => 0,
        Some(Address::Short(mut bytes)) => {
            bytes.reverse();
            buf[..2].copy_from_slice(&bytes);
            2
        }
        Some(Address::Extended(mut bytes)) => {
            bytes.reverse();
            buf[..8].copy_from_slice(&bytes);
            8
        }
    }
}

impl Repr {
    /// Parse the MAC header of a frame.
    ///
    /// Returns the header and its length, the auxiliary security header
    /// included. The payload starts at that offset.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is shorter than the header, or longer than 127
    ///   bytes, or the frame version or an addressing mode is unknown.
    pub fn parse(buf: &[u8]) -> Result<(Repr, usize), Malformed> {
        // A frame is at most 127 bytes, and starts with the frame control
        // field and a sequence number.
        if buf.len() < 3 || buf.len() > 127 {
            return Err(Malformed);
        }

        let fc = u16::from_le_bytes([buf[0], buf[1]]);
        let frame_type = FrameType((fc & 0b111) as u8);
        let security_enabled = fc & (1 << 3) != 0;
        let frame_pending = fc & (1 << 4) != 0;
        let ack_request = fc & (1 << 5) != 0;
        let pan_id_compression = fc & (1 << 6) != 0;
        let dst_addr_mode = AddressingMode(((fc >> 10) & 0b11) as u8);
        let frame_version = FrameVersion(((fc >> 12) & 0b11) as u8);
        let src_addr_mode = AddressingMode(((fc >> 14) & 0b11) as u8);

        // We don't handle unknown frame versions.
        if !matches!(
            frame_version,
            FrameVersion::Ieee802154_2003 | FrameVersion::Ieee802154_2006 | FrameVersion::Ieee802154
        ) {
            return Err(Malformed);
        }

        // We don't handle unknown addressing modes.
        for mode in [dst_addr_mode, src_addr_mode] {
            if !matches!(
                mode,
                AddressingMode::Absent | AddressingMode::Short | AddressingMode::Extended
            ) {
                return Err(Malformed);
            }
        }

        // We don't handle absent addressing mode with PAN ID compression for older frame versions.
        if matches!(
            frame_version,
            FrameVersion::Ieee802154_2003 | FrameVersion::Ieee802154_2006
        ) && pan_id_compression
            && dst_addr_mode == AddressingMode::Absent
            && src_addr_mode == AddressingMode::Absent
        {
            return Err(Malformed);
        }

        let sequence_number = match frame_type {
            FrameType::Beacon
            | FrameType::Data
            | FrameType::Acknowledgement
            | FrameType::MacCommand
            | FrameType::Multipurpose => Some(buf[2]),
            _ => None,
        };

        // Which frame types carry addressing fields.
        let has_addressing = match frame_type {
            FrameType::Beacon | FrameType::Data | FrameType::MacCommand | FrameType::Multipurpose => true,
            FrameType::Acknowledgement => frame_version == FrameVersion::Ieee802154,
            _ => false,
        };

        let mut offset = 3;
        let (mut dst_pan_id, mut dst_addr, mut src_pan_id, mut src_addr) = (None, None, None, None);
        if has_addressing
            && let Some((dst_pan, dst_mode, src_pan, src_mode)) =
                addr_present_flags(frame_version, dst_addr_mode, src_addr_mode, pan_id_compression)
        {
            if dst_pan {
                let raw = take(buf, &mut offset, 2)?;
                dst_pan_id = Some(Pan(u16::from_le_bytes([raw[0], raw[1]])));
            }
            dst_addr = Some(parse_addr(buf, &mut offset, dst_mode)?);
            if src_pan {
                let raw = take(buf, &mut offset, 2)?;
                src_pan_id = Some(Pan(u16::from_le_bytes([raw[0], raw[1]])));
            }
            src_addr = Some(parse_addr(buf, &mut offset, src_mode)?);
        }

        if security_enabled {
            // The security control byte, then the frame counter and the key
            // identifier its bits say are there.
            let b = *buf.get(offset).ok_or(Malformed)?;
            let frame_counter_suppressed = (b >> 5) & 0b1 == 0b1;
            let key_identifier_len = match (b >> 3) & 0b11 {
                0 => 0,
                1 => 1,
                2 => 5,
                _ => 9,
            };
            offset += 1 + if frame_counter_suppressed { 0 } else { 4 } + key_identifier_len;
            if offset > buf.len() {
                return Err(Malformed);
            }
        }

        Ok((
            Repr {
                frame_type,
                security_enabled,
                frame_pending,
                ack_request,
                sequence_number,
                pan_id_compression,
                frame_version,
                dst_pan_id,
                dst_addr,
                src_pan_id,
                src_addr,
            },
            offset,
        ))
    }

    /// Return the length of the MAC header this will emit.
    pub const fn buffer_len(&self) -> usize {
        3 + 2
            + match self.dst_addr {
                Some(Address::Absent) | None => 0,
                Some(Address::Short(_)) => 2,
                Some(Address::Extended(_)) => 8,
            }
            + if !self.pan_id_compression { 2 } else { 0 }
            + match self.src_addr {
                Some(Address::Absent) | None => 0,
                Some(Address::Short(_)) => 2,
                Some(Address::Extended(_)) => 8,
            }
    }

    /// Write the MAC header into the front of `buf`.
    ///
    /// Writes exactly [`buffer_len`](Self::buffer_len) bytes. A missing
    /// sequence number or PAN identifier is written as zero.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, buf: &mut [u8]) {
        let addr_mode = |addr: Option<Address>| match addr {
            None | Some(Address::Absent) => AddressingMode::Absent,
            Some(Address::Short(_)) => AddressingMode::Short,
            Some(Address::Extended(_)) => AddressingMode::Extended,
        };
        let fc = (self.frame_type.0 as u16 & 0b111)
            | (self.security_enabled as u16) << 3
            | (self.frame_pending as u16) << 4
            | (self.ack_request as u16) << 5
            | (self.pan_id_compression as u16) << 6
            | (addr_mode(self.dst_addr).0 as u16) << 10
            | (self.frame_version.0 as u16 & 0b11) << 12
            | (addr_mode(self.src_addr).0 as u16) << 14;
        buf[0..2].copy_from_slice(&fc.to_le_bytes());
        buf[2] = self.sequence_number.unwrap_or(0);

        let dst_pan = match self.dst_pan_id {
            Some(pan) => pan,
            None => Pan(0),
        };
        buf[3..5].copy_from_slice(&dst_pan.as_bytes());
        let mut offset = 5;
        offset += emit_addr(&mut buf[offset..], self.dst_addr);
        if !self.pan_id_compression {
            let src_pan = match self.src_pan_id {
                Some(pan) => pan,
                None => Pan(0),
            };
            buf[offset..offset + 2].copy_from_slice(&src_pan.as_bytes());
            offset += 2;
        }
        emit_addr(&mut buf[offset..], self.src_addr);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "IEEE802.15.4 frame type={}", self.frame_type)?;

        if let Some(seq) = self.sequence_number {
            write!(f, " seq={seq:02x}")?;
        }

        if let Some(pan) = self.dst_pan_id {
            write!(f, " dst-pan={pan}")?;
        }

        if let Some(pan) = self.src_pan_id {
            write!(f, " src-pan={pan}")?;
        }

        if let Some(addr) = self.dst_addr {
            write!(f, " dst={addr}")?;
        }

        if let Some(addr) = self.src_addr {
            write!(f, " src={addr}")?;
        }

        Ok(())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "IEEE802.15.4 frame type={}", self.frame_type);

        if let Some(seq) = self.sequence_number {
            defmt::write!(f, " seq={:02x}", seq);
        }

        if let Some(pan) = self.dst_pan_id {
            defmt::write!(f, " dst-pan={}", pan);
        }

        if let Some(pan) = self.src_pan_id {
            defmt::write!(f, " src-pan={}", pan);
        }

        if let Some(addr) = self.dst_addr {
            defmt::write!(f, " dst={}", addr);
        }

        if let Some(addr) = self.src_addr {
            defmt::write!(f, " src={}", addr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_broadcast() {
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_unicast());
    }

    /// Only an extended address has an EUI-64: the address with the U/L bit flipped.
    #[test]
    fn test_as_eui_64() {
        assert_eq!(
            Address::Extended([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]).as_eui_64(),
            Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
        );
        assert_eq!(Address::Short([0x12, 0x34]).as_eui_64(), None);
        assert_eq!(Address::Absent.as_eui_64(), None);
    }

    /// Emitting a header and parsing it back round-trips, even into a buffer
    /// full of stale bytes: emit writes every byte of the header.
    #[test]
    fn emit_parse_roundtrip() {
        let repr = Repr {
            frame_type: FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: true,
            pan_id_compression: true,
            frame_version: FrameVersion::Ieee802154,
            sequence_number: Some(1),
            dst_pan_id: Some(Pan(0xabcd)),
            dst_addr: Some(Address::BROADCAST),
            src_pan_id: None,
            src_addr: Some(Address::Extended([0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00])),
        };

        let len = repr.buffer_len();
        assert_eq!(len, 3 + 2 + 2 + 8);

        let mut buffer = [0xffu8; 127];
        repr.emit(&mut buffer[..len]);

        let (parsed, header_len) = Repr::parse(&buffer[..len]).unwrap();
        assert_eq!(header_len, len);
        assert_eq!(parsed, repr);
    }

    #[test]
    fn extended_addr() {
        let frame = [
            0b0000_0001,
            0b1100_1100, // frame control
            0b0,         // seq
            0xcd,
            0xab, // pan id
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x01, // dst addr
            0x03,
            0x04, // pan id
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x02, // src addr
        ];
        let (repr, header_len) = Repr::parse(&frame).unwrap();
        assert_eq!(header_len, frame.len());
        assert_eq!(repr.frame_type, FrameType::Data);
        assert_eq!(
            repr.dst_addr,
            Some(Address::Extended([0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]))
        );
        assert_eq!(
            repr.src_addr,
            Some(Address::Extended([0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]))
        );
        assert_eq!(repr.dst_pan_id, Some(Pan(0xabcd)));
        assert_eq!(repr.src_pan_id, Some(Pan(0x0403)));
    }

    #[test]
    fn short_addr() {
        let frame = [
            0x01, 0x98, // frame control
            0x00, // sequence number
            0x34, 0x12, 0x78, 0x56, // PAN identifier and address of destination
            0x34, 0x12, 0xbc, 0x9a, // PAN identifier and address of source
        ];
        let (repr, header_len) = Repr::parse(&frame).unwrap();
        assert_eq!(header_len, frame.len());
        assert_eq!(repr.frame_type, FrameType::Data);
        assert!(!repr.security_enabled);
        assert!(!repr.frame_pending);
        assert!(!repr.ack_request);
        assert!(!repr.pan_id_compression);
        assert_eq!(repr.frame_version, FrameVersion::Ieee802154_2006);
        assert_eq!(repr.sequence_number, Some(0));
        assert_eq!(repr.dst_pan_id, Some(Pan(0x1234)));
        assert_eq!(repr.dst_addr, Some(Address::Short([0x56, 0x78])));
        assert_eq!(repr.src_pan_id, Some(Pan(0x1234)));
        assert_eq!(repr.src_addr, Some(Address::Short([0x9a, 0xbc])));
    }

    #[test]
    fn zolertia_remote() {
        let frame = [
            0x41, 0xd8, // frame control
            0x01, // sequence number
            0xcd, 0xab, // Destination PAN id
            0xff, 0xff, // Short destination address
            0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // Extended source address
            0x2b, 0x00, 0x00, 0x00, // payload
        ];
        let (repr, header_len) = Repr::parse(&frame).unwrap();
        assert_eq!(repr.frame_type, FrameType::Data);
        assert!(!repr.security_enabled);
        assert!(!repr.frame_pending);
        assert!(!repr.ack_request);
        assert!(repr.pan_id_compression);
        assert_eq!(repr.frame_version, FrameVersion::Ieee802154_2006);
        assert_eq!(repr.dst_addr, Some(Address::BROADCAST));
        assert_eq!(&frame[header_len..], &[0x2b, 0x00, 0x00, 0x00]);
    }

    /// A frame with link-layer security: the header length covers the
    /// auxiliary security header, so the payload starts after it.
    #[test]
    fn security() {
        let frame = [
            0x69, 0xdc, // frame control
            0x32, // sequence number
            0xcd, 0xab, // destination PAN id
            0xbf, 0x9b, 0x15, 0x06, 0x00, 0x4b, 0x12, 0x00, // extended destination address
            0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // extended source address
            0x05, // security control field
            0x31, 0x01, 0x00, 0x00, // frame counter
            0x3e, 0xe8, 0xfb, 0x85, 0xe4, 0xcc, 0xf4, 0x48, 0x90, 0xfe, 0x56, 0x66, 0xf7, 0x1c, 0x65, 0x9e,
            0xf9, // data
            0x93, 0xc8, 0x34, 0x2e, // MIC
        ];
        let (repr, header_len) = Repr::parse(&frame).unwrap();
        assert_eq!(repr.frame_type, FrameType::Data);
        assert!(repr.security_enabled);
        assert!(!repr.frame_pending);
        assert!(repr.ack_request);
        assert!(repr.pan_id_compression);
        assert_eq!(repr.frame_version, FrameVersion::Ieee802154_2006);
        assert_eq!(repr.sequence_number, Some(0x32));
        assert_eq!(repr.dst_pan_id, Some(Pan(0xabcd)));
        assert_eq!(
            repr.dst_addr,
            Some(Address::Extended([0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf]))
        );
        assert_eq!(repr.src_pan_id, None);
        assert_eq!(
            repr.src_addr,
            Some(Address::Extended([0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7]))
        );
        // 3 + dst pan + two extended addresses + security control + frame counter.
        assert_eq!(header_len, 3 + 2 + 8 + 8 + 1 + 4);
        // The data and the MIC are what remains.
        assert_eq!(frame.len() - header_len, 17 + 4);
    }

    /// Truncated frames are rejected, never panicked on.
    #[test]
    fn truncated() {
        let frame = [
            0x41, 0xd8, 0x01, 0xcd, 0xab, 0xff, 0xff, 0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00,
        ];
        assert!(Repr::parse(&frame).is_ok());
        for len in 0..frame.len() {
            assert_eq!(Repr::parse(&frame[..len]), Err(Malformed));
        }
        // Frames longer than 127 bytes are not valid either.
        assert_eq!(Repr::parse(&[0u8; 128]), Err(Malformed));
    }
}
