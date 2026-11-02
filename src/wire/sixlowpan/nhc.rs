//! Next header compression ([RFC 6282 § 4]).
//!
//! [RFC 6282 § 4]: https://datatracker.ietf.org/doc/html/rfc6282#section-4
use super::{DISPATCH_EXT_HEADER, DISPATCH_UDP_HEADER, Malformed, NextHeader};
use crate::wire::IpProtocol;
use crate::wire::take;

/// The kind of compressed next header a buffer starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NhcPacket {
    /// A compressed IPv6 extension header, see [`ExtHeaderRepr`].
    ExtHeader,
    /// A compressed UDP header, see [`UdpNhcRepr`].
    UdpHeader,
}

impl NhcPacket {
    /// Read the dispatch byte of a compressed next header.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is empty, or the dispatch is neither an
    ///   extension header nor a UDP header.
    pub fn dispatch(buffer: &[u8]) -> Result<Self, Malformed> {
        let raw = buffer;
        if raw.is_empty() {
            return Err(Malformed);
        }

        if raw[0] >> 4 == DISPATCH_EXT_HEADER {
            // We have a compressed IPv6 Extension Header.
            Ok(Self::ExtHeader)
        } else if raw[0] >> 3 == DISPATCH_UDP_HEADER {
            // We have a compressed UDP header.
            Ok(Self::UdpHeader)
        } else {
            Err(Malformed)
        }
    }
}

/// The IPv6 extension header a compressed extension header stands for.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ExtHeaderId {
    HopByHopHeader,
    RoutingHeader,
    FragmentHeader,
    DestinationOptionsHeader,
    MobilityHeader,
    Header,
    Reserved,
}

impl From<ExtHeaderId> for IpProtocol {
    fn from(val: ExtHeaderId) -> Self {
        match val {
            ExtHeaderId::HopByHopHeader => Self::HopByHop,
            ExtHeaderId::RoutingHeader => Self::Ipv6Route,
            ExtHeaderId::FragmentHeader => Self::Ipv6Frag,
            ExtHeaderId::DestinationOptionsHeader => Self::Ipv6Opts,
            ExtHeaderId::MobilityHeader => Self::from(0),
            ExtHeaderId::Header => Self::from(0),
            ExtHeaderId::Reserved => Self::from(0),
        }
    }
}

/// The fields of a 6LoWPAN NHC extension header.
///
/// The header has the following format ([RFC 6282 § 4.2]):
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | 1 | 1 | 0 |    EID    |NH |
/// +---+---+---+---+---+---+---+---+
/// ```
/// An inline next header, if NH is clear, and the length follow it.
///
/// [RFC 6282 § 4.2]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.2
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtHeaderRepr {
    pub ext_header_id: ExtHeaderId,
    pub next_header: NextHeader,
    /// The length of the payload, in bytes.
    pub length: u8,
}

impl ExtHeaderRepr {
    /// Parse a compressed extension header from the front of `buf`.
    ///
    /// Returns the header and its length, not counting the payload.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is shorter than the header, or does not start
    ///   with an extension header dispatch.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), Malformed> {
        if buf.is_empty() {
            return Err(Malformed);
        }
        let b = buf[0];
        if b >> 4 != DISPATCH_EXT_HEADER {
            return Err(Malformed);
        }
        let ext_header_id = match (b >> 1) & 0b111 {
            0 => ExtHeaderId::HopByHopHeader,
            1 => ExtHeaderId::RoutingHeader,
            2 => ExtHeaderId::FragmentHeader,
            3 => ExtHeaderId::DestinationOptionsHeader,
            4 => ExtHeaderId::MobilityHeader,
            5 | 6 => ExtHeaderId::Reserved,
            _ => ExtHeaderId::Header,
        };
        let mut offset = 1;
        let next_header = if b & 1 == 0 {
            NextHeader::Uncompressed(IpProtocol::from(take(buf, &mut offset, 1)?[0]))
        } else {
            NextHeader::Compressed
        };
        let length = take(buf, &mut offset, 1)?[0];
        Ok((
            Self {
                ext_header_id,
                next_header,
                length,
            },
            offset,
        ))
    }

    /// Return the length of the header this will emit, not counting the payload.
    pub const fn buffer_len(&self) -> usize {
        2 + matches!(self.next_header, NextHeader::Uncompressed(_)) as usize
    }

    /// Write the header into the front of `buf`.
    ///
    /// Writes exactly [`buffer_len`](Self::buffer_len) bytes.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, buf: &mut [u8]) {
        let mut b = DISPATCH_EXT_HEADER << 4;
        b |= match self.ext_header_id {
            ExtHeaderId::HopByHopHeader => 0,
            ExtHeaderId::RoutingHeader => 1,
            ExtHeaderId::FragmentHeader => 2,
            ExtHeaderId::DestinationOptionsHeader => 3,
            ExtHeaderId::MobilityHeader => 4,
            ExtHeaderId::Reserved => 5,
            ExtHeaderId::Header => 7,
        } << 1;
        let mut offset = 1;
        match self.next_header {
            NextHeader::Compressed => b |= 1,
            NextHeader::Uncompressed(nh) => {
                buf[1] = nh.into();
                offset = 2;
            }
        }
        buf[0] = b;
        buf[offset] = self.length;
    }
}

/// The fields of a 6LoWPAN NHC UDP header.
///
/// The header starts with the following byte ([RFC 6282 § 4.3]):
/// ```txt
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | 1 | 1 | 1 | 0 | C |   P   |
/// +---+---+---+---+---+---+---+---+
/// ```
/// C says whether the checksum is elided, P how much of the ports is.
/// The inline port bits and the checksum follow it.
///
/// [RFC 6282 § 4.3]: https://datatracker.ietf.org/doc/html/rfc6282#section-4.3
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UdpNhcRepr {
    pub src_port: u16,
    pub dst_port: u16,
    /// The checksum. `None` when it is elided: the receiver must recompute it
    /// over the whole datagram.
    pub checksum: Option<u16>,
}

impl UdpNhcRepr {
    /// Parse a compressed UDP header from the front of `buf`.
    ///
    /// Returns the header and its length, not counting the payload.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is shorter than the header, or does not start
    ///   with a UDP header dispatch.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), Malformed> {
        if buf.is_empty() {
            return Err(Malformed);
        }
        let b = buf[0];
        if b >> 3 != DISPATCH_UDP_HEADER {
            return Err(Malformed);
        }
        let mut offset = 1;
        let (src_port, dst_port) = match b & 0b11 {
            0b00 => {
                let p = take(buf, &mut offset, 4)?;
                (u16::from_be_bytes([p[0], p[1]]), u16::from_be_bytes([p[2], p[3]]))
            }
            0b01 => {
                let p = take(buf, &mut offset, 3)?;
                (u16::from_be_bytes([p[0], p[1]]), 0xf000 + p[2] as u16)
            }
            0b10 => {
                let p = take(buf, &mut offset, 3)?;
                (0xf000 + p[0] as u16, u16::from_be_bytes([p[1], p[2]]))
            }
            _ => {
                let p = take(buf, &mut offset, 1)?;
                (0xf0b0 + (p[0] >> 4) as u16, 0xf0b0 + (p[0] & 0x0f) as u16)
            }
        };
        let checksum = if b & 0b100 == 0 {
            let c = take(buf, &mut offset, 2)?;
            Some(u16::from_be_bytes([c[0], c[1]]))
        } else {
            None
        };
        Ok((
            Self {
                src_port,
                dst_port,
                checksum,
            },
            offset,
        ))
    }

    /// Return the length of the header this will emit, not counting the payload.
    pub fn buffer_len(&self) -> usize {
        1 + match (self.src_port, self.dst_port) {
            (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => 1,
            (0xf000..=0xf0ff, _) | (_, 0xf000..=0xf0ff) => 3,
            (_, _) => 4,
        } + if self.checksum.is_some() { 2 } else { 0 }
    }

    /// Write the header into the front of `buf`.
    ///
    /// Writes exactly [`buffer_len`](Self::buffer_len) bytes.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, buf: &mut [u8]) {
        let mut b = DISPATCH_UDP_HEADER << 3;
        let offset;
        match (self.src_port, self.dst_port) {
            (0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf) => {
                // Both ports compress to 4 bits.
                b |= 0b11;
                buf[1] = (((self.src_port - 0xf0b0) as u8) << 4) | ((self.dst_port - 0xf0b0) as u8);
                offset = 2;
            }
            (0xf000..=0xf0ff, _) => {
                // The source port compresses to 8 bits.
                b |= 0b10;
                buf[1] = (self.src_port - 0xf000) as u8;
                buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
                offset = 4;
            }
            (_, 0xf000..=0xf0ff) => {
                // The destination port compresses to 8 bits.
                b |= 0b01;
                buf[1..3].copy_from_slice(&self.src_port.to_be_bytes());
                buf[3] = (self.dst_port - 0xf000) as u8;
                offset = 4;
            }
            (_, _) => {
                // Neither port compresses.
                buf[1..3].copy_from_slice(&self.src_port.to_be_bytes());
                buf[3..5].copy_from_slice(&self.dst_port.to_be_bytes());
                offset = 5;
            }
        }
        match self.checksum {
            Some(checksum) => buf[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes()),
            None => b |= 1 << 2,
        }
        buf[0] = b;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ROUTING_SR_PACKET: [u8; 32] = [
        0xe3, 0x1e, 0x03, 0x03, 0x99, 0x30, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x06, 0x00, 0x06,
        0x00, 0x06, 0x00, 0x06, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_source_routing_deconstruct() {
        let (header, header_len) = ExtHeaderRepr::parse(&ROUTING_SR_PACKET).unwrap();
        assert_eq!(header_len, 2);
        assert_eq!(header.next_header, NextHeader::Compressed);
        assert_eq!(header.ext_header_id, ExtHeaderId::RoutingHeader);
        assert_eq!(header.length, 30);
        assert_eq!(&ROUTING_SR_PACKET[header_len..][..header.length as usize], {
            &ROUTING_SR_PACKET[2..]
        });
    }

    #[test]
    fn test_source_routing_emit() {
        let ext_hdr = ExtHeaderRepr {
            ext_header_id: ExtHeaderId::RoutingHeader,
            next_header: NextHeader::Compressed,
            length: 30,
        };

        let mut buffer = [0u8; 32];
        ext_hdr.emit(&mut buffer[..ext_hdr.buffer_len()]);
        buffer[ext_hdr.buffer_len()..].copy_from_slice(&ROUTING_SR_PACKET[2..]);

        assert_eq!(&buffer[..], ROUTING_SR_PACKET);
    }

    #[test]
    fn ext_header_nh_inlined() {
        let bytes = [0xe2, 0x3a, 0x6, 0x3, 0x0, 0xff, 0x0, 0x0, 0x0];

        let (header, header_len) = ExtHeaderRepr::parse(&bytes).unwrap();
        assert_eq!(header_len, 3);
        assert_eq!(header.length, 6);
        assert_eq!(header.ext_header_id, ExtHeaderId::RoutingHeader);
        assert_eq!(header.next_header, NextHeader::Uncompressed(IpProtocol::Icmpv6));

        assert_eq!(&bytes[header_len..], [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ext_header_nh_elided() {
        let bytes = [0xe3, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00];

        let (header, header_len) = ExtHeaderRepr::parse(&bytes).unwrap();
        assert_eq!(header_len, 2);
        assert_eq!(header.length, 6);
        assert_eq!(header.ext_header_id, ExtHeaderId::RoutingHeader);
        assert_eq!(header.next_header, NextHeader::Compressed);

        assert_eq!(&bytes[header_len..], [0x03, 0x00, 0xff, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ext_header_emit() {
        let ext_header = ExtHeaderRepr {
            ext_header_id: ExtHeaderId::RoutingHeader,
            next_header: NextHeader::Compressed,
            length: 6,
        };

        let len = ext_header.buffer_len();
        let mut buffer = [0xffu8; 8];
        ext_header.emit(&mut buffer[..len]);

        assert_eq!(ExtHeaderRepr::parse(&buffer[..len]), Ok((ext_header, len)));
    }

    #[test]
    fn udp_nhc_fields() {
        let bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];

        let (udp, header_len) = UdpNhcRepr::parse(&bytes).unwrap();
        assert_eq!(header_len, 7);
        assert_eq!(udp.checksum, Some(0x28c4));
        assert_eq!(udp.src_port, 5678);
        assert_eq!(udp.dst_port, 8765);
    }

    #[test]
    fn udp_emit() {
        let udp = UdpNhcRepr {
            src_port: 0xf0b1,
            dst_port: 0xf001,
            checksum: Some(0x1234),
        };

        let payload = b"Hello World!";

        let len = udp.buffer_len();
        let mut buffer = [0xffu8; 32];
        udp.emit(&mut buffer[..len]);
        buffer[len..len + payload.len()].copy_from_slice(&payload[..]);

        assert_eq!(UdpNhcRepr::parse(&buffer[..len]), Ok((udp, len)));
        assert_eq!(&buffer[len..len + payload.len()], b"Hello World!");
    }

    /// Every port encoding round-trips, including the 4-bit one for two
    /// `0xf0bX` ports (RFC 6282 §4.3.3).
    #[test]
    fn udp_port_modes() {
        for (src_port, dst_port, header_len) in [
            (0xf0b1, 0xf0b2, 4),
            (0xf0b1, 0xf001, 6),
            (0xf0b1, 1234, 6),
            (1234, 0xf0b1, 6),
            (0xf0ff, 0xf0ff, 6),
            (1234, 5678, 7),
        ] {
            let udp = UdpNhcRepr {
                src_port,
                dst_port,
                checksum: Some(0xabcd),
            };
            assert_eq!(udp.buffer_len(), header_len);
            let mut buffer = [0xffu8; 8];
            udp.emit(&mut buffer[..header_len]);
            assert_eq!(UdpNhcRepr::parse(&buffer[..header_len]), Ok((udp, header_len)));
        }
    }

    /// An elided checksum parses as `None` and emits with the C bit set.
    #[test]
    fn udp_checksum_elided() {
        let udp = UdpNhcRepr {
            src_port: 1234,
            dst_port: 5678,
            checksum: None,
        };
        assert_eq!(udp.buffer_len(), 5);
        let mut buffer = [0xffu8; 5];
        udp.emit(&mut buffer);
        assert_eq!(buffer[0], 0b1111_0100);
        assert_eq!(UdpNhcRepr::parse(&buffer), Ok((udp, 5)));
    }
}
