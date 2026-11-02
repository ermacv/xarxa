//! 6LoWPAN: IPv6 over IEEE 802.15.4 ([RFC 4944] framing and fragmentation,
//! [RFC 6282] header compression).
//!
//! [RFC 4944]: https://datatracker.ietf.org/doc/html/rfc4944
//! [RFC 6282]: https://datatracker.ietf.org/doc/html/rfc6282

use crate::error::Malformed;
use crate::wire::IpProtocol;

pub mod frag;
pub mod iphc;
pub mod nhc;

const ADDRESS_CONTEXT_LENGTH: usize = 8;

/// A 6LoWPAN address context: a 64-bit prefix that compressed addresses may
/// refer to by index instead of carrying it inline.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AddressContext(pub [u8; ADDRESS_CONTEXT_LENGTH]);

/// The kind of 6LoWPAN header a frame's payload starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SixlowpanPacket {
    /// A fragment header, see [`SixlowpanFragRepr`](crate::wire::SixlowpanFragRepr).
    FragmentHeader,
    /// A compressed IPv6 header, see [`SixlowpanIphcRepr`](crate::wire::SixlowpanIphcRepr).
    IphcHeader,
}

const DISPATCH_FIRST_FRAGMENT_HEADER: u8 = 0b11000;
const DISPATCH_FRAGMENT_HEADER: u8 = 0b11100;
const DISPATCH_IPHC_HEADER: u8 = 0b011;
const DISPATCH_UDP_HEADER: u8 = 0b11110;
const DISPATCH_EXT_HEADER: u8 = 0b1110;

impl SixlowpanPacket {
    /// Read the dispatch byte of a 6LoWPAN payload.
    ///
    /// # Errors
    /// - `Malformed`: if the payload is empty, or the dispatch is neither a
    ///   fragment header nor an IPHC header.
    pub fn dispatch(buffer: &[u8]) -> Result<Self, Malformed> {
        let raw = buffer;

        if raw.is_empty() {
            return Err(Malformed);
        }

        if raw[0] >> 3 == DISPATCH_FIRST_FRAGMENT_HEADER || raw[0] >> 3 == DISPATCH_FRAGMENT_HEADER {
            Ok(Self::FragmentHeader)
        } else if raw[0] >> 5 == DISPATCH_IPHC_HEADER {
            Ok(Self::IphcHeader)
        } else {
            Err(Malformed)
        }
    }
}

/// The next header field of a compressed header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NextHeader {
    /// The next header is compressed too, with NHC.
    Compressed,
    /// The next header is carried inline.
    Uncompressed(IpProtocol),
}

impl core::fmt::Display for NextHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NextHeader::Compressed => write!(f, "compressed"),
            NextHeader::Uncompressed(protocol) => write!(f, "{protocol}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NextHeader {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            NextHeader::Compressed => defmt::write!(fmt, "compressed"),
            NextHeader::Uncompressed(protocol) => defmt::write!(fmt, "{}", protocol),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sixlowpan_fragment_emit() {
        let repr = frag::Repr::FirstFragment {
            size: 0xff,
            tag: 0xabcd,
        };
        let mut buffer = [0xffu8; 4];

        assert_eq!(repr.buffer_len(), 4);
        repr.emit(&mut buffer);

        assert_eq!(buffer, [0xc0, 0xff, 0xab, 0xcd]);
        assert_eq!(frag::Repr::parse(&buffer), Ok(repr));

        let repr = frag::Repr::Fragment {
            size: 0xff,
            tag: 0xabcd,
            offset: 0xcc,
        };
        let mut buffer = [0xffu8; 5];

        assert_eq!(repr.buffer_len(), 5);
        repr.emit(&mut buffer);

        assert_eq!(buffer, [0xe0, 0xff, 0xab, 0xcd, 0xcc]);
        assert_eq!(frag::Repr::parse(&buffer), Ok(repr));
    }

    #[test]
    fn sixlowpan_three_fragments() {
        use crate::wire::Ieee802154Address;
        use crate::wire::Ieee802154Repr;

        let key = frag::Key {
            ll_src_addr: Ieee802154Address::Extended([50, 147, 130, 47, 40, 8, 62, 217]),
            ll_dst_addr: Ieee802154Address::Extended([26, 11, 66, 66, 66, 66, 66, 66]),
            datagram_size: 307,
            datagram_tag: 63,
        };

        let frame1 = [
            0x41, 0xcc, 0x92, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9, 0x3e, 0x08, 0x28, 0x2f,
            0x82, 0x93, 0x32, 0xc1, 0x33, 0x00, 0x3f, 0x6e, 0x33, 0x02, 0x35, 0x3d, 0xf0, 0xd2, 0x5f, 0x1b, 0x39, 0xb4,
            0x6b, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72,
            0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74,
            0x65, 0x74, 0x75, 0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c,
            0x69, 0x74, 0x2e, 0x20, 0x41, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x20, 0x64, 0x75, 0x69, 0x20, 0x6f, 0x64,
            0x69, 0x6f, 0x2c, 0x20, 0x69, 0x61, 0x63, 0x75, 0x6c, 0x69, 0x73, 0x20, 0x76, 0x65, 0x6c, 0x20, 0x72,
        ];

        let (ieee802154_repr, header_len) = Ieee802154Repr::parse(&frame1).unwrap();
        let payload = &frame1[header_len..];
        assert_eq!(SixlowpanPacket::dispatch(payload), Ok(SixlowpanPacket::FragmentHeader));

        let frag = frag::Repr::parse(payload).unwrap();
        assert_eq!(frag.size(), 307);
        assert_eq!(frag.tag(), 0x003f);
        assert_eq!(frag.offset(), 0);
        assert!(frag.is_first_fragment());
        assert_eq!(frag.key(&ieee802154_repr), key);

        let frame2 = [
            0x41, 0xcc, 0x93, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9, 0x3e, 0x08, 0x28, 0x2f,
            0x82, 0x93, 0x32, 0xe1, 0x33, 0x00, 0x3f, 0x11, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x20, 0x61, 0x74, 0x2c, 0x20,
            0x74, 0x72, 0x69, 0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6e, 0x75, 0x6e, 0x63,
            0x20, 0x65, 0x72, 0x61, 0x74, 0x20, 0x63, 0x75, 0x72, 0x61, 0x65, 0x2e, 0x20, 0x4c, 0x6f, 0x72, 0x65, 0x6d,
            0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61,
            0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72, 0x20, 0x61,
            0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74,
        ];

        let (ieee802154_repr, header_len) = Ieee802154Repr::parse(&frame2).unwrap();
        let payload = &frame2[header_len..];
        assert_eq!(SixlowpanPacket::dispatch(payload), Ok(SixlowpanPacket::FragmentHeader));

        let frag = frag::Repr::parse(payload).unwrap();
        assert_eq!(frag.size(), 307);
        assert_eq!(frag.tag(), 0x003f);
        assert_eq!(frag.offset(), 136 / 8);
        assert!(!frag.is_first_fragment());
        assert_eq!(frag.key(&ieee802154_repr), key);

        let frame3 = [
            0x41, 0xcc, 0x94, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9, 0x3e, 0x08, 0x28, 0x2f,
            0x82, 0x93, 0x32, 0xe1, 0x33, 0x00, 0x3f, 0x1d, 0x2e, 0x20, 0x41, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x6d, 0x20,
            0x64, 0x75, 0x69, 0x20, 0x6f, 0x64, 0x69, 0x6f, 0x2c, 0x20, 0x69, 0x61, 0x63, 0x75, 0x6c, 0x69, 0x73, 0x20,
            0x76, 0x65, 0x6c, 0x20, 0x72, 0x75, 0x74, 0x72, 0x75, 0x6d, 0x20, 0x61, 0x74, 0x2c, 0x20, 0x74, 0x72, 0x69,
            0x73, 0x74, 0x69, 0x71, 0x75, 0x65, 0x20, 0x6e, 0x6f, 0x6e, 0x20, 0x6e, 0x75, 0x6e, 0x63, 0x20, 0x65, 0x72,
            0x61, 0x74, 0x20, 0x63, 0x75, 0x72, 0x61, 0x65, 0x2e, 0x20, 0x0a,
        ];

        let (ieee802154_repr, header_len) = Ieee802154Repr::parse(&frame3).unwrap();
        let payload = &frame3[header_len..];
        assert_eq!(SixlowpanPacket::dispatch(payload), Ok(SixlowpanPacket::FragmentHeader));

        let frag = frag::Repr::parse(payload).unwrap();
        assert_eq!(frag.size(), 307);
        assert_eq!(frag.tag(), 0x003f);
        assert_eq!(frag.offset(), 232 / 8);
        assert!(!frag.is_first_fragment());
        assert_eq!(frag.key(&ieee802154_repr), key);
    }
}
