//! IPv6 extension headers (RFC 8200 §4): the common (next header, length) prefix,
//! and the TLV option walk shared by the Hop-by-Hop and Destination Options headers.

use crate::error::Malformed;
use crate::wire::ip::Protocol;

/// A read wrapper around an IPv6 extension header.
///
/// All IPv6 extension headers (except Fragment) share the same layout: a next
/// header field, a length field in units of 8 octets not counting the first 8,
/// and header-specific data.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct ExtHeader<'a> {
    buffer: &'a [u8],
}

mod field {
    pub const NXT_HDR: usize = 0;
    pub const LENGTH: usize = 1;
    pub const DATA_START: usize = 2;
}

impl<'a> ExtHeader<'a> {
    /// Imbue a raw octet buffer with extension header structure.
    pub const fn new_unchecked(buffer: &'a [u8]) -> ExtHeader<'a> {
        ExtHeader { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a [u8]) -> Result<ExtHeader<'a>, Malformed> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    pub fn check_len(&self) -> Result<(), Malformed> {
        if self.buffer.len() < field::DATA_START || self.buffer.len() < self.header_len() {
            Err(Malformed)
        } else {
            Ok(())
        }
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.buffer[field::NXT_HDR])
    }

    /// Return the length of the whole extension header, in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.buffer[field::LENGTH] as usize + 1) * 8
    }

    /// The header-specific data: for the Hop-by-Hop and Destination Options
    /// headers, the TLV-encoded options.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        &self.buffer[field::DATA_START..self.header_len()]
    }
}

open_enum! {
    /// IPv6 option type, from the Hop-by-Hop or Destination Options TLVs.
    pub enum OptionType(u8) {
        /// 1 byte of padding (this option has no length or data).
        Pad1        = 0,
        /// Multiple bytes of padding.
        PadN        = 1,
        /// Router alert (RFC 2711).
        RouterAlert = 5,
    }
}

open_enum! {
    /// The value of an IPv6 Router Alert Header Option.
    ///
    /// Router Alert options always contain exactly one `u16`; see [RFC 2711 § 2.1].
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub enum RouterAlert(u16) {
        /// The packet contains a Multicast Listener Discovery message.
        MulticastListenerDiscovery = 0,
        /// The packet contains an RSVP message.
        Rsvp = 1,
        /// The packet contains an Active Networks message.
        ActiveNetworks = 2,
    }
}

impl RouterAlert {
    /// Per [RFC 2711 § 2.1], Router Alert options always have 2 bytes of data.
    ///
    /// [RFC 2711 § 2.1]: https://tools.ietf.org/html/rfc2711#section-2.1
    pub const DATA_LEN: u8 = 2;
}

/// The action required of a node that does not recognize an option, from the two
/// highest-order bits of the option type (RFC 8200 §4.2).
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OptionFailureAction {
    /// Skip the option and continue processing the header.
    Skip,
    /// Discard the packet silently.
    Discard,
    /// Discard the packet and send an ICMP Parameter Problem error.
    DiscardSendError,
    /// Discard the packet and send an ICMP Parameter Problem error, but only if
    /// the packet's destination was not a multicast address.
    DiscardSendErrorIfUnicast,
}

impl OptionType {
    /// The action required if this option is not recognized.
    pub fn failure_action(&self) -> OptionFailureAction {
        match self.0 >> 6 {
            0b00 => OptionFailureAction::Skip,
            0b01 => OptionFailureAction::Discard,
            0b10 => OptionFailureAction::DiscardSendError,
            0b11 => OptionFailureAction::DiscardSendErrorIfUnicast,
            _ => unreachable!(),
        }
    }
}

/// An iterator over TLV-encoded IPv6 options, yielding
/// `(offset, option type, option data)`. The offset is of the option's first
/// byte, relative to the start of the options.
///
/// A malformed option (a length overrunning the buffer) yields one `Err` and
/// then ends the iteration.
pub struct OptionsIter<'a> {
    options: &'a [u8],
    offset: usize,
}

impl<'a> OptionsIter<'a> {
    /// Iterate over the options in an [`ExtHeader::data`] slice.
    pub fn new(options: &'a [u8]) -> Self {
        Self { options, offset: 0 }
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<(usize, OptionType, &'a [u8]), Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.options.len() {
            return None;
        }
        let offset = self.offset;
        let option_type = OptionType::from(self.options[offset]);
        if option_type == OptionType::Pad1 {
            // Pad1 is a bare type byte, with no length or data.
            self.offset = offset + 1;
            return Some(Ok((offset, option_type, &[][..])));
        }
        let data = self
            .options
            .get(offset + 1)
            .and_then(|&len| self.options.get(offset + 2..offset + 2 + len as usize));
        match data {
            Some(data) => {
                self.offset = offset + 2 + data.len();
                Some(Ok((offset, option_type, data)))
            }
            None => {
                self.offset = usize::MAX;
                Some(Err(Malformed))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ext_header() {
        // Hop-by-hop: next header UDP, length 0 (8 bytes total), router alert + Pad2.
        let bytes = [0x11, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
        let header = ExtHeader::new_checked(&bytes).unwrap();
        assert_eq!(header.next_header(), Protocol::Udp);
        assert_eq!(header.header_len(), 8);
        assert_eq!(header.data(), &bytes[2..8]);

        let options: Vec<_> = OptionsIter::new(header.data()).map(Result::unwrap).collect();
        assert_eq!(
            options,
            vec![
                (0, OptionType::RouterAlert, &bytes[4..6]),
                (4, OptionType::PadN, &bytes[8..8]),
            ]
        );

        // Length 1: 16 bytes total, one PadN.
        let header = ExtHeader::new_checked(&REPR_PACKET_PAD12).unwrap();
        assert_eq!(header.next_header(), Protocol::Tcp);
        assert_eq!(header.header_len(), 16);
        assert_eq!(header.data(), &REPR_PACKET_PAD12[2..]);
        let options: Vec<_> = OptionsIter::new(header.data()).map(Result::unwrap).collect();
        assert_eq!(options, vec![(0, OptionType::PadN, &[0u8; 12][..])]);
    }

    static REPR_PACKET_PAD4: [u8; 8] = [0x6, 0x0, 0x1, 0x4, 0x0, 0x0, 0x0, 0x0];
    static REPR_PACKET_PAD12: [u8; 16] = [
        0x06, 0x1, 0x1, 0x0C, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    #[test]
    fn test_ext_header_check_len() {
        // Empty and one-byte buffers.
        assert_eq!(ExtHeader::new_checked(&REPR_PACKET_PAD4[..0]), Err(Malformed));
        assert_eq!(ExtHeader::new_checked(&REPR_PACKET_PAD4[..1]), Err(Malformed));
        // One byte short of the length the header claims.
        assert_eq!(ExtHeader::new_checked(&REPR_PACKET_PAD4[..7]), Err(Malformed));
        assert_eq!(ExtHeader::new_checked(&REPR_PACKET_PAD12[..15]), Err(Malformed));
        // Exactly the claimed length.
        assert!(ExtHeader::new_checked(&REPR_PACKET_PAD4).is_ok());
        assert!(ExtHeader::new_checked(&REPR_PACKET_PAD12).is_ok());
        // A length field claiming more than the buffer holds.
        let bytes = [0x06, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        assert_eq!(ExtHeader::new_checked(&bytes), Err(Malformed));
    }

    /// Bytes past the header's own length are not part of its data.
    #[test]
    fn test_ext_header_overlong() {
        let mut bytes = REPR_PACKET_PAD4.to_vec();
        bytes.push(0);
        let header = ExtHeader::new_checked(&bytes).unwrap();
        assert_eq!(header.header_len(), 8);
        assert_eq!(header.data().len(), 6);

        let mut bytes = REPR_PACKET_PAD12.to_vec();
        bytes.push(0);
        let header = ExtHeader::new_checked(&bytes).unwrap();
        assert_eq!(header.header_len(), 16);
        assert_eq!(header.data().len(), 14);
    }

    /// Every option shape: Pad1, PadN of several sizes, router alert and an
    /// unknown type, whole and truncated.
    #[test]
    fn test_option_parse() {
        fn first(bytes: &[u8]) -> Option<Result<(usize, OptionType, &[u8]), Malformed>> {
            OptionsIter::new(bytes).next()
        }

        // Pad1.
        assert_eq!(first(&[0x0]), Some(Ok((0, OptionType::Pad1, &[][..]))));
        // PadN.
        assert_eq!(first(&[0x1, 0x0]), Some(Ok((0, OptionType::PadN, &[][..]))));
        assert_eq!(first(&[0x1, 0x1, 0x0]), Some(Ok((0, OptionType::PadN, &[0][..]))));
        assert_eq!(first(&[0x1, 0x1]), Some(Err(Malformed)));
        assert_eq!(first(&[0x1]), Some(Err(Malformed)));
        // PadN followed by a bare, truncated option.
        let mut iter = OptionsIter::new(&[0x1, 0x7, 0, 0, 0, 0, 0, 0, 0, 0xff]);
        assert_eq!(iter.next(), Some(Ok((0, OptionType::PadN, &[0; 7][..]))));
        assert_eq!(iter.next(), Some(Err(Malformed)));
        assert_eq!(iter.next(), None);
        // Router alert, every known value and an unknown one.
        for (bytes, value) in [
            ([0x05, 0x02, 0x00, 0x00], RouterAlert::MulticastListenerDiscovery),
            ([0x05, 0x02, 0x00, 0x01], RouterAlert::Rsvp),
            ([0x05, 0x02, 0x00, 0x02], RouterAlert::ActiveNetworks),
            ([0x05, 0x02, 0xbe, 0xef], RouterAlert(0xbeef)),
        ] {
            let (offset, option_type, data) = first(&bytes).unwrap().unwrap();
            assert_eq!(offset, 0);
            assert_eq!(option_type, OptionType::RouterAlert);
            assert_eq!(data.len(), RouterAlert::DATA_LEN as usize);
            assert_eq!(RouterAlert::from(u16::from_be_bytes([data[0], data[1]])), value);
        }
        assert_eq!(first(&[0x05, 0x02, 0x00]), Some(Err(Malformed)));
        // Unknown type.
        assert_eq!(
            first(&[0xff, 0x3, 0x0, 0x0, 0x0]),
            Some(Ok((0, OptionType(255), &[0; 3][..])))
        );
        assert_eq!(OptionType::from(0xff), OptionType(255));
        assert_eq!(first(&[0xff, 0x3, 0x0, 0x0]), Some(Err(Malformed)));
        assert_eq!(first(&[0xff]), Some(Err(Malformed)));
        // Nothing at all.
        assert_eq!(first(&[]), None);
    }

    #[test]
    fn test_options_iter() {
        let options = [
            0x00, 0x01, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x11, 0x00, 0x05, 0x02, 0x00, 0x01, 0x01,
            0x08, 0x00,
        ];
        let mut iter = OptionsIter::new(&options);
        assert_eq!(iter.next(), Some(Ok((0, OptionType::Pad1, &[][..]))));
        assert_eq!(iter.next(), Some(Ok((1, OptionType::PadN, &[0x00][..]))));
        assert_eq!(iter.next(), Some(Ok((4, OptionType::PadN, &[0x00, 0x00][..]))));
        assert_eq!(iter.next(), Some(Ok((8, OptionType::PadN, &[][..]))));
        assert_eq!(iter.next(), Some(Ok((10, OptionType::Pad1, &[][..]))));
        assert_eq!(iter.next(), Some(Ok((11, OptionType(0x11), &[][..]))));
        let (offset, option_type, data) = iter.next().unwrap().unwrap();
        assert_eq!((offset, option_type), (13, OptionType::RouterAlert));
        assert_eq!(
            RouterAlert::from(u16::from_be_bytes([data[0], data[1]])),
            RouterAlert::Rsvp
        );
        // A PadN claiming 8 data bytes with only one left.
        assert_eq!(iter.next(), Some(Err(Malformed)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_failure_action() {
        assert_eq!(OptionType(0x02).failure_action(), OptionFailureAction::Skip);
        assert_eq!(OptionType(0x42).failure_action(), OptionFailureAction::Discard);
        assert_eq!(OptionType(0x82).failure_action(), OptionFailureAction::DiscardSendError);
        assert_eq!(
            OptionType(0xc2).failure_action(),
            OptionFailureAction::DiscardSendErrorIfUnicast
        );
    }
}
