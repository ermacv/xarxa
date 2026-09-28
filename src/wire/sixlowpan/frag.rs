//! 6LoWPAN fragment headers ([RFC 4944 § 5.3]).
//!
//! [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3

use super::{DISPATCH_FIRST_FRAGMENT_HEADER, DISPATCH_FRAGMENT_HEADER};
use crate::error::Malformed;
use crate::wire::{Ieee802154Address, Ieee802154Repr};

/// Key used for identifying all the link fragments that belong to the same packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Key {
    pub(crate) ll_src_addr: Ieee802154Address,
    pub(crate) ll_dst_addr: Ieee802154Address,
    pub(crate) datagram_size: u16,
    pub(crate) datagram_tag: u16,
}

/// The length of a first fragment header.
pub const FIRST_FRAGMENT_HEADER_SIZE: usize = 4;
/// The length of a subsequent fragment header.
pub const NEXT_FRAGMENT_HEADER_SIZE: usize = 5;

/// The fields of a 6LoWPAN fragment header.
///
/// A first fragment header has the following format ([RFC 4944 § 5.3]):
/// ```txt
///                      1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1 1 0 0 0|    datagram_size    |         datagram_tag          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Subsequent fragment headers have the following format:
/// ```txt
///                      1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1 1 1 0 0|    datagram_size    |         datagram_tag          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |datagram_offset|
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Repr {
    /// The first fragment of a datagram.
    FirstFragment {
        /// The size of the whole IPv6 datagram.
        size: u16,
        /// The tag shared by every fragment of the datagram.
        tag: u16,
    },
    /// Any fragment but the first.
    Fragment {
        /// The size of the whole IPv6 datagram.
        size: u16,
        /// The tag shared by every fragment of the datagram.
        tag: u16,
        /// The offset of this fragment, in units of 8 octets.
        offset: u8,
    },
}

impl core::fmt::Display for Repr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Repr::FirstFragment { size, tag } => {
                write!(f, "FirstFrag size={size} tag={tag}")
            }
            Repr::Fragment { size, tag, offset } => {
                write!(f, "NthFrag size={size} tag={tag} offset={offset}")
            }
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Repr::FirstFragment { size, tag } => {
                defmt::write!(fmt, "FirstFrag size={} tag={}", size, tag);
            }
            Repr::Fragment { size, tag, offset } => {
                defmt::write!(fmt, "NthFrag size={} tag={} offset={}", size, tag, offset);
            }
        }
    }
}

impl Repr {
    /// Parse a fragment header from the front of `buf`.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is shorter than the header, or does not start
    ///   with a fragment header dispatch.
    pub fn parse(buf: &[u8]) -> Result<Self, Malformed> {
        if buf.len() < FIRST_FRAGMENT_HEADER_SIZE {
            return Err(Malformed);
        }
        let size = u16::from_be_bytes([buf[0], buf[1]]) & 0b111_1111_1111;
        let tag = u16::from_be_bytes([buf[2], buf[3]]);
        match buf[0] >> 3 {
            DISPATCH_FIRST_FRAGMENT_HEADER => Ok(Self::FirstFragment { size, tag }),
            DISPATCH_FRAGMENT_HEADER => {
                if buf.len() < NEXT_FRAGMENT_HEADER_SIZE {
                    return Err(Malformed);
                }
                Ok(Self::Fragment {
                    size,
                    tag,
                    offset: buf[4],
                })
            }
            _ => Err(Malformed),
        }
    }

    /// The size of the whole IPv6 datagram.
    pub const fn size(&self) -> u16 {
        match self {
            Self::FirstFragment { size, .. } | Self::Fragment { size, .. } => *size,
        }
    }

    /// The tag shared by every fragment of the datagram.
    pub const fn tag(&self) -> u16 {
        match self {
            Self::FirstFragment { tag, .. } | Self::Fragment { tag, .. } => *tag,
        }
    }

    /// The offset of this fragment, in units of 8 octets. Zero for the first.
    pub const fn offset(&self) -> u8 {
        match self {
            Self::FirstFragment { .. } => 0,
            Self::Fragment { offset, .. } => *offset,
        }
    }

    /// Whether this is the header of a first fragment.
    pub const fn is_first_fragment(&self) -> bool {
        matches!(self, Self::FirstFragment { .. })
    }

    /// Return the length of the header.
    pub const fn buffer_len(&self) -> usize {
        match self {
            Self::FirstFragment { .. } => FIRST_FRAGMENT_HEADER_SIZE,
            Self::Fragment { .. } => NEXT_FRAGMENT_HEADER_SIZE,
        }
    }

    /// The key identifying the datagram this fragment belongs to.
    ///
    /// # Panics
    /// Panics if the MAC header has no source or destination address.
    pub fn key(&self, ieee802154_repr: &Ieee802154Repr) -> Key {
        Key {
            ll_src_addr: ieee802154_repr.src_addr.unwrap(),
            ll_dst_addr: ieee802154_repr.dst_addr.unwrap(),
            datagram_size: self.size(),
            datagram_tag: self.tag(),
        }
    }

    /// Write the header into the front of `buf`.
    ///
    /// Writes exactly [`buffer_len`](Self::buffer_len) bytes.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, buf: &mut [u8]) {
        match *self {
            Self::FirstFragment { size, tag } => {
                let word = ((DISPATCH_FIRST_FRAGMENT_HEADER as u16) << 11) | (size & 0b111_1111_1111);
                buf[0..2].copy_from_slice(&word.to_be_bytes());
                buf[2..4].copy_from_slice(&tag.to_be_bytes());
            }
            Self::Fragment { size, tag, offset } => {
                let word = ((DISPATCH_FRAGMENT_HEADER as u16) << 11) | (size & 0b111_1111_1111);
                buf[0..2].copy_from_slice(&word.to_be_bytes());
                buf[2..4].copy_from_slice(&tag.to_be_bytes());
                buf[4] = offset;
            }
        }
    }
}
