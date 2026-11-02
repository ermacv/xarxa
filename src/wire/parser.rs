//! Parsing addresses, CIDR blocks and socket addresses from strings.
//!
//! The parser is copied from `library/core/src/net/parser.rs`.
//!
//! Two deviations:
//!
//! - IPv6 scope ids (`[fe80::1%2]:80`) are rejected since our `SocketAddr` doesn't have a field for it.
//! - Extended to parse CIDR blocks which `std` doesn't have.

use core::str::FromStr;

use crate::error::ParseError;
#[cfg(feature = "ipv4")]
use crate::wire::Ipv4Cidr;
use crate::wire::{IpAddr, IpCidr, SocketAddr};
#[cfg(feature = "ipv6")]
use crate::wire::{Ipv6Addr, Ipv6Cidr};

trait ReadNumberHelper: Sized {
    const ZERO: Self;
    fn checked_mul(&self, other: u32) -> Option<Self>;
    fn checked_add(&self, other: u32) -> Option<Self>;
}

macro_rules! impl_helper {
    ($($t:ty)*) => ($(impl ReadNumberHelper for $t {
        const ZERO: Self = 0;
        #[inline]
        fn checked_mul(&self, other: u32) -> Option<Self> {
            Self::checked_mul(*self, other.try_into().ok()?)
        }
        #[inline]
        fn checked_add(&self, other: u32) -> Option<Self> {
            Self::checked_add(*self, other.try_into().ok()?)
        }
    })*)
}

impl_helper! { u8 u16 u32 }

struct Parser<'a> {
    // Parsing as ASCII, so can use byte array.
    state: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Parser<'a> {
        Parser { state: input }
    }

    /// Run a parser, and restore the pre-parse state if it fails.
    fn read_atomically<T, F>(&mut self, inner: F) -> Option<T>
    where
        F: FnOnce(&mut Parser<'_>) -> Option<T>,
    {
        let state = self.state;
        let result = inner(self);
        if result.is_none() {
            self.state = state;
        }
        result
    }

    /// Run a parser, but fail if the entire input wasn't consumed.
    /// Doesn't run atomically.
    fn parse_with<T, F>(&mut self, inner: F) -> Result<T, ParseError>
    where
        F: FnOnce(&mut Parser<'_>) -> Option<T>,
    {
        let result = inner(self);
        if self.state.is_empty() { result } else { None }.ok_or(ParseError)
    }

    /// Reads the next character from the input
    fn read_char(&mut self) -> Option<char> {
        self.state.split_first().map(|(&b, tail)| {
            self.state = tail;
            char::from(b)
        })
    }

    #[must_use]
    /// Reads the next character from the input if it matches the target.
    fn read_given_char(&mut self, target: char) -> Option<()> {
        self.read_atomically(|p| p.read_char().and_then(|c| if c == target { Some(()) } else { None }))
    }

    /// Helper for reading separators in an indexed loop. Reads the separator
    /// character iff index > 0, then runs the parser. When used in a loop,
    /// the separator character will only be read on index > 0 (see
    /// read_ipv4_addr for an example)
    fn read_separator<T, F>(&mut self, sep: char, index: usize, inner: F) -> Option<T>
    where
        F: FnOnce(&mut Parser<'_>) -> Option<T>,
    {
        self.read_atomically(move |p| {
            if index > 0 {
                p.read_given_char(sep)?;
            }
            inner(p)
        })
    }

    /// Reads a number off the front of the input in the given radix, stopping at the first
    /// non-digit character or eof. Fails if the number has more digits than `max_digits`, if there
    /// is no number, if the number overflows `T`, or if there are leading zeros but
    /// `allow_zero_prefix` is false.
    ///
    /// `max_digits` must be in 1..=6.
    fn read_radix_max_digits<T: ReadNumberHelper + TryFrom<u32>>(
        &mut self,
        radix: u32,
        max_digits: u32,
        allow_zero_prefix: bool,
    ) -> Option<T> {
        debug_assert!(1 <= max_digits);
        debug_assert!(max_digits <= 6); // Works for any radix in u32
        self.read_atomically(|p| {
            let first = p.read_char()?.to_digit(radix)?;
            let mut result = first;
            let mut digit_count = 1;

            while let Some(digit) = p.read_atomically(|p| p.read_char()?.to_digit(radix)) {
                if digit_count >= max_digits {
                    return None;
                }
                result *= radix;
                result += digit;
                digit_count += 1;
            }

            if !allow_zero_prefix && first == 0 && digit_count > 1 {
                None
            } else {
                result.try_into().ok()
            }
        })
    }

    /// Reads a decimal number off the front of the input, stopping at the first non-digit character
    /// or eof. Fails if there is no number, or if the number overflows `T`. Allows an arbitrary
    /// amount of leading zeros.
    fn read_decimal<T: ReadNumberHelper>(&mut self) -> Option<T> {
        self.read_atomically(|p| {
            let first = p.read_char()?.to_digit(10)?;
            let mut result = T::ZERO.checked_add(first)?;

            while let Some(digit) = p.read_atomically(|p| p.read_char()?.to_digit(10)) {
                result = result.checked_mul(10)?;
                result = result.checked_add(digit)?;
            }

            Some(result)
        })
    }

    /// Reads an IPv4 address.
    ///
    /// Always compiled, even without `ipv4`: an IPv6 address may end in an
    /// embedded IPv4 one.
    fn read_ipv4_addr(&mut self) -> Option<::core::net::Ipv4Addr> {
        self.read_atomically(|p| {
            let mut groups = [0; 4];

            for (i, slot) in groups.iter_mut().enumerate() {
                *slot = p.read_separator('.', i, |p| {
                    // Disallow octal number in IP string.
                    // https://tools.ietf.org/html/rfc6943#section-3.1.1
                    p.read_radix_max_digits(10, 3, false)
                })?;
            }

            Some(groups.into())
        })
    }

    /// Reads an IPv6 address.
    #[cfg(feature = "ipv6")]
    fn read_ipv6_addr(&mut self) -> Option<Ipv6Addr> {
        /// Read a chunk of an IPv6 address into `groups`. Returns the number
        /// of groups read, along with a bool indicating if an embedded
        /// trailing IPv4 address was read. Specifically, read a series of
        /// colon-separated IPv6 groups (0x0000 - 0xFFFF), with an optional
        /// trailing embedded IPv4 address.
        fn read_groups(p: &mut Parser<'_>, groups: &mut [u16]) -> (usize, bool) {
            let limit = groups.len();

            for (i, slot) in groups.iter_mut().enumerate() {
                // Try to read a trailing embedded IPv4 address. There must be
                // at least two groups left.
                if i < limit - 1 {
                    let ipv4 = p.read_separator(':', i, |p| p.read_ipv4_addr());

                    if let Some(v4_addr) = ipv4 {
                        let [one, two, three, four] = v4_addr.octets();
                        groups[i] = u16::from_be_bytes([one, two]);
                        groups[i + 1] = u16::from_be_bytes([three, four]);
                        return (i + 2, true);
                    }
                }

                let group = p.read_separator(':', i, |p| p.read_radix_max_digits(16, 4, true));

                match group {
                    Some(g) => *slot = g,
                    None => return (i, false),
                }
            }
            (groups.len(), false)
        }

        self.read_atomically(|p| {
            // Read the front part of the address; either the whole thing, or up
            // to the first ::
            let mut head = [0; 8];
            let (head_size, head_ipv4) = read_groups(p, &mut head);

            if head_size == 8 {
                return Some(head.into());
            }

            // IPv4 part is not allowed before `::`
            if head_ipv4 {
                return None;
            }

            // Read `::` if previous code parsed less than 8 groups.
            // `::` indicates one or more groups of 16 bits of zeros.
            p.read_given_char(':')?;
            p.read_given_char(':')?;

            // Read the back part of the address. The :: must contain at least one
            // set of zeroes, so our max length is 7.
            let mut tail = [0; 7];
            let limit = 8 - (head_size + 1);
            let (tail_size, _) = read_groups(p, &mut tail[..limit]);

            // Concat the head and tail of the IP address
            head[(8 - tail_size)..8].copy_from_slice(&tail[..tail_size]);

            Some(head.into())
        })
    }

    /// Reads an IP address, either IPv4 or IPv6.
    fn read_ip_addr(&mut self) -> Option<IpAddr> {
        #[cfg(feature = "ipv4")]
        if let Some(addr) = self.read_ipv4_addr() {
            return Some(IpAddr::V4(addr));
        }
        #[cfg(feature = "ipv6")]
        if let Some(addr) = self.read_ipv6_addr() {
            return Some(IpAddr::V6(addr));
        }
        None
    }

    /// Reads a `:` followed by a port in base 10.
    fn read_port(&mut self) -> Option<u16> {
        self.read_atomically(|p| {
            p.read_given_char(':')?;
            p.read_decimal()
        })
    }

    /// Reads a `/` followed by a prefix length in base 10.
    ///
    /// Not in `core::net`, which has no CIDR type. Shaped like `read_port`.
    fn read_prefix_len(&mut self) -> Option<u8> {
        self.read_atomically(|p| {
            p.read_given_char('/')?;
            p.read_decimal()
        })
    }

    /// Reads an IPv4 address with a port.
    #[cfg(feature = "ipv4")]
    fn read_socket_addr_v4(&mut self) -> Option<SocketAddr> {
        self.read_atomically(|p| {
            let ip = p.read_ipv4_addr()?;
            let port = p.read_port()?;
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        })
    }

    /// Reads an IPv6 address with a port.
    ///
    /// Unlike `core::net`, a `%scope_id` between the address and the `]` is
    /// not accepted.
    #[cfg(feature = "ipv6")]
    fn read_socket_addr_v6(&mut self) -> Option<SocketAddr> {
        self.read_atomically(|p| {
            p.read_given_char('[')?;
            let ip = p.read_ipv6_addr()?;
            p.read_given_char(']')?;

            let port = p.read_port()?;
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        })
    }

    /// Reads an IP address with a port.
    fn read_socket_addr(&mut self) -> Option<SocketAddr> {
        #[cfg(feature = "ipv4")]
        if let Some(addr) = self.read_socket_addr_v4() {
            return Some(addr);
        }
        #[cfg(feature = "ipv6")]
        if let Some(addr) = self.read_socket_addr_v6() {
            return Some(addr);
        }
        None
    }

    /// Reads an IPv4 address with a prefix length.
    #[cfg(feature = "ipv4")]
    fn read_ipv4_cidr(&mut self) -> Option<Ipv4Cidr> {
        self.read_atomically(|p| {
            let addr = p.read_ipv4_addr()?;
            let prefix_len = p.read_prefix_len()?;
            Ipv4Cidr::try_new(addr, prefix_len)
        })
    }

    /// Reads an IPv6 address with a prefix length.
    #[cfg(feature = "ipv6")]
    fn read_ipv6_cidr(&mut self) -> Option<Ipv6Cidr> {
        self.read_atomically(|p| {
            let addr = p.read_ipv6_addr()?;
            let prefix_len = p.read_prefix_len()?;
            Ipv6Cidr::try_new(addr, prefix_len)
        })
    }

    /// Reads a CIDR block, either IPv4 or IPv6.
    fn read_ip_cidr(&mut self) -> Option<IpCidr> {
        #[cfg(feature = "ipv4")]
        if let Some(cidr) = self.read_ipv4_cidr() {
            return Some(IpCidr::V4(cidr));
        }
        #[cfg(feature = "ipv6")]
        if let Some(cidr) = self.read_ipv6_cidr() {
            return Some(IpCidr::V6(cidr));
        }
        None
    }
}

impl FromStr for IpAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<IpAddr, ParseError> {
        Parser::new(s.as_bytes()).parse_with(|p| p.read_ip_addr())
    }
}

impl FromStr for SocketAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<SocketAddr, ParseError> {
        Parser::new(s.as_bytes()).parse_with(|p| p.read_socket_addr())
    }
}

impl FromStr for IpCidr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<IpCidr, ParseError> {
        Parser::new(s.as_bytes()).parse_with(|p| p.read_ip_cidr())
    }
}

#[cfg(feature = "ipv4")]
impl FromStr for Ipv4Cidr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Ipv4Cidr, ParseError> {
        Parser::new(s.as_bytes()).parse_with(|p| p.read_ipv4_cidr())
    }
}

#[cfg(feature = "ipv6")]
impl FromStr for Ipv6Cidr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Ipv6Cidr, ParseError> {
        Parser::new(s.as_bytes()).parse_with(|p| p.read_ipv6_cidr())
    }
}

#[cfg(test)]
mod test {
    #![allow(unused)]

    use super::*;

    // Ported from `library/coretests/tests/net/parser.rs`, with the address
    // types swapped for xarxa's and the scope id case inverted.

    const PORT: u16 = 8080;

    const IPV4: ::core::net::Ipv4Addr = ::core::net::Ipv4Addr::new(192, 168, 0, 1);
    const IPV4_STR: &str = "192.168.0.1";
    const IPV4_STR_PORT: &str = "192.168.0.1:8080";
    const IPV4_STR_WITH_OCTAL: &str = "0127.0.0.1";
    const IPV4_STR_WITH_HEX: &str = "0x10.0.0.1";

    const IPV6: ::core::net::Ipv6Addr = ::core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xc0a8, 0x1);
    const IPV6_STR_FULL: &str = "2001:db8:0:0:0:0:c0a8:1";
    const IPV6_STR_COMPRESS: &str = "2001:db8::c0a8:1";
    const IPV6_STR_V4: &str = "2001:db8::192.168.0.1";
    const IPV6_STR_V4_WITH_OCTAL: &str = "2001:db8::0127.0.0.1";
    const IPV6_STR_V4_WITH_HEX: &str = "2001:db8::0x10.0.0.1";
    const IPV6_STR_PORT: &str = "[2001:db8::c0a8:1]:8080";
    const IPV6_STR_PORT_SCOPE_ID: &str = "[2001:db8::c0a8:1%1337]:8080";

    #[cfg(feature = "ipv6")]
    fn v6(s: &str) -> Ipv6Addr {
        match s.parse::<IpAddr>().unwrap() {
            IpAddr::V6(addr) => addr,
            #[cfg(feature = "ipv4")]
            other => panic!("{s} parsed as {other}"),
        }
    }

    #[cfg(feature = "ipv4")]
    #[test]
    fn parse_ipv4() {
        assert_eq!(IPV4_STR.parse(), Ok(IpAddr::V4(IPV4)));

        assert!(IPV4_STR_PORT.parse::<IpAddr>().is_err());
        assert!(IPV4_STR_WITH_OCTAL.parse::<IpAddr>().is_err());
        assert!(IPV4_STR_WITH_HEX.parse::<IpAddr>().is_err());
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn parse_ipv6() {
        assert_eq!(IPV6_STR_FULL.parse(), Ok(IpAddr::V6(IPV6)));
        assert_eq!(IPV6_STR_COMPRESS.parse(), Ok(IpAddr::V6(IPV6)));
        assert_eq!(IPV6_STR_V4.parse(), Ok(IpAddr::V6(IPV6)));

        assert!(IPV6_STR_V4_WITH_OCTAL.parse::<IpAddr>().is_err());
        assert!(IPV6_STR_V4_WITH_HEX.parse::<IpAddr>().is_err());
        assert!(IPV6_STR_PORT.parse::<IpAddr>().is_err());
    }

    #[test]
    fn parse_ip() {
        #[cfg(feature = "ipv4")]
        assert_eq!(IPV4_STR.parse(), Ok(IpAddr::V4(IPV4)));

        #[cfg(feature = "ipv6")]
        {
            assert_eq!(IPV6_STR_FULL.parse(), Ok(IpAddr::V6(IPV6)));
            assert_eq!(IPV6_STR_COMPRESS.parse(), Ok(IpAddr::V6(IPV6)));
            assert_eq!(IPV6_STR_V4.parse(), Ok(IpAddr::V6(IPV6)));
        }

        assert!(IPV4_STR_PORT.parse::<IpAddr>().is_err());
        assert!(IPV6_STR_PORT.parse::<IpAddr>().is_err());
        assert!("".parse::<IpAddr>().is_err());
        assert!("x".parse::<IpAddr>().is_err());
    }

    #[cfg(feature = "ipv4")]
    #[test]
    fn parse_socket_v4() {
        assert_eq!(IPV4_STR_PORT.parse(), Ok(SocketAddr::new(IpAddr::V4(IPV4), PORT)));
        assert_eq!(
            "0.0.0.0:0".parse(),
            Ok(SocketAddr::new(IpAddr::V4(::core::net::Ipv4Addr::UNSPECIFIED), 0))
        );

        assert!(IPV4_STR.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_FULL.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_COMPRESS.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_V4.parse::<SocketAddr>().is_err());
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn parse_socket_v6() {
        assert_eq!(IPV6_STR_PORT.parse(), Ok(SocketAddr::new(IpAddr::V6(IPV6), PORT)));
        assert_eq!(
            "[::]:8080".parse(),
            Ok(SocketAddr::new(IpAddr::V6(::core::net::Ipv6Addr::UNSPECIFIED), PORT))
        );

        assert!(IPV4_STR.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_FULL.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_COMPRESS.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_V4.parse::<SocketAddr>().is_err());
    }

    /// Where xarxa departs from `core::net`, which parses the scope id and
    /// keeps it in a `SocketAddrV6`.
    #[cfg(feature = "ipv6")]
    #[test]
    fn parse_socket_v6_scope_id_rejected() {
        assert!(IPV6_STR_PORT_SCOPE_ID.parse::<SocketAddr>().is_err());
        assert!("[fe80::1%0]:8080".parse::<SocketAddr>().is_err());
        assert!("fe80::1%1337".parse::<IpAddr>().is_err());
    }

    #[test]
    fn parse_socket() {
        #[cfg(feature = "ipv4")]
        assert_eq!(IPV4_STR_PORT.parse(), Ok(SocketAddr::new(IpAddr::V4(IPV4), PORT)));

        #[cfg(feature = "ipv6")]
        assert_eq!(IPV6_STR_PORT.parse(), Ok(SocketAddr::new(IpAddr::V6(IPV6), PORT)));

        assert!(IPV4_STR.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_FULL.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_COMPRESS.parse::<SocketAddr>().is_err());
        assert!(IPV6_STR_V4.parse::<SocketAddr>().is_err());
        assert!("".parse::<SocketAddr>().is_err());
        assert!("x".parse::<SocketAddr>().is_err());
    }

    /// Ports are read like `core::net` reads them: decimal digits only, any
    /// number of leading zeros, no sign.
    #[test]
    fn parse_port() {
        #[cfg(feature = "ipv4")]
        {
            assert_eq!(
                "1.2.3.4:0".parse(),
                Ok(SocketAddr::new(IpAddr::V4(::core::net::Ipv4Addr::new(1, 2, 3, 4)), 0))
            );
            assert_eq!(
                "1.2.3.4:65535".parse(),
                Ok(SocketAddr::new(
                    IpAddr::V4(::core::net::Ipv4Addr::new(1, 2, 3, 4)),
                    65535
                ))
            );
            assert_eq!(
                "1.2.3.4:0000008080".parse(),
                Ok(SocketAddr::new(
                    IpAddr::V4(::core::net::Ipv4Addr::new(1, 2, 3, 4)),
                    PORT
                ))
            );

            assert!("1.2.3.4:65536".parse::<SocketAddr>().is_err());
            assert!("1.2.3.4:+80".parse::<SocketAddr>().is_err());
            assert!("1.2.3.4:-1".parse::<SocketAddr>().is_err());
            assert!("1.2.3.4:0x50".parse::<SocketAddr>().is_err());
            assert!("1.2.3.4:".parse::<SocketAddr>().is_err());
            assert!("1.2.3.4: 80".parse::<SocketAddr>().is_err());
        }

        #[cfg(feature = "ipv6")]
        {
            assert!("[::1]:+80".parse::<SocketAddr>().is_err());
            assert!("[::1]80".parse::<SocketAddr>().is_err());
            assert!("[::1]:".parse::<SocketAddr>().is_err());
            assert!("[::1]".parse::<SocketAddr>().is_err());
            assert!("[]:80".parse::<SocketAddr>().is_err());
            assert!("[[::1]]:80".parse::<SocketAddr>().is_err());
            assert!("[::1]:80]".parse::<SocketAddr>().is_err());
            assert!("[::1:80".parse::<SocketAddr>().is_err());
        }
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn ipv6_corner_cases() {
        assert_eq!(v6("1::"), Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(v6("1:1::"), Ipv6Addr::new(1, 1, 0, 0, 0, 0, 0, 0));
        assert_eq!(v6("::1"), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(v6("::1:1"), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 1, 1));
        assert_eq!(v6("::"), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(v6("::192.168.0.1"), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc0a8, 0x1));
        assert_eq!(v6("::1:192.168.0.1"), Ipv6Addr::new(0, 0, 0, 0, 0, 1, 0xc0a8, 0x1));
        assert_eq!(
            v6("1:1:1:1:1:1:192.168.0.1"),
            Ipv6Addr::new(1, 1, 1, 1, 1, 1, 0xc0a8, 0x1)
        );
    }

    // Things that might not seem like failures but are
    #[cfg(feature = "ipv6")]
    #[test]
    fn ipv6_corner_failures() {
        // No IP address before the ::
        assert!("1:192.168.0.1::".parse::<IpAddr>().is_err());

        // :: must have at least 1 set of zeroes
        assert!("1:1:1:1::1:1:1:1".parse::<IpAddr>().is_err());

        // Need brackets for a port
        assert!("1:1:1:1:1:1:1:1:8080".parse::<SocketAddr>().is_err());
    }

    // `core::net` has no CIDR type, so these are xarxa's own. The prefix
    // length is read exactly like a port.

    #[cfg(feature = "ipv4")]
    #[test]
    fn parse_ipv4_cidr() {
        assert_eq!("192.168.0.1/24".parse(), Ok(Ipv4Cidr::new(IPV4, 24)));
        assert_eq!("192.168.0.1/24".parse(), Ok(IpCidr::V4(Ipv4Cidr::new(IPV4, 24))));
        assert_eq!("192.168.0.1/0".parse(), Ok(Ipv4Cidr::new(IPV4, 0)));
        assert_eq!("192.168.0.1/32".parse(), Ok(Ipv4Cidr::new(IPV4, 32)));
        assert_eq!("192.168.0.1/0024".parse(), Ok(Ipv4Cidr::new(IPV4, 24)));

        assert!("192.168.0.1/33".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1/256".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1/+24".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1/-1".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1/".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1".parse::<Ipv4Cidr>().is_err());
        assert!("192.168.0.1/24/25".parse::<Ipv4Cidr>().is_err());
        assert!(IPV4_STR_WITH_OCTAL.parse::<Ipv4Cidr>().is_err());
        assert!("/24".parse::<Ipv4Cidr>().is_err());
        assert!("1".parse::<Ipv4Cidr>().is_err());
        assert!("".parse::<Ipv4Cidr>().is_err());

        assert!("192.168.0.1/33".parse::<IpCidr>().is_err());
        assert!("192.168.0.1".parse::<IpCidr>().is_err());
        assert!("/24".parse::<IpCidr>().is_err());
        assert!("".parse::<IpCidr>().is_err());
    }

    #[cfg(feature = "ipv6")]
    #[test]
    fn parse_ipv6_cidr() {
        assert_eq!("2001:db8::c0a8:1/64".parse(), Ok(Ipv6Cidr::new(IPV6, 64)));
        assert_eq!("2001:db8::c0a8:1/64".parse(), Ok(IpCidr::V6(Ipv6Cidr::new(IPV6, 64))));
        assert_eq!("2001:db8::c0a8:1/0".parse(), Ok(Ipv6Cidr::new(IPV6, 0)));
        assert_eq!("2001:db8::c0a8:1/128".parse(), Ok(Ipv6Cidr::new(IPV6, 128)));
        assert_eq!("2001:db8::c0a8:1/0064".parse(), Ok(Ipv6Cidr::new(IPV6, 64)));

        assert!("2001:db8::c0a8:1/129".parse::<Ipv6Cidr>().is_err());
        assert!("2001:db8::c0a8:1/256".parse::<Ipv6Cidr>().is_err());
        assert!("2001:db8::c0a8:1/+64".parse::<Ipv6Cidr>().is_err());
        assert!("2001:db8::c0a8:1/".parse::<Ipv6Cidr>().is_err());
        assert!("2001:db8::c0a8:1".parse::<Ipv6Cidr>().is_err());
        assert!("[2001:db8::c0a8:1]/64".parse::<Ipv6Cidr>().is_err());
        assert!("fe80::1%1337/64".parse::<Ipv6Cidr>().is_err());
        assert!("2001:db8::c0a8:1|64".parse::<Ipv6Cidr>().is_err());
        assert!("fe80::1::/64".parse::<Ipv6Cidr>().is_err());

        assert!("2001:db8::c0a8:1/129".parse::<IpCidr>().is_err());
        assert!("2001:db8::c0a8:1|64".parse::<IpCidr>().is_err());
        assert!("fe80::1::/64".parse::<IpCidr>().is_err());
    }

    /// Everything the `Display` impls print parses back to the same value.
    #[test]
    fn round_trip_display() {
        #[cfg(feature = "ipv4")]
        {
            let addr = IpAddr::V4(IPV4);
            let sock = SocketAddr::new(addr, PORT);
            let cidr = IpCidr::V4(Ipv4Cidr::new(IPV4, 24));
            assert_eq!(format!("{addr}").parse(), Ok(addr));
            assert_eq!(format!("{sock}").parse(), Ok(sock));
            assert_eq!(format!("{cidr}").parse(), Ok(cidr));
        }

        #[cfg(feature = "ipv6")]
        {
            let addr = IpAddr::V6(IPV6);
            let sock = SocketAddr::new(addr, PORT);
            let cidr = IpCidr::V6(Ipv6Cidr::new(IPV6, 64));
            assert_eq!(format!("{addr}").parse(), Ok(addr));
            assert_eq!(format!("{sock}").parse(), Ok(sock));
            assert_eq!(format!("{cidr}").parse(), Ok(cidr));
        }
    }
}
