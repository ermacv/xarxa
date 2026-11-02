/// Unwrap a parse result in ingress code, returning early (with the function's
/// default return value) on a malformed packet.
macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                trace!("iface: malformed ingress packet");
                return Default::default();
            }
        }
    };
}

macro_rules! open_enum {
    (
        $( #[$enum_attr:meta] )*
        pub enum $name:ident($ty:ty) {
            $(
              $( #[$variant_attr:meta] )*
              $variant:ident = $value:expr
            ),+ $(,)?
        }
    ) => {
        $( #[$enum_attr] )*
        #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
        pub struct $name(pub $ty);

        #[allow(non_upper_case_globals)]
        impl $name {
            $(
              $( #[$variant_attr] )*
              pub const $variant: Self = Self($value);
            )*
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match *self {
                    $( Self::$variant => f.write_str(stringify!($variant)), )*
                    Self(other) => write!(f, "0x{:01$x}", other, ::core::mem::size_of::<$ty>() * 2),
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }

        #[cfg(feature = "defmt")]
        impl ::defmt::Format for $name {
            fn format(&self, f: ::defmt::Formatter) {
                // The variant names are interned into the ELF (never sent over the
                // wire) by deriving `Format` on a fieldless mirror enum. `intern!`
                // itself can't be used here: it's a proc macro that requires a
                // string literal, and `stringify!($variant)` isn't one yet at the
                // point it would see it.
                #[derive(::defmt::Format)]
                #[allow(non_camel_case_types)]
                enum Names {
                    $( $variant, )*
                }

                let name = match *self {
                    $( Self::$variant => Names::$variant, )*
                    Self(other) => {
                        ::defmt::write!(f, "{:#x}", other);
                        return;
                    }
                };
                ::defmt::write!(f, "{}", name);
            }
        }

        impl ::core::convert::From<$ty> for $name {
            fn from(value: $ty) -> Self {
                Self(value)
            }
        }

        impl ::core::convert::From<$name> for $ty {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    }
}

/// Define a handle type over one of the generated `config::*_index` modules.
///
/// Each handle wraps an index type chosen by `build.rs` from the matching
/// `*_COUNT` knob: `()` when only one slot exists, `u8`/`u16`/`u32` for
/// larger counts, and `usize` with `alloc` (where the knobs are ignored).
/// The generated `config::*_index` modules hold the type and its `usize`
/// conversions.
macro_rules! define_handle {
    ($(#[$m:meta])* $name:ident($($index:ident)::+)) => {
        $(#[$m])*
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($($index)::+::Index);

        impl $name {
            #[inline]
            pub(crate) const fn new(index: usize) -> Self {
                Self($($index)::+::from_usize(index))
            }

            #[inline]
            pub(crate) const fn index(self) -> usize {
                $($index)::+::to_usize(self.0)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    /// The size a handle over a slab of `count` slots should have.
    ///
    /// Mirrors the type choice in `build.rs`. With `alloc` the knobs are
    /// ignored and every handle is a `usize`.
    fn expected_size(count: usize) -> usize {
        if cfg!(feature = "alloc") {
            size_of::<usize>()
        } else {
            match count {
                1 => 0,
                2..=256 => 1,
                257..=65536 => 2,
                _ => 4,
            }
        }
    }

    /// Check a handle's size, and that `new`/`index` round-trip every index a
    /// full slab can hold.
    macro_rules! check_handle {
        ($handle:ty, $count:expr) => {
            let count: usize = $count;
            assert_eq!(size_of::<$handle>(), expected_size(count));
            for i in 0..count {
                let h = <$handle>::new(i);
                assert_eq!(h.index(), i);
                assert_eq!(h, <$handle>::new(i));
            }
        };
    }

    #[test]
    fn handle_sizes() {
        check_handle!(crate::iface::IfaceHandle, crate::config::IFACE_COUNT);
        #[cfg(feature = "udp")]
        check_handle!(crate::udp::UdpHandle, crate::config::UDP_SOCKET_COUNT);
        #[cfg(feature = "_raw")]
        check_handle!(crate::raw::RawHandle, crate::config::RAW_SOCKET_COUNT);
        #[cfg(feature = "tcp")]
        check_handle!(crate::tcp::TcpHandle, crate::config::TCP_SOCKET_COUNT);
        #[cfg(feature = "tcp-listener")]
        check_handle!(crate::tcp::TcpListenerHandle, crate::config::TCP_LISTENER_COUNT);
        #[cfg(feature = "dns")]
        check_handle!(crate::dns::DnsQueryHandle, crate::config::DNS_MAX_QUERY_COUNT);
    }
}
