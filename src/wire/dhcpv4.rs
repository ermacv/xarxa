// See https://tools.ietf.org/html/rfc2131 for the DHCP specification.

use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};
use core::iter;

use crate::error::Malformed;
use crate::wire::arp::Hardware;
use crate::wire::{EthernetAddress, Ipv4Addr};

/// The UDP port DHCP servers listen on.
pub const SERVER_PORT: u16 = 67;
/// The UDP port DHCP clients listen on.
pub const CLIENT_PORT: u16 = 68;

/// The magic cookie that starts the options field of every DHCP packet.
pub const MAGIC_NUMBER: u32 = 0x63825363;

/// DHCP Hostname option code.
const OPTION_KIND_HOSTNAME: u8 = 12;

open_enum! {
    /// The opcode of a DHCP packet.
    pub enum OpCode(u8) {
        Request = 1,
        Reply = 2,
    }
}

open_enum! {
    /// The message type of a DHCP packet, from the message type option.
    pub enum MessageType(u8) {
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8,
    }
}

bitflags! {
    /// The flags field of a DHCP packet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u16 {
        /// Ask the server to broadcast its replies.
        const BROADCAST = 0b1000_0000_0000_0000;
    }
}

impl MessageType {
    /// The opcode that goes with a message type.
    pub const fn opcode(&self) -> OpCode {
        match *self {
            MessageType::Discover
            | MessageType::Inform
            | MessageType::Request
            | MessageType::Decline
            | MessageType::Release => OpCode::Request,
            MessageType::Offer | MessageType::Ack | MessageType::Nak => OpCode::Reply,
            _ => OpCode(0),
        }
    }
}

/// Writes DHCP options into the options field of a packet, one after the other.
///
/// Returned by [`Packet::options_mut`].
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OptionWriter<'a> {
    buffer: &'a mut [u8],
    written: usize,
}

impl<'a> OptionWriter<'a> {
    /// Start writing options at the beginning of `buffer`.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, written: 0 }
    }

    /// Write one option.
    ///
    /// # Errors
    /// - `Malformed`: if the option data is longer than 255 bytes, or does not
    ///   fit in the remaining space.
    pub fn emit(&mut self, option: DhcpOption<'_>) -> Result<(), Malformed> {
        if option.data.len() > u8::MAX as _ {
            return Err(Malformed);
        }

        let total_len = 2 + option.data.len();
        if self.buffer.len() < total_len {
            return Err(Malformed);
        }

        let (buf, rest) = core::mem::take(&mut self.buffer).split_at_mut(total_len);
        self.buffer = rest;
        self.written += total_len;

        buf[0] = option.kind;
        buf[1] = option.data.len() as _;
        buf[2..].copy_from_slice(option.data);

        Ok(())
    }

    /// Write the end marker. No more options can be written after this.
    ///
    /// # Errors
    /// - `Malformed`: if there is no space left.
    pub fn end(&mut self) -> Result<(), Malformed> {
        if self.buffer.is_empty() {
            return Err(Malformed);
        }

        self.buffer[0] = field::OPT_END;
        self.buffer = &mut [];
        self.written += 1;
        Ok(())
    }

    /// How many bytes have been written so far, the end marker included.
    pub fn written(&self) -> usize {
        self.written
    }
}

/// One DHCP option: a kind and its data.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DhcpOption<'a> {
    /// The option code.
    pub kind: u8,
    /// The option data.
    pub data: &'a [u8],
}

impl<'a> DhcpOption<'a> {
    /// Constructs a DHCP Hostname option.
    ///
    /// The maximum length of the hostname slice must be at most 255 bytes.
    ///
    /// # Usage
    ///
    /// ```no_run
    /// # use xarxa::wire::DhcpOption;
    /// let opt = DhcpOption::hostname(b"my_device");
    /// ```
    pub fn hostname(hostname: &'a [u8]) -> Self {
        Self {
            kind: OPTION_KIND_HOSTNAME,
            data: hostname,
        }
    }
}

/// A read/write wrapper around a Dynamic Host Configuration Protocol packet buffer.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

pub(crate) mod field {
    #![allow(non_snake_case)]
    #![allow(unused)]

    use crate::wire::field::*;

    pub const OP: usize = 0;
    pub const HTYPE: usize = 1;
    pub const HLEN: usize = 2;
    pub const HOPS: usize = 3;
    pub const XID: Field = 4..8;
    pub const SECS: Field = 8..10;
    pub const FLAGS: Field = 10..12;
    pub const CIADDR: Field = 12..16;
    pub const YIADDR: Field = 16..20;
    pub const SIADDR: Field = 20..24;
    pub const GIADDR: Field = 24..28;
    pub const CHADDR: Field = 28..34;
    pub const SNAME: Field = 34..108;
    pub const FILE: Field = 108..236;
    pub const MAGIC_NUMBER: Field = 236..240;
    pub const OPTIONS: Rest = 240..;

    // Vendor Extensions
    pub const OPT_END: u8 = 255;
    pub const OPT_PAD: u8 = 0;
    pub const OPT_SUBNET_MASK: u8 = 1;
    pub const OPT_TIME_OFFSET: u8 = 2;
    pub const OPT_ROUTER: u8 = 3;
    pub const OPT_TIME_SERVER: u8 = 4;
    pub const OPT_NAME_SERVER: u8 = 5;
    pub const OPT_DOMAIN_NAME_SERVER: u8 = 6;
    pub const OPT_LOG_SERVER: u8 = 7;
    pub const OPT_COOKIE_SERVER: u8 = 8;
    pub const OPT_LPR_SERVER: u8 = 9;
    pub const OPT_IMPRESS_SERVER: u8 = 10;
    pub const OPT_RESOURCE_LOCATION_SERVER: u8 = 11;
    pub const OPT_HOST_NAME: u8 = 12;
    pub const OPT_BOOT_FILE_SIZE: u8 = 13;
    pub const OPT_MERIT_DUMP: u8 = 14;
    pub const OPT_DOMAIN_NAME: u8 = 15;
    pub const OPT_SWAP_SERVER: u8 = 16;
    pub const OPT_ROOT_PATH: u8 = 17;
    pub const OPT_EXTENSIONS_PATH: u8 = 18;

    // IP Layer Parameters per Host
    pub const OPT_IP_FORWARDING: u8 = 19;
    pub const OPT_NON_LOCAL_SOURCE_ROUTING: u8 = 20;
    pub const OPT_POLICY_FILTER: u8 = 21;
    pub const OPT_MAX_DATAGRAM_REASSEMBLY_SIZE: u8 = 22;
    pub const OPT_DEFAULT_TTL: u8 = 23;
    pub const OPT_PATH_MTU_AGING_TIMEOUT: u8 = 24;
    pub const OPT_PATH_MTU_PLATEAU_TABLE: u8 = 25;

    // IP Layer Parameters per Interface
    pub const OPT_INTERFACE_MTU: u8 = 26;
    pub const OPT_ALL_SUBNETS_ARE_LOCAL: u8 = 27;
    pub const OPT_BROADCAST_ADDRESS: u8 = 28;
    pub const OPT_PERFORM_MASK_DISCOVERY: u8 = 29;
    pub const OPT_MASK_SUPPLIER: u8 = 30;
    pub const OPT_PERFORM_ROUTER_DISCOVERY: u8 = 31;
    pub const OPT_ROUTER_SOLICITATION_ADDRESS: u8 = 32;
    pub const OPT_STATIC_ROUTE: u8 = 33;

    // Link Layer Parameters per Interface
    pub const OPT_TRAILER_ENCAPSULATION: u8 = 34;
    pub const OPT_ARP_CACHE_TIMEOUT: u8 = 35;
    pub const OPT_ETHERNET_ENCAPSULATION: u8 = 36;

    // TCP Parameters
    pub const OPT_TCP_DEFAULT_TTL: u8 = 37;
    pub const OPT_TCP_KEEPALIVE_INTERVAL: u8 = 38;
    pub const OPT_TCP_KEEPALIVE_GARBAGE: u8 = 39;

    // Application and Service Parameters
    pub const OPT_NIS_DOMAIN: u8 = 40;
    pub const OPT_NIS_SERVERS: u8 = 41;
    pub const OPT_NTP_SERVERS: u8 = 42;
    pub const OPT_VENDOR_SPECIFIC_INFO: u8 = 43;
    pub const OPT_NETBIOS_NAME_SERVER: u8 = 44;
    pub const OPT_NETBIOS_DISTRIBUTION_SERVER: u8 = 45;
    pub const OPT_NETBIOS_NODE_TYPE: u8 = 46;
    pub const OPT_NETBIOS_SCOPE: u8 = 47;
    pub const OPT_X_WINDOW_FONT_SERVER: u8 = 48;
    pub const OPT_X_WINDOW_DISPLAY_MANAGER: u8 = 49;
    pub const OPT_NIS_PLUS_DOMAIN: u8 = 64;
    pub const OPT_NIS_PLUS_SERVERS: u8 = 65;
    pub const OPT_MOBILE_IP_HOME_AGENT: u8 = 68;
    pub const OPT_SMTP_SERVER: u8 = 69;
    pub const OPT_POP3_SERVER: u8 = 70;
    pub const OPT_NNTP_SERVER: u8 = 71;
    pub const OPT_WWW_SERVER: u8 = 72;
    pub const OPT_FINGER_SERVER: u8 = 73;
    pub const OPT_IRC_SERVER: u8 = 74;
    pub const OPT_STREETTALK_SERVER: u8 = 75;
    pub const OPT_STDA_SERVER: u8 = 76;

    // DHCP Extensions
    pub const OPT_REQUESTED_IP: u8 = 50;
    pub const OPT_IP_LEASE_TIME: u8 = 51;
    pub const OPT_OPTION_OVERLOAD: u8 = 52;
    pub const OPT_TFTP_SERVER_NAME: u8 = 66;
    pub const OPT_BOOTFILE_NAME: u8 = 67;
    pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
    pub const OPT_SERVER_IDENTIFIER: u8 = 54;
    pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
    pub const OPT_MESSAGE: u8 = 56;
    pub const OPT_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
    pub const OPT_RENEWAL_TIME_VALUE: u8 = 58;
    pub const OPT_REBINDING_TIME_VALUE: u8 = 59;
    pub const OPT_VENDOR_CLASS_ID: u8 = 60;
    pub const OPT_CLIENT_ID: u8 = 61;
}

/// Length of the fixed part of a DHCP packet, everything before the options.
pub const HEADER_LEN: usize = field::MAGIC_NUMBER.end;

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with DHCP packet structure.
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
        if len < HEADER_LEN { Err(Malformed) } else { Ok(()) }
    }

    /// Return the operation code of this packet.
    pub fn opcode(&self) -> OpCode {
        OpCode::from(self.buffer[field::OP])
    }

    /// Return the hardware protocol type (e.g. ethernet).
    pub fn hardware_type(&self) -> Hardware {
        Hardware::from(u16::from(self.buffer[field::HTYPE]))
    }

    /// Return the length of a hardware address in bytes (e.g. 6 for ethernet).
    pub fn hardware_len(&self) -> u8 {
        self.buffer[field::HLEN]
    }

    /// Return the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn transaction_id(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::XID])
    }

    /// Return the hardware address of the client (called `chaddr` in the specification).
    ///
    /// Only ethernet is supported, so this returns an `EthernetAddress`.
    pub fn client_hardware_address(&self) -> EthernetAddress {
        EthernetAddress::from_bytes(&self.buffer[field::CHADDR])
    }

    /// Return the value of the `hops` field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn hops(&self) -> u8 {
        self.buffer[field::HOPS]
    }

    /// Return the value of the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn secs(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::SECS])
    }

    /// Return the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn magic_number(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::MAGIC_NUMBER])
    }

    /// Return the Ipv4 address of the client, zero if not set.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn client_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.buffer[field::CIADDR].try_into().unwrap())
    }

    /// Return the value of the `yiaddr` field, zero if not set.
    pub fn your_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.buffer[field::YIADDR].try_into().unwrap())
    }

    /// Return the value of the `siaddr` field, zero if not set.
    pub fn server_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.buffer[field::SIADDR].try_into().unwrap())
    }

    /// Return the value of the `giaddr` field, zero if not set.
    pub fn relay_agent_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.buffer[field::GIADDR].try_into().unwrap())
    }

    /// Return the flags field.
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(NetworkEndian::read_u16(&self.buffer[field::FLAGS]))
    }

    /// Return an iterator over the options.
    ///
    /// Iteration stops at the end marker, at the end of the buffer, or at the
    /// first malformed option.
    #[inline]
    pub fn options(&self) -> impl Iterator<Item = DhcpOption<'_>> + '_ {
        let mut buf = &self.buffer[field::OPTIONS];
        iter::from_fn(move || {
            loop {
                match buf.first().copied() {
                    // No more options, return.
                    None => return None,
                    Some(field::OPT_END) => return None,

                    // Skip padding.
                    Some(field::OPT_PAD) => buf = &buf[1..],
                    Some(kind) => {
                        if buf.len() < 2 {
                            return None;
                        }

                        let len = buf[1] as usize;

                        if buf.len() < 2 + len {
                            return None;
                        }

                        let opt = DhcpOption {
                            kind,
                            data: &buf[2..2 + len],
                        };

                        buf = &buf[2 + len..];
                        return Some(opt);
                    }
                }
            }
        })
    }

    /// Return the data of the first option of the given kind, if present.
    pub fn option(&self, kind: u8) -> Option<&[u8]> {
        self.options().find(|opt| opt.kind == kind).map(|opt| opt.data)
    }

    /// Return the message type, from the message type option.
    ///
    /// # Errors
    /// - `Malformed`: if the option is missing or malformed.
    pub fn message_type(&self) -> Result<MessageType, Malformed> {
        match self.option(field::OPT_DHCP_MESSAGE_TYPE) {
            Some(&[value]) => Ok(MessageType::from(value)),
            _ => Err(Malformed),
        }
    }

    /// Return the `sname` (server name) field as a string.
    ///
    /// # Errors
    /// - `Malformed`: if the field is empty or not valid UTF-8.
    pub fn sname(&self) -> Result<&str, Malformed> {
        let data = &self.buffer[field::SNAME];
        let len = data.iter().position(|&x| x == 0).ok_or(Malformed)?;
        if len == 0 {
            return Err(Malformed);
        }

        let data = core::str::from_utf8(&data[..len]).map_err(|_| Malformed)?;
        Ok(data)
    }

    /// Return the `file` (boot file name) field as a string.
    ///
    /// # Errors
    /// - `Malformed`: if the field is empty or not valid UTF-8.
    pub fn boot_file(&self) -> Result<&str, Malformed> {
        let data = &self.buffer[field::FILE];
        let len = data.iter().position(|&x| x == 0).ok_or(Malformed)?;
        if len == 0 {
            return Err(Malformed);
        }
        let data = core::str::from_utf8(&data[..len]).map_err(|_| Malformed)?;
        Ok(data)
    }

    /// Set the optional `sname` (“server name”) and `file` (“boot file name”) fields to zero.
    ///
    /// The fields are not commonly used, so we set their value always to zero. **This method
    /// must be called when creating a packet, otherwise the emitted values for these fields
    /// are undefined!**
    pub fn set_sname_and_boot_file_to_zero(&mut self) {
        self.buffer[field::SNAME].fill(0);
        self.buffer[field::FILE].fill(0);
    }

    /// Set the `OpCode` for the packet.
    pub fn set_opcode(&mut self, value: OpCode) {
        self.buffer[field::OP] = value.into();
    }

    /// Set the hardware address type (only ethernet is supported).
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let number: u16 = value.into();
        assert!(number <= u16::from(u8::MAX));
        self.buffer[field::HTYPE] = number as u8;
    }

    /// Set the hardware address length.
    ///
    /// Only ethernet is supported, so this field should be set to the value `6`.
    pub fn set_hardware_len(&mut self, value: u8) {
        self.buffer[field::HLEN] = value;
    }

    /// Set the transaction ID.
    ///
    /// The transaction ID (called `xid` in the specification) is a random number used to
    /// associate messages and responses between client and server. The number is chosen by
    /// the client.
    pub fn set_transaction_id(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::XID], value)
    }

    /// Set the ethernet address of the client.
    ///
    /// Sets the `chaddr` field.
    pub fn set_client_hardware_address(&mut self, value: EthernetAddress) {
        self.buffer[field::CHADDR].copy_from_slice(value.as_bytes());
    }

    /// Set the hops field.
    ///
    /// The `hops` field is set to zero by clients and optionally used by relay agents.
    pub fn set_hops(&mut self, value: u8) {
        self.buffer[field::HOPS] = value;
    }

    /// Set the `secs` field.
    ///
    /// The secs field is filled by clients and describes the number of seconds elapsed
    /// since client began process.
    pub fn set_secs(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::SECS], value);
    }

    /// Set the value of the `magic cookie` field in the DHCP options.
    ///
    /// This field should be always be `0x63825363`.
    pub fn set_magic_number(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::MAGIC_NUMBER], value);
    }

    /// Set the Ipv4 address of the client.
    ///
    /// This corresponds to the `ciaddr` field in the DHCP specification. According to it,
    /// this field is “only filled in if client is in `BOUND`, `RENEW` or `REBINDING` state
    /// and can respond to ARP requests”.
    pub fn set_client_ip(&mut self, value: Ipv4Addr) {
        self.buffer[field::CIADDR].copy_from_slice(&value.octets());
    }

    /// Set the value of the `yiaddr` field.
    pub fn set_your_ip(&mut self, value: Ipv4Addr) {
        self.buffer[field::YIADDR].copy_from_slice(&value.octets());
    }

    /// Set the value of the `siaddr` field.
    pub fn set_server_ip(&mut self, value: Ipv4Addr) {
        self.buffer[field::SIADDR].copy_from_slice(&value.octets());
    }

    /// Set the value of the `giaddr` field.
    pub fn set_relay_agent_ip(&mut self, value: Ipv4Addr) {
        self.buffer[field::GIADDR].copy_from_slice(&value.octets());
    }

    /// Set the flags to the specified value.
    pub fn set_flags(&mut self, val: Flags) {
        NetworkEndian::write_u16(&mut self.buffer[field::FLAGS], val.bits());
    }

    /// Return a writer for the options field.
    #[inline]
    pub fn options_mut(&mut self) -> OptionWriter<'_> {
        OptionWriter::new(&mut self.buffer[field::OPTIONS])
    }

    /// Fill in the fixed part of a client message: opcode, Ethernet hardware type and
    /// length, zero hops and `secs`, zero `sname` and `file`, and the magic cookie.
    ///
    /// The addresses, flags, transaction ID and options are left for the caller.
    pub fn fill_client_header(&mut self, message_type: MessageType, client_hardware_address: EthernetAddress) {
        self.set_sname_and_boot_file_to_zero();
        self.set_opcode(message_type.opcode());
        self.set_hardware_type(Hardware::Ethernet);
        self.set_hardware_len(EthernetAddress::SIZE as u8);
        self.set_hops(0);
        self.set_secs(0);
        self.set_client_hardware_address(client_hardware_address);
        self.set_magic_number(MAGIC_NUMBER);
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static DISCOVER_BYTES: &[u8] = &[
        0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42,
        0x32, 0x04, 0x00, 0x00, 0x00, 0x00, 0x39, 0x2, 0x5, 0xdc, 0x37, 0x04, 0x01, 0x03, 0x06, 0x2a, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    const IP_NULL: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
    const CLIENT_MAC: EthernetAddress = EthernetAddress([0x0, 0x0b, 0x82, 0x01, 0xfc, 0x42]);
    const DHCP_SIZE: u16 = 1500;

    #[test]
    fn test_deconstruct_discover() {
        let mut bytes = DISCOVER_BYTES.to_vec();
        let packet = Packet::new_checked(&mut bytes).unwrap();
        assert_eq!(packet.magic_number(), MAGIC_NUMBER);
        assert_eq!(packet.opcode(), OpCode::Request);
        assert_eq!(packet.hardware_type(), Hardware::Ethernet);
        assert_eq!(packet.hardware_len(), EthernetAddress::SIZE as u8);
        assert_eq!(packet.hops(), 0);
        assert_eq!(packet.transaction_id(), 0x3d1d);
        assert_eq!(packet.secs(), 0);
        assert_eq!(packet.client_ip(), IP_NULL);
        assert_eq!(packet.your_ip(), IP_NULL);
        assert_eq!(packet.server_ip(), IP_NULL);
        assert_eq!(packet.relay_agent_ip(), IP_NULL);
        assert_eq!(packet.client_hardware_address(), CLIENT_MAC);
        assert_eq!(packet.message_type(), Ok(MessageType::Discover));

        let mut options = packet.options();
        assert_eq!(
            options.next(),
            Some(DhcpOption {
                kind: field::OPT_DHCP_MESSAGE_TYPE,
                data: &[0x01]
            })
        );
        assert_eq!(
            options.next(),
            Some(DhcpOption {
                kind: field::OPT_CLIENT_ID,
                data: &[0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42],
            })
        );
        assert_eq!(
            options.next(),
            Some(DhcpOption {
                kind: field::OPT_REQUESTED_IP,
                data: &[0x00, 0x00, 0x00, 0x00],
            })
        );
        assert_eq!(
            options.next(),
            Some(DhcpOption {
                kind: field::OPT_MAX_DHCP_MESSAGE_SIZE,
                data: &DHCP_SIZE.to_be_bytes(),
            })
        );
        assert_eq!(
            options.next(),
            Some(DhcpOption {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: &[1, 3, 6, 42]
            })
        );
        assert_eq!(options.next(), None);
    }

    #[test]
    fn test_construct_discover() {
        let mut bytes = vec![0xa5; 276];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.fill_client_header(MessageType::Discover, CLIENT_MAC);
        packet.set_transaction_id(0x3d1d);
        packet.set_client_ip(IP_NULL);
        packet.set_your_ip(IP_NULL);
        packet.set_server_ip(IP_NULL);
        packet.set_relay_agent_ip(IP_NULL);
        packet.set_flags(Flags::empty());

        let mut options = packet.options_mut();
        options
            .emit(DhcpOption {
                kind: field::OPT_DHCP_MESSAGE_TYPE,
                data: &[MessageType::Discover.into()],
            })
            .unwrap();
        options
            .emit(DhcpOption {
                kind: field::OPT_CLIENT_ID,
                data: &[0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42],
            })
            .unwrap();
        options
            .emit(DhcpOption {
                kind: field::OPT_REQUESTED_IP,
                data: &IP_NULL.octets(),
            })
            .unwrap();
        options
            .emit(DhcpOption {
                kind: field::OPT_MAX_DHCP_MESSAGE_SIZE,
                data: &DHCP_SIZE.to_be_bytes(),
            })
            .unwrap();
        options
            .emit(DhcpOption {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: &[1, 3, 6, 42],
            })
            .unwrap();
        options.end().unwrap();
        let written = options.written();
        assert_eq!(HEADER_LEN + written, DISCOVER_BYTES.len() - 7);

        // The old packet had 7 bytes of trailing zero padding.
        assert_eq!(
            &bytes[..HEADER_LEN + written],
            &DISCOVER_BYTES[..DISCOVER_BYTES.len() - 7]
        );
    }

    #[test]
    fn test_option_writer_full() {
        let mut bytes = [0u8; 4];
        let mut writer = OptionWriter::new(&mut bytes);
        assert_eq!(writer.emit(DhcpOption { kind: 1, data: &[1, 2] }), Ok(()));
        assert_eq!(writer.emit(DhcpOption { kind: 1, data: &[1] }), Err(Malformed));
        assert_eq!(writer.end(), Err(Malformed));
        assert_eq!(writer.written(), 4);
    }

    #[test]
    fn test_too_short() {
        let mut bytes = [0u8; HEADER_LEN - 1];
        assert!(Packet::new_checked(&mut bytes).is_err());
    }

    #[test]
    fn test_dhcp_option_hostname() {
        let mut bytes = [0u8; 256];
        let mut writer = OptionWriter::new(&mut bytes);
        let hostname = b"this_is_my_host.name";
        let hostname_opt = DhcpOption::hostname(hostname);

        assert_eq!(writer.emit(hostname_opt), Ok(()));
        assert_eq!(writer.end(), Ok(()));
        assert_eq!(writer.written(), 23);

        let mut expected = [
            12, // Option code
            20, // Len of option
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // hostname
            255, // End code
        ];

        expected[2..22].copy_from_slice(b"this_is_my_host.name");
        assert_eq!(bytes[..23], expected);
    }

    #[test]
    fn test_dhcp_hostname_too_long() {
        let mut bytes = [0u8; 1024];
        let mut writer = OptionWriter::new(&mut bytes);
        let hostname: [u8; 256] = ['a' as u8; 256];
        let hostname_opt = DhcpOption::hostname(&hostname);
        assert_eq!(writer.emit(hostname_opt), Err(Malformed));
    }
}
