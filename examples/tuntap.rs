//! Bare minimum example: bring up a TUN/TAP interface, reply to pings, and echo
//! UDP datagrams received on port 6969.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example tuntap -- tap0        # TAP (Ethernet medium)
//! cargo run --example tuntap -- --tun tun0  # TUN (IP medium)
//! ```
//!
//! Then, on the host:
//!
//! ```sh
//! sudo ip link set up dev tap0
//! sudo ip addr add 192.168.69.100/24 dev tap0
//! sudo ip addr add fdaa::100/64 dev tap0
//! ping 192.168.69.1
//! ping fdaa::1
//! nc -u 192.168.69.1 6969
//! nc -u fdaa::1 6969
//! ```

mod common;

use std::os::unix::io::AsRawFd;

use xarxa::Stack;
use xarxa::driver_impls::{TunTapDriver, wait};
use xarxa::time::Instant;
use xarxa::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let hardware_addr = if let Some(pos) = args.iter().position(|a| a == "--tun") {
        args.remove(pos);
        HardwareAddress::Ip
    } else {
        HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
    };
    let name = args.first().map(String::as_str).unwrap_or("tap0");

    let packet_allocator = common::packet_allocator();
    let driver = TunTapDriver::new(name, hardware_addr, packet_allocator).unwrap();
    let fd = driver.as_raw_fd();

    let mut stack = Stack::new(random_seed(), packet_allocator);
    let iface = stack.add_iface(Box::new(driver)).unwrap();
    stack
        .iface(iface)
        .set_ip_addrs([
            IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
            IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64),
            IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64),
        ])
        .unwrap();

    // Off-link traffic routes to the host's address on this interface.
    stack
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 100), iface)
        .unwrap();

    let udp_handle = stack.add_udp_socket().unwrap();
    stack
        .udp_socket(udp_handle)
        .bind(6969, IpListenEndpoint::UNSPECIFIED)
        .unwrap();

    loop {
        let deadline = stack.poll(Instant::now());

        // Echo received datagrams back to their sender.
        let mut socket = stack.udp_socket(udp_handle);
        while let Ok(packet) = socket.recv() {
            let meta = packet.meta();
            log::info!("udp: echoing {} octets to {}", packet.payload().len(), meta);
            let data = packet.payload().to_vec();
            drop(packet); // free the buffer before sending
            socket.send_slice(&data, meta.endpoint).unwrap();
        }

        let timeout = (deadline != Instant::MAX).then(|| {
            let now = Instant::now();
            if deadline <= now {
                std::time::Duration::ZERO
            } else {
                (deadline - now).into()
            }
        });
        wait(fd, timeout).unwrap();
    }
}

/// Quick-and-dirty entropy for the example's PRNG seed. Real firmware should
/// use a hardware RNG or another unpredictable source.
fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
