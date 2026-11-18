//! Sockets, epoll and events (WASIX).
//!
//! wasix-libc passes its own `AF_*`, `SOCK_*` and `SO_*` numbers to the host, which are the v1
//! values below; the shims translate each to Linux's explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::{Fd, GuestLayout, Ptr, layout, newtype_layout, proc::OptionTimestamp};

/// `address_family` (`u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addressfamily(pub u8);

impl Addressfamily {
    pub const UNSPEC: Self = Self(0);
    pub const INET4: Self = Self(1);
    pub const INET6: Self = Self(2);
    pub const UNIX: Self = Self(3);
}

/// `sock_type` (`u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socktype(pub u8);

impl Socktype {
    pub const UNUSED: Self = Self(0);
    pub const STREAM: Self = Self(1);
    pub const DGRAM: Self = Self(2);
    pub const RAW: Self = Self(3);
    pub const SEQPACKET: Self = Self(4);

    /// wasix-libc's `SOCK_NONBLOCK`, which its `socket()` leaves in the type argument.
    pub const LIBC_NONBLOCK: u32 = 0x4000;
    /// wasix-libc's `SOCK_CLOEXEC`, likewise.
    pub const LIBC_CLOEXEC: u32 = 0x2000;
}

/// `sock_status` (`u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockStatus(pub u8);

impl SockStatus {
    pub const OPENING: Self = Self(0);
    pub const OPENED: Self = Self(1);
    pub const CLOSED: Self = Self(2);
    pub const FAILED: Self = Self(3);
}

/// `sock_option` (`u8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Sockoption(pub u8);

impl Sockoption {
    pub const NOOP: Self = Self(0);
    pub const REUSE_PORT: Self = Self(1);
    pub const REUSE_ADDR: Self = Self(2);
    pub const NO_DELAY: Self = Self(3);
    pub const DONT_ROUTE: Self = Self(4);
    pub const ONLY_V6: Self = Self(5);
    pub const BROADCAST: Self = Self(6);
    pub const MULTICAST_LOOP_V4: Self = Self(7);
    pub const MULTICAST_LOOP_V6: Self = Self(8);
    pub const PROMISCUOUS: Self = Self(9);
    pub const LISTENING: Self = Self(10);
    pub const LAST_ERROR: Self = Self(11);
    pub const KEEP_ALIVE: Self = Self(12);
    pub const LINGER: Self = Self(13);
    pub const OOB_INLINE: Self = Self(14);
    pub const RECV_BUF_SIZE: Self = Self(15);
    pub const SEND_BUF_SIZE: Self = Self(16);
    pub const RECV_LOWAT: Self = Self(17);
    pub const SEND_LOWAT: Self = Self(18);
    pub const RECV_TIMEOUT: Self = Self(19);
    pub const SEND_TIMEOUT: Self = Self(20);
    pub const CONNECT_TIMEOUT: Self = Self(21);
    pub const ACCEPT_TIMEOUT: Self = Self(22);
    pub const TTL: Self = Self(23);
    pub const MULTICAST_TTL_V4: Self = Self(24);
    pub const TYPE: Self = Self(25);
    pub const PROTO: Self = Self(26);
    /// The highest option v1 defines.
    pub const MAX: Self = Self::PROTO;
}

/// `riflags` (`u16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiFlags(pub u16);

impl RiFlags {
    pub const RECV_PEEK: Self = Self(1 << 0);
    pub const RECV_WAITALL: Self = Self(1 << 1);
    pub const RECV_DATA_TRUNCATED: Self = Self(1 << 2);
    pub const RECV_DONT_WAIT: Self = Self(1 << 3);
}

/// `roflags` (`u16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoFlags(pub u16);

impl RoFlags {
    pub const RECV_DATA_TRUNCATED: Self = Self(1 << 0);
}

/// `siflags` (`u16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiFlags(pub u16);

impl SiFlags {
    pub const SEND_DONT_WAIT: Self = Self(1 << 0);
}

/// `sdflags` (`u8`): the directions `sock_shutdown` closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sdflags(pub u8);

impl Sdflags {
    pub const RD: Self = Self(1 << 0);
    pub const WR: Self = Self(1 << 1);
}

/// `eventfdflags` (`u16`). wasix-libc truncates `eventfd`'s flags to 16 bits, so its
/// `EFD_NONBLOCK` (`O_NONBLOCK`, the fdflags bit) arrives here and `EFD_CLOEXEC` does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eventfdflags(pub u16);

impl Eventfdflags {
    pub const SEMAPHORE: Self = Self(1 << 0);
    pub const NONBLOCK: Self = Self(1 << 2);
}

/// `epoll_type` (`u32`): v1's own bit numbering, translated explicitly to Linux's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollType(pub u32);

impl EpollType {
    pub const EPOLLIN: Self = Self(1 << 0);
    pub const EPOLLOUT: Self = Self(1 << 1);
    pub const EPOLLRDHUP: Self = Self(1 << 2);
    pub const EPOLLPRI: Self = Self(1 << 3);
    pub const EPOLLERR: Self = Self(1 << 4);
    pub const EPOLLHUP: Self = Self(1 << 5);
    pub const EPOLLET: Self = Self(1 << 6);
    pub const EPOLLONESHOT: Self = Self(1 << 7);
}

/// `epoll_ctl` (`u32`). The witx numbering (ADD 0, MOD 1, DEL 2) is not what the guest sends:
/// wasix-libc passes musl's Linux values through, and the v1 host decoded those, keeping 0 as
/// a second ADD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollCtl(pub u32);

impl EpollCtl {
    /// The witx `ADD`, which the v1 host still accepted.
    pub const ADD_WITX: Self = Self(0);
    pub const ADD: Self = Self(1);
    pub const DEL: Self = Self(2);
    pub const MOD: Self = Self(3);
}

newtype_layout!(
    Addressfamily(u8),
    Socktype(u8),
    SockStatus(u8),
    Sockoption(u8),
    RiFlags(u16),
    RoFlags(u16),
    SiFlags(u16),
    Sdflags(u8),
    Eventfdflags(u16),
    EpollType(u32),
    EpollCtl(u32),
);

layout! {
    /// Legacy `__wasi_addr_port_t`: IP input ports are host-order and output ports are
    /// network-order. IPv6 has no flow info or scope id in this layout.
    pub struct AddrPort (size 20, align 2) {
        pub tag: Addressfamily = 0,
        pub port: [u8; 2] = 2,
        pub octets: [u8; 16] = 4,
    }
}

layout! {
    /// wasix-libc's longer Unix-address variant.
    pub struct UnixAddrPort (size 110, align 2) {
        pub tag: Addressfamily = 0,
        pub payload: [u8; 108] = 2,
    }
}

layout! {
    /// Extended address storage inside the wasix-libc route record.
    pub struct Addr (size 110, align 2) {
        pub tag: Addressfamily = 0,
        pub payload: [u8; 108] = 2,
    }
}

layout! {
    /// `addr_ip`: an IP address as `resolve` returns it, the address bytes at 2 (inet4 in the
    /// first four).
    pub struct AddrIp (size 18, align 2) {
        pub tag: Addressfamily = 0,
        pub octets: [u8; 16] = 2,
    }
}

layout! {
    /// `addr_cidr`: a tagged IP address followed by the prefix length (at 6 for inet4, at 26
    /// for inet6).
    pub struct AddrCidr (size 28, align 2) {
        pub tag: Addressfamily = 0,
        pub payload: [u8; 26] = 2,
    }
}

layout! {
    /// `addr_ip6`, a multicast group: the address, then flow info and scope id.
    pub struct AddrIp6 (size 24, align 2) {
        pub octets: [u8; 16] = 0,
        pub flow_info: [u8; 4] = 16,
        pub scope_id: [u8; 4] = 20,
    }
}

layout! {
    /// `hardware_address`.
    pub struct HardwareAddress (size 6, align 1) {
        pub octets: [u8; 6] = 0,
    }
}

layout! {
    /// `route` in api_wasix.h; the legacy Rust host type has narrower IP unions.
    pub struct Route (size 176, align 8) {
        pub cidr: AddrCidr = 0,
        pub via_router: Addr = 28,
        pub preferred_until: OptionTimestamp = 144,
        pub expires_at: OptionTimestamp = 160,
    }
}

/// `addr_ip4`: an IPv4 address in network order.
pub type AddrIp4 = [u8; 4];

layout! {
    /// `epoll_data`: wider than Linux's `epoll_data_t`; the compat layer keeps it host-side.
    pub struct EpollData (size 24, align 8) {
        pub ptr: Ptr = 0,
        pub fd: Fd = 4,
        pub data1: u32 = 8,
        pub data2: u64 = 16,
    }
}

layout! {
    /// `epoll_event`.
    pub struct EpollEvent (size 32, align 8) {
        pub events: EpollType = 0,
        pub data: EpollData = 8,
    }
}

/// An address decoded from a guest address union or a Linux `sockaddr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SockAddr {
    Inet(SocketAddr),
    /// The path, up to its first NUL.
    Unix(Vec<u8>),
    /// `UNSPEC`: no address.
    Unspec,
}

/// The `sun_path` bytes in the payload of a [`UnixAddrPort`]: a path up to its NUL, or an
/// abstract name (a leading NUL) up to its last non-NUL byte. wasix-libc copies `sun_path` into
/// a zeroed payload and keeps no length, so an abstract name's trailing NULs are lost; one of
/// only NULs is unnamed.
fn unix_payload(p: &[u8]) -> &[u8] {
    match p.first() {
        Some(0) => &p[..p.iter().rposition(|&b| b != 0).map_or(0, |last| last + 1)],
        _ => &p[..p.iter().position(|&b| b == 0).unwrap_or(p.len())],
    }
}

impl AddrPort {
    pub fn decode(&self) -> Option<SocketAddr> {
        let port = u16::from_le_bytes(self.port);
        match self.tag {
            Addressfamily::INET4 => {
                let ip: [u8; 4] = self.octets[..4].try_into().unwrap();
                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            Addressfamily::INET6 => Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(self.octets),
                port,
                0,
                0,
            ))),
            _ => None,
        }
    }

    pub fn encode(addr: SocketAddr) -> Self {
        let ip = AddrIp::new(addr.ip());
        Self {
            tag: ip.tag,
            port: addr.port().to_be_bytes(),
            octets: ip.octets,
        }
    }
}

impl UnixAddrPort {
    pub(crate) fn path(&self) -> &[u8] {
        unix_payload(&self.payload)
    }

    #[cfg(test)]
    pub(crate) fn new(path: &[u8]) -> Self {
        let mut out = Self::ZERO;
        out.tag = Addressfamily::UNIX;
        let len = path.len().min(out.payload.len() - 1);
        out.payload[..len].copy_from_slice(&path[..len]);
        out
    }
}

impl AddrIp {
    pub fn new(ip: IpAddr) -> Self {
        let mut out = Self::ZERO;
        match ip {
            IpAddr::V4(v4) => {
                out.tag = Addressfamily::INET4;
                out.octets[..4].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.tag = Addressfamily::INET6;
                out.octets = v6.octets();
            }
        }
        out
    }
}

impl AddrCidr {
    pub fn new(ip: IpAddr, prefix: u8) -> Self {
        let mut out = Self::ZERO;
        match ip {
            IpAddr::V4(v4) => {
                out.tag = Addressfamily::INET4;
                out.payload[..4].copy_from_slice(&v4.octets());
                out.payload[4] = prefix;
            }
            IpAddr::V6(v6) => {
                out.tag = Addressfamily::INET6;
                out.payload[..16].copy_from_slice(&v6.octets());
                out.payload[24] = prefix;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes wasix-libc's `sockaddr_to_wasi` produces for `127.0.0.1:9000`.
    #[test]
    fn addr_port_matches_libc_bytes() {
        let mut bytes = [0u8; AddrPort::SIZE];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&9000u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let addr = AddrPort::read_from(&bytes).unwrap();
        assert_eq!(addr.decode(), Some("127.0.0.1:9000".parse().unwrap()));
        let mut out = [0u8; AddrPort::SIZE];
        addr.write_to(&mut out);
        assert_eq!(out, bytes);
    }

    #[test]
    fn cidr_prefix_positions() {
        let v4 = AddrCidr::new("10.0.0.2".parse().unwrap(), 24);
        let mut bytes = [0u8; AddrCidr::SIZE];
        v4.write_to(&mut bytes);
        assert_eq!(&bytes[..7], &[1, 0, 10, 0, 0, 2, 24]);
        let v6 = AddrCidr::new("::1".parse().unwrap(), 128);
        v6.write_to(&mut bytes);
        assert_eq!((bytes[0], bytes[17], bytes[26]), (2, 1, 128));
    }
}
