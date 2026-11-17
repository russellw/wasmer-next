//! AF_PACKET sockets over the optional backend uplink frame transport.

use std::sync::{Arc, Mutex};

use wasixv2_abi::{AddressFamily, MsgFlags, OpenFlags, SocketFlags, SocketOption, SocketType};
use wasixv2_host::Host;
use wasixv2_syscalls::{Caller, Errno, LocalFuture, SysResult};
use wasixv2_vfs::Cap;
use wasixv2_vnet::{
    BackendFrames, FrameKind,
    bpf::{Device, ETH_HLEN, Packet, SockFilter},
    iface::flags::{IFF_LOOPBACK, IFF_UP},
};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue, poll_wait};

use crate::{
    Kernel,
    file::{Backing, FileObject, Io, OpenFile},
    ns::NetNs,
    socket::{Blocking, RCV, Timeouts, WaitOn},
    sync::MutexExt,
};

/// The largest Ethernet frame carrying a 16-bit-length network packet.
pub(crate) const MAX_FRAME: usize = 65535 + ETH_HLEN;
/// `sizeof(struct sockaddr_ll)` and `offsetof(struct sockaddr_ll, sll_addr)`.
const SOCKADDR_LL: usize = 20;
const SLL_ADDR: usize = 12;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
/// `SO_SNDBUF` and `SO_RCVBUF`'s default.
const BUF_DEFAULT: i32 = 212_992;
/// `PACKET_VERSION`, and `TPACKET_V1`, the format without a ring of its own.
const PACKET_VERSION: i32 = 10;
const TPACKET_V1: i32 = 0;

pub(crate) struct PacketSocket {
    kind: SocketType,
    /// The network namespace the socket was made in (`sock_net`).
    pub(crate) net: Arc<NetNs>,
    state: Mutex<PacketState>,
    /// The queue shared with the backend frame endpoint.
    wait: WaitQueue,
    pub(crate) timeouts: Timeouts,
    /// `SO_ATTACH_FILTER`'s program, applied before retaining a frame.
    filter: Mutex<SockFilter>,
    /// `po->tp_version`.
    tp_version: Mutex<i32>,
    host: Arc<dyn Host>,
}

#[derive(Default)]
struct PacketState {
    /// `po->num` (network byte order) and `po->ifindex`.
    bound: (u16, u32),
    frames: Option<Arc<dyn BackendFrames>>,
    pending: Option<(Vec<u8>, Vec<u8>)>,
    promiscuous: u32,
}

impl PacketSocket {
    /// `packet_bind`: a `sockaddr_ll` naming an interface of the namespace (0 for every one),
    /// and the protocol to take (0 keeps the socket's).
    pub(crate) fn bind(&self, raw: &[u8]) -> Result<i32, Errno> {
        if raw.len() < SOCKADDR_LL
            || i32::from(u16::from_le_bytes([raw[0], raw[1]])) != AddressFamily::AF_PACKET.0
        {
            return Err(Errno::EINVAL);
        }
        let protocol = u16::from_le_bytes([raw[2], raw[3]]);
        let index = i32::from_le_bytes(raw[4..8].try_into().unwrap());
        if index != 0 && !self.interfaces().iter().any(|i| i.index as i32 == index) {
            return Err(Errno::ENODEV);
        }
        let mut state = self.state.lock_or_recover();
        let next = (
            if protocol == 0 {
                state.bound.0
            } else {
                protocol
            },
            index as u32,
        );
        if state.bound != next {
            if let Some(frames) = state.frames.take()
                && state.promiscuous != 0
            {
                frames.set_promiscuous(false)?;
            }
            state.pending = None;
            state.bound = next;
        }
        match self.endpoint(&mut state) {
            Ok(_) | Err(Errno::EOPNOTSUPP) => Ok(0),
            Err(err) => Err(err),
        }
    }

    fn interfaces(&self) -> Vec<wasixv2_vnet::Interface> {
        self.net
            .network
            .as_ref()
            .map(|n| n.interfaces())
            .unwrap_or_default()
    }

    /// `packet_getname`: the protocol, the bound interface with its hardware type and address.
    pub(crate) fn local_addr(&self) -> Vec<u8> {
        let (protocol, index) = self.state.lock_or_recover().bound;
        let mut raw = vec![0; SOCKADDR_LL];
        raw[..2].copy_from_slice(&(AddressFamily::AF_PACKET.0 as u16).to_le_bytes());
        raw[2..4].copy_from_slice(&protocol.to_le_bytes());
        raw[4..8].copy_from_slice(&(index as i32).to_le_bytes());
        let iface = self.interfaces().into_iter().find(|i| i.index == index);
        let Some(iface) = iface else {
            raw.truncate(SLL_ADDR);
            return raw;
        };
        let hatype = match iface.flags & IFF_LOOPBACK != 0 {
            true => ARPHRD_LOOPBACK,
            false => ARPHRD_ETHER,
        };
        raw[8..10].copy_from_slice(&hatype.to_le_bytes());
        raw[11] = 6;
        raw[SLL_ADDR..SLL_ADDR + 6].copy_from_slice(&iface.mac);
        raw.truncate(SLL_ADDR + 6);
        raw
    }

    pub(crate) fn queue(&self) -> WaitQueue {
        self.wait.clone()
    }

    fn endpoint(&self, state: &mut PacketState) -> Result<Arc<dyn BackendFrames>, Errno> {
        let (protocol, index) = state.bound;
        let net = self.net.network.as_ref().ok_or(Errno::EOPNOTSUPP)?;
        let uplink = net.packet_uplink();
        if uplink == 0 || (index != 0 && index != uplink) {
            return Err(Errno::EOPNOTSUPP);
        }
        if let Some(frames) = &state.frames {
            return Ok(frames.clone());
        }
        let endpoint = net.backend_frames(protocol, self.wait.clone())?;
        if state.promiscuous != 0 {
            endpoint.set_promiscuous(true)?;
        }
        state.frames = Some(endpoint.clone());
        Ok(endpoint)
    }

    pub(crate) fn send(&self, data: &[u8], to: Option<&[u8]>) -> Result<usize, Errno> {
        let mut state = self.state.lock_or_recover();
        let (protocol, bound) = state.bound;
        let index = match to {
            None => {
                if bound == 0 {
                    self.endpoint(&mut state).map_err(|e| {
                        if e == Errno::EOPNOTSUPP {
                            Errno::ENXIO
                        } else {
                            e
                        }
                    })?;
                    self.net.network.as_ref().map_or(0, |n| n.packet_uplink())
                } else {
                    bound
                }
            }
            Some(raw) if raw.len() < SLL_ADDR => return Err(Errno::EINVAL),
            Some(raw) => u32::from_le_bytes(raw[4..8].try_into().unwrap()),
        };
        let iface = self
            .interfaces()
            .into_iter()
            .find(|i| i.index == index)
            .ok_or(Errno::ENXIO)?;
        if iface.flags & IFF_UP == 0 {
            return Err(Errno::ENETDOWN);
        }
        if iface.flags & IFF_LOOPBACK != 0
            || self
                .net
                .network
                .as_ref()
                .is_none_or(|n| index != n.packet_uplink())
        {
            return Err(Errno::EOPNOTSUPP);
        }
        let frames = self.endpoint(&mut state)?;
        let header = if self.kind == SocketType::SOCK_DGRAM {
            0
        } else {
            ETH_HLEN
        };
        if data.len() > iface.mtu as usize + header {
            return Err(Errno::EMSGSIZE);
        }
        if self.kind == SocketType::SOCK_DGRAM {
            let to = to.ok_or(Errno::EINVAL)?;
            if to.len() < SLL_ADDR + 6 || to[11] != 6 {
                return Err(Errno::EINVAL);
            }
            let mut frame = Vec::with_capacity(ETH_HLEN + data.len());
            frame.extend_from_slice(&to[SLL_ADDR..SLL_ADDR + 6]);
            frame.extend_from_slice(&iface.mac);
            let ether = if to[2..4] == [0, 0] {
                protocol.to_le_bytes()
            } else {
                to[2..4].try_into().unwrap()
            };
            frame.extend_from_slice(&ether);
            frame.extend_from_slice(data);
            frames.send(&frame).map(|n| n.saturating_sub(ETH_HLEN))
        } else {
            if data.len() < ETH_HLEN {
                return Err(Errno::EINVAL);
            }
            frames.send(data)
        }
    }

    /// Take backend frames through protocol and socket BPF admission before retaining one
    /// for poll/MSG_PEEK. The backend owns the arrival queue and wakes our wait queue.
    fn fill(&self, state: &mut PacketState) -> Result<(), Errno> {
        if state.pending.is_some() {
            return Ok(());
        }
        let frames = match self.endpoint(state) {
            Err(Errno::EOPNOTSUPP) => return Err(Errno::EAGAIN),
            result => result?,
        };
        let (protocol, _) = state.bound;
        let index = self.net.network.as_ref().map_or(0, |n| n.packet_uplink());
        let mut buffer = vec![0; MAX_FRAME];
        loop {
            let (len, kind) = frames.recv(&mut buffer)?;
            if len < ETH_HLEN || len > buffer.len() {
                continue;
            }
            let data = &buffer[..len];
            let ether = u16::from_be_bytes([data[12], data[13]]);
            if protocol == 0 || (u16::from_be(protocol) != 3 && u16::from_be(protocol) != ether) {
                continue;
            }
            let pkttype = match kind {
                FrameKind::Host => 0,
                FrameKind::Broadcast => 1,
                FrameKind::Multicast => 2,
                FrameKind::OtherHost => 3,
                FrameKind::Outgoing => 4,
            };
            let start = if self.kind == SocketType::SOCK_DGRAM {
                ETH_HLEN
            } else {
                0
            };
            let packet = Packet {
                frame: data,
                mac: Some(0),
                network: ETH_HLEN,
                data: start,
                pay_offset: 0,
                protocol: ether,
                pkttype,
                dev: Some(Device {
                    ifindex: index,
                    hatype: ARPHRD_ETHER,
                }),
            };
            let Some(keep) = self.filter.lock_or_recover().trim(&packet, 0) else {
                continue;
            };
            let mut addr = vec![0; SOCKADDR_LL];
            addr[..2].copy_from_slice(&(AddressFamily::AF_PACKET.0 as u16).to_le_bytes());
            addr[2..4].copy_from_slice(&data[12..14]);
            addr[4..8].copy_from_slice(&index.to_le_bytes());
            addr[8..10].copy_from_slice(&ARPHRD_ETHER.to_le_bytes());
            addr[10] = pkttype;
            addr[11] = 6;
            addr[12..18].copy_from_slice(&data[6..12]);
            state.pending = Some((data[start..start + keep].to_vec(), addr));
            return Ok(());
        }
    }

    pub(crate) async fn recv(
        &self,
        wait: &mut Blocking<'_>,
        peek: bool,
    ) -> SysResult<(Vec<u8>, Vec<u8>)> {
        wait.wait(WaitOn::Queue(&self.wait), PollMask::READABLE, || {
            let mut state = self.state.lock_or_recover();
            self.fill(&mut state)?;
            Ok(if peek {
                state.pending.as_ref().unwrap().clone()
            } else {
                state.pending.take().unwrap()
            })
        })
        .await
    }

    pub(crate) fn blocking<'a>(&'a self, io: Io<'a>, dir: usize, flags: MsgFlags) -> Blocking<'a> {
        Blocking::new(&*self.host, io, flags, self.timeouts.get(dir))
    }

    /// `sk_setsockopt` for this socket: the filter's options; the rest only describe the
    /// descriptor.
    pub(crate) fn setsockopt(&self, name: i32, value: &[u8]) -> Result<(), Errno> {
        match SockFilter::handles(name) {
            true => self.filter.lock_or_recover().set(name, value),
            false => Ok(()),
        }
    }

    /// `packet_setsockopt` at `SOL_PACKET`. `PACKET_VERSION` takes the ring formats Linux
    /// knows; formats with a ring of their own (`TPACKET_V2`, `TPACKET_V3`) are
    /// refused (`EINVAL`), which tells programs to read with `recvfrom` instead.
    /// Promiscuous memberships are forwarded to the backend; rings and fanout
    /// remain unsupported (`ENOPROTOOPT`).
    pub(crate) fn set_packet_option(&self, name: i32, value: &[u8]) -> Result<(), Errno> {
        // packet_mreq: ifindex, type, alen, address[8].
        if name == 1 || name == 2 {
            if value.len() < 16 {
                return Err(Errno::EINVAL);
            }
            let index = u32::from_le_bytes(value[..4].try_into().unwrap());
            if !self.interfaces().iter().any(|i| i.index == index) {
                return Err(Errno::ENODEV);
            }
            if u16::from_le_bytes(value[4..6].try_into().unwrap()) != 1 {
                return Err(Errno::ENOPROTOOPT);
            }
            let mut state = self.state.lock_or_recover();
            if self
                .net
                .network
                .as_ref()
                .is_none_or(|n| n.packet_uplink() != index)
            {
                return Err(Errno::ENOPROTOOPT);
            }
            let frames = match self.endpoint(&mut state) {
                Err(Errno::EOPNOTSUPP) => return Err(Errno::ENOPROTOOPT),
                result => result?,
            };
            let count = state.promiscuous;
            let next = if name == 1 {
                count.checked_add(1).ok_or(Errno::ENOBUFS)?
            } else {
                count.saturating_sub(1)
            };
            if (count == 0) != (next == 0) {
                frames.set_promiscuous(next != 0)?;
            }
            state.promiscuous = next;
            return Ok(());
        }
        if name != PACKET_VERSION {
            return Err(Errno::ENOPROTOOPT);
        }
        let value: [u8; 4] = value.try_into().map_err(|_| Errno::EINVAL)?;
        match i32::from_le_bytes(value) {
            TPACKET_V1 => {
                *self.tp_version.lock_or_recover() = TPACKET_V1;
                Ok(())
            }
            // `TPACKET_V2` and `TPACKET_V3` exist, but not here; anything else never did.
            _ => Err(Errno::EINVAL),
        }
    }

    /// `packet_getsockopt` at `SOL_PACKET`: `PACKET_VERSION`.
    pub(crate) fn packet_option(&self, name: i32) -> Result<Vec<u8>, Errno> {
        match name {
            PACKET_VERSION => Ok(self.tp_version.lock_or_recover().to_le_bytes().to_vec()),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    /// `SOL_SOCKET` options as `sock_getsockopt` answers them for this socket.
    pub(crate) fn getsockopt(&self, name: i32) -> Result<Vec<u8>, Errno> {
        let int = |v: i32| Ok(v.to_le_bytes().to_vec());
        if SockFilter::handles(name) {
            let mut out = vec![0; wasixv2_vnet::bpf::MAX_PROGRAM_LEN];
            let n = self.filter.lock_or_recover().get(name, &mut out)?;
            out.truncate(n);
            return Ok(out);
        }
        match SocketOption(name) {
            SocketOption::SO_TYPE => int(self.kind.0),
            SocketOption::SO_PROTOCOL => int(i32::from(self.state.lock_or_recover().bound.0)),
            SocketOption::SO_DOMAIN => int(AddressFamily::AF_PACKET.0),
            SocketOption::SO_ERROR => int(0),
            SocketOption::SO_SNDBUF | SocketOption::SO_RCVBUF => int(BUF_DEFAULT),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }
}

pub(crate) fn downcast(object: Arc<dyn FileObject>) -> Option<Arc<PacketSocket>> {
    let any: Arc<dyn std::any::Any + Send + Sync> = object;
    any.downcast().ok()
}

impl Pollable for PacketSocket {
    /// Register before inspecting the backend, then report admitted receive data.
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        poll_wait(&mut table, &self.wait);
        let mut state = self.state.lock_or_recover();
        let mut mask = match self.endpoint(&mut state) {
            Ok(frames) => frames.poll(None) & !PollMask::READABLE,
            Err(Errno::EOPNOTSUPP) => PollMask::WRITABLE,
            Err(_) => PollMask::ERR,
        };
        match self.fill(&mut state) {
            Ok(()) => mask |= PollMask::READABLE,
            Err(Errno::EAGAIN) => {}
            Err(_) => mask |= PollMask::ERR,
        }
        mask
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        let mut state = self.state.lock_or_recover();
        if state.promiscuous != 0
            && let Some(frames) = state.frames.take()
        {
            let _ = frames.set_promiscuous(false);
        }
    }
}

impl FileObject for PacketSocket {
    fn messages(&self) -> bool {
        true
    }

    fn read<'a>(&'a self, io: Io<'a>, buf: &'a mut [u8]) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(async move {
            let mut wait = self.blocking(io, RCV, MsgFlags(0));
            let (frame, _) = self.recv(&mut wait, false).await?;
            let len = buf.len().min(frame.len());
            buf[..len].copy_from_slice(&frame[..len]);
            Ok(len)
        })
    }

    fn write<'a>(&'a self, io: Io<'a>, data: &'a [u8]) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(async move {
            let mut wait = self.blocking(io, crate::socket::SND, MsgFlags(0));
            wait.wait(WaitOn::Queue(&self.wait), PollMask::WRITABLE, || {
                self.send(data, None)
            })
            .await
        })
    }
}

impl Kernel {
    /// `packet_create`: `CAP_NET_RAW` over the owner of the caller's network namespace
    /// (`ns_capable(net->user_ns, CAP_NET_RAW)`), then a raw or datagram socket; `protocol` is
    /// the Ethernet type in network byte order, as given.
    pub(crate) fn packet_socket(
        &self,
        caller: &Caller<'_>,
        kind: SocketType,
        protocol: i32,
        flags: SocketFlags,
    ) -> SysResult<OpenFile> {
        if !self.net_capable(caller, Cap::NetRaw) {
            return Err(Errno::EPERM.into());
        }
        if kind != SocketType::SOCK_RAW && kind != SocketType::SOCK_DGRAM {
            return Err(Errno::ESOCKTNOSUPPORT.into());
        }
        let protocol = u16::try_from(protocol).map_err(|_| Errno::EINVAL)?;
        let socket = PacketSocket {
            kind,
            net: self.ns(caller).net.clone(),
            state: Mutex::new(PacketState {
                bound: (protocol, 0),
                ..PacketState::default()
            }),
            wait: WaitQueue::new(),
            timeouts: Timeouts::default(),
            filter: Mutex::new(SockFilter::default()),
            tp_version: Mutex::new(TPACKET_V1),
            host: self.host.clone(),
        };
        let mut status = OpenFlags::O_RDWR;
        if flags.contains(SocketFlags::SOCK_NONBLOCK) {
            status |= OpenFlags::O_NONBLOCK;
        }
        let file = OpenFile::new(
            Backing::Stream(
                Arc::new(socket),
                self.pseudo.socket(self.cred(caller).fs_owner()),
            ),
            status,
        );
        Ok(file)
    }
}
