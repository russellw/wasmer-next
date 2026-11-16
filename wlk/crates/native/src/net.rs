//! Native Linux socket syscall translation into WLK's virtual network stack.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use wasixv2_abi::{
    AddressFamily, Buf, ConstSockaddrPtr, Fd, FdPair, MsgFlags, ShutdownHow, SockaddrPtr,
    SocketFlags, SocketLevel, Socklen, SocklenPtr,
};
use wasixv2_host::Host;
use wasixv2_syscalls::{Syscall, UserSlice, UserSliceMut};
use wasixv2_vnet::{Backend, Net, NetConfig, Network};
use wasixv2_vnet_host::HostBackend;

use crate::{BridgeMemory, platform::Request};

const SOCKADDR_MAX: usize = 128;

/// Build the WLK network stack backed by host TCP/UDP sockets.
///
/// Guest connections to host loopback services use `10.0.2.2`; guest listeners bound to
/// `0.0.0.0` or another non-loopback address are published on host `127.0.0.1` at the same
/// port. Guest-only `127.0.0.1` listeners stay private.
pub fn network(host: Arc<dyn Host>) -> io::Result<Arc<dyn Network>> {
    // TODO: pass the WLK Host into HostBackend when it supports host-backed resolver and socket
    // services; the current backend owns its mio reactor and reads resolver settings itself.
    drop(host);
    let backend: Arc<dyn Backend> = HostBackend::new()?;
    let config = NetConfig {
        auto_publish: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ..NetConfig::host_default()
    };
    Ok(Net::new(config, Some(backend)))
}

/// Translate a Linux x86_64 socket syscall to the matching WLK syscall.
///
/// Pointers are mapped into the stopped tracee's memory through `BridgeMemory`; the resulting
/// WLK syscall continues to use the kernel's virtual descriptors and virtual network.
pub fn translate(request: Request, memory: &mut BridgeMemory) -> io::Result<Option<Syscall>> {
    let args = request.args;
    let fd = Fd(args[0] as i32);
    let call = match request.nr {
        libc::SYS_socket => Some(Syscall::Socket {
            family: AddressFamily(args[0] as i32),
            r#type: args[1] as i32,
            protocol: args[2] as i32,
        }),
        libc::SYS_connect => {
            let addr_len = socket_len(args[2]);
            let addr = map_ptr(memory, args[1], addr_len, true, false)?;
            Some(Syscall::Connect {
                fd,
                uservaddr: ConstSockaddrPtr::new(addr),
                addrlen: addr_len as Socklen,
            })
        }
        libc::SYS_accept => {
            let (addr, addr_len) = map_sockaddr_out(memory, args[1], args[2])?;
            Some(Syscall::Accept {
                fd,
                upeer_sockaddr: SockaddrPtr::new(addr),
                upeer_addrlen: SocklenPtr::new(addr_len),
            })
        }
        libc::SYS_sendto => {
            let len = bounded_len(args[2]);
            let buf = map_ptr(memory, args[1], len, true, false)?;
            let addr_len = socket_len(args[5]);
            let addr = map_ptr(memory, args[4], addr_len, true, false)?;
            Some(Syscall::Sendto {
                fd,
                buff: UserSlice::new(buf, len as u32),
                flags: MsgFlags(args[3] as u32),
                addr: ConstSockaddrPtr::new(addr),
                addr_len: addr_len as Socklen,
            })
        }
        libc::SYS_recvfrom => {
            let len = bounded_len(args[2]);
            let buf = map_ptr(memory, args[1], len, false, true)?;
            let (addr, addr_len) = map_sockaddr_out(memory, args[4], args[5])?;
            Some(Syscall::Recvfrom {
                fd,
                ubuf: UserSliceMut::new(buf, len as u32),
                flags: MsgFlags(args[3] as u32),
                addr: SockaddrPtr::new(addr),
                addr_len: SocklenPtr::new(addr_len),
            })
        }
        libc::SYS_shutdown => Some(Syscall::Shutdown {
            fd,
            how: ShutdownHow(args[1] as i32),
        }),
        libc::SYS_bind => {
            let addr_len = socket_len(args[2]);
            let addr = map_ptr(memory, args[1], addr_len, true, false)?;
            Some(Syscall::Bind {
                fd,
                umyaddr: ConstSockaddrPtr::new(addr),
                addrlen: addr_len as Socklen,
            })
        }
        libc::SYS_listen => Some(Syscall::Listen {
            fd,
            backlog: args[1] as i32,
        }),
        libc::SYS_getsockname => {
            let (addr, addr_len) = map_sockaddr_out(memory, args[1], args[2])?;
            Some(Syscall::Getsockname {
                fd,
                usockaddr: SockaddrPtr::new(addr),
                usockaddr_len: SocklenPtr::new(addr_len),
            })
        }
        libc::SYS_getpeername => {
            let (addr, addr_len) = map_sockaddr_out(memory, args[1], args[2])?;
            Some(Syscall::Getpeername {
                fd,
                usockaddr: SockaddrPtr::new(addr),
                usockaddr_len: SocklenPtr::new(addr_len),
            })
        }
        libc::SYS_socketpair => {
            let pair = map_ptr(memory, args[3], 2 * std::mem::size_of::<i32>(), false, true)?;
            Some(Syscall::Socketpair {
                family: AddressFamily(args[0] as i32),
                r#type: args[1] as i32,
                protocol: args[2] as i32,
                usockvec: FdPair::new(pair),
            })
        }
        libc::SYS_setsockopt => {
            let len = bounded_len(args[4]);
            let optval = map_ptr(memory, args[3], len, true, false)?;
            Some(Syscall::Setsockopt {
                fd,
                level: SocketLevel(args[1] as i32),
                optname: args[2] as i32,
                optval: UserSlice::new(optval, len as u32),
            })
        }
        libc::SYS_getsockopt => {
            // TODO: map only the initial optlen value once BridgeMemory can safely inspect it
            // before dispatch; this bounded region lets WLK read optlen and copy option results.
            let optval = map_ptr(memory, args[3], crate::MAX_TRANSFER, false, true)?;
            let optlen = map_ptr(memory, args[4], std::mem::size_of::<Socklen>(), true, true)?;
            Some(Syscall::Getsockopt {
                fd,
                level: SocketLevel(args[1] as i32),
                optname: args[2] as i32,
                optval: Buf::new(optval),
                optlen: SocklenPtr::new(optlen),
            })
        }
        libc::SYS_accept4 => {
            let (addr, addr_len) = map_sockaddr_out(memory, args[1], args[2])?;
            Some(Syscall::Accept4 {
                fd,
                upeer_sockaddr: SockaddrPtr::new(addr),
                upeer_addrlen: SocklenPtr::new(addr_len),
                flags: SocketFlags(args[3] as u32),
            })
        }
        _ => None,
    };
    Ok(call)
}

fn map_sockaddr_out(memory: &mut BridgeMemory, addr: u64, addr_len: u64) -> io::Result<(u32, u32)> {
    let addr = map_ptr(memory, addr, SOCKADDR_MAX, false, true)?;
    let addr_len = map_ptr(memory, addr_len, std::mem::size_of::<Socklen>(), true, true)?;
    Ok((addr, addr_len))
}

fn map_ptr(
    memory: &mut BridgeMemory,
    ptr: u64,
    len: usize,
    read: bool,
    write: bool,
) -> io::Result<u32> {
    if ptr == 0 {
        Ok(0)
    } else {
        memory.map(ptr, len, read, write)
    }
}

fn bounded_len(len: u64) -> usize {
    len.min(crate::MAX_TRANSFER as u64) as usize
}

fn socket_len(len: u64) -> usize {
    bounded_len(len)
}
