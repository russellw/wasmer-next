//! Classic virtual-net websocket wire subset, using bincode's legacy fixed-width format.
//!
//! Tags and field order are from `lib/virtual-net/src/meta.rs`, not a guest ABI. Keeping this
//! adapter private to the driver avoids a runtime dependency on the v1 networking stack.
use crate::transport::{Command, Event, SocketControl};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer, Found, Lookup, LookupError, Shutdown,
    provider::{Cidr, Reply, Request, Route},
};

/// Maximum complete websocket message, checked before decoding any variable-length field.
pub const MAX_FRAME: usize = 1024 * 1024;

fn pack(value: impl Serialize) -> Result<Vec<u8>, Errno> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy()).map_err(|_| Errno::EPROTO)
}

/// Encode only records this backend needs. Unsupported DNS forms belong to an explicitly
/// configured resolver provider (e.g. DoH); the classic Resolve record only names a host.
pub fn encode(command: &Command) -> Result<Vec<u8>, Errno> {
    let out = match command {
        Command::SetOption {
            request,
            socket,
            control,
        } => match control {
            SocketControl::Ttl(value) => pack((1u32, socket, 27u32, value, request))?,
            SocketControl::Linger(value) => pack((1u32, socket, 30u32, value, request))?,
            SocketControl::NoDelay(value) => pack((1u32, socket, 38u32, value, request))?,
            SocketControl::KeepAlive(value) => pack((1u32, socket, 40u32, value, request))?,
            SocketControl::Broadcast(value) => pack((1u32, socket, 46u32, value, request))?,
            SocketControl::MulticastLoopV4(value) => pack((1u32, socket, 48u32, value, request))?,
            SocketControl::MulticastLoopV6(value) => pack((1u32, socket, 50u32, value, request))?,
            SocketControl::MulticastTtlV4(value) => pack((1u32, socket, 52u32, value, request))?,
            SocketControl::JoinMulticastV4 { multiaddr, iface } => {
                pack((1u32, socket, 54u32, multiaddr, iface, request))?
            }
            SocketControl::LeaveMulticastV4 { multiaddr, iface } => {
                pack((1u32, socket, 55u32, multiaddr, iface, request))?
            }
            SocketControl::JoinMulticastV6 { multiaddr, iface } => {
                pack((1u32, socket, 56u32, multiaddr, iface, request))?
            }
            SocketControl::LeaveMulticastV6 { multiaddr, iface } => {
                pack((1u32, socket, 57u32, multiaddr, iface, request))?
            }
        },
        Command::BindStream {
            request,
            socket,
            bind,
        } => {
            let operation = match bind.purpose {
                wasixv2_vnet::endpoint::EndpointBindPurpose::Bind => 16u32,
                wasixv2_vnet::endpoint::EndpointBindPurpose::Listen { .. } => 15u32,
            };
            pack((
                0u32,
                operation,
                socket,
                bind.requested,
                bind.v6only,
                bind.reuse_port,
                bind.reuse_addr,
                Some(request),
            ))?
        }
        Command::ConnectFrom {
            request,
            socket,
            peer,
            local: _,
            requested_bind,
            bound_addr,
        } => {
            if requested_bind.is_some() {
                // Only a genuinely admitted bound resource may use ConnectBound.
                bound_addr.ok_or(Errno::EINVAL)?;
                pack((1u32, socket, 23u32, peer, Some(request)))?
            } else {
                let local = SocketAddr::new(
                    if peer.is_ipv4() {
                        IpAddr::from([0, 0, 0, 0])
                    } else {
                        IpAddr::from([0u16; 8])
                    },
                    0,
                );
                pack((0u32, 19u32, socket, local, peer, Some(request)))?
            }
        }
        Command::ListenFrom {
            request, socket, ..
        } => pack((1u32, socket, 22u32, Some(request)))?,
        Command::ListenReserved {
            request,
            socket,
            member,
            v6only,
            ..
        } => pack((
            0u32,
            15u32,
            socket,
            member.local,
            v6only,
            false,
            false,
            Some(request),
        ))?,
        Command::CloseSelected { request, socket } => pack((1u32, socket, 21u32, Some(request)))?,
        Command::Provider { request, operation } => match operation {
            Request::Bridge {
                network,
                token,
                security,
            } => pack((0u32, 0u32, network, token, *security as u32, Some(request)))?,
            Request::Unbridge => pack((0u32, 2u32, Some(request)))?,
            Request::Dhcp => pack((0u32, 3u32, Some(request)))?,
            Request::AddAddress(a) => pack((0u32, 4u32, a.ip, a.prefix, Some(request)))?,
            Request::RemoveAddress(ip) => pack((0u32, 5u32, ip, Some(request)))?,
            Request::ClearAddresses => pack((0u32, 6u32, Some(request)))?,
            Request::Addresses => pack((0u32, 7u32, Some(request)))?,
            Request::Mac => pack((0u32, 8u32, Some(request)))?,
            Request::Gateway(ip) => pack((0u32, 9u32, ip, Some(request)))?,
            Request::AddRoute(r) => pack((
                0u32,
                10u32,
                &r.cidr,
                r.via_router,
                r.preferred_until.map(Duration::from_nanos),
                r.expires_at.map(Duration::from_nanos),
                Some(request),
            ))?,
            Request::RemoveRoute(ip) => pack((0u32, 11u32, ip, Some(request)))?,
            Request::ClearRoutes => pack((0u32, 12u32, Some(request)))?,
            Request::Routes => pack((0u32, 13u32, Some(request)))?,
        },
        Command::Connect {
            request,
            socket,
            peer,
        } => {
            let local = SocketAddr::new(
                if peer.is_ipv4() {
                    IpAddr::from([0, 0, 0, 0])
                } else {
                    IpAddr::from([0u16; 8])
                },
                0,
            );
            pack((0u32, 19u32, socket, local, peer, Some(request)))?
        }
        Command::Bind {
            request,
            socket,
            addr,
        } => pack((0u32, 17u32, socket, addr, false, false, Some(request)))?,
        Command::Listen {
            request,
            socket,
            addr,
        } => pack((
            0u32,
            15u32,
            socket,
            addr,
            addr.is_ipv6(),
            false,
            false,
            Some(request),
        ))?,
        Command::Lookup {
            request,
            lookup: Lookup::Name(host),
        } => pack((
            0u32,
            20u32,
            format!("{}.", host.trim_end_matches('.')),
            None::<u16>,
            None::<IpAddr>,
            Some(request),
        ))?,
        Command::Lookup {
            request,
            lookup: Lookup::Addr(addr),
        } => pack((4u32, 1u32, 1u32, request, addr))?,
        Command::Lookup {
            request,
            lookup: Lookup::Forward(message),
        } => pack((4u32, 1u32, 2u32, request, message))?,
        Command::SendUrgent {
            request,
            socket,
            data,
        } => pack((4u32, 1u32, 0u32, request, socket, data))?,
        Command::Send {
            request,
            socket,
            data,
        } => pack((2u32, socket, data, Some(request)))?,
        // The reference server ignores SendTo entirely without Some(req_id), although it
        // sends no success acknowledgment. Zero is reserved for these unacknowledged sends.
        Command::SendTo { socket, data, addr } => pack((3u32, socket, data, addr, Some(0u64)))?,
        Command::Close { socket } => pack((1u32, socket, 21u32, None::<u64>))?,
        Command::Reset { socket } => {
            pack((1u32, socket, 30u32, Some(Duration::ZERO), None::<u64>))?
        }
        Command::Shutdown {
            request,
            socket,
            how,
        } => {
            let how = match how {
                Shutdown::Read => 0u32,
                Shutdown::Write => 1,
                Shutdown::Both => 2,
            };
            pack((1u32, socket, 44u32, how, Some(request)))?
        }
        Command::LocalAddr { request, socket } => pack((1u32, socket, 25u32, Some(request)))?,
        Command::Accept { socket, child } => pack((1u32, socket, 24u32, child, None::<u64>))?,
    };
    if out.len() > MAX_FRAME {
        return Err(Errno::EMSGSIZE);
    }
    Ok(out)
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn get<T: DeserializeOwned>(&mut self) -> Result<T, Errno> {
        let (value, n) = bincode::serde::decode_from_slice(
            self.0,
            bincode::config::legacy().with_limit::<MAX_FRAME>(),
        )
        .map_err(|_| Errno::EPROTO)?;
        self.0 = &self.0[n..];
        Ok(value)
    }
}

/// Decode a complete message; malformed, oversized and trailing data are protocol failures.
pub fn decode(frame: &[u8]) -> Result<Event, Errno> {
    if frame.len() > MAX_FRAME {
        return Err(Errno::EMSGSIZE);
    }
    let mut r = Reader(frame);
    let event = match r.get::<u32>()? {
        0 => {
            let request = r.get()?;
            match r.get::<u32>()? {
                0 => Event::Complete {
                    request,
                    result: Ok(()),
                },
                1 => Event::Complete {
                    request,
                    result: Err(network_error(r.get()?)?),
                },
                9 => Event::Provider {
                    request,
                    reply: Reply::Mac(r.get()?),
                },
                10 => Event::Provider {
                    request,
                    reply: Reply::Addresses(r.get::<Vec<Cidr>>()?),
                },
                11 => {
                    #[derive(serde::Deserialize)]
                    struct ClassicRoute {
                        cidr: Cidr,
                        via_router: IpAddr,
                        preferred_until: Option<Duration>,
                        expires_at: Option<Duration>,
                    }
                    let nanos =
                        |d: Duration| u64::try_from(d.as_nanos()).map_err(|_| Errno::EPROTO);
                    let routes = r
                        .get::<Vec<ClassicRoute>>()?
                        .into_iter()
                        .map(|r| {
                            Ok(Route {
                                cidr: r.cidr,
                                via_router: r.via_router,
                                preferred_until: r.preferred_until.map(nanos).transpose()?,
                                expires_at: r.expires_at.map(nanos).transpose()?,
                            })
                        })
                        .collect::<Result<Vec<_>, Errno>>()?;
                    Event::Provider {
                        request,
                        reply: Reply::Routes(routes),
                    }
                }
                8 => Event::LocalAddr {
                    request,
                    addr: r.get()?,
                },
                5 => Event::Lookup {
                    request,
                    result: Ok(Found {
                        answer: Answer::Addrs {
                            canonical: String::new(),
                            addrs: r.get()?,
                        },
                        ttl: 30,
                    }),
                },
                // Connect/listen/bind return their socket ID; it is assigned by the client.
                12 => {
                    let _: u64 = r.get()?;
                    Event::Complete {
                        request,
                        result: Ok(()),
                    }
                }
                _ => return Err(Errno::EPROTO),
            }
        }
        1 => Event::Data {
            socket: r.get()?,
            data: r.get()?,
        },
        2 => Event::Datagram {
            socket: r.get()?,
            data: r.get()?,
            addr: r.get()?,
        },
        3 => {
            let socket = r.get()?;
            let request = r.get()?;
            let amount: u64 = r.get()?;
            Event::Sent {
                socket,
                request,
                amount: amount.try_into().map_err(|_| Errno::EPROTO)?,
            }
        }
        4 => Event::SendError {
            socket: r.get()?,
            request: r.get()?,
            error: network_error(r.get()?)?,
        },
        5 => Event::Accepted {
            socket: r.get()?,
            child: r.get()?,
            peer: r.get()?,
        },
        6 => Event::Eof { socket: r.get()? },
        // Extension envelope: version 1. Errnos are Linux numeric values, not NetworkError.
        7 => {
            if r.get::<u32>()? != 1 {
                return Err(Errno::EPROTO);
            }
            match r.get::<u32>()? {
                0 => Event::Reset {
                    socket: r.get()?,
                    error: relay_errno(r.get()?)?,
                },
                1 => Event::DatagramError {
                    socket: r.get()?,
                    error: relay_errno(r.get()?)?,
                },
                2 => {
                    let request = r.get()?;
                    let ttl = r.get()?;
                    let answer = match r.get::<u32>()? {
                        0 => Answer::Name(r.get()?),
                        1 => Answer::Message(r.get()?),
                        _ => return Err(Errno::EPROTO),
                    };
                    Event::Lookup {
                        request,
                        result: Ok(Found { ttl, answer }),
                    }
                }
                4 => Event::DatagramRefused {
                    socket: r.get()?,
                    destination: r.get()?,
                    offender: r.get()?,
                    payload: r.get()?,
                },
                3 => Event::Urgent {
                    socket: r.get()?,
                    data: r.get()?,
                },
                _ => return Err(Errno::EPROTO),
            }
        }
        _ => return Err(Errno::EPROTO),
    };
    if !r.0.is_empty() {
        return Err(Errno::EPROTO);
    }
    Ok(event)
}

/// Explicit NetworkError variants, never guessed from a websocket close code. The codec is
/// transport translation only; Linux socket errno policy stays in vnet/kernel.
fn network_error(tag: u32) -> Result<Errno, Errno> {
    Ok(match tag {
        0 => Errno::EBADF,
        1 => Errno::EEXIST,
        2 | 3 | 12 | 19 | 21 | 26 => Errno::EIO,
        4 => Errno::EADDRINUSE,
        5 => Errno::EADDRNOTAVAIL,
        6 => Errno::EPIPE,
        7 => Errno::ENOMEM,
        8 => Errno::ECONNABORTED,
        9 => Errno::ECONNREFUSED,
        10 => Errno::ECONNRESET,
        11 => Errno::EINTR,
        13 => Errno::EINVAL,
        14 => Errno::EMSGSIZE,
        15 => Errno::ENOTCONN,
        16 => Errno::ENODEV,
        17 => Errno::EACCES,
        18 => Errno::ETIMEDOUT,
        20 => Errno::EAGAIN,
        22 => Errno::EMFILE,
        23 => Errno::EOPNOTSUPP,
        24 => Errno::ENETUNREACH,
        25 => Errno::EHOSTUNREACH,
        _ => return Err(Errno::EPROTO),
    })
}

/// Classic resolution errors carry no trustworthy NXDOMAIN/TTL information.
pub(crate) fn lookup_error(_: Errno) -> LookupError {
    LookupError::Failed
}

fn relay_errno(value: i32) -> Result<Errno, Errno> {
    if (1..=4095).contains(&value) {
        Ok(Errno(value))
    } else {
        Err(Errno::EPROTO)
    }
}
