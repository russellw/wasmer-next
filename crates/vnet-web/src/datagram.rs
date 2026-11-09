//! Source-only relay UDP uses the SAME admitted flow and its existing outgoing FIFO.
//! A queued setter is accepted locally; readbacks retain their once completion until
//! actual result or local driver cutoff. No physical destination/interface is invented.
use crate::{
    SocketControl,
    backend::{Packet, Shared},
    endpoints::Resource,
};
use std::{net::SocketAddr, sync::Arc};
use wasixv2_abi::{Errno, IpOption, Ipv6Option, SocketLevel, SocketOption};
use wasixv2_vnet::{DatagramReadback, DatagramReadbackValue, StreamState};

pub(crate) type Done = Box<dyn FnOnce(Result<DatagramReadbackValue, Errno>) + Send>;
pub(crate) enum Output {
    Packet(Packet),
    Control(SocketControl),
    Readback { query: DatagramReadback, done: Done },
}
impl Output {
    pub fn charge(&self) -> usize {
        match self {
            Self::Packet(packet) => packet.data.len().max(1),
            // Fixed-size records use the existing byte budget too.
            Self::Control(_) | Self::Readback { .. } => 64,
        }
    }
}
pub(crate) struct Dispatch {
    pub socket: u64,
    pub generation: u64,
    pub resource: Arc<Resource>,
    pub source: Option<wasixv2_vnet::endpoint::EndpointSourceId>,
    pub packet: bool,
}
pub(crate) struct Readback {
    pub socket: u64,
    pub query: DatagramReadback,
    pub generation: u64,
    pub resource: Option<Arc<Resource>>,
    pub done: Option<Done>,
}
impl Readback {
    pub fn finish(
        mut self,
        result: Result<DatagramReadbackValue, Errno>,
    ) -> Option<crate::options::Completion> {
        self.done
            .take()
            .map(|done| crate::options::Completion::readback(done, result))
    }
}

pub(crate) fn enqueue(shared: &Shared, socket: u64, output: Output) -> Result<(), Errno> {
    let mut inner = shared.inner.lock().unwrap();
    if !inner.online || inner.selected_close.is_some() {
        return Err(Errno::ENETDOWN);
    }
    let flow = inner.flows.get_mut(&socket).ok_or(Errno::ECANCELED)?;
    if flow.released
        || flow.reset
        || flow.state == StreamState::Closed
        || flow.selected.as_ref().is_some_and(|resource| {
            let state = resource.state.lock().unwrap();
            state.closing || state.close_requested || state.close.is_some()
        })
    {
        return Err(Errno::ECANCELED);
    }
    if flow.state != StreamState::Established {
        return Err(Errno::EAGAIN);
    }
    let charge = output.charge();
    if charge
        > shared
            .config
            .buffer_bytes
            .saturating_sub(flow.outgoing_bytes)
    {
        return Err(Errno::EAGAIN);
    }
    flow.outgoing_bytes += charge;
    flow.outgoing.push_back(output);
    drop(inner);
    shared.wake.wake();
    Ok(())
}

/// Exact old scalar/group setter surface; recv-error bookkeeping stays in
/// DatagramErrors. A numeric namespace interface is never translated to a host one.
pub(crate) fn control(level: i32, name: i32, value: &[u8]) -> Result<Option<SocketControl>, Errno> {
    let int = || {
        if value.len() == 1
            && level == SocketLevel::SOL_IP.0
            && matches!(name, x if x==IpOption::IP_MULTICAST_LOOP.0 || x==IpOption::IP_MULTICAST_TTL.0)
        {
            Ok(i32::from(value[0]))
        } else {
            wasixv2_vnet::opts::read_int(value)
        }
    };
    let ttl = || {
        let value = int()?;
        u32::try_from(if value == -1 { 64 } else { value }).map_err(|_| Errno::EINVAL)
    };
    Ok(Some(if level == SocketLevel::SOL_IP.0 {
        if name == IpOption::IP_TTL.0 {
            SocketControl::Ttl(ttl()?)
        } else if name == IpOption::IP_MULTICAST_LOOP.0 {
            SocketControl::MulticastLoopV4(int()? != 0)
        } else if name == IpOption::IP_MULTICAST_TTL.0 {
            SocketControl::MulticastTtlV4(ttl()?)
        } else if name == IpOption::IP_ADD_MEMBERSHIP.0 || name == IpOption::IP_DROP_MEMBERSHIP.0 {
            let bytes = value.get(..8).ok_or(Errno::EINVAL)?;
            if value.len() >= 12 && i32::from_le_bytes(value[8..12].try_into().unwrap()) != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            let multiaddr = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[..4]).unwrap());
            let iface = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).unwrap());
            if name == IpOption::IP_ADD_MEMBERSHIP.0 {
                SocketControl::JoinMulticastV4 { multiaddr, iface }
            } else {
                SocketControl::LeaveMulticastV4 { multiaddr, iface }
            }
        } else {
            return Ok(None);
        }
    } else if level == SocketLevel::SOL_IPV6.0 {
        if name == Ipv6Option::IPV6_MULTICAST_LOOP.0 {
            SocketControl::MulticastLoopV6(int()? != 0)
        } else if name == Ipv6Option::IPV6_ADD_MEMBERSHIP.0
            || name == Ipv6Option::IPV6_DROP_MEMBERSHIP.0
        {
            let bytes = value.get(..20).ok_or(Errno::EINVAL)?;
            let multiaddr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap());
            let iface = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
            if name == Ipv6Option::IPV6_ADD_MEMBERSHIP.0 {
                SocketControl::JoinMulticastV6 { multiaddr, iface }
            } else {
                SocketControl::LeaveMulticastV6 { multiaddr, iface }
            }
        } else {
            return Ok(None);
        }
    } else if level == SocketLevel::SOL_SOCKET.0 && name == SocketOption::SO_BROADCAST.0 {
        SocketControl::Broadcast(int()? != 0)
    } else {
        return Ok(None);
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Flag(bool),
    Ttl(u32),
}
impl Value {
    pub(crate) fn readback(self, query: DatagramReadback) -> Result<DatagramReadbackValue, Errno> {
        let value = match self {
            Self::Flag(value) => DatagramReadbackValue::Flag(value),
            Self::Ttl(value) => DatagramReadbackValue::Ttl(value),
        };
        if query.accepts(value) {
            Ok(value)
        } else {
            Err(Errno::EPROTO)
        }
    }
}
pub(crate) fn address(
    query: DatagramReadback,
    address: SocketAddr,
) -> Result<DatagramReadbackValue, Errno> {
    match query {
        DatagramReadback::Local => Ok(DatagramReadbackValue::Local(address)),
        DatagramReadback::Peer => Ok(DatagramReadbackValue::Peer(Some(address))),
        _ => Err(Errno::EPROTO),
    }
}
