//! Multicast: a socket's multicast options and group memberships (`do_ip_setsockopt`'s and
//! `do_ipv6_setsockopt`'s multicast cases, `net/ipv4/igmp.c`'s `ip_mc_join_group` and
//! `ip_mc_sf_allow`, `net/ipv6/mcast.c`'s `ipv6_sock_mc_join` and `inet6_mc_check`), and where
//! a multicast datagram is received (`ip_mc_output`, `ip6_finish_output2`, `ip_route_input_mc`,
//! `ip6_mc_input`). There are no IGMP or MLD messages: an interface is in a group while a
//! membership holds it, and a namespace across a veth receives what is sent to a group its end
//! is in.
//!
//! Each membership has a source filter (`ip_mc_source`, `ip_mc_msfilter`, `ip6_mc_source`,
//! `ip6_mc_msfilter`): `INCLUDE` some sources or `EXCLUDE` some (a plain join excludes none).
//! The socket takes from a source its filter allows (`ip_mc_sf_allow`, `inet6_mc_check`), and
//! the interface receives from a source some membership's filter allows (`ip_check_mc_rcu`).

use std::{
    mem::offset_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use wasixv2_abi::{
    Errno, GroupFilter, GroupReq, GroupSourceReq, GuestLayout, IpMreq, IpMreqSource, IpMreqn,
    IpMsfilter, IpOption, Ipv6Mreq, Ipv6Option, SockaddrIn, SockaddrIn6, SockaddrStorage,
    SocketLevel,
};

use crate::{
    NetResult, SocketKind,
    iface::{Interfaces, LinkKind, SourceFilter},
    net::{Net, NetState},
    opts::{read_int, write_bytes, write_int},
};

const SOL_IP: i32 = SocketLevel::SOL_IP.0;
const SOL_IPV6: i32 = SocketLevel::SOL_IPV6.0;
/// `MCAST_JOIN_GROUP` and `MCAST_LEAVE_GROUP`, which take a `struct group_req`; missing from
/// the generated ABI constants.
pub(crate) const MCAST_JOIN_GROUP: i32 = 42;
pub(crate) const MCAST_LEAVE_GROUP: i32 = 45;
/// The source-filter options of `MCAST_*`, which take a `struct group_source_req`, and
/// `MCAST_MSFILTER`, which takes a `struct group_filter`.
const MCAST_BLOCK_SOURCE: i32 = 43;
const MCAST_UNBLOCK_SOURCE: i32 = 44;
const MCAST_JOIN_SOURCE_GROUP: i32 = 46;
const MCAST_LEAVE_SOURCE_GROUP: i32 = 47;
const MCAST_MSFILTER: i32 = 48;
/// `MCAST_EXCLUDE`, `MCAST_INCLUDE`.
const MCAST_EXCLUDE: u32 = 0;
const MCAST_INCLUDE: u32 = 1;
/// The guest layouts of the options' payloads (wasixv2-abi): sizes and field offsets.
const SS_LEN: usize = SockaddrStorage::SIZE;
const SIN_ADDR: usize = offset_of!(SockaddrIn, sin_addr);
const SIN6_ADDR: usize = offset_of!(SockaddrIn6, sin6_addr);
const IP_MREQ_LEN: usize = IpMreq::SIZE;
const IP_MREQN_LEN: usize = IpMreqn::SIZE;
const IMR_ADDRESS: usize = offset_of!(IpMreqn, imr_address);
const IMR_IFINDEX: usize = offset_of!(IpMreqn, imr_ifindex);
const IPV6_MREQ_LEN: usize = Ipv6Mreq::SIZE;
const IPV6MR_IFINDEX: usize = offset_of!(Ipv6Mreq, ipv6mr_ifindex);
const IP_MREQ_SOURCE_LEN: usize = IpMreqSource::SIZE;
const IMR_INTERFACE: usize = offset_of!(IpMreqSource, imr_interface);
const IMR_SOURCEADDR: usize = offset_of!(IpMreqSource, imr_sourceaddr);
/// `IP_MSFILTER_SIZE(0)`: up to the sources.
const IP_MSFILTER_LEN: usize = offset_of!(IpMsfilter, imsf_slist);
const IMSF_INTERFACE: usize = offset_of!(IpMsfilter, imsf_interface);
const IMSF_FMODE: usize = offset_of!(IpMsfilter, imsf_fmode);
const IMSF_NUMSRC: usize = offset_of!(IpMsfilter, imsf_numsrc);
const GROUP_REQ_LEN: usize = GroupReq::SIZE;
const GR_GROUP: usize = offset_of!(GroupReq, gr_group);
const GROUP_SOURCE_REQ_LEN: usize = GroupSourceReq::SIZE;
const GSR_GROUP: usize = offset_of!(GroupSourceReq, gsr_group);
const GSR_SOURCE: usize = offset_of!(GroupSourceReq, gsr_source);
/// `GROUP_FILTER_SIZE(0)`: up to the sources.
const GROUP_FILTER_LEN: usize = offset_of!(GroupFilter, gf_slist);
const GF_GROUP: usize = offset_of!(GroupFilter, gf_group);
const GF_FMODE: usize = offset_of!(GroupFilter, gf_fmode);
const GF_NUMSRC: usize = offset_of!(GroupFilter, gf_numsrc);
/// `net.ipv4.igmp_max_msf`, `sysctl_mld_max_msf`: the sources one filter may name.
const IGMP_MAX_MSF: usize = 10;
const MLD_MAX_MSF: usize = 64;
/// `net.ipv4.igmp_max_memberships`.
const IGMP_MAX_MEMBERSHIPS: usize = 20;
/// `AF_INET`, `AF_INET6`.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Admission on one actual external resource, without owning that resource or inventing an
/// effective physical interface for a zero/address-selected request.
#[derive(Clone)]
struct ProviderMembership(Weak<dyn crate::endpoint::EndpointBound>);
impl std::fmt::Debug for ProviderMembership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderMembership(..)")
    }
}
impl PartialEq for ProviderMembership {
    fn eq(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ProviderMembership {}

/// One membership of a socket (`struct ip_mc_socklist`, `struct ipv6_mc_socklist`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Membership {
    group: IpAddr,
    /// The interface it was made on.
    ifindex: u32,
    /// IPv4's `imr_address`, which a leave by address matches.
    address: Ipv4Addr,
    /// The literal interface request, before namespace route selection.
    requested_index: u32,
    /// Whether this record holds a namespace interface reference, separate from its literal
    /// physical request. An external request need not name a synthetic namespace interface.
    namespace_ref: bool,
    provider: Option<ProviderMembership>,
    /// Names the membership's filter on the interface.
    id: u64,
    /// `sfmode`: `MCAST_INCLUDE`, else `MCAST_EXCLUDE`.
    include: bool,
    /// `sflist`, `None` while there is none. IPv4 keeps an emptied list, IPv6 drops it.
    sources: Option<Vec<IpAddr>>,
}

impl Membership {
    fn new(group: IpAddr, ifindex: u32, address: Ipv4Addr, include: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            group,
            ifindex,
            address,
            requested_index: ifindex,
            namespace_ref: true,
            provider: None,
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            include,
            sources: None,
        }
    }

    fn filter(&self) -> SourceFilter {
        SourceFilter {
            id: self.id,
            group: self.group,
            include: self.include,
            sources: self.sources.clone().unwrap_or_default(),
        }
    }

    /// `ip_mc_sf_allow`'s and `inet6_mc_check`'s test of the filter.
    fn allows(&self, src: IpAddr) -> bool {
        match &self.sources {
            None => !self.include,
            Some(list) => self.include == list.contains(&src),
        }
    }
}

/// `ip_mc_find_dev`: the interface by index, else by address, else the route to the group.
fn find_dev4(ifs: &Interfaces, group: Ipv4Addr, address: Ipv4Addr, ifindex: u32) -> Option<u32> {
    match (ifindex, address.is_unspecified()) {
        (0, false) => ifs.link_with_addr(address.into()),
        (0, true) => ifs.route(group.into()).ok().map(|d| d.oif),
        (i, _) => ifs.link(i).map(|l| l.index),
    }
}

/// `ip6_mc_find_idev`: the interface by index, else the route to the group.
fn find_dev6(ifs: &Interfaces, ifindex: u32) -> Option<u32> {
    match ifindex {
        0 => ifs.mc6_default_oif(),
        i => ifs.link(i).map(|l| l.index),
    }
}

/// A source filter change of [`Mcast::set_source`].
struct SourceChange {
    add: bool,
    include: bool,
    source: IpAddr,
}

/// A socket's multicast state: the options of both families and the memberships made.
#[derive(Clone, Debug)]
pub(crate) struct Mcast {
    /// `mc_ttl`, `IP_MULTICAST_TTL`.
    pub ttl: u8,
    /// `IP_MULTICAST_LOOP`, `IP_MULTICAST_ALL`.
    pub loop4: bool,
    pub all4: bool,
    /// `IP_MULTICAST_IF`: `mc_index` and `mc_addr`.
    pub index4: u32,
    /// Literal index before namespace address-to-interface resolution, for physical replay.
    pub requested_index4: u32,
    pub addr4: Ipv4Addr,
    /// `mcast_hops`, `IPV6_MULTICAST_HOPS`.
    pub hops6: u8,
    /// `IPV6_MULTICAST_LOOP`, `IPV6_MULTICAST_ALL`, `IPV6_MULTICAST_IF`.
    pub loop6: bool,
    pub all6: bool,
    pub oif6: u32,
    groups: Vec<Membership>,
}

impl Default for Mcast {
    fn default() -> Self {
        Self {
            ttl: 1,
            loop4: true,
            all4: true,
            index4: 0,
            requested_index4: 0,
            addr4: Ipv4Addr::UNSPECIFIED,
            hops6: 1,
            loop6: true,
            all6: true,
            oif6: 0,
            groups: Vec::new(),
        }
    }
}

/// Whether `(level, name)` is a multicast option this module handles.
pub(crate) fn handles(level: i32, name: i32) -> bool {
    let v4 = [
        IpOption::IP_MULTICAST_IF.0,
        IpOption::IP_MULTICAST_TTL.0,
        IpOption::IP_MULTICAST_LOOP.0,
        IpOption::IP_MULTICAST_ALL.0,
        IpOption::IP_ADD_MEMBERSHIP.0,
        IpOption::IP_DROP_MEMBERSHIP.0,
        IpOption::IP_BLOCK_SOURCE.0,
        IpOption::IP_UNBLOCK_SOURCE.0,
        IpOption::IP_ADD_SOURCE_MEMBERSHIP.0,
        IpOption::IP_DROP_SOURCE_MEMBERSHIP.0,
        IpOption::IP_MSFILTER.0,
        MCAST_JOIN_GROUP,
        MCAST_LEAVE_GROUP,
        MCAST_BLOCK_SOURCE,
        MCAST_UNBLOCK_SOURCE,
        MCAST_JOIN_SOURCE_GROUP,
        MCAST_LEAVE_SOURCE_GROUP,
        MCAST_MSFILTER,
    ];
    let v6 = [
        Ipv6Option::IPV6_MULTICAST_IF.0,
        Ipv6Option::IPV6_MULTICAST_HOPS.0,
        Ipv6Option::IPV6_MULTICAST_LOOP.0,
        Ipv6Option::IPV6_MULTICAST_ALL.0,
        Ipv6Option::IPV6_ADD_MEMBERSHIP.0,
        Ipv6Option::IPV6_DROP_MEMBERSHIP.0,
        MCAST_JOIN_GROUP,
        MCAST_LEAVE_GROUP,
        MCAST_BLOCK_SOURCE,
        MCAST_UNBLOCK_SOURCE,
        MCAST_JOIN_SOURCE_GROUP,
        MCAST_LEAVE_SOURCE_GROUP,
        MCAST_MSFILTER,
    ];
    (level == SOL_IP && v4.contains(&name)) || (level == SOL_IPV6 && v6.contains(&name))
}

/// `do_ip_setsockopt`'s reading of an `int` option: an `int`, or a single byte for a shorter
/// value, and 0 for none.
fn ip_int(value: &[u8]) -> i32 {
    match value.len() {
        0 => 0,
        1..4 => i32::from(value[0]),
        _ => i32::from_le_bytes(value[..4].try_into().expect("4 bytes")),
    }
}

/// `do_ip_getsockopt`'s writing of an `int` value: a byte for a short buffer and a value that
/// fits.
fn ip_int_out(out: &mut [u8], v: i32) -> usize {
    match out.len() < 4 && !out.is_empty() && (0..=255).contains(&v) {
        true => write_bytes(out, &[v as u8]),
        false => write_int(out, v),
    }
}

fn v4_at(value: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(&value[at..at + 4]).expect("4 bytes"))
}

fn u32_at(value: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(value[at..at + 4].try_into().expect("4 bytes"))
}

/// A validated selected-provider change. Preparation only reads interface state.
/// Committing a join can still fail if its interface disappeared during provider work.
pub(crate) struct PreparedMcast {
    next: Mcast,
    change: Option<(bool, Membership)>,
}
impl PreparedMcast {
    pub(crate) fn state(&self) -> &Mcast {
        &self.next
    }

    pub(crate) fn admit_provider(&mut self, bound: &Arc<dyn crate::endpoint::EndpointBound>) {
        if let Some((true, member)) = &self.change
            && let Some(record) = self
                .next
                .groups
                .iter_mut()
                .find(|record| record.id == member.id)
        {
            record.provider = Some(ProviderMembership(Arc::downgrade(bound)));
        }
    }

    pub(crate) fn commit(self, net: &Net) -> NetResult<Mcast> {
        if let Some((join, member)) = &self.change {
            if !member.namespace_ref {
                return Ok(self.next);
            }
            net.update_interfaces(|ifs| {
                if *join {
                    ifs.join_group(member.ifindex, member.filter())?;
                } else {
                    ifs.leave_group(member.ifindex, member.group, member.id);
                }
                Ok::<(), Errno>(())
            })?;
        }
        Ok(self.next)
    }
}

impl Mcast {
    pub(crate) fn prepare_selected(
        &self,
        net: &Net,
        kind: SocketKind,
        bound_dev: u32,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> NetResult<PreparedMcast> {
        let mut next = self.clone();
        let mut change = None;
        match (level, name) {
            (SOL_IP, n)
                if n == IpOption::IP_ADD_MEMBERSHIP.0 || n == IpOption::IP_DROP_MEMBERSHIP.0 =>
            {
                if kind == SocketKind::Stream {
                    return Err(Errno::EPROTO);
                }
                if value.len() < IP_MREQ_LEN {
                    return Err(Errno::EINVAL);
                }
                let index = if value.len() >= IP_MREQN_LEN {
                    u32_at(value, IMR_IFINDEX)
                } else {
                    0
                };
                let (group, address) = (v4_at(value, 0), v4_at(value, IMR_ADDRESS));
                if n == IpOption::IP_ADD_MEMBERSHIP.0 {
                    let member = self.prepare_physical_join4(group, address, index)?;
                    next.groups.push(member.clone());
                    change = Some((true, member));
                } else {
                    let at = self.physical_leave(group.into(), address, index)?;
                    change = Some((false, next.groups.remove(at)));
                }
            }
            (SOL_IPV6, n)
                if n == Ipv6Option::IPV6_ADD_MEMBERSHIP.0
                    || n == Ipv6Option::IPV6_DROP_MEMBERSHIP.0 =>
            {
                if value.len() < IPV6_MREQ_LEN {
                    return Err(Errno::EINVAL);
                }
                if kind == SocketKind::Stream {
                    return Err(Errno::EPROTO);
                }
                let (group, index) = (v6_at(value, 0), u32_at(value, IPV6MR_IFINDEX));
                if n == Ipv6Option::IPV6_ADD_MEMBERSHIP.0 {
                    let member = self.prepare_physical_join6(group, index)?;
                    next.groups.push(member.clone());
                    change = Some((true, member));
                } else {
                    let at = self.physical_leave(group.into(), Ipv4Addr::UNSPECIFIED, index)?;
                    change = Some((false, next.groups.remove(at)));
                }
            }
            // Preserve the literal physical interface hint. Availability is authoritative
            // only after this same selected resource accepts the option.
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_IF.0 => {
                if value.len() < 4 {
                    return Err(Errno::EINVAL);
                }
                let (address, index) = match value.len() {
                    IP_MREQN_LEN.. => (v4_at(value, IMR_ADDRESS), u32_at(value, IMR_IFINDEX)),
                    IP_MREQ_LEN.. => (v4_at(value, IMR_ADDRESS), 0),
                    _ => (v4_at(value, 0), 0),
                };
                if bound_dev != 0 && index != 0 && index != bound_dev {
                    return Err(Errno::EINVAL);
                }
                next.addr4 = address;
                next.index4 = index;
                next.requested_index4 = index;
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_IF.0 => {
                if kind == SocketKind::Stream {
                    return Err(Errno::ENOPROTOOPT);
                }
                if value.len() < 4 {
                    return Err(Errno::EINVAL);
                }
                let index = u32_at(value, 0);
                if bound_dev != 0 && index != 0 && index != bound_dev {
                    return Err(Errno::EINVAL);
                }
                next.oif6 = index;
            }
            // These setters only change scalar fields; they never join/leave an interface.
            (SOL_IP, n)
                if n == IpOption::IP_MULTICAST_TTL.0 || n == IpOption::IP_MULTICAST_LOOP.0 =>
            {
                next.set(net, kind, bound_dev, level, name, value)?;
            }
            (SOL_IPV6, n)
                if n == Ipv6Option::IPV6_MULTICAST_HOPS.0
                    || n == Ipv6Option::IPV6_MULTICAST_LOOP.0 =>
            {
                next.set(net, kind, bound_dev, level, name, value)?;
            }
            _ => return Err(Errno::EOPNOTSUPP),
        }
        Ok(PreparedMcast { next, change })
    }

    fn prepare_physical_join4(
        &self,
        group: Ipv4Addr,
        address: Ipv4Addr,
        index: u32,
    ) -> NetResult<Membership> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group = IpAddr::V4(group);
        if self
            .groups
            .iter()
            .any(|m| m.group == group && m.requested_index == index && m.address == address)
        {
            return Err(Errno::EADDRINUSE);
        }
        if self.groups.iter().filter(|m| m.group.is_ipv4()).count() >= IGMP_MAX_MEMBERSHIPS {
            return Err(Errno::ENOBUFS);
        }
        let mut member = Membership::new(group, index, address, false);
        // Physical indices/addresses are never namespace interface identities.
        member.namespace_ref = false;
        member.requested_index = index;
        Ok(member)
    }

    fn prepare_physical_join6(&self, group: Ipv6Addr, index: u32) -> NetResult<Membership> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group = IpAddr::V6(group);
        if self
            .groups
            .iter()
            .any(|m| m.group == group && m.requested_index == index)
        {
            return Err(Errno::EADDRINUSE);
        }
        let mut member = Membership::new(group, index, Ipv4Addr::UNSPECIFIED, false);
        member.namespace_ref = false;
        member.requested_index = index;
        Ok(member)
    }

    fn physical_leave(&self, group: IpAddr, address: Ipv4Addr, index: u32) -> NetResult<usize> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let matches =
            |m: &Membership| m.group == group && m.requested_index == index && m.address == address;
        self.groups
            .iter()
            .position(matches)
            .or_else(|| {
                let mut group_members = self
                    .groups
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.group == group);
                let (at, _) = group_members.next()?;
                group_members.next().is_none().then_some(at)
            })
            .ok_or(Errno::EADDRNOTAVAIL)
    }

    pub(crate) fn admit_provider(&mut self, bound: &Arc<dyn crate::endpoint::EndpointBound>) {
        for member in &mut self.groups {
            member.provider = Some(ProviderMembership(Arc::downgrade(bound)));
        }
    }

    /// A zero/address-selected interface is not a wildcard policy. Admission requires a
    /// matching physical membership on this SAME live resource, whose provider enforces
    /// the physical choice. Source filtering and literal nonzero interface hints still apply.
    pub(crate) fn allows_selected(
        &self,
        group: IpAddr,
        source: IpAddr,
        interface: u32,
        bound: &Arc<dyn crate::endpoint::EndpointBound>,
    ) -> bool {
        self.groups.iter().any(|member| {
            member.group == group
                && member.allows(source)
                && (member.requested_index == 0 || member.requested_index == interface)
                && member
                    .provider
                    .as_ref()
                    .and_then(|admission| admission.0.upgrade())
                    .is_some_and(|resource| Arc::ptr_eq(&resource, bound))
        })
    }

    /// Current memberships as fresh-bind operations, preserving the original interface hint.
    pub(crate) fn backend_memberships(&self) -> NetResult<Vec<(i32, i32, Vec<u8>)>> {
        let mut out = Vec::new();
        for member in &self.groups {
            if member.include || member.sources.is_some() {
                return Err(Errno::EOPNOTSUPP);
            }
            match member.group {
                IpAddr::V4(group) => {
                    let mut bytes = group.octets().to_vec();
                    bytes.extend(member.address.octets());
                    bytes.extend(member.requested_index.to_le_bytes());
                    out.push((SOL_IP, IpOption::IP_ADD_MEMBERSHIP.0, bytes));
                }
                IpAddr::V6(group) => {
                    let mut bytes = group.octets().to_vec();
                    bytes.extend(member.requested_index.to_le_bytes());
                    out.push((SOL_IPV6, Ipv6Option::IPV6_ADD_MEMBERSHIP.0, bytes));
                }
            }
        }
        Ok(out)
    }

    /// `setsockopt` of a multicast option (see [`handles`]) on a socket of type `kind` in
    /// `net`. `bound_dev` is `SO_BINDTODEVICE`'s interface, 0 for none.
    pub(crate) fn set(
        &mut self,
        net: &Net,
        kind: SocketKind,
        bound_dev: u32,
        level: i32,
        name: i32,
        value: &[u8],
    ) -> NetResult<()> {
        let stream = kind == SocketKind::Stream;
        match (level, name) {
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_TTL.0 => {
                if stream || value.is_empty() {
                    return Err(Errno::EINVAL);
                }
                let ttl = match ip_int(value) {
                    -1 => 1,
                    v @ 0..=255 => v,
                    _ => return Err(Errno::EINVAL),
                };
                self.ttl = ttl as u8;
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_LOOP.0 => {
                if value.is_empty() {
                    return Err(Errno::EINVAL);
                }
                self.loop4 = ip_int(value) != 0;
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_ALL.0 => {
                if value.is_empty() {
                    return Err(Errno::EINVAL);
                }
                self.all4 = match ip_int(value) {
                    0 => false,
                    1 => true,
                    _ => return Err(Errno::EINVAL),
                };
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_IF.0 => {
                if stream {
                    return Err(Errno::EINVAL);
                }
                self.set_if4(net, bound_dev, value)?;
            }
            // Only these and IPv6's two refuse a connection-oriented socket (`EPROTO`), before
            // the length here, after it for IPv6 (`do_ip_setsockopt`, `do_ipv6_setsockopt`);
            // the protocol-independent and source-specific ones join for any socket.
            (SOL_IP, n)
                if n == IpOption::IP_ADD_MEMBERSHIP.0 || n == IpOption::IP_DROP_MEMBERSHIP.0 =>
            {
                if stream {
                    return Err(Errno::EPROTO);
                }
                if value.len() < IP_MREQ_LEN {
                    return Err(Errno::EINVAL);
                }
                let ifindex = match value.len() >= IP_MREQN_LEN {
                    true => u32_at(value, IMR_IFINDEX),
                    false => 0,
                };
                let (group, address) = (v4_at(value, 0), v4_at(value, IMR_ADDRESS));
                match n == IpOption::IP_ADD_MEMBERSHIP.0 {
                    true => self.join4(net, group, address, ifindex, false)?,
                    false => self.leave4(net, group, address, ifindex)?,
                }
            }
            (SOL_IP | SOL_IPV6, MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP) => {
                if value.len() < GROUP_REQ_LEN {
                    return Err(Errno::EINVAL);
                }
                let ifindex = u32_at(value, 0);
                let family = u16::from_le_bytes([value[GR_GROUP], value[GR_GROUP + 1]]);
                let join = name == MCAST_JOIN_GROUP;
                match level {
                    SOL_IP => {
                        if family != AF_INET {
                            return Err(Errno::EADDRNOTAVAIL);
                        }
                        let group = v4_at(value, GR_GROUP + SIN_ADDR);
                        match join {
                            true => {
                                self.join4(net, group, Ipv4Addr::UNSPECIFIED, ifindex, false)?
                            }
                            false => self.leave4(net, group, Ipv4Addr::UNSPECIFIED, ifindex)?,
                        }
                    }
                    _ => {
                        if family != AF_INET6 {
                            return Err(Errno::EADDRNOTAVAIL);
                        }
                        let group = v6_at(value, GR_GROUP + SIN6_ADDR);
                        match join {
                            true => self.join6(net, group, ifindex, false)?,
                            false => self.leave6(net, group, ifindex)?,
                        }
                    }
                }
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_HOPS.0 => {
                if stream {
                    return Err(Errno::ENOPROTOOPT);
                }
                self.hops6 = match read_int(value)? {
                    -1 => 1,
                    v @ 0..=255 => v as u8,
                    _ => return Err(Errno::EINVAL),
                };
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_LOOP.0 => {
                self.loop6 = match read_int(value)? {
                    0 => false,
                    1 => true,
                    _ => return Err(Errno::EINVAL),
                };
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_ALL.0 => {
                self.all6 = read_int(value)? != 0;
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_IF.0 => {
                if stream {
                    return Err(Errno::ENOPROTOOPT);
                }
                let index = read_int(value)? as u32;
                if index != 0 {
                    if net.state().ifaces.link(index).is_none() {
                        return Err(Errno::ENODEV);
                    }
                    if bound_dev != 0 && bound_dev != index {
                        return Err(Errno::EINVAL);
                    }
                }
                self.oif6 = index;
            }
            (SOL_IPV6, n)
                if n == Ipv6Option::IPV6_ADD_MEMBERSHIP.0
                    || n == Ipv6Option::IPV6_DROP_MEMBERSHIP.0 =>
            {
                if value.len() < IPV6_MREQ_LEN {
                    return Err(Errno::EINVAL);
                }
                if stream {
                    return Err(Errno::EPROTO);
                }
                let (group, ifindex) = (v6_at(value, 0), u32_at(value, IPV6MR_IFINDEX));
                match n == Ipv6Option::IPV6_ADD_MEMBERSHIP.0 {
                    true => self.join6(net, group, ifindex, false)?,
                    false => self.leave6(net, group, ifindex)?,
                }
            }
            (SOL_IP, n)
                if [
                    IpOption::IP_BLOCK_SOURCE.0,
                    IpOption::IP_UNBLOCK_SOURCE.0,
                    IpOption::IP_ADD_SOURCE_MEMBERSHIP.0,
                    IpOption::IP_DROP_SOURCE_MEMBERSHIP.0,
                ]
                .contains(&n) =>
            {
                self.mreq_source(net, n, value)?
            }
            (SOL_IP, n) if n == IpOption::IP_MSFILTER.0 => self.ip_msfilter(net, value)?,
            (
                SOL_IP | SOL_IPV6,
                MCAST_BLOCK_SOURCE
                | MCAST_UNBLOCK_SOURCE
                | MCAST_JOIN_SOURCE_GROUP
                | MCAST_LEAVE_SOURCE_GROUP,
            ) => self.group_source(net, level == SOL_IPV6, name, value)?,
            (SOL_IP | SOL_IPV6, MCAST_MSFILTER) => {
                self.group_filter(net, level == SOL_IPV6, value)?
            }
            _ => return Err(Errno::ENOPROTOOPT),
        }
        Ok(())
    }

    /// `IP_BLOCK_SOURCE`, `IP_UNBLOCK_SOURCE`, `IP_ADD_SOURCE_MEMBERSHIP` and
    /// `IP_DROP_SOURCE_MEMBERSHIP` (`do_ip_setsockopt`): a `struct ip_mreq_source` of exactly
    /// its size. Adding a source membership joins the group in `INCLUDE` mode first, unless
    /// the socket is in it already.
    fn mreq_source(&mut self, net: &Net, name: i32, value: &[u8]) -> NetResult<()> {
        if value.len() != IP_MREQ_SOURCE_LEN {
            return Err(Errno::EINVAL);
        }
        let (group, address, source) = (
            v4_at(value, 0),
            v4_at(value, IMR_INTERFACE),
            v4_at(value, IMR_SOURCEADDR),
        );
        let (add, include) = match IpOption(name) {
            IpOption::IP_BLOCK_SOURCE => (true, false),
            IpOption::IP_UNBLOCK_SOURCE => (false, false),
            IpOption::IP_ADD_SOURCE_MEMBERSHIP => {
                match self.join4(net, group, address, 0, true) {
                    Ok(()) | Err(Errno::EADDRINUSE) => {}
                    Err(e) => return Err(e),
                }
                (true, true)
            }
            _ => (false, true),
        };
        let change = SourceChange {
            add,
            include,
            source: source.into(),
        };
        self.source4(net, group, address, 0, change)
    }

    /// `do_mcast_group_source`, `do_ipv6_mcast_group_source`: a `struct group_source_req` of
    /// exactly its size, both addresses of the level's family (`EADDRNOTAVAIL`).
    fn group_source(&mut self, net: &Net, v6: bool, name: i32, value: &[u8]) -> NetResult<()> {
        if value.len() != GROUP_SOURCE_REQ_LEN {
            return Err(Errno::EINVAL);
        }
        let ifindex = u32_at(value, 0);
        let (group, source) = match (
            ss_addr(value, GSR_GROUP, v6),
            ss_addr(value, GSR_SOURCE, v6),
        ) {
            (Some(group), Some(source)) => (group, source),
            _ => return Err(Errno::EADDRNOTAVAIL),
        };
        let (add, include) = match name {
            MCAST_BLOCK_SOURCE => (true, false),
            MCAST_UNBLOCK_SOURCE => (false, false),
            MCAST_JOIN_SOURCE_GROUP => {
                let joined = match (group, v6) {
                    (IpAddr::V6(g), true) => self.join6(net, g, ifindex, true),
                    (IpAddr::V4(g), _) => self.join4(net, g, Ipv4Addr::UNSPECIFIED, ifindex, true),
                    _ => unreachable!("of the level's family"),
                };
                match joined {
                    Ok(()) | Err(Errno::EADDRINUSE) => {}
                    Err(e) => return Err(e),
                }
                (true, true)
            }
            _ => (false, true),
        };
        let change = SourceChange {
            add,
            include,
            source,
        };
        match group {
            IpAddr::V4(g) => self.source4(net, g, Ipv4Addr::UNSPECIFIED, ifindex, change),
            IpAddr::V6(g) => self.source6(net, g, ifindex, change),
        }
    }

    /// `ip_mc_source`: the membership of the interface the request names must exist
    /// (`EINVAL`).
    fn source4(
        &mut self,
        net: &Net,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
        change: SourceChange,
    ) -> NetResult<()> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = find_dev4(&net.state().ifaces, group, address, ifindex).ok_or(Errno::ENODEV)?;
        let at = self
            .groups
            .iter()
            .position(|m| m.group == IpAddr::V4(group) && m.ifindex == index)
            .ok_or(Errno::EINVAL)?;
        self.set_source(net, at, change, false)
    }

    /// `ip6_mc_source`: the membership of the interface named, or of the group on any for
    /// none, must exist (`EINVAL`).
    fn source6(
        &mut self,
        net: &Net,
        group: Ipv6Addr,
        ifindex: u32,
        change: SourceChange,
    ) -> NetResult<()> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        find_dev6(&net.state().ifaces, ifindex).ok_or(Errno::ENODEV)?;
        let at = self
            .groups
            .iter()
            .position(|m| m.group == IpAddr::V6(group) && (ifindex == 0 || m.ifindex == ifindex))
            .ok_or(Errno::EINVAL)?;
        self.set_source(net, at, change, true)
    }

    /// The common part of `ip_mc_source` and `ip6_mc_source` for the membership at `at`: a
    /// filter with a list keeps its mode (`EINVAL`), one without switches; removing a source
    /// not there, or adding one already there, is `EADDRNOTAVAIL`, past the sysctl's count
    /// `ENOBUFS`; removing the last source of an `INCLUDE` filter leaves the group.
    fn set_source(
        &mut self,
        net: &Net,
        at: usize,
        change: SourceChange,
        v6: bool,
    ) -> NetResult<()> {
        let m = &mut self.groups[at];
        if m.sources.is_some() && m.include != change.include {
            return Err(Errno::EINVAL);
        }
        m.include = change.include;
        let result = match (change.add, &mut m.sources) {
            (false, None) => Err(Errno::EADDRNOTAVAIL),
            (false, Some(list)) => match list.iter().position(|s| *s == change.source) {
                None => Err(Errno::EADDRNOTAVAIL),
                Some(_) if list.len() == 1 && change.include => {
                    let m = self.groups.remove(at);
                    net.update_interfaces(|ifs| ifs.leave_group(m.ifindex, m.group, m.id));
                    return Ok(());
                }
                Some(i) => {
                    list.remove(i);
                    if v6 && list.is_empty() {
                        m.sources = None;
                    }
                    Ok(())
                }
            },
            (true, list) => {
                let max = if v6 { MLD_MAX_MSF } else { IGMP_MAX_MSF };
                let list = list.get_or_insert_with(Vec::new);
                if list.len() >= max {
                    Err(Errno::ENOBUFS)
                } else if list.contains(&change.source) {
                    Err(Errno::EADDRNOTAVAIL)
                } else {
                    list.push(change.source);
                    Ok(())
                }
            }
        };
        let (index, filter) = (m.ifindex, m.filter());
        net.update_interfaces(|ifs| ifs.set_source_filter(index, filter));
        result
    }

    /// `IP_MSFILTER` (`do_ip_setsockopt`): a `struct ip_msfilter` of at least its fixed part
    /// whose sources fit (`EINVAL`), at most `igmp_max_msf` of them (`ENOBUFS`).
    fn ip_msfilter(&mut self, net: &Net, value: &[u8]) -> NetResult<()> {
        if value.len() < IP_MSFILTER_LEN {
            return Err(Errno::EINVAL);
        }
        let numsrc = u32_at(value, IMSF_NUMSRC) as usize;
        if numsrc > IGMP_MAX_MSF {
            return Err(Errno::ENOBUFS);
        }
        if IP_MSFILTER_LEN + 4 * numsrc > value.len() {
            return Err(Errno::EINVAL);
        }
        let sources = (0..numsrc)
            .map(|i| IpAddr::V4(v4_at(value, IP_MSFILTER_LEN + 4 * i)))
            .collect();
        let (group, address, fmode) = (
            v4_at(value, 0),
            v4_at(value, IMSF_INTERFACE),
            u32_at(value, IMSF_FMODE),
        );
        self.msfilter4(net, group, address, 0, fmode, sources)
    }

    /// `MCAST_MSFILTER` (`ip_set_mcast_msfilter`, `ipv6_set_mcast_msfilter`): a `struct
    /// group_filter` whose sources fit (`EINVAL`), at most the sysctl's count (`ENOBUFS`);
    /// for IPv4 every address must be one (`EADDRNOTAVAIL`), IPv6 reads them as IPv6's.
    fn group_filter(&mut self, net: &Net, v6: bool, value: &[u8]) -> NetResult<()> {
        if value.len() < GROUP_FILTER_LEN {
            return Err(Errno::EINVAL);
        }
        let numsrc = u32_at(value, GF_NUMSRC) as usize;
        let max = if v6 { MLD_MAX_MSF } else { IGMP_MAX_MSF };
        if numsrc > max {
            return Err(Errno::ENOBUFS);
        }
        if GROUP_FILTER_LEN + SS_LEN * numsrc > value.len() {
            return Err(Errno::EINVAL);
        }
        let ifindex = u32_at(value, 0);
        let fmode = u32_at(value, GF_FMODE);
        let at = |i: usize| GROUP_FILTER_LEN + SS_LEN * i;
        if v6 {
            let group = v6_at(value, GF_GROUP + SIN6_ADDR);
            let sources = (0..numsrc).map(|i| IpAddr::V6(v6_at(value, at(i) + SIN6_ADDR)));
            return self.msfilter6(net, group, ifindex, fmode, sources.collect());
        }
        let Some(IpAddr::V4(group)) = ss_addr(value, GF_GROUP, false) else {
            return Err(Errno::EADDRNOTAVAIL);
        };
        let sources: Option<Vec<IpAddr>> =
            (0..numsrc).map(|i| ss_addr(value, at(i), false)).collect();
        let sources = sources.ok_or(Errno::EADDRNOTAVAIL)?;
        self.msfilter4(net, group, Ipv4Addr::UNSPECIFIED, ifindex, fmode, sources)
    }

    /// `ip_mc_msfilter`: the whole filter of a membership; `INCLUDE` nothing leaves the group.
    fn msfilter4(
        &mut self,
        net: &Net,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
        fmode: u32,
        sources: Vec<IpAddr>,
    ) -> NetResult<()> {
        if !group.is_multicast() || (fmode != MCAST_INCLUDE && fmode != MCAST_EXCLUDE) {
            return Err(Errno::EINVAL);
        }
        let index = find_dev4(&net.state().ifaces, group, address, ifindex).ok_or(Errno::ENODEV)?;
        if fmode == MCAST_INCLUDE && sources.is_empty() {
            return self.leave4(net, group, address, index);
        }
        let at = self
            .groups
            .iter()
            .position(|m| m.group == IpAddr::V4(group) && m.ifindex == index)
            .ok_or(Errno::EINVAL)?;
        self.replace_filter(net, at, fmode == MCAST_INCLUDE, sources);
        Ok(())
    }

    /// `ip6_mc_msfilter`: as `ip_mc_msfilter`, of the membership made on exactly `ifindex`.
    fn msfilter6(
        &mut self,
        net: &Net,
        group: Ipv6Addr,
        ifindex: u32,
        fmode: u32,
        sources: Vec<IpAddr>,
    ) -> NetResult<()> {
        if !group.is_multicast() || (fmode != MCAST_INCLUDE && fmode != MCAST_EXCLUDE) {
            return Err(Errno::EINVAL);
        }
        find_dev6(&net.state().ifaces, ifindex).ok_or(Errno::ENODEV)?;
        if fmode == MCAST_INCLUDE && sources.is_empty() {
            return self.leave6(net, group, ifindex);
        }
        let at = self
            .groups
            .iter()
            .position(|m| m.group == IpAddr::V6(group) && m.ifindex == ifindex)
            .ok_or(Errno::EINVAL)?;
        self.replace_filter(net, at, fmode == MCAST_INCLUDE, sources);
        Ok(())
    }

    fn replace_filter(&mut self, net: &Net, at: usize, include: bool, sources: Vec<IpAddr>) {
        let m = &mut self.groups[at];
        m.include = include;
        m.sources = (!sources.is_empty()).then_some(sources);
        let (index, filter) = (m.ifindex, m.filter());
        net.update_interfaces(|ifs| ifs.set_source_filter(index, filter));
    }

    /// `IP_MULTICAST_IF`: an `ip_mreqn`, an `ip_mreq` or an `in_addr`. The unspecified address
    /// without an index clears it; an address no interface has, or an index no interface has,
    /// is `EADDRNOTAVAIL`.
    fn set_if4(&mut self, net: &Net, bound_dev: u32, value: &[u8]) -> NetResult<()> {
        if value.len() < 4 {
            return Err(Errno::EINVAL);
        }
        let (address, mut index) = match value.len() {
            IP_MREQN_LEN.. => (v4_at(value, IMR_ADDRESS), u32_at(value, IMR_IFINDEX)),
            IP_MREQ_LEN.. => (v4_at(value, IMR_ADDRESS), 0),
            _ => (v4_at(value, 0), 0),
        };
        if index == 0 && address.is_unspecified() {
            self.index4 = 0;
            self.requested_index4 = 0;
            self.addr4 = Ipv4Addr::UNSPECIFIED;
            return Ok(());
        }
        let requested_index = index;
        {
            let st = net.state();
            let found = match index {
                0 => st.ifaces.link_with_addr(address.into()),
                i => st.ifaces.link(i).map(|l| l.index),
            };
            index = found.ok_or(Errno::EADDRNOTAVAIL)?;
        }
        if bound_dev != 0 && index != bound_dev {
            return Err(Errno::EINVAL);
        }
        self.index4 = index;
        self.requested_index4 = requested_index;
        self.addr4 = address;
        Ok(())
    }

    /// `ip_mc_join_group`: the interface by index, by address, else the route to the group
    /// (`ip_mc_find_dev`).
    /// `include` is the mode of a source-specific join (`ip_mc_join_group_ssm`); a plain one
    /// excludes nothing.
    fn prepare_join4(
        &self,
        ifs: &Interfaces,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
        include: bool,
    ) -> NetResult<Membership> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group_ip = IpAddr::V4(group);
        let index = find_dev4(ifs, group, address, ifindex).ok_or(Errno::ENODEV)?;
        if self
            .groups
            .iter()
            .any(|m| m.group == group_ip && m.ifindex == index)
        {
            return Err(Errno::EADDRINUSE);
        }
        if self.groups.iter().filter(|m| m.group.is_ipv4()).count() >= IGMP_MAX_MEMBERSHIPS {
            return Err(Errno::ENOBUFS);
        }
        let mut membership = Membership::new(group_ip, index, address, include);
        membership.requested_index = ifindex;
        Ok(membership)
    }

    fn join4(
        &mut self,
        net: &Net,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
        include: bool,
    ) -> NetResult<()> {
        net.update_interfaces(|ifs| {
            let m = self.prepare_join4(ifs, group, address, ifindex, include)?;
            ifs.join_group(m.ifindex, m.filter())?;
            self.groups.push(m);
            Ok(())
        })
    }

    fn prepare_leave4(
        &self,
        ifs: &Interfaces,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
    ) -> NetResult<usize> {
        let group_ip = IpAddr::V4(group);
        let found = match (ifindex, address.is_unspecified()) {
            (0, false) => ifs.link_with_addr(address.into()),
            (0, true) => ifs.route(group_ip).ok().map(|d| d.oif),
            (i, _) => ifs.link(i).map(|l| l.index),
        };
        if ifindex == 0 && address.is_unspecified() && found.is_none() {
            return Err(Errno::ENODEV);
        }
        self.groups
            .iter()
            .position(|m| {
                m.group == group_ip
                    && match (ifindex, address.is_unspecified()) {
                        (0, true) => true,
                        (0, false) => m.address == address,
                        (i, _) => m.ifindex == i,
                    }
            })
            .ok_or(Errno::EADDRNOTAVAIL)
    }

    /// `ip_mc_leave_group`: by index if given, else by the address it was made with.
    fn leave4(
        &mut self,
        net: &Net,
        group: Ipv4Addr,
        address: Ipv4Addr,
        ifindex: u32,
    ) -> NetResult<()> {
        net.update_interfaces(|ifs| {
            let at = self.prepare_leave4(ifs, group, address, ifindex)?;
            let m = self.groups.remove(at);
            if m.namespace_ref {
                ifs.leave_group(m.ifindex, m.group, m.id);
            }
            Ok(())
        })
    }

    fn prepare_join6(
        &self,
        ifs: &Interfaces,
        group: Ipv6Addr,
        ifindex: u32,
        include: bool,
    ) -> NetResult<Membership> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group_ip = IpAddr::V6(group);
        if self
            .groups
            .iter()
            .any(|m| m.group == group_ip && (ifindex == 0 || m.ifindex == ifindex))
        {
            return Err(Errno::EADDRINUSE);
        }
        let index = find_dev6(ifs, ifindex).ok_or(Errno::ENODEV)?;
        let mut m = Membership::new(group_ip, index, Ipv4Addr::UNSPECIFIED, include);
        m.requested_index = ifindex;
        Ok(m)
    }

    /// `ipv6_sock_mc_join`: the interface by index, else the route to the group.
    fn join6(&mut self, net: &Net, group: Ipv6Addr, ifindex: u32, include: bool) -> NetResult<()> {
        // Keep IPv6's duplicate check before taking the interface state, as before.
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group_ip = IpAddr::V6(group);
        if self
            .groups
            .iter()
            .any(|m| m.group == group_ip && (ifindex == 0 || m.ifindex == ifindex))
        {
            return Err(Errno::EADDRINUSE);
        }
        net.update_interfaces(|ifs| {
            let m = self.prepare_join6(ifs, group, ifindex, include)?;
            ifs.join_group(m.ifindex, m.filter())?;
            self.groups.push(m);
            Ok(())
        })
    }

    fn prepare_leave6(&self, group: Ipv6Addr, ifindex: u32) -> NetResult<usize> {
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let group_ip = IpAddr::V6(group);
        self.groups
            .iter()
            .position(|m| m.group == group_ip && (ifindex == 0 || m.ifindex == ifindex))
            .ok_or(Errno::EADDRNOTAVAIL)
    }

    /// `ipv6_sock_mc_drop`.
    fn leave6(&mut self, net: &Net, group: Ipv6Addr, ifindex: u32) -> NetResult<()> {
        let at = self.prepare_leave6(group, ifindex)?;
        let m = self.groups.remove(at);
        net.update_interfaces(|ifs| ifs.leave_group(m.ifindex, m.group, m.id));
        Ok(())
    }

    /// `ip_mc_drop_socket`, `ipv6_sock_mc_close`: the socket's memberships end with it.
    /// What a socket accepted from a listener starts with: its options, no memberships
    /// (`inet_csk_clone_lock`, `tcp_v6_syn_recv_sock`).
    pub(crate) fn inherit(&self) -> Self {
        Self {
            groups: Vec::new(),
            ..self.clone()
        }
    }

    /// IPV6_ADDRFORM releases only IPv6 memberships (__ipv6_sock_mc_close).
    pub(crate) fn drop_ipv6(&mut self, net: &Net) {
        net.update_interfaces(|ifs| {
            self.groups.retain(|m| {
                if m.group.is_ipv6() {
                    if m.namespace_ref {
                        ifs.leave_group(m.ifindex, m.group, m.id);
                    }
                    false
                } else {
                    true
                }
            });
        });
    }

    pub(crate) fn drop_all(&mut self, net: &Net) {
        if self.groups.is_empty() {
            return;
        }
        let groups = std::mem::take(&mut self.groups);
        net.update_interfaces(|ifs| {
            for m in groups {
                if m.namespace_ref {
                    ifs.leave_group(m.ifindex, m.group, m.id);
                }
            }
        });
    }

    /// `getsockopt` of a multicast option; the membership ones have no value
    /// (`ENOPROTOOPT`, as Linux's). The filters' (`IP_MSFILTER`, `MCAST_MSFILTER`) read the
    /// request from `out`, which holds what the caller passed.
    pub(crate) fn get(
        &self,
        net: &Net,
        kind: SocketKind,
        level: i32,
        name: i32,
        out: &mut [u8],
    ) -> NetResult<usize> {
        Ok(match (level, name) {
            (SOL_IP, n) if n == IpOption::IP_MSFILTER.0 => return self.get_ip_msfilter(net, out),
            (SOL_IP | SOL_IPV6, MCAST_MSFILTER) => {
                return self.get_group_filter(level == SOL_IPV6, out);
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_TTL.0 => {
                ip_int_out(out, i32::from(self.ttl))
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_LOOP.0 => {
                ip_int_out(out, i32::from(self.loop4))
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_ALL.0 => {
                ip_int_out(out, i32::from(self.all4))
            }
            (SOL_IP, n) if n == IpOption::IP_MULTICAST_IF.0 => {
                write_bytes(out, &self.addr4.octets())
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_HOPS.0 => {
                write_int(out, i32::from(self.hops6))
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_LOOP.0 => {
                write_int(out, i32::from(self.loop6))
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_ALL.0 => {
                write_int(out, i32::from(self.all6))
            }
            (SOL_IPV6, n) if n == Ipv6Option::IPV6_MULTICAST_IF.0 => {
                if kind == SocketKind::Stream {
                    return Err(Errno::ENOPROTOOPT);
                }
                write_int(out, self.oif6 as i32)
            }
            _ => return Err(Errno::ENOPROTOOPT),
        })
    }

    /// `ip_mc_sf_allow` and `inet6_mc_check`: whether the socket takes a datagram from `src`
    /// to `group` that arrived on interface `iif`: by the filter of its membership of the
    /// group (on that interface, for IPv4), else by `IP_MULTICAST_ALL`/`IPV6_MULTICAST_ALL`.
    pub(crate) fn allows(&self, group: IpAddr, src: IpAddr, iif: u32) -> bool {
        let member = self
            .groups
            .iter()
            .find(|m| m.group == group && (group.is_ipv6() || m.ifindex == iif));
        match (member, group) {
            (Some(m), _) => m.allows(src),
            (None, IpAddr::V4(_)) => self.all4,
            (None, IpAddr::V6(_)) => self.all6,
        }
    }

    /// `ip_mc_msfget`: the filter of the membership the `struct ip_msfilter` names, as many
    /// of its sources as the request's `imsf_numsrc` asks for, and their count.
    fn get_ip_msfilter(&self, net: &Net, out: &mut [u8]) -> NetResult<usize> {
        if out.len() < IP_MSFILTER_LEN {
            return Err(Errno::EINVAL);
        }
        let (group, address) = (v4_at(out, 0), v4_at(out, IMSF_INTERFACE));
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let index = find_dev4(&net.state().ifaces, group, address, 0).ok_or(Errno::ENODEV)?;
        let m = self
            .groups
            .iter()
            .find(|m| m.group == IpAddr::V4(group) && m.ifindex == index)
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let list = m.sources.clone().unwrap_or_default();
        let copy = list.len().min(u32_at(out, IMSF_NUMSRC) as usize);
        let copy = copy.min((out.len() - IP_MSFILTER_LEN) / 4);
        out[IMSF_FMODE..IMSF_FMODE + 4].copy_from_slice(&u32::from(m.include).to_le_bytes());
        out[IMSF_NUMSRC..IMSF_NUMSRC + 4].copy_from_slice(&(list.len() as u32).to_le_bytes());
        for (i, src) in list.iter().take(copy).enumerate() {
            let at = IP_MSFILTER_LEN + 4 * i;
            if let IpAddr::V4(v4) = src {
                out[at..at + 4].copy_from_slice(&v4.octets());
            }
        }
        Ok(IP_MSFILTER_LEN + 4 * copy)
    }

    /// `ip_mc_gsfget`, `ip6_mc_msfget`: as `ip_mc_msfget` for a `struct group_filter`, of the
    /// membership made on exactly `gf_interface`, each source in a `sockaddr_storage`.
    fn get_group_filter(&self, v6: bool, out: &mut [u8]) -> NetResult<usize> {
        if out.len() < GROUP_FILTER_LEN {
            return Err(Errno::EINVAL);
        }
        let group = match v6 {
            true => IpAddr::V6(v6_at(out, GF_GROUP + SIN6_ADDR)),
            false => ss_addr(out, GF_GROUP, false).ok_or(Errno::EINVAL)?,
        };
        if !group.is_multicast() {
            return Err(Errno::EINVAL);
        }
        let ifindex = u32_at(out, 0);
        let m = self
            .groups
            .iter()
            .find(|m| m.group == group && m.ifindex == ifindex)
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let list = m.sources.clone().unwrap_or_default();
        let copy = list.len().min(u32_at(out, GF_NUMSRC) as usize);
        let copy = copy.min((out.len() - GROUP_FILTER_LEN) / SS_LEN);
        out[GF_FMODE..GF_FMODE + 4].copy_from_slice(&u32::from(m.include).to_le_bytes());
        out[GF_NUMSRC..GF_NUMSRC + 4].copy_from_slice(&(list.len() as u32).to_le_bytes());
        for (i, src) in list.iter().take(copy).enumerate() {
            let at = GROUP_FILTER_LEN + SS_LEN * i;
            let slot = &mut out[at..at + SS_LEN];
            slot.fill(0);
            match src {
                IpAddr::V4(v4) => {
                    slot[..2].copy_from_slice(&AF_INET.to_le_bytes());
                    slot[SIN_ADDR..SIN_ADDR + 4].copy_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    slot[..2].copy_from_slice(&AF_INET6.to_le_bytes());
                    slot[SIN6_ADDR..SIN6_ADDR + 16].copy_from_slice(&v6.octets());
                }
            }
        }
        Ok(GROUP_FILTER_LEN + SS_LEN * copy)
    }

    /// The hop limit and loopback of a datagram to `group`.
    pub(crate) fn ttl_loop(&self, group: IpAddr) -> (u8, bool) {
        match group {
            IpAddr::V4(_) => (self.ttl, self.loop4),
            IpAddr::V6(_) => (self.hops6, self.loop6),
        }
    }

    /// The original selected physical hint, never a namespace-resolved interface index.
    pub(crate) fn physical_interface(&self, group: IpAddr) -> (u32, Option<IpAddr>) {
        let (_, address) = self.interface(group);
        (
            if group.is_ipv4() {
                self.requested_index4
            } else {
                self.oif6
            },
            address,
        )
    }

    /// `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF` for a datagram to `group`: the interface (0 for
    /// none) and IPv4's source address.
    pub(crate) fn interface(&self, group: IpAddr) -> (u32, Option<IpAddr>) {
        match group {
            IpAddr::V4(_) => (
                self.index4,
                Some(self.addr4.into()).filter(|a: &IpAddr| !a.is_unspecified()),
            ),
            IpAddr::V6(_) => (self.oif6, None),
        }
    }
}

fn v6_at(value: &[u8], at: usize) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(&value[at..at + 16]).expect("16 bytes"))
}

/// The address of the `sockaddr_storage` at `at` if it is of the family, as a `sockaddr_in6`
/// or `sockaddr_in`.
fn ss_addr(value: &[u8], at: usize, v6: bool) -> Option<IpAddr> {
    let family = u16::from_le_bytes([value[at], value[at + 1]]);
    match v6 {
        true => (family == AF_INET6).then(|| IpAddr::V6(v6_at(value, at + SIN6_ADDR))),
        false => (family == AF_INET).then(|| IpAddr::V4(v4_at(value, at + SIN_ADDR))),
    }
}

/// Where a multicast datagram leaves from, decided as `ip_route_output_key_hash_rcu` and
/// `ip6_route_output` do for a multicast destination.
pub(crate) struct McRoute {
    pub oif: u32,
    /// The source address; the unspecified one if the interface has none.
    pub src: IpAddr,
}

impl Net {
    /// The interface and source address of a datagram to `group`: the interface asked for
    /// (`ENODEV` if there is none, `ENETUNREACH` if it is down or, for IPv6, loopback or
    /// without IPv6), else the interface holding
    /// the source address asked for, else the route to the group (IPv4) or the default
    /// multicast route (IPv6).
    pub(crate) fn mc_route(
        &self,
        group: IpAddr,
        oif: u32,
        src: Option<IpAddr>,
    ) -> NetResult<McRoute> {
        let st = self.state();
        let ifs = &st.ifaces;
        let oif = match (oif, src) {
            (0, Some(src)) => ifs.link_with_addr(src).ok_or(Errno::ENETUNREACH)?,
            (0, None) if group.is_ipv6() => ifs.mc6_default_oif().ok_or(Errno::ENETUNREACH)?,
            (0, None) => ifs.route(group)?.oif,
            (i, _) => i,
        };
        let link = ifs.link(oif).ok_or(Errno::ENODEV)?;
        // IPv6 reaches a group only through an `ff00::/8` route, which loopback has none of.
        let v6_route = !link.is_loopback() && !link.ipv6_disabled;
        if !link.is_up() || (group.is_ipv6() && !v6_route) {
            return Err(Errno::ENETUNREACH);
        }
        let unspecified = match group {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let src = src
            .or_else(|| ifs.mc_source(oif, group))
            .unwrap_or(unspecified);
        Ok(McRoute { oif, src })
    }

    /// The namespaces and interfaces that receive a datagram from `src` to `group` sent out
    /// interface `oif` with hop limit `ttl` (where the interface's filters let `src` in): the sender's own namespace on `oif` if `looped`
    /// (`IP_MULTICAST_LOOP`) and `oif` is in the group (`ip_mc_output`'s copy, which a
    /// loopback interface makes no separate copy of: what it sends it receives), and through a
    /// veth with carrier, while `ttl` lets it leave, the peer's namespace if the peer's end is
    /// in the group. The uplink carries no multicast to the host, as slirp's does not.
    pub(crate) fn mc_receivers(
        &self,
        group: IpAddr,
        src: IpAddr,
        oif: u32,
        looped: bool,
        ttl: u8,
    ) -> Vec<(Arc<Net>, u32)> {
        let (kind, member) = {
            let st = self.state();
            let Some(link) = st.ifaces.link(oif) else {
                return Vec::new();
            };
            (link.kind.clone(), link.accepts(group, src))
        };
        let mut out = Vec::new();
        match kind {
            LinkKind::Loopback => {
                if member {
                    out.push((self.arc(), oif));
                }
                return out;
            }
            _ if looped && member => out.push((self.arc(), oif)),
            _ => {}
        }
        if let LinkKind::Veth(end) = kind
            && ttl > 0
            && end.carrier()
        {
            let (peer, index) = end.peer();
            if let Some(peer) = peer.upgrade() {
                let receives = peer
                    .state()
                    .ifaces
                    .link(index)
                    .is_some_and(|l| l.is_up() && l.accepts(group, src));
                if receives {
                    out.push((peer, index));
                }
            }
        }
        out
    }

    /// The index of the interface named `name` (`SO_BINDTODEVICE`), 0 for none.
    pub(crate) fn device_index(&self, name: &[u8]) -> u32 {
        if name.is_empty() {
            return 0;
        }
        let st = self.state();
        st.ifaces
            .links()
            .iter()
            .find(|l| l.name.as_bytes() == name)
            .map_or(0, |l| l.index)
    }
}

impl NetState {
    /// Every live UDP socket bound to `port`, to offer a multicast datagram to; each decides
    /// whether it takes it (`__udp_is_mcast_sock`).
    pub(crate) fn udp_on_port(&self, port: u16) -> Vec<std::sync::Weak<crate::UdpSocket>> {
        self.udp
            .entries()
            .filter(|(p, w)| *p == port && w.strong_count() > 0)
            .map(|(_, w)| w.clone())
            .collect()
    }
}
