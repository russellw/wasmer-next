//! Optional controls for the provider carrying a namespace's external socket traffic.
//!
//! These are provider operations, not Linux route lifetimes. In particular both deadline
//! values are opaque nanosecond values interpreted by that provider, exactly as in v1.
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use wasixv2_abi::Errno;

/// Private host-adapter ioctl transport on an AF_NETLINK/NETLINK_ROUTE descriptor.
/// Argument: four little-endian u32s (input pointer/length, output pointer/capacity).
/// The return is the encoded reply length; PROBE takes a 0 (read) or 1 (mutation) argument.
pub const PROBE: u32 = 0x574c_4b00;
pub const CALL: u32 = 0x574c_4b01;
pub const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cidr {
    pub ip: IpAddr,
    pub prefix: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub cidr: Cidr,
    pub via_router: IpAddr,
    pub preferred_until: Option<u64>,
    pub expires_at: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    Unencrypted,
    AnyEncryption,
    ClassicEncryption,
    DoubleEncryption,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Bridge {
        network: String,
        token: String,
        security: Security,
    },
    Unbridge,
    Dhcp,
    AddAddress(Cidr),
    RemoveAddress(IpAddr),
    ClearAddresses,
    Addresses,
    Mac,
    Gateway(IpAddr),
    AddRoute(Route),
    RemoveRoute(IpAddr),
    ClearRoutes,
    Routes,
}
impl Request {
    pub fn mutates(&self) -> bool {
        !matches!(self, Self::Addresses | Self::Mac | Self::Routes)
    }
    pub fn validate(&self) -> Result<(), Errno> {
        if let Self::Bridge { network, token, .. } = self
            && network.len().saturating_add(token.len()) > MAX_MESSAGE - 64
        {
            return Err(Errno::EMSGSIZE);
        }
        let cidr = match self {
            Self::AddAddress(a) => Some(a),
            Self::AddRoute(r) => {
                if r.cidr.ip.is_ipv4() != r.via_router.is_ipv4() {
                    return Err(Errno::EINVAL);
                }
                Some(&r.cidr)
            }
            _ => None,
        };
        if cidr.is_some_and(|a| a.prefix > if a.ip.is_ipv4() { 32 } else { 128 }) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    None,
    Acquired(Vec<IpAddr>),
    Addresses(Vec<Cidr>),
    Mac([u8; 6]),
    Routes(Vec<Route>),
}

/// Only explicitly promised readbacks are required after a successful operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readback {
    pub addresses: bool,
    pub mac: bool,
    pub routes: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub active: Option<bool>,
    /// A sent bridge/unbridge had no trustworthy acknowledgement. Getters cannot resolve it.
    pub active_unknown: bool,
    pub addresses: Option<Vec<Cidr>>,
    pub mac: Option<[u8; 6]>,
    pub routes: Option<Vec<Route>>,
}
/// A mutation can have committed remotely even when a promised readback then fails.
/// `reconciliation` reports that distinct state; no rollback is implied. A later successful
/// transaction repeats all promised readbacks and restores the namespace's availability.
pub struct Completion {
    pub result: Result<Reply, Errno>,
    pub snapshot: Snapshot,
    pub reconciliation: Option<Errno>,
}
impl Completion {
    pub fn error(error: Errno) -> Self {
        Self {
            result: Err(error),
            snapshot: Snapshot::default(),
            reconciliation: None,
        }
    }
}
pub type Done = Box<dyn FnOnce(Completion) + Send>;

/// Bound to the exact transport of one namespace. Implementors serialize the entire
/// operation, promised readback and callback publication. An accepted operation retains
/// its callback through waiter cancellation, calls it once outside its locks, and never
/// replays a request after an ambiguous disconnect. No blocking I/O runs on the guest thread.
pub trait Provider: Send + Sync {
    fn start(&self, request: Request, done: Done);
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Errno> {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::legacy())
        .map_err(|_| Errno::EINVAL)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(Errno::EMSGSIZE);
    }
    Ok(bytes)
}
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Errno> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Errno::EMSGSIZE);
    }
    let (value, used) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<MAX_MESSAGE>(),
    )
    .map_err(|_| Errno::EINVAL)?;
    if used != bytes.len() {
        return Err(Errno::EINVAL);
    }
    Ok(value)
}

/// Pins both provider and namespace publication until the accepted transaction completes.
pub(crate) struct NamespaceProvider {
    pub net: Arc<crate::Net>,
    pub provider: Arc<dyn Provider>,
}
impl Provider for NamespaceProvider {
    fn start(&self, request: Request, done: Done) {
        let net = self.net.clone();
        self.provider.start(
            request,
            Box::new(move |mut completion| {
                if (completion.result.is_ok() || completion.reconciliation.is_some())
                    && let Err(error) =
                        net.publish_provider(&completion.snapshot, completion.reconciliation)
                {
                    completion.reconciliation = Some(error);
                }
                if let Some(error) = completion.reconciliation {
                    completion.result = Err(error);
                }
                done(completion);
            }),
        );
    }
}
