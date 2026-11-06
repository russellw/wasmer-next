//! The shared native host-terminal policy used by `wasmer run`.

pub(super) use wasixv2::terminal::{HostTerminal, resume, suspend};
