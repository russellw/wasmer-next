//! How a v1 shim fails: with what a v2 syscall said, or with a v1 errno of its own.

use wasixv2_syscalls::{Fault, SysErr};

use crate::abi;

/// The error of a v1 shim body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A v2 syscall failed or was interrupted; [`crate::shim::call`] runs the return-to-guest
    /// path, which may rerun the body or turn the interruption into `EINTR`.
    Sys(SysErr),
    /// The shim's own verdict, in v1 numbering (for errnos with no Linux counterpart, such as
    /// `NOTCAPABLE`, or v1-specific choices).
    V1(abi::Errno),
}

pub type V1Result<T> = Result<T, Error>;

impl From<SysErr> for Error {
    fn from(err: SysErr) -> Self {
        match err {
            SysErr::NamespaceBoundary | SysErr::NamespaceMutation => {
                Self::V1(abi::Errno::NOTCAPABLE)
            }
            err => Self::Sys(err),
        }
    }
}

/// Structural root mutation has operation-specific v1 errors. Intermediate
/// lookup denial remains NOTCAPABLE and ordinary Linux errors stay unchanged.
pub(crate) fn mutation(error: SysErr, verdict: abi::Errno) -> Error {
    match error {
        SysErr::NamespaceMutation => Error::V1(verdict),
        error => error.into(),
    }
}

impl From<wasixv2_abi::Errno> for Error {
    fn from(errno: wasixv2_abi::Errno) -> Self {
        Self::Sys(SysErr::Errno(errno))
    }
}

impl From<Fault> for Error {
    fn from(_: Fault) -> Self {
        Self::Sys(SysErr::Errno(wasixv2_abi::Errno::EFAULT))
    }
}

impl From<abi::Errno> for Error {
    fn from(errno: abi::Errno) -> Self {
        Self::V1(errno)
    }
}

/// The value an errno-returning import hands the guest.
pub fn encode(result: Result<(), abi::Errno>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(errno) => i32::from(errno.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_namespace_verdicts_preserve_operation_specific_v1_errors() {
        assert_eq!(
            Error::from(SysErr::NamespaceBoundary),
            Error::V1(abi::Errno::NOTCAPABLE)
        );
        for verdict in [abi::Errno::ACCES, abi::Errno::INVAL, abi::Errno::NOTCAPABLE] {
            assert_eq!(
                mutation(SysErr::NamespaceMutation, verdict),
                Error::V1(verdict)
            );
            assert_eq!(
                mutation(SysErr::NamespaceBoundary, verdict),
                Error::V1(abi::Errno::NOTCAPABLE)
            );
            assert_eq!(
                mutation(SysErr::Errno(wasixv2_abi::Errno::ENOENT), verdict),
                Error::Sys(SysErr::Errno(wasixv2_abi::Errno::ENOENT))
            );
        }
        assert_eq!(Error::from(SysErr::Restart), Error::Sys(SysErr::Restart));
    }
}
