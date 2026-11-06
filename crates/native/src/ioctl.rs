//! Bounded native ioctl argument translation for the syscall bridge.

use wasixv2_abi::{Fd, IoctlRequest};
use wasixv2_syscalls::Syscall;

use crate::{BridgeMemory, platform::Request};

/// Translate the terminal ioctl layouts whose native pointer widths are known.
pub(super) fn translate(
    request: Request,
    memory: &mut BridgeMemory,
) -> Result<Option<Syscall>, i64> {
    if request.nr != libc::SYS_ioctl {
        return Ok(None);
    }

    let command = IoctlRequest(request.args[1] as u32);
    let (size, reads, writes) = match command {
        IoctlRequest::TCGETS => (36, false, true),
        IoctlRequest::TCSETS | IoctlRequest::TCSETSW | IoctlRequest::TCSETSF => (36, true, false),
        IoctlRequest::TIOCGWINSZ => (8, false, true),
        IoctlRequest::TIOCSWINSZ => (8, true, false),
        IoctlRequest::TIOCGPGRP
        | IoctlRequest::TIOCGSID
        | IoctlRequest::TIOCOUTQ
        | IoctlRequest::TIOCGSOFTCAR
        | IoctlRequest::TIOCGETD
        | IoctlRequest::TIOCGEXCL
        | IoctlRequest::FIONREAD => (4, false, true),
        IoctlRequest::TIOCSPGRP
        | IoctlRequest::TIOCSSOFTCAR
        | IoctlRequest::TIOCSETD
        | IoctlRequest::FIONBIO => (4, true, false),
        _ => {
            let scalar = match command {
                IoctlRequest::TCSBRK
                | IoctlRequest::TCXONC
                | IoctlRequest::TCFLSH
                | IoctlRequest::TCSBRKP
                | IoctlRequest::TIOCSCTTY => Some(request.args[2] as u32),
                IoctlRequest::TIOCEXCL
                | IoctlRequest::TIOCNXCL
                | IoctlRequest::TIOCNOTTY
                | IoctlRequest::TIOCSBRK
                | IoctlRequest::TIOCCBRK
                | IoctlRequest::TIOCVHANGUP
                | IoctlRequest::FIOCLEX
                | IoctlRequest::FIONCLEX => Some(0),
                _ => None,
            };
            let Some(arg) = scalar else {
                // TODO(native): add ABI-specific layouts for additional pointerful ioctls.
                return Err(-(libc::ENOTTY as i64));
            };
            return Ok(Some(Syscall::Ioctl {
                fd: Fd(request.args[0] as i32),
                cmd: command,
                arg,
            }));
        }
    };

    // TODO(native): the WLK ABI currently exposes ioctl arguments as 32-bit guest pointers.
    let arg = memory
        .map(request.args[2], size, reads, writes)
        .map_err(|_| -(libc::EFAULT as i64))?;
    Ok(Some(Syscall::Ioctl {
        fd: Fd(request.args[0] as i32),
        cmd: command,
        arg,
    }))
}
