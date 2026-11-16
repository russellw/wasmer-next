//! Native clear-TID and futex syscall translation into WLK.

use std::io;

use wasixv2_abi::{FutexOp, S32Ptr, U32Ptr};
use wasixv2_syscalls::Syscall;

use crate::{BridgeMemory, platform::Request};

const FUTEX_WAIT: i32 = FutexOp::FUTEX_WAIT.0;
const FUTEX_WAKE: i32 = FutexOp::FUTEX_WAKE.0;
const FUTEX_REQUEUE: i32 = FutexOp::FUTEX_REQUEUE.0;
const FUTEX_CMP_REQUEUE: i32 = FutexOp::FUTEX_CMP_REQUEUE.0;
const FUTEX_WAIT_BITSET: i32 = FutexOp::FUTEX_WAIT_BITSET.0;
const FUTEX_WAKE_BITSET: i32 = FutexOp::FUTEX_WAKE_BITSET.0;

/// Translate `set_tid_address` and supported non-PI futex calls into WLK syscalls.
pub fn translate(request: Request, memory: &mut BridgeMemory) -> io::Result<Option<Syscall>> {
    if request.nr == libc::SYS_set_robust_list {
        // TODO: translate the native 64-bit robust-list layout into WLK's guest representation.
        return Ok(None);
    }
    if request.nr == libc::SYS_set_tid_address {
        let tidptr = if request.args[0] == 0 {
            0
        } else {
            memory.map_alias(request.args[0], 4, true, true)?
        };
        return Ok(Some(Syscall::SetTidAddress {
            tidptr: S32Ptr::new(tidptr),
        }));
    }
    if request.nr != libc::SYS_futex {
        return Ok(None);
    }

    let args = request.args;
    let raw_op = args[1] as i32;
    let command = raw_op & FutexOp::FUTEX_CMD_MASK.0;
    if !matches!(
        command,
        FUTEX_WAIT
            | FUTEX_WAKE
            | FUTEX_REQUEUE
            | FUTEX_CMP_REQUEUE
            | FUTEX_WAIT_BITSET
            | FUTEX_WAKE_BITSET
    ) {
        return Ok(None);
    }

    if args[0] != 0 && !args[0].is_multiple_of(4) {
        // TODO: return EINVAL directly when the native translator can carry immediate errno;
        // map_alias otherwise gives an unaligned native word an aligned WLK address.
        return Ok(None);
    }
    if matches!(command, FUTEX_REQUEUE | FUTEX_CMP_REQUEUE)
        && args[4] != 0
        && !args[4].is_multiple_of(4)
    {
        return Ok(None);
    }

    if command == FUTEX_WAIT_BITSET && args[3] != 0 && raw_op & FutexOp::FUTEX_CLOCK_REALTIME.0 == 0
    {
        // TODO: normalize absolute CLOCK_MONOTONIC deadlines from host uptime to TokioHost's
        // elapsed-since-start clock before forwarding these waits.
        return Ok(None);
    }

    let uaddr = map_futex_word(memory, args[0])?;
    let uaddr2 = if matches!(command, FUTEX_REQUEUE | FUTEX_CMP_REQUEUE) {
        map_futex_word(memory, args[4])?
    } else {
        0
    };
    let utime = if matches!(command, FUTEX_WAIT | FUTEX_WAIT_BITSET) {
        if args[3] == 0 {
            0
        } else {
            memory.map_alias(
                args[3],
                std::mem::size_of::<wasixv2_abi::KernelTimespec>(),
                true,
                false,
            )?
        }
    } else if matches!(command, FUTEX_REQUEUE | FUTEX_CMP_REQUEUE) {
        args[3] as u32
    } else {
        0
    };

    Ok(Some(Syscall::FutexTime64 {
        uaddr: U32Ptr::new(uaddr),
        op: FutexOp(raw_op),
        val: args[2] as u32,
        utime,
        uaddr2: U32Ptr::new(uaddr2),
        val3: args[5] as u32,
    }))
}

fn map_futex_word(memory: &mut BridgeMemory, native: u64) -> io::Result<u32> {
    if native == 0 {
        Ok(0)
    } else {
        memory.map_alias(native, 4, true, true)
    }
}
