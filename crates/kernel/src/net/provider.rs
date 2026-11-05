//! Namespace-pinned optional provider controls for the v1 adapter. This private ioctl
//! envelope does not extend Linux rtnetlink or expose a process-global provider pointer.
use crate::{Kernel, netlink::NetlinkSocket};
use std::sync::{Arc, Mutex};
use wasixv2_abi::IoctlRequest;
use wasixv2_syscalls::{Caller, Errno, SysResult};
use wasixv2_vfs::Cap;
use wasixv2_vnet::provider::{self, Reply, Request};
use wasixv2_wait::{PollMask, WaitQueue, wait_event};

impl Kernel {
    pub(crate) async fn provider_ioctl(
        &self,
        caller: &Caller<'_>,
        socket: &NetlinkSocket,
        request: IoctlRequest,
        arg: u32,
    ) -> SysResult<i32> {
        if !socket.supports_provider_control() {
            return Err(Errno::ENOTTY.into());
        }
        let admin = || {
            self.cred(caller)
                .ns_capable(socket.net.user_ns(), Cap::NetAdmin)
                && socket
                    .opener
                    .ns_capable(socket.net.user_ns(), Cap::NetAdmin)
        };
        if request.0 == provider::PROBE {
            if arg > 1 {
                return Err(Errno::EINVAL.into());
            }
            if arg == 1 && !admin() {
                return Err(Errno::EPERM.into());
            }
            return Ok(i32::from(
                socket
                    .net
                    .network
                    .as_ref()
                    .and_then(|n| n.provider())
                    .is_some(),
            ));
        }
        let mut header = [0u8; 16];
        caller
            .memory()
            .read(arg, &mut header)
            .await
            .map_err(|_| Errno::EFAULT)?;
        let word = |n| u32::from_le_bytes(header[n..n + 4].try_into().unwrap());
        let (input, length, output, capacity) = (word(0), word(4), word(8), word(12));
        if length as usize > provider::MAX_MESSAGE || capacity as usize > provider::MAX_MESSAGE {
            return Err(Errno::EMSGSIZE.into());
        }
        let mut bytes = vec![0; length as usize];
        caller
            .memory()
            .read(input, &mut bytes)
            .await
            .map_err(|_| Errno::EFAULT)?;
        let operation: Request = provider::decode(&bytes)?;
        if operation.mutates() && !admin() {
            return Err(Errno::EPERM.into());
        }
        operation.validate()?;
        let provider = socket
            .net
            .network
            .as_ref()
            .and_then(|n| n.provider())
            .ok_or(Errno::EOPNOTSUPP)?;
        // No kernel/namespace lock spans the asynchronous provider operation. The socket
        // pins its original namespace through setns/unshare and through waiter cancellation.
        struct Wait {
            result: Mutex<Option<Result<Reply, Errno>>>,
            queue: WaitQueue,
        }
        let wait = Arc::new(Wait {
            result: Mutex::new(None),
            queue: WaitQueue::new(),
        });
        let completed = wait.clone();
        provider.start(
            operation,
            Box::new(move |completion| {
                *completed.result.lock().unwrap() = Some(completion.result);
                completed.queue.wake(PollMask::IN);
            }),
        );
        // The accepted transaction continues after interruption, while dropping this wait
        // unregisters the guest's waker. Never return Restart: that could replay a mutation.
        let interrupt = self.interrupt(caller);
        let reply = wait_event(
            &wait.queue,
            || wait.result.lock().unwrap().take(),
            &*interrupt,
        )
        .await
        .map_err(|_| Errno::EINTR)??;
        let bytes = provider::encode(&reply)?;
        if bytes.len() > capacity as usize {
            return Err(Errno::EOVERFLOW.into());
        }
        caller
            .memory()
            .write(output, &bytes)
            .await
            .map_err(|_| Errno::EFAULT)?;
        Ok(bytes.len() as i32)
    }
}
