//! Namespace-pinned optional provider controls for the v1 adapter. This private ioctl
//! envelope does not extend Linux rtnetlink or expose a process-global provider pointer.
use crate::{Kernel, netlink::NetlinkSocket};
use std::{
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};
use wasixv2_abi::IoctlRequest;
use wasixv2_syscalls::{Caller, Errno, SysResult};
use wasixv2_vfs::Cap;
use wasixv2_vnet::provider::{self, Reply, Request};

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
            result: Option<Result<Reply, Errno>>,
            waker: Option<Waker>,
        }
        let wait = Arc::new(Mutex::new(Wait {
            result: None,
            waker: None,
        }));
        let completed = wait.clone();
        provider.start(
            operation,
            Box::new(move |completion| {
                let wake = {
                    let mut wait = completed.lock().unwrap();
                    wait.result = Some(completion.result);
                    wait.waker.take()
                };
                if let Some(wake) = wake {
                    wake.wake();
                }
            }),
        );
        let reply = std::future::poll_fn(|cx| {
            let mut wait = wait.lock().unwrap();
            if let Some(result) = wait.result.take() {
                Poll::Ready(result)
            } else {
                wait.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await?;
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
