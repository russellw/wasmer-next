//! Syscall layer that traces every call, its arguments and its result.

use wasixv2_syscalls::MaybeFuture;
use wasixv2_syscalls::{Caller, Layer, SysResult, Syscall, SyscallRet, Syscalls, dispatch};

/// Emits one `tracing` event per syscall, after it completes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Trace;

impl<S: Syscalls> Layer<S> for Trace {
    fn lookup_host<'a>(
        &'a self,
        caller: &'a Caller<'_>,
        name: &'a str,
        port: Option<u16>,
        next: &'a S,
    ) -> Option<wasixv2_syscalls::LocalFuture<'a, SysResult<Vec<std::net::IpAddr>>>> {
        let future = next.lookup_host(caller, name, port)?;
        Some(Box::pin(async move {
            let result = future.await;
            tracing::trace!(task = caller.task().0, name, ?port, ?result, "host lookup");
            result
        }))
    }

    fn call<'a>(
        &'a self,
        caller: &'a Caller<'_>,
        call: Syscall,
        next: &'a S,
    ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
        dispatch(next, caller, call).map(move |ret| {
            tracing::trace!(task = caller.task().0, ?call, ?ret, "syscall");
            ret
        })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use futures::executor::block_on;
    use wasixv2_syscalls::{
        Errno, Fault, Fd, Layered, LocalFuture, SysErr, TaskId, UserMemory, UserSlice, UserSliceMut,
    };

    use super::*;

    struct NoMemory;

    impl UserMemory for NoMemory {
        fn read<'a>(&'a self, _: u32, _: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }

        fn write<'a>(&'a self, _: u32, _: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }

        fn size(&self) -> LocalFuture<'_, u64> {
            Box::pin(async { 0 })
        }

        fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
            Box::pin(async { None })
        }
    }

    #[derive(Default)]
    struct Recorder(RefCell<Vec<Syscall>>);

    impl Syscalls for Recorder {
        fn read<'a>(
            &'a self,
            _: &'a Caller<'_>,
            fd: Fd,
            buf: UserSliceMut,
        ) -> MaybeFuture<'a, SysResult<u32>> {
            MaybeFuture::Future(Box::pin(async move {
                self.0.borrow_mut().push(Syscall::Read { fd, buf });
                Err(SysErr::Errno(Errno::EBADF))
            }))
        }

        fn write<'a>(
            &'a self,
            _: &'a Caller<'_>,
            fd: Fd,
            buf: UserSlice,
        ) -> MaybeFuture<'a, SysResult<u32>> {
            MaybeFuture::Future(Box::pin(async move {
                self.0.borrow_mut().push(Syscall::Write { fd, buf });
                Ok(buf.len)
            }))
        }

        fn exit_group<'a>(
            &'a self,
            _: &'a Caller<'_>,
            status: i32,
        ) -> MaybeFuture<'a, SysResult<()>> {
            MaybeFuture::Future(Box::pin(async move {
                self.0
                    .borrow_mut()
                    .push(Syscall::ExitGroup { error_code: status });
                Ok(())
            }))
        }
    }

    #[test]
    fn forwards_calls_and_results_unchanged() {
        let stack = Layered::new(Trace, Recorder::default());
        let caller = Caller::new(TaskId(1), &NoMemory);

        let written = block_on(stack.write(&caller, Fd(1), UserSlice::new(16, 5)));
        let read = block_on(stack.read(&caller, Fd(7), UserSliceMut::new(0, 1)));
        let exited = block_on(stack.exit_group(&caller, 3));

        assert_eq!(written, Ok(5));
        assert_eq!(read, Err(SysErr::Errno(Errno::EBADF)));
        assert_eq!(exited, Ok(()));
        assert_eq!(
            *stack.inner.0.borrow(),
            [
                Syscall::Write {
                    fd: Fd(1),
                    buf: UserSlice::new(16, 5)
                },
                Syscall::Read {
                    fd: Fd(7),
                    buf: UserSliceMut::new(0, 1)
                },
                Syscall::ExitGroup { error_code: 3 },
            ]
        );
    }
    struct ReadyPid;
    impl Syscalls for ReadyPid {
        fn getpid<'a>(&'a self, _: &'a Caller<'_>) -> MaybeFuture<'a, SysResult<i32>> {
            MaybeFuture::Ready(Ok(19))
        }
    }

    #[test]
    fn tracing_preserves_ready_results() {
        let memory = NoMemory;
        let caller = Caller::new(TaskId(1), &memory);
        let result = Trace.call(&caller, Syscall::Getpid, &ReadyPid);
        assert!(matches!(
            result,
            MaybeFuture::Ready(Ok(SyscallRet::Getpid(19)))
        ));
    }
    struct HostLookup;
    impl Syscalls for HostLookup {
        fn lookup_host<'a>(
            &'a self,
            _: &'a Caller<'_>,
            name: &'a str,
            port: Option<u16>,
        ) -> Option<LocalFuture<'a, SysResult<Vec<std::net::IpAddr>>>> {
            Some(Box::pin(async move {
                assert_eq!(name, "Original.Name.");
                assert_eq!(port, Some(443));
                Err(Errno::EACCES.into())
            }))
        }
    }
    struct UnknownLayer;
    impl<S: Syscalls> Layer<S> for UnknownLayer {
        fn call<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: Syscall,
            _: &'a S,
        ) -> MaybeFuture<'a, SysResult<SyscallRet>> {
            panic!("host hooks are not guest syscall values")
        }
    }
    struct Events(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl tracing::Subscriber for Events {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    write!(&mut self.0, "{}={value:?};", field.name()).unwrap();
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    #[test]
    fn host_hook_requires_layer_opt_in_and_trace_delegates_exact_error_with_event() {
        let caller = Caller::new(TaskId(7), &NoMemory);
        let denied = Layered::new(UnknownLayer, HostLookup);
        assert!(
            denied
                .lookup_host(&caller, "Original.Name.", Some(443))
                .is_none()
        );
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Events(events.clone()), || {
            let stack = Layered::new(Trace, HostLookup);
            assert_eq!(
                block_on(
                    stack
                        .lookup_host(&caller, "Original.Name.", Some(443))
                        .unwrap()
                ),
                Err(SysErr::Errno(Errno::EACCES))
            );
        });
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        for value in ["host lookup", "Original.Name.", "443", "EACCES"] {
            assert!(
                events[0].contains(value),
                "missing {value} in {}",
                events[0]
            );
        }
    }
}
