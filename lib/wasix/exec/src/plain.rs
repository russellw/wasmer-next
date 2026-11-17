//! Commands whose guest imports are entirely provided by the embedder.

use std::sync::{
    Arc,
    atomic::{AtomicI32, Ordering},
};

use wasixv2_syscalls::{Control, Errno, LocalFuture, SignalFrame, Syscalls, TaskId};
use wasmer::{
    AsyncFunctionEnvMut, Function, FunctionEnv, Imports, Instance, Memory, Module, RuntimeError,
    StoreMut, Value,
};
use wasmparser::{Encoding, Parser, Payload};

use crate::{
    Abi, AbiInstance, Entry, EntryReturn, ExecEnv, ExecError, ImportDeclarations, LoadError, Role,
    Sigreturn, VforkResume, preempt,
};

pub(crate) struct PlainCommand(pub ImportDeclarations);

/// Identifies the execution imports injected into a compiled command.
#[doc(hidden)]
pub fn is_command_runtime_import(import: &wasmer::ImportType) -> bool {
    import.module() == preempt::HOOK_MODULE
        && matches!(import.ty(), wasmer::ExternType::Function(_))
}

impl<S: Syscalls + Control + Send + Sync + 'static> Abi<S> for PlainCommand {
    fn name(&self) -> &'static str {
        "plain-command"
    }

    fn matches(&self, module: &Module) -> bool {
        module.imports().all(|import| {
            is_command_runtime_import(&import)
                || self.0.provides_import(import.module(), import.name())
        })
    }

    fn matches_image(&self, image: &[u8]) -> bool {
        // Inspect the original imports, before the instrumentation adds runtime imports.
        for payload in Parser::new(0).parse_all(image) {
            match payload {
                Ok(Payload::Version {
                    encoding: Encoding::Module,
                    ..
                }) => {}
                Ok(Payload::Version { .. }) | Err(_) => return false,
                Ok(Payload::ImportSection(imports)) => {
                    if !imports.into_imports().all(|import| {
                        import
                            .is_ok_and(|import| self.0.provides_import(import.module, import.name))
                    }) {
                        return false;
                    }
                }
                Ok(_) => {}
            }
        }
        true
    }

    fn imports(&self, _: &mut StoreMut<'_>, _: &FunctionEnv<ExecEnv<S>>, _: &Module) -> Imports {
        Imports::new()
    }

    fn bind(
        &self,
        instance: &Instance,
        _: &mut StoreMut<'_>,
        _: TaskId,
        role: Role,
    ) -> Result<Arc<dyn AbiInstance<S>>, ExecError> {
        if role != Role::Process {
            return Err(ExecError::Load(LoadError::Format(Errno::EOPNOTSUPP)));
        }
        Ok(Arc::new(PlainInstance {
            entry: instance.exports.get_function("_start")?.clone(),
            status: AtomicI32::new(0),
        }))
    }

    fn exported_memory(&self, instance: &Instance) -> Result<Option<Memory>, wasmer::ExportError> {
        Ok(instance.exports.get_memory("memory").ok().cloned())
    }
}

struct PlainInstance {
    entry: Function,
    status: AtomicI32,
}

impl<S: Send + Sync + 'static> AbiInstance<S> for PlainInstance {
    fn supports_process_creation(&self) -> bool {
        false
    }

    fn start<'a>(&'a self, entry: &'a Entry<'a, S>) -> LocalFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async move {
            let values = entry.call_once(&self.entry, &[]).await?;
            let status = match &*values {
                [] => 0,
                [Value::I32(status)] => *status,
                _ => {
                    return Err(RuntimeError::new(
                        "plain command entry must return () or i32",
                    ));
                }
            };
            self.status.store(status, Ordering::Relaxed);
            Ok(())
        })
    }

    fn on_entry_return(&self) -> EntryReturn {
        EntryReturn::Exit(self.status.load(Ordering::Relaxed))
    }

    fn start_thread<'a>(
        &'a self,
        _: &'a Entry<'a, S>,
        _: i32,
        _: u32,
    ) -> LocalFuture<'a, Result<(), RuntimeError>> {
        Box::pin(async { Err(unsupported()) })
    }

    fn on_thread_return(&self) -> EntryReturn {
        EntryReturn::Fault
    }

    fn deliver_signal<'a>(
        &'a self,
        _: &'a AsyncFunctionEnvMut<ExecEnv<S>>,
        _: &'a SignalFrame,
        _: bool,
    ) -> LocalFuture<'a, Result<Sigreturn, RuntimeError>> {
        Box::pin(async {
            Err(RuntimeError::new(
                "plain commands have no guest signal handler",
            ))
        })
    }

    fn vfork_resume<'a>(
        &'a self,
        _: &'a AsyncFunctionEnvMut<ExecEnv<S>>,
        _: TaskId,
        _: i32,
    ) -> LocalFuture<'a, VforkResume> {
        Box::pin(async { VforkResume::Unwind(unsupported()) })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn unsupported() -> RuntimeError {
    RuntimeError::new("plain commands do not support threads or fork")
}
