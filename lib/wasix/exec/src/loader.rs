//! Turning executables and side modules into compiled modules. An embedder plugs in a
//! [`Loader`] to pick the engine per executable and to cache compiled modules. With the ABIs it
//! serves, the loader is what Linux's binary format handlers are: [`Abis`](crate::Abis) answers
//! the kernel's [`Binfmt`](wasixv2_syscalls::Binfmt) questions from the loader's
//! [`Loader::probe`] and the ABIs' import checks, before `execve`'s point of no return.

use std::error::Error;

use wasixv2_host::{Host, LocalFuture};
use wasixv2_syscalls::{Errno, Image};
use wasmer::{CompileError, Engine, Module};
use wasmer_types::ModuleHash;

/// Why a [`Loader`] could not produce a module.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The image is in no format the loader runs. From [`Loader::probe`], `execve` fails with
    /// the errno (normally `ENOEXEC`) and the caller keeps its image.
    #[error("not an executable format the loader runs ({0:?})")]
    Format(Errno),
    /// Anything else, such as a module that does not compile.
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

impl LoadError {
    /// [`LoadError::Other`] for `err`.
    pub fn other(err: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Other(err.into())
    }
}

impl From<CompileError> for LoadError {
    fn from(err: CompileError) -> Self {
        Self::other(err)
    }
}

/// Compiles process images and their dynamically linked side modules. For process images,
/// a loader adds the preemption points [`crate::load`] does (see [`crate::instrument`]) so
/// the guest can notice signals while it computes.
pub trait Loader: Send + Sync {
    /// Whether an image whose file starts with `header` (its first
    /// [`BINPRM_BUF_SIZE`](wasixv2_syscalls::BINPRM_BUF_SIZE) bytes, or all of a shorter file)
    /// is in a format [`Loader::load`] handles. `execve` asks before it reads the rest of the
    /// file, so an image this refuses with [`LoadError::Format`] fails `execve` instead of
    /// killing the process. By default, a WebAssembly binary: wasm's magic and version 1.
    fn probe(&self, header: &[u8]) -> Result<(), LoadError> {
        match header.starts_with(WASM_HEADER) {
            true => Ok(()),
            false => Err(LoadError::Format(Errno::ENOEXEC)),
        }
    }

    /// The module for `image`, a WebAssembly binary the kernel loaded for a process that ran
    /// on `engine` until now, and the engine that compiled it, which the image's instances
    /// run on. A loader that caches can tell images apart by [`Image::identity`] without
    /// looking at their bytes.
    fn load<'a>(
        &'a self,
        engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>>;

    /// Load or compile a side module using the exact engine of its main instance.
    /// `wasm` is the final compiler input, including TLS relocation and instrumentation.
    /// Use the supplied cache key, which also identifies engine configuration, and add
    /// a namespace if the embedder uses compiler settings that the engine does not expose.
    /// Implement this to support dylink with a custom loader.
    fn load_side_module<'a>(
        &'a self,
        _host: &'a dyn Host,
        _engine: &'a Engine,
        _key: ModuleHash,
        _wasm: Vec<u8>,
    ) -> LocalFuture<'a, Result<Module, LoadError>> {
        Box::pin(async { Err(LoadError::other("loader does not support side modules")) })
    }
}

/// The preamble of a WebAssembly module: the magic and version 1. Components (a later
/// version) are a different format.
const WASM_HEADER: &[u8] = b"\0asm\x01\0\0\0";

/// The default [`Loader`]: [`crate::load`] with the engine the process ran on, without a cache.
pub struct Compile;

impl Loader for Compile {
    fn load<'a>(
        &'a self,
        engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
        Box::pin(async move { Ok((engine.clone(), crate::load(engine, image.bytes())?)) })
    }

    fn load_side_module<'a>(
        &'a self,
        host: &'a dyn Host,
        engine: &'a Engine,
        _key: ModuleHash,
        wasm: Vec<u8>,
    ) -> LocalFuture<'a, Result<Module, LoadError>> {
        Box::pin(async move {
            #[cfg(not(target_arch = "wasm32"))]
            let module = {
                let engine = engine.clone();
                host.executor()
                    .run_blocking(move || Module::new(&engine, wasm))
                    .await?
            };
            #[cfg(target_arch = "wasm32")]
            let module = {
                let _ = host;
                // A JS engine and its modules belong to the current realm.
                Module::new(engine, wasm)?
            };
            Ok(module)
        })
    }
}
