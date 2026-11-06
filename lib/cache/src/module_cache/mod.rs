//! Asynchronous caches for compiled modules, partitioned by engine and artifact format.
//!
//! This module retains the SHA-256 compiler-input keys and versioned filesystem
//! layout used by package execution. The crate's root [`crate::Cache`] API and
//! its Blake3 keys remain separate.

mod compile;
mod fallback;
#[cfg(feature = "module-cache-filesystem")]
mod filesystem;
mod hashed_module;
/// Compilation and download progress callbacks.
pub mod progress;
mod shared;
mod thread_local;
mod types;

#[cfg(feature = "module-cache-filesystem")]
pub use self::filesystem::FileSystemCache;
pub use self::{
    compile::{ModuleCompileError, load_module},
    fallback::FallbackCache,
    hashed_module::HashedModuleData,
    shared::SharedCache,
    thread_local::ThreadLocalCache,
    types::{CacheError, ModuleCache},
};
pub use wasmer_types::ModuleHash;
