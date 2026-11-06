mod backend_source;
mod filesystem_source;
mod in_memory_source;
mod inputs;
mod local_registry_source;
mod multi_source;
mod outputs;
mod resolve;
mod source;
#[doc(hidden)]
pub mod utils;
mod web_source;

pub use self::{
    backend_source::{BackendSource, QueryCache},
    filesystem_source::FileSystemSource,
    in_memory_source::InMemorySource,
    inputs::{
        Command, Dependency, DistributionInfo, FileSystemMapping, PackageInfo, PackageSummary,
        WebcHash,
    },
    local_registry_source::LocalRegistrySource,
    multi_source::{MultiSource, MultiSourceStrategy},
    outputs::{
        DependencyGraph, Edge, ItemLocation, Node, Resolution, ResolvedFileSystemMapping,
        ResolvedPackage,
    },
    resolve::{ResolveError, resolve, resolve_dependency_graph, validate_dependency_graph},
    source::{QueryError, Source},
    web_source::WebSource,
};

// Preserve the native threaded and browser execution behavior of the acquisition helpers.
pub(crate) fn block_in_place<Ret>(thunk: impl FnOnce() -> Ret) -> Ret {
    #[cfg(feature = "acquisition-thread")]
    {
        tokio::task::block_in_place(thunk)
    }
    #[cfg(not(feature = "acquisition-thread"))]
    {
        thunk()
    }
}

pub(crate) async fn spawn_blocking<F, R>(f: F) -> Result<R, tokio::task::JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    #[cfg(target_arch = "wasm32")]
    {
        Ok(block_in_place(f))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::spawn_blocking(f).await
    }
}
