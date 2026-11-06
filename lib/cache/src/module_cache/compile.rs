use super::{
    CacheError, ModuleCache,
    progress::{ModuleLoadProgress, ModuleLoadProgressReporter},
};
use wasmer::{Engine, Module};
use wasmer_types::{CompilationProgressCallback, ModuleHash};

/// A compilation failure carrying the exact compiler-input cache key.
#[derive(Debug, thiserror::Error)]
#[error("compile error: {error:?}")]
pub struct ModuleCompileError {
    /// Hash of the bytes passed to the compiler.
    pub module_hash: ModuleHash,
    /// Original compiler failure.
    pub error: wasmer::CompileError,
}

/// Load or compile immutable module bytes through the configured module cache.
///
/// `wasm_hash` must identify these exact compiler-input bytes, including any
/// preparation and instrumentation. The supplied key is trusted, not recomputed.
#[tracing::instrument(target = "wasmer_wasix::runtime", level = "debug", skip_all)]
pub async fn load_module(
    engine: &Engine,
    module_cache: &(dyn ModuleCache + Send + Sync),
    wasm_hash: ModuleHash,
    wasm: &[u8],
    on_progress: Option<ModuleLoadProgressReporter>,
) -> Result<Module, ModuleCompileError> {
    let result = if let Some(on_progress) = &on_progress {
        module_cache
            .load_with_progress(wasm_hash, engine, on_progress.clone())
            .await
    } else {
        module_cache.load(wasm_hash, engine).await
    };

    match result {
        Ok(module) => return Ok(module),
        Err(CacheError::NotFound) => {}
        Err(other) => {
            tracing::event!(target: "wasmer_wasix::runtime", tracing::Level::WARN,
                %wasm_hash,
                error=&other as &dyn std::error::Error,
                "Unable to load the cached module",
            );
        }
    }

    let res = if let Some(progress) = on_progress {
        #[allow(unused_variables)]
        let p = CompilationProgressCallback::new(move |p| {
            progress.notify(ModuleLoadProgress::CompilingModule(p))
        });
        #[cfg(feature = "module-cache-sys")]
        {
            if engine.is_sys() {
                use wasmer::sys::NativeEngineExt;
                engine.new_module_with_progress(wasm, p)
            } else {
                Module::new(&engine, wasm)
            }
        }
        #[cfg(not(feature = "module-cache-sys"))]
        {
            Module::new(&engine, wasm)
        }
    } else {
        Module::new(&engine, wasm)
    };

    let module = res.map_err(|err| ModuleCompileError {
        module_hash: wasm_hash,
        error: err,
    })?;

    // TODO: pass a [`HashedModule`] struct that is safe by construction.
    if let Err(e) = module_cache.save(wasm_hash, engine, &module).await {
        tracing::event!(target: "wasmer_wasix::runtime", tracing::Level::WARN,
            %wasm_hash,
            error=&e as &dyn std::error::Error,
            "Unable to cache the compiled module",
        );
    }

    Ok(module)
}
