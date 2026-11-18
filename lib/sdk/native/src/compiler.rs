//! Compiled modules retain their allocating feature engines through one cache owner.
use crate::client::ClientInner;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};
use wasixv2::{Image, ImageId, LoadError, Loader, LocalFuture};
#[cfg(not(target_os = "windows"))]
use wasmer::sys::{Cranelift, EngineBuilder};
use wasmer::{Engine, Module};
use wasmer_cache::module_cache::{
    FileSystemCache, ModuleCache, ModuleHash, SharedCache, load_module,
};
use wasmer_types::Features;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Shared(ImageId),
    Bytes(ModuleHash),
}
struct Loaded {
    engine: Engine,
    module: Module,
    _image: Image,
}
/// The sys artifact contains code pointers into its allocating Engine. Keep
/// cache entries and that exact feature-engine pool alive as a single owner.
/// Field order drops cached Modules before their allocating Engines.
pub(crate) struct CompilationOwner {
    cache: Arc<dyn ModuleCache + Send + Sync>,
    engines: Mutex<Vec<(Features, Engine)>>,
    #[cfg(feature = "napi-v8")]
    context: wasmer_napi::NapiCtx,
}
impl CompilationOwner {
    pub(crate) fn new(
        directory: &Path,
        handle: tokio::runtime::Handle,
        #[cfg(feature = "napi-v8")] context: wasmer_napi::NapiCtx,
    ) -> Arc<Self> {
        Arc::new(Self {
            cache: Arc::new(
                SharedCache::default().with_fallback(FileSystemCache::new(directory, handle)),
            ),
            engines: Mutex::default(),
            #[cfg(feature = "napi-v8")]
            context,
        })
    }
    fn engine(&self, bytes: &[u8]) -> anyhow::Result<Engine> {
        let features = Features::detect_from_wasm(bytes)?;
        let mut engines = self.engines.lock().unwrap();
        if let Some((_, engine)) = engines.iter().find(|(existing, _)| existing == &features) {
            return Ok(engine.clone());
        }
        #[cfg(not(target_os = "windows"))]
        let mut engine = EngineBuilder::new(Cranelift::default())
            .set_features(Some(features.clone()))
            .engine();
        #[cfg(all(feature = "napi-v8", not(target_os = "windows")))]
        engine.set_tunables(wasmer_napi::budgeted_tunables(self.context.budget()));
        #[cfg(not(target_os = "windows"))]
        let engine: Engine = engine.into();
        #[cfg(target_os = "windows")]
        let engine: Engine = wasmer::v8::V8::new().into();
        #[cfg(all(feature = "napi-v8", target_os = "windows"))]
        anyhow::bail!("N-API memory budgets require a native sys compiler backend");
        engines.push((features, engine.clone()));
        Ok(engine)
    }
}

pub(crate) struct NativeLoader {
    // Drop per-run Modules before releasing the shared allocation owner.
    modules: Mutex<HashMap<Key, Loaded>>,
    owner: Arc<CompilationOwner>,
}
impl NativeLoader {
    pub(crate) fn new(
        client: &ClientInner,
        #[cfg(feature = "napi-v8")] context: wasmer_napi::NapiCtx,
    ) -> Arc<Self> {
        #[cfg(not(feature = "napi-v8"))]
        let owner = client.compilation.clone();
        // Native instantiation uses Store engine tunables. Budgeted N-API
        // engines and their in-memory cache belong to this run, sharing only
        // immutable persistent artifact bytes with other runs.
        #[cfg(feature = "napi-v8")]
        let owner =
            CompilationOwner::new(&client.compiled_cache, client.services.handle(), context);
        Arc::new(Self {
            modules: Mutex::default(),
            owner,
        })
    }
    pub(crate) async fn compile(&self, bytes: &[u8]) -> anyhow::Result<(Engine, Module)> {
        let prepared = wasixv2_dylink::prepare_image(bytes)?;
        let (input, failed) = if prepared == bytes {
            wasixv2::prepare_for_compile(&prepared)?
        } else {
            (wasixv2::instrument(&prepared)?, None)
        };
        let engine = self.owner.engine(&input)?;
        let module = load_module(
            &engine,
            self.owner.cache.as_ref(),
            ModuleHash::new(&input),
            &input,
            None,
        )
        .await?;
        if let Some(error) = failed {
            wasixv2::warn_not_preemptible(&error);
        }
        Ok((engine, module))
    }
    pub(crate) fn compile_capi(&self, bytes: &[u8]) -> anyhow::Result<Module> {
        // Nested C API modules preserve their imports and entry semantics. They
        // use this run's feature engine and memory budget, as the old resolver did.
        let engine = self.owner.engine(bytes)?;
        // C API reflection exposes the actual imports/exports, and its caller
        // supplies the corresponding extern array. Instrumentation would change
        // that public contract. This host-call cache key is the original input.
        Ok(futures::executor::block_on(load_module(
            &engine,
            self.owner.cache.as_ref(),
            ModuleHash::new(bytes),
            bytes,
            None,
        ))?)
    }
}
impl Loader for NativeLoader {
    fn load<'a>(
        &'a self,
        _engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
        Box::pin(async move {
            let key = image
                .identity()
                .map_or_else(|| Key::Bytes(ModuleHash::new(image.bytes())), Key::Shared);
            if let Some(loaded) = self.modules.lock().unwrap().get(&key) {
                return Ok((loaded.engine.clone(), loaded.module.clone()));
            }
            let (engine, module) = self
                .compile(image.bytes())
                .await
                .map_err(LoadError::other)?;
            self.modules.lock().unwrap().insert(
                key,
                Loaded {
                    engine: engine.clone(),
                    module: module.clone(),
                    _image: image.clone(),
                },
            );
            Ok((engine, module))
        })
    }

    fn load_side_module<'a>(
        &'a self,
        host: &'a dyn wasixv2::Host,
        engine: &'a Engine,
        key: ModuleHash,
        wasm: Vec<u8>,
    ) -> LocalFuture<'a, Result<Module, LoadError>> {
        Box::pin(async move {
            let cache = self.owner.cache.clone();
            let engine = engine.clone();
            host.executor()
                .run_blocking(move || {
                    futures::executor::block_on(load_module(
                        &engine,
                        cache.as_ref(),
                        key,
                        &wasm,
                        None,
                    ))
                })
                .await
                .map_err(LoadError::other)
        })
    }
}
