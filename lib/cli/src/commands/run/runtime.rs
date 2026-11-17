//! Package acquisition and module compilation used by `wasmer run`.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Error};
use futures::future::BoxFuture;
use indicatif::ProgressBar;
use sha2::Digest as _;
use wasmer::{Engine, Module};
use wasmer_cache::module_cache::{
    self, HashedModuleData, ModuleCache, ModuleCompileError,
    progress::{ModuleLoadProgress, ModuleLoadProgressReporter},
};
use wasmer_config::{
    filesystem::MappedDirectory,
    package::{PackageHash, PackageId, PackageSource},
};
use wasmer_package::{
    loader::{LoadedPackage, PackageDownloader},
    resolver::{self, PackageInfo, PackageSummary, QueryError, Resolution, Source},
};
use webc::Container;

/// The compilation service used for the machine's prepared module bytes.
pub(super) trait ModuleCompiler: Send + Sync {
    fn compile<'a>(
        &'a self,
        input: HashedModuleData,
        engine: &'a Engine,
    ) -> BoxFuture<'a, Result<Module, ModuleCompileError>>;
}

#[derive(Debug)]
struct ExecutorOwner(Option<tokio::runtime::Runtime>);
impl Drop for ExecutorOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(std::time::Duration::ZERO);
        }
    }
}

/// Host services for resolving package bytes and compiling modules.
#[derive(Debug)]
pub(super) struct RunContext {
    executor: ExecutorOwner,
    pub engine: Engine,
    source: Arc<dyn Source + Send + Sync>,
    downloader: PackageDownloader,
    module_cache: Arc<dyn ModuleCache + Send + Sync>,
    progress: ProgressBar,
    quiet_mode: bool,
    files: Mutex<HashMap<PackageId, PathBuf>>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PackageTree {
    pub files: HashMap<PackageId, PathBuf>,
    pub root: Option<PackageId>,
    pub root_is_local_dir: bool,
}

#[derive(Debug, Clone)]
pub(super) struct RunPackage {
    pub package: LoadedPackage,
    pub tree: PackageTree,
    pub additional_host_mapped_directories: Vec<MappedDirectory>,
}

impl RunContext {
    pub fn new(
        executor: tokio::runtime::Runtime,
        engine: Engine,
        source: impl Source + Send + 'static,
        downloader: PackageDownloader,
        module_cache: Arc<dyn ModuleCache + Send + Sync>,
        progress: ProgressBar,
        quiet_mode: bool,
    ) -> Self {
        Self {
            executor: ExecutorOwner(Some(executor)),
            engine,
            source: Arc::new(MonitoringSource {
                inner: Arc::new(source),
                progress: progress.clone(),
            }),
            downloader,
            module_cache,
            progress,
            quiet_mode,
            files: Mutex::default(),
        }
    }

    pub fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.executor.0.as_ref().unwrap().handle().block_on(future)
    }

    async fn load_container(&self, summary: &PackageSummary) -> Result<Container, Error> {
        let id = summary.package_id();
        self.progress.set_message(format!("Downloading {id}"));
        let container = self.downloader.load(summary).await?;
        if let Some(file) = self
            .downloader
            .cache()
            .map(|cache| cache.path(&summary.dist.webc_sha256))
            .filter(|path| path.is_file())
        {
            self.files.lock().unwrap().insert(id, file);
        }
        Ok(container)
    }

    pub async fn load_registry(&self, specifier: &PackageSource) -> Result<RunPackage, Error> {
        let summary = self.source.latest(specifier).await.map_err(|error| {
            resolver::ResolveError::Registry {
                package: specifier.clone(),
                error: Box::new(error),
            }
        })?;
        let root = self.load_container(&summary).await?;
        let resolution =
            resolver::resolve(&summary.package_id(), &summary.pkg, self.source.as_ref())
                .await
                .context("Dependency resolution failed")?;
        self.load_resolved(root, resolution, false).await
    }

    pub async fn load_webc(&self, root: Container) -> Result<RunPackage, Error> {
        let id = PackageInfo::package_id_from_manifest(root.manifest())?
            .or_else(|| {
                root.webc_hash()
                    .map(|hash| PackageId::Hash(PackageHash::from_sha256_bytes(hash)))
            })
            .ok_or_else(|| Error::msg("webc file did not provide its hash"))?;
        let info = PackageInfo::from_manifest(id, root.manifest(), root.version())?;
        let resolution = resolver::resolve(&info.id, &info, self.source.as_ref()).await?;
        self.load_resolved(root, resolution, false).await
    }

    pub async fn load_dir(&self, dir: &Path) -> Result<RunPackage, Error> {
        let hash = sha2::Sha256::digest(dir.display().to_string().as_bytes()).into();
        let id = PackageId::Hash(PackageHash::from_sha256_bytes(hash));
        let manifest_path = dir.join("wasmer.toml");
        let root: Container =
            wasmer_package::package::Package::from_manifest(&manifest_path)?.into();
        let info = PackageInfo::from_manifest(id, root.manifest(), root.version())?;
        let resolution = resolver::resolve(&info.id, &info, self.source.as_ref()).await?;
        let mut package = self.load_resolved(root, resolution, true).await?;
        let manifest = std::fs::read_to_string(&manifest_path).unwrap();
        let manifest: wasmer_config::package::Manifest = toml::from_str(&manifest).unwrap();
        package.additional_host_mapped_directories.extend(
            manifest
                .fs
                .into_iter()
                .map(|(guest, host)| {
                    anyhow::Ok(MappedDirectory {
                        host: dir.join(host).canonicalize()?,
                        guest,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(package)
    }

    async fn load_resolved(
        &self,
        root: Container,
        resolution: Resolution,
        local: bool,
    ) -> Result<RunPackage, Error> {
        let mut containers = wasmer_package::loader::fetch_dependencies(
            &resolution.package,
            &resolution.graph,
            |summary| async move { self.load_container(&summary).await },
        )
        .await?;
        containers.insert(resolution.package.root_package.clone(), root);
        wasixv2::preflight_resolved_filesystem(&containers, &resolution.package, local)?;
        let package = LoadedPackage::from_containers(resolution, containers)?;
        let files = self.files.lock().unwrap();
        let tree = PackageTree {
            files: files
                .iter()
                .filter(|(id, _)| package.containers.contains_key(*id))
                .map(|(id, path)| (id.clone(), path.clone()))
                .collect(),
            root: Some(package.resolution.package.root_package.clone()),
            root_is_local_dir: local,
        };
        Ok(RunPackage {
            package,
            tree,
            additional_host_mapped_directories: Vec::new(),
        })
    }

    async fn compile_module(
        &self,
        input: HashedModuleData,
        engine: &Engine,
    ) -> Result<Module, ModuleCompileError> {
        if self.quiet_mode {
            return module_cache::load_module(
                engine,
                self.module_cache.as_ref(),
                *input.hash(),
                input.wasm(),
                None,
            )
            .await;
        }
        use std::fmt::Write as _;
        let short_hash = input.hash().short_hash();
        let progress_msg = format!("Compiling module ({short_hash})");
        let pb = self.progress.clone();
        let on_progress = Some(ModuleLoadProgressReporter::new({
            let base_msg = progress_msg.clone();
            move |prog| {
                let msg = match prog {
                    ModuleLoadProgress::CompilingModule(c) => {
                        let mut msg = base_msg.clone();
                        if let (Some(step), Some(step_count)) =
                            (c.phase_step(), c.phase_step_count())
                        {
                            pb.set_length(step_count);
                            pb.set_position(step);
                            // Note: writing to strings can not fail.
                            if step_count != 0 {
                                write!(
                                    &mut msg,
                                    " ({:.0}%)",
                                    100.0 * step as f32 / step_count as f32
                                )
                                .unwrap();
                            }
                        };
                        pb.tick();

                        msg
                    }
                    _ => base_msg.clone(),
                };

                pb.set_message(msg);
                Ok(())
            }
        }));

        let style = indicatif::ProgressStyle::default_bar()
            .template("{spinner} {wide_bar:.cyan/blue} {msg}")
            .expect("invalid progress bar template");
        self.progress.set_style(style);

        self.progress.reset();
        if self.progress.is_hidden() {
            self.progress
                .set_draw_target(indicatif::ProgressDrawTarget::stderr());
        }
        self.progress.set_message(progress_msg);

        let result = module_cache::load_module(
            engine,
            self.module_cache.as_ref(),
            *input.hash(),
            input.wasm(),
            on_progress,
        )
        .await;
        self.progress
            .set_style(indicatif::ProgressStyle::default_spinner());
        self.progress.reset();
        self.progress.finish_and_clear();
        result
    }
}

impl ModuleCompiler for RunContext {
    fn compile<'a>(
        &'a self,
        input: HashedModuleData,
        engine: &'a Engine,
    ) -> BoxFuture<'a, Result<Module, ModuleCompileError>> {
        Box::pin(self.compile_module(input, engine))
    }
}

#[derive(Debug)]
struct MonitoringSource {
    inner: Arc<dyn Source + Send + Sync>,
    progress: ProgressBar,
}
#[async_trait::async_trait]
impl Source for MonitoringSource {
    async fn query(&self, package: &PackageSource) -> Result<Vec<PackageSummary>, QueryError> {
        self.progress.set_message(format!("Looking up {package}"));
        self.inner.query(package).await
    }
}

#[cfg(all(test, feature = "sys"))]
mod tests {
    use super::*;
    use wasmer_cache::module_cache::SharedCache;
    use wasmer_package::http::{HttpClient, HttpRequest, HttpResponse};

    #[derive(Debug)]
    struct NoHttp;
    impl HttpClient for NoHttp {
        fn request(&self, _: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
            panic!("unexpected HTTP request for local preflight fixture")
        }
    }

    #[test]
    fn filesystem_failure_precedes_command_failure_and_local_root_skips_its_volume() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/cli/tests/packages/nested-mounted-paths/out.webc");
        let root = wasmer_package::utils::from_disk(fixture).unwrap();
        let id = PackageId::Hash(PackageHash::from_sha256_bytes([0; 32]));
        let mut info =
            PackageInfo::from_manifest(id.clone(), root.manifest(), root.version()).unwrap();
        info.dependencies.clear();
        info.entrypoint = None;
        info.commands = vec![resolver::Command {
            name: "absent-command".to_string(),
        }];
        info.filesystem = vec![resolver::FileSystemMapping {
            volume_name: "absent-volume".to_string(),
            mount_path: "/app".to_string(),
            original_path: None,
            dependency_name: None,
        }];
        let source = resolver::InMemorySource::new();
        let context = RunContext::new(
            tokio::runtime::Runtime::new().unwrap(),
            Engine::default(),
            source,
            PackageDownloader::new(Arc::new(NoHttp)),
            Arc::new(SharedCache::default()),
            ProgressBar::hidden(),
            true,
        );
        let resolution = context
            .block_on(resolver::resolve(&id, &info, context.source.as_ref()))
            .unwrap();
        let error = context
            .block_on(context.load_resolved(root.clone(), resolution.clone(), false))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("doesn't have a \"absent-volume\" volume"),
            "{error:#}"
        );

        let error = context
            .block_on(context.load_resolved(root, resolution, true))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Unable to find the \"absent-command\" command metadata"),
            "{error:#}"
        );
    }
}
