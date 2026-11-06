use crate::{
    Command, CommandSelector, Error, FileSystem, MountMode, Package, PackageLoadOptions,
    PackageLoadProgress, PackageSource, Result, SandboxFileSystem, Wasmer, process::ProcessControl,
};
use crate::{provider_net::ProviderNetwork, provider_runtime::ProviderRuntime};
use std::{
    collections::BTreeMap,
    future::{Future, IntoFuture},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use virtual_net::{DynVirtualNetworking, NetworkError, host::LocalNetworking};

/// Builds a process-free sandbox.
#[derive(Debug)]
pub struct SandboxBuilder {
    client: Wasmer,
    packages: Vec<PackageSource>,
    package_load_options: PackageLoadOptions,
    files: Vec<(PathBuf, Vec<u8>)>,
    env: BTreeMap<String, String>,
    mounts: Vec<MountSpec>,
    workspace_provider: Option<Arc<dyn FileSystem>>,
    network: NetworkPolicy,
    network_provider: Option<DynVirtualNetworking>,
}

/// A value that can be mounted into a sandbox as an external filesystem.
///
/// Implemented for every [`FileSystem`] provider (including [`Directory`]) and
/// for `Arc<dyn FileSystem>`, so shared providers mount without manual
/// coercion.
///
/// [`Directory`]: crate::Directory
pub trait IntoFileSystem {
    fn into_filesystem(self) -> Arc<dyn FileSystem>;
}

impl IntoFileSystem for Arc<dyn FileSystem> {
    fn into_filesystem(self) -> Arc<dyn FileSystem> {
        self
    }
}

impl<T: FileSystem> IntoFileSystem for T {
    fn into_filesystem(self) -> Arc<dyn FileSystem> {
        Arc::new(self)
    }
}

impl SandboxBuilder {
    pub(crate) fn new(client: Wasmer) -> Self {
        Self {
            client,
            packages: Vec::new(),
            package_load_options: PackageLoadOptions::default(),
            files: Vec::new(),
            env: BTreeMap::new(),
            mounts: Vec::new(),
            workspace_provider: None,
            network: NetworkPolicy::Disabled,
            network_provider: None,
        }
    }

    /// Add a package that will be resolved before sandbox creation completes.
    #[must_use]
    pub fn package(mut self, source: impl Into<PackageSource>) -> Self {
        self.packages.push(source.into());
        self
    }

    /// Observe package acquisition performed before sandbox creation.
    #[must_use]
    pub fn on_package_progress(
        mut self,
        observer: impl Fn(PackageLoadProgress) + Send + Sync + 'static,
    ) -> Self {
        self.package_load_options = self.package_load_options.on_progress(observer);
        self
    }

    /// Seed a file. Relative paths resolve beneath `/workspace`.
    #[must_use]
    pub fn file(mut self, path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) -> Self {
        self.files.push((path.into(), bytes.into()));
        self
    }

    /// Set one sandbox-wide environment value.
    ///
    /// Sandbox values apply to every command; per-command values override
    /// them. Environment variables are visible to all code in the sandbox.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set several sandbox-wide environment values.
    #[must_use]
    pub fn envs<I, K, V>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env.extend(
            values
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    /// Mount an external filesystem provider at an absolute guest path.
    #[must_use]
    pub fn mount(
        mut self,
        guest_path: impl Into<PathBuf>,
        filesystem: impl IntoFileSystem,
        mode: MountMode,
    ) -> Self {
        self.mounts.push(MountSpec {
            guest_path: guest_path.into(),
            filesystem: filesystem.into_filesystem(),
            mode,
        });
        self
    }

    /// Select the storage provider for `/workspace` and the sandbox filesystem API.
    /// The default is an in-memory filesystem shared by all sandbox processes.
    #[must_use]
    pub fn storage(mut self, filesystem: impl IntoFileSystem) -> Self {
        self.workspace_provider = Some(filesystem.into_filesystem());
        self
    }

    /// Configure guest networking.
    ///
    /// Networking is disabled by default. [`NetworkPolicy::Host`] selects the
    /// target's explicitly installed host bridge (native sockets on `sys`,
    /// the injected JavaScript bridge on Node) and is therefore an
    /// unrestricted capability grant.
    #[must_use]
    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.network = policy;
        self.network_provider = None;
        self
    }

    /// Install a target-specific virtual network provider.
    ///
    /// Most applications should use [`SandboxBuilder::network`]. This escape
    /// hatch is intended for SDK facades and embedders that bridge sockets to
    /// a platform facility, such as a browser service worker.
    #[must_use]
    pub fn network_provider(mut self, provider: DynVirtualNetworking) -> Self {
        self.network_provider = Some(provider);
        self
    }

    /// Resolve packages and create the sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is closed, a package cannot be loaded, or
    /// a seeded workspace file cannot be written.
    #[deprecated(note = "await the sandbox builder directly")]
    pub async fn start(self) -> Result<Sandbox> {
        self.create().await
    }

    async fn create(self) -> Result<Sandbox> {
        self.client.ensure_open()?;
        let _admission = self.client.inner.services.admit()?;

        let mut packages = Vec::with_capacity(self.packages.len());
        for package in self
            .client
            .packages()
            .load_many_with_options(self.packages, self.package_load_options)
            .await?
        {
            if !packages
                .iter()
                .any(|installed: &Package| installed.same_as(&package))
            {
                packages.push(package);
            }
        }

        let provider_runtime = ProviderRuntime::new(self.client.inner.services.clone());
        let workspace = self
            .workspace_provider
            .unwrap_or_else(|| Arc::new(crate::Directory::new()));
        let fs = SandboxFileSystem::new(workspace.clone(), provider_runtime.clone());
        for (path, bytes) in self.files {
            fs.write(path, bytes).await?;
        }
        let mut mounts = Vec::with_capacity(self.mounts.len());
        for mount in self.mounts {
            validate_mount_path(&mount.guest_path)?;
            if mounts
                .iter()
                .any(|existing: &MountSpec| existing.guest_path == mount.guest_path)
            {
                return Err(Error::InvalidGuestPath {
                    path: mount.guest_path,
                    message: "a filesystem is already mounted at this path".to_owned(),
                });
            }
            mounts.push(mount);
        }

        let provider = self.network_provider.or_else(|| match self.network {
            NetworkPolicy::Disabled => None,
            NetworkPolicy::Host => {
                Some(Arc::new(LocalNetworking::default()) as DynVirtualNetworking)
            }
        });
        // Probes own a separate existing provider group. Every Machine receives
        // its own namespace and group from this same immutable provider choice.
        let probe_network = provider.as_ref().map(|provider| {
            ProviderNetwork::new(provider.clone(), self.client.inner.services.clone())
        });
        let client = self.client.clone();
        let sandbox = Sandbox {
            inner: Arc::new(SandboxInner {
                client: self.client,
                packages: RwLock::new(packages),
                workspace,
                provider_runtime,
                fs,
                env: self.env,
                mounts,
                network_provider: provider,
                probe_network,
                lifecycle: Mutex::default(),
                changed: tokio::sync::Notify::new(),
                closed: AtomicBool::new(false),
                close_started: AtomicBool::new(false),
                close_result: tokio::sync::watch::channel(None).0,
            }),
        };
        {
            let mut registered =
                client
                    .inner
                    .sandboxes
                    .lock()
                    .map_err(|_| Error::InternalState {
                        message: "the sandbox registry lock is poisoned".into(),
                    })?;
            client.ensure_open()?;
            registered.retain(|entry| entry.strong_count() != 0);
            registered.push(Arc::downgrade(&sandbox.inner));
        }
        Ok(sandbox)
    }
}

impl IntoFuture for SandboxBuilder {
    type Output = Result<Sandbox>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.create())
    }
}

/// A persistent package composition and workspace from which commands run.
#[derive(Clone)]
pub struct Sandbox {
    pub(crate) inner: Arc<SandboxInner>,
}

#[cfg_attr(not(feature = "sys"), allow(dead_code))]
pub(crate) struct SandboxInner {
    pub(crate) client: Wasmer,
    pub(crate) packages: RwLock<Vec<Package>>,
    pub(crate) workspace: Arc<dyn FileSystem>,
    pub(crate) fs: SandboxFileSystem,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) mounts: Vec<MountSpec>,
    pub(crate) provider_runtime: ProviderRuntime,
    network_provider: Option<DynVirtualNetworking>,
    probe_network: Option<Arc<ProviderNetwork>>,
    lifecycle: Mutex<Lifecycle>,
    changed: tokio::sync::Notify,
    close_started: AtomicBool,
    close_result: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
    closed: AtomicBool,
}

/// Guest network authority for a sandbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NetworkPolicy {
    /// Guest socket operations fail; no external network is reachable.
    #[default]
    Disabled,
    /// Guest sockets use the host network without address filtering.
    Host,
}

#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "sys"), allow(dead_code))]
pub(crate) struct MountSpec {
    pub(crate) guest_path: PathBuf,
    pub(crate) filesystem: Arc<dyn FileSystem>,
    pub(crate) mode: MountMode,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sandbox")
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

fn validate_mount_path(path: &Path) -> Result<()> {
    // Guest paths are rooted Unix paths. `is_absolute()` is always false for
    // wasm32-unknown-unknown in current Rust std, even for `/native`.
    if !path.has_root() {
        return Err(Error::InvalidGuestPath {
            path: path.to_owned(),
            message: "mount paths must be absolute".to_owned(),
        });
    }
    super::fs::validate_guest_path(path)?;
    if path == Path::new("/") || path == Path::new("/workspace") {
        return Err(Error::InvalidGuestPath {
            path: path.to_owned(),
            message: "the root and `/workspace` are reserved mount points".to_owned(),
        });
    }
    Ok(())
}

impl Sandbox {
    /// Construct a command. Resolution occurs when it is executed.
    #[must_use]
    pub fn command(&self, selector: impl Into<CommandSelector>) -> Command {
        Command::new(self.clone(), selector.into())
    }

    /// Resolve and atomically add a package to this sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the client or sandbox is closed, package resolution
    /// fails, or internal package state is unavailable.
    pub async fn install_package(&self, source: impl Into<PackageSource>) -> Result<Package> {
        self.install_package_with_options(source, PackageLoadOptions::default())
            .await
    }

    /// Load and install a package with optional acquisition progress.
    pub async fn install_package_with_options(
        &self,
        source: impl Into<PackageSource>,
        options: PackageLoadOptions,
    ) -> Result<Package> {
        self.ensure_open()?;
        let package = self
            .inner
            .client
            .packages()
            .load_with_options(source, options)
            .await?;
        self.ensure_open()?;
        let mut packages = self
            .inner
            .packages
            .write()
            .map_err(|_| Error::InternalState {
                message: "the installed-package lock is poisoned".to_owned(),
            })?;
        if let Some(installed) = packages
            .iter()
            .find(|installed| installed.same_as(&package))
        {
            return Ok(installed.clone());
        }
        packages.push(package.clone());
        Ok(package)
    }

    /// Access the persistent `/workspace` filesystem.
    #[must_use]
    pub fn fs(&self) -> &SandboxFileSystem {
        &self.inner.fs
    }

    /// Access guest port facilities.
    #[must_use]
    pub fn ports(&self) -> Ports {
        Ports {
            sandbox: self.clone(),
        }
    }

    /// Close the sandbox, kill its live processes, and reject future work.
    ///
    /// # Errors
    ///
    /// Returns an error if internal process state is unavailable.
    pub(crate) fn begin_close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.kill_registered();
        if !self.inner.close_started.swap(true, Ordering::AcqRel) {
            let inner = self.inner.clone();
            let completed = self.inner.close_result.clone();
            if let Err(error) = self.inner.client.inner.services.cleanup(async move {
                let mut failure = None;
                if let Some(network) = &inner.probe_network {
                    if let Err(error) = network.close().await {
                        failure.get_or_insert_with(|| error.to_string());
                    }
                }
                // Registration and the admission count share a lock. Every provisional
                // launch registers its owner before releasing its admission lease.
                loop {
                    let notified = inner.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if inner.lifecycle.lock().unwrap().launches == 0 {
                        break;
                    }
                    notified.await;
                }
                let processes: Vec<_> = inner
                    .lifecycle
                    .lock()
                    .unwrap()
                    .processes
                    .iter()
                    .filter_map(Weak::upgrade)
                    .collect();
                for process in processes {
                    if let Err(error) = process.close().await {
                        failure.get_or_insert_with(|| error.to_string());
                    }
                }
                if let Err(error) = inner.provider_runtime.close().await {
                    failure.get_or_insert_with(|| error.to_string());
                }
                completed.send_replace(Some(failure.map_or(Ok(()), Err)));
                Ok(())
            }) {
                self.inner
                    .close_result
                    .send_replace(Some(Err(error.to_string())));
            }
        }
    }
    pub async fn close(&self) -> Result<()> {
        self.begin_close();
        let mut completed = self.inner.close_result.subscribe();
        loop {
            {
                let value = completed.borrow_and_update().clone();
                if let Some(result) = value {
                    return result.map_err(|message| Error::Execution { message });
                }
            }
            completed.changed().await.map_err(|_| Error::Task {
                message: "sandbox close owner stopped".into(),
            })?;
        }
    }
    fn kill_registered(&self) {
        for process in self
            .inner
            .lifecycle
            .lock()
            .unwrap()
            .processes
            .iter()
            .filter_map(Weak::upgrade)
        {
            process.kill();
        }
    }
    pub(crate) fn admit(&self) -> Result<LaunchLease> {
        let mut state = self.inner.lifecycle.lock().unwrap();
        self.ensure_open()?;
        state.launches = state
            .launches
            .checked_add(1)
            .ok_or_else(|| Error::InternalState {
                message: "launch count exhausted".into(),
            })?;
        Ok(LaunchLease(self.inner.clone()))
    }

    pub(crate) fn ensure_open(&self) -> Result<()> {
        self.inner.client.ensure_open()?;
        if self.inner.closed.load(Ordering::Acquire) {
            Err(Error::SandboxClosed)
        } else {
            Ok(())
        }
    }

    pub(crate) fn run_network(&self) -> (Arc<wasixv2_vnet::Net>, Option<Arc<ProviderNetwork>>) {
        let scope = self.inner.network_provider.as_ref().map(|provider| {
            ProviderNetwork::new(provider.clone(), self.inner.client.inner.services.clone())
        });
        let mut config = if scope.is_some() {
            wasixv2_vnet::NetConfig::host_default()
        } else {
            wasixv2_vnet::NetConfig::default()
        };
        if scope.is_some() {
            config.auto_publish = Some(std::net::Ipv4Addr::UNSPECIFIED.into());
        } else {
            config.policy = Some(Arc::new(DisabledNetwork));
        }
        (
            wasixv2_vnet::Net::new(
                config,
                scope
                    .clone()
                    .map(|scope| scope as Arc<dyn wasixv2_vnet::Backend>),
            ),
            scope,
        )
    }

    pub(crate) fn register_process(&self, process: &Arc<ProcessControl>) -> Result<()> {
        let mut state = self
            .inner
            .lifecycle
            .lock()
            .map_err(|_| Error::InternalState {
                message: "the process registry lock is poisoned".into(),
            })?;
        state.processes.retain(|entry| entry.strong_count() != 0);
        state.processes.push(Arc::downgrade(process));
        if self.ensure_open().is_err() {
            process.kill();
        }
        Ok(())
    }
}

/// Guest port facilities for one sandbox.
#[derive(Clone, Debug)]
pub struct Ports {
    sandbox: Sandbox,
}

/// How often [`Ports::wait`] probes the guest port.
const PORT_PROBE_INTERVAL: Duration = Duration::from_millis(50);

impl Ports {
    /// Wait until a guest TCP listener accepts connections on `port`.
    ///
    /// The probe uses the sandbox's own network policy, so it observes
    /// exactly what the guest exposed and fails with
    /// [`Error::CapabilityUnavailable`] when networking is disabled.
    ///
    /// A successful probe opens and immediately closes one real TCP
    /// connection. Servers that accept only once or count connections should
    /// use an application-level readiness signal instead.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] when the port does not accept a connection
    /// within `timeout`, and [`Error::CapabilityUnavailable`] when the
    /// sandbox has no networking.
    pub async fn wait(&self, port: u16, timeout: Duration) -> Result<()> {
        let operation = format!("guest port {port} to accept connections");
        if timeout.is_zero() {
            return Err(Error::Timeout { operation });
        }

        let peer = SocketAddr::from(([127, 0, 0, 1], port));
        let local = SocketAddr::from(([0, 0, 0, 0], 0));
        self.sandbox.ensure_open()?;
        let networking =
            self.sandbox
                .inner
                .probe_network
                .clone()
                .ok_or(Error::CapabilityUnavailable {
                    capability: "port probing requires sandbox networking",
                })?;
        let deadline = Box::pin(tokio::time::sleep(timeout));
        let probe = Box::pin(async {
            loop {
                self.sandbox.ensure_open()?;
                let result = networking.probe_tcp(local, peer).await;
                self.sandbox.ensure_open()?;
                match result {
                    Ok(()) => return Ok(()),
                    Err(NetworkError::Unsupported) => {
                        return Err(Error::CapabilityUnavailable {
                            capability: "port probing requires sandbox networking",
                        });
                    }
                    Err(_not_yet_listening) => {}
                }
                tokio::time::sleep(PORT_PROBE_INTERVAL).await;
            }
        });

        match futures::future::select(probe, deadline).await {
            futures::future::Either::Left((result, _deadline)) => result,
            futures::future::Either::Right(((), _probe)) => Err(Error::Timeout { operation }),
        }
    }
}

#[derive(Debug)]
struct DisabledNetwork;
impl wasixv2_vnet::NetworkPolicy for DisabledNetwork {
    fn allows_socket(
        &self,
        _address: SocketAddr,
        _direction: wasixv2_vnet::PolicyDirection,
    ) -> bool {
        false
    }
    fn allows_domain(&self, _domain: &str) -> bool {
        false
    }
    fn resolved_domain(&self, _domain: &str, _addresses: &[std::net::IpAddr]) {}
}

#[derive(Default)]
struct Lifecycle {
    launches: usize,
    processes: Vec<Weak<ProcessControl>>,
}
pub(crate) struct LaunchLease(Arc<SandboxInner>);
impl Drop for LaunchLease {
    fn drop(&mut self) {
        self.0.lifecycle.lock().unwrap().launches -= 1;
        self.0.changed.notify_waiters();
    }
}

#[cfg(all(test, feature = "napi-v8"))]
mod napi_hook_tests {
    #[test]
    fn napi_runtime_hooks_implement_the_wasix_hook_contract() {
        fn assert_hook<T: wasixv2::InstantiationHook<wasixv2::MachineSyscalls>>() {}
        assert_hook::<wasmer_napi::NapiHook>();
    }
}
