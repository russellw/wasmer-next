//! The opt-in guest `wasmer run` command and its embedder-supplied resolver.

use std::{io, sync::Arc};

use bytes::Bytes;
use wasixv2_abi::{Fd, OpenFlags};
use wasixv2_vfs::FileType;
use wasmer_config::package::PackageSource;

use super::import::{RuntimePackages, matches_atom};
use crate::{
    CommandContext, CommandFile, CommandOutcome, Errno, Image, LocalFuture, MachineBuilder,
    MemoryBudget, ResolvedLayout, VirtualCommand, errno_to_io,
};

const USAGE: &[u8] = b"Usage: wasmer run [--] TARGET [ARGS...]\n";
const MAX_SPECIFIER: usize = 4096;
const MAX_LOCAL_BYTES: usize = 128 * 1024 * 1024;

/// An embedder's workload-scoped package acquisition service. Inputs from the guest have already
/// been classified as registry names or hashes, or decoded from a readable guest WEBC file.
pub trait RuntimePackageResolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, specifier: &'a str) -> LocalFuture<'a, io::Result<RuntimePackage>>;

    fn resolve_local(
        &self,
        _container: webc::Container,
    ) -> LocalFuture<'_, io::Result<RuntimePackage>> {
        Box::pin(async { Err(errno_to_io(Errno::EOPNOTSUPP)) })
    }
}

/// A resolved package tree and the command to run from it.
pub struct RuntimePackage {
    /// Identity of the effective layout, including resolved dependencies.
    pub identity: [u8; 32],
    pub layout: ResolvedLayout,
    pub entrypoint: String,
    pub defaults: RuntimeCommandDefaults,
}

/// Defaults applied before starting a command via `wasmer run`.
#[derive(Clone, Default)]
pub struct RuntimeCommandDefaults {
    pub argv0: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<String>,
}

/// Enables the guest `wasmer` command at the selected paths.
///
/// A local `.wasm` file must have its executable bit set and be on an exec-allowed mount.
pub struct WasmerCommandConfig {
    pub resolver: Arc<dyn RuntimePackageResolver>,
    pub limit: usize,
    pub allow_local: bool,
    pub paths: Vec<String>,
}

pub(crate) struct RuntimePackageConfig {
    resolver: Option<Arc<dyn RuntimePackageResolver>>,
    limit: usize,
    allow_local: bool,
    paths: Option<Vec<String>>,
}

impl Default for RuntimePackageConfig {
    fn default() -> Self {
        Self {
            resolver: None,
            limit: 128,
            allow_local: true,
            paths: None,
        }
    }
}

impl RuntimePackageConfig {
    pub(crate) fn finish(self) -> Option<WasmerCommandConfig> {
        Some(WasmerCommandConfig {
            resolver: self.resolver?,
            limit: self.limit,
            allow_local: self.allow_local,
            paths: self.paths.unwrap_or_else(|| vec!["/bin/wasmer".into()]),
        })
    }
}

impl MachineBuilder {
    /// Enables guest `wasmer run` at `/bin/wasmer`, with guest-local files allowed.
    pub fn runtime_package_resolver(mut self, resolver: Arc<dyn RuntimePackageResolver>) -> Self {
        self.runtime_package_config.resolver = Some(resolver);
        self.runtime_package_config.allow_local = true;
        self.runtime_package_config.paths = None;
        self
    }

    /// Caps distinct runtime package imports. The default is 128.
    pub fn runtime_package_limit(mut self, limit: usize) -> Self {
        self.runtime_package_config.limit = limit;
        self
    }

    /// Enables guest `wasmer run` with explicit command paths and local-file policy.
    pub fn wasmer_command(mut self, config: WasmerCommandConfig) -> Self {
        self.runtime_package_config = RuntimePackageConfig {
            resolver: Some(config.resolver),
            limit: config.limit,
            allow_local: config.allow_local,
            paths: Some(config.paths),
        };
        self
    }
}

pub(crate) struct WasmerCommand {
    pub(crate) resolver: Arc<dyn RuntimePackageResolver>,
    pub(crate) packages: Arc<RuntimePackages>,
    pub(crate) allow_local: bool,
    pub(crate) budget: Option<Arc<dyn MemoryBudget>>,
}

impl VirtualCommand for WasmerCommand {
    fn name(&self) -> &str {
        "wasmer"
    }

    fn run<'a>(&'a self, cx: CommandContext<'a>) -> LocalFuture<'a, CommandOutcome> {
        use tracing::Instrument;
        Box::pin(
            self.run_as(cx)
                .instrument(tracing::debug_span!("wasmer_command")),
        )
    }
}

impl WasmerCommand {
    async fn run_as(&self, cx: CommandContext<'_>) -> CommandOutcome {
        let mut args = cx.args().iter().skip(1).map(Vec::as_slice);
        match args.next() {
            Some(b"-h" | b"--help") => return message(&cx, Fd(1), USAGE, 0).await,
            Some(b"-V" | b"--version") => {
                let version = format!("wasmer {}\n", wasmer_types::VERSION);
                return message(&cx, Fd(1), version.as_bytes(), 0).await;
            }
            Some(b"run") => {}
            _ => return message(&cx, Fd(2), USAGE, 2).await,
        }
        let target = match args.next() {
            Some(b"--") => args.next(),
            other => other,
        };
        let Some(target) = target.filter(|target| !target.is_empty()) else {
            return message(&cx, Fd(2), USAGE, 2).await;
        };
        let target = target.to_vec();
        let mut args = args.peekable();
        if args.peek() == Some(&b"--".as_slice()) {
            args.next();
        }
        let args: Vec<_> = args.map(<[u8]>::to_vec).collect();
        let package = match self.source(&cx, &target).await {
            Ok(Source::Wasm(file)) => {
                let argv = std::iter::once(target).chain(args).collect();
                let env = cx.env().to_vec();
                return finish_exec(cx.exec_file(file.file(), argv, env).await, false).await;
            }
            Ok(Source::Package(package)) => package,
            Err(error) => return error.print(&cx).await,
        };

        let imported = match self.packages.import(&cx.fs().vfs, &package).await {
            Ok(imported) => imported,
            Err(error) => return CommandError::install(error).print(&cx).await,
        };
        let (argv, env) = default_args(&cx, &package, args);
        let path = imported.public.entrypoint.as_bytes();
        match cx.open(path, OpenFlags::O_RDONLY).await {
            Ok(file) if matches_atom(file.shared_contents().await, &imported.atom) => {
                // Execute the file we matched, even if its name is replaced before exec.
                return finish_exec(cx.exec_file(file.file(), argv, env).await, false).await;
            }
            Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) | Ok(_) => {}
            Err(error) => {
                tracing::debug!(?error, "cannot access runtime package entrypoint");
                return CommandError::NOT_EXECUTABLE.print(&cx).await;
            }
        }
        tracing::warn!(entrypoint = %imported.public.entrypoint, "runtime package entrypoint is shadowed");
        match imported.open_entrypoint(&cx.fs().vfs).await {
            Ok(file) => finish_exec(cx.exec_file(&file, argv, env).await, true).await,
            Err(error) => {
                tracing::debug!(%error, "cannot open shadowed runtime package entrypoint");
                CommandError::NOT_EXECUTABLE.print(&cx).await
            }
        }
    }

    async fn source(&self, cx: &CommandContext<'_>, target: &[u8]) -> Result<Source, CommandError> {
        // Registry identifiers may include a namespace separator. Try an existing guest
        // regular file first, then parse an implicit target as a registry identifier.
        let explicit = [b"/".as_slice(), b"./", b"../"]
            .iter()
            .any(|prefix| target.starts_with(prefix));
        if explicit || !target.windows(3).any(|window| window == b"://") {
            match cx
                .open(target, OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK)
                .await
            {
                Ok(file) if file.file().file_type() == FileType::Regular => {
                    if !self.allow_local {
                        return Err(CommandError(126, b"wasmer: local files are disabled\n"));
                    }
                    return self.local(file).await;
                }
                Ok(_) | Err(Errno::ENOENT | Errno::ENOTDIR) if !explicit => {}
                Err(Errno::ENOENT) => return Err(CommandError::NOT_FOUND),
                Err(Errno::ENAMETOOLONG) => return Err(CommandError::INVALID),
                Ok(_) | Err(_) => return Err(CommandError::NOT_EXECUTABLE),
            }
        }
        if target.len() > MAX_SPECIFIER {
            return Err(CommandError::INVALID);
        }
        let specifier = std::str::from_utf8(target).map_err(|_| CommandError::INVALID)?;
        match specifier.parse::<PackageSource>() {
            Ok(PackageSource::Ident(_)) => self
                .resolver
                .resolve(specifier)
                .await
                .map(Source::Package)
                .map_err(CommandError::resolve),
            Ok(PackageSource::Path(_)) => Err(CommandError::NOT_FOUND),
            _ => Err(CommandError::INVALID),
        }
    }

    async fn local(&self, file: CommandFile) -> Result<Source, CommandError> {
        let mut header = [0; 8];
        let size = read_to_end(&file, &mut header)
            .await
            .map_err(|_| CommandError::NOT_EXECUTABLE)?;
        if header[..size].starts_with(b"\0asm\x01\0\0\0") {
            return Ok(Source::Wasm(file));
        }
        let bytes = ImageBytes::read(&file, self.budget.as_ref())
            .await
            .map_err(|err| {
                tracing::debug!(?err, "cannot read guest-local package");
                CommandError(1, b"wasmer: cannot read local package\n")
            })?;
        let version = webc::detect(bytes.as_ref()).map_err(|_| CommandError::NOT_EXECUTABLE)?;
        let container = webc::Container::from_bytes_and_version(bytes, version)
            .map_err(|_| CommandError::NOT_EXECUTABLE)?;
        self.resolver
            .resolve_local(container)
            .await
            .map(Source::Package)
            .map_err(CommandError::resolve)
    }
}

enum Source {
    Wasm(CommandFile),
    Package(RuntimePackage),
}

async fn finish_exec(
    result: Result<crate::Executed, (CommandContext<'_>, Errno)>,
    shadowed: bool,
) -> CommandOutcome {
    match result {
        Ok(executed) => CommandOutcome::Exec(executed),
        Err((cx, error)) => {
            tracing::debug!(?error, "wasmer command could not exec");
            if error == Errno::ENOENT && !shadowed {
                CommandError::NOT_FOUND.print(&cx).await
            } else {
                CommandError::NOT_EXECUTABLE.print(&cx).await
            }
        }
    }
}

fn default_args(
    cx: &CommandContext<'_>,
    package: &RuntimePackage,
    args: Vec<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let defaults = &package.defaults;
    let argv0 = defaults.argv0.as_ref().unwrap_or(&package.entrypoint);
    let argv = std::iter::once(argv0.as_bytes().to_vec())
        .chain(defaults.args.iter().map(|arg| arg.as_bytes().to_vec()))
        .chain(args)
        .collect();
    let mut env = cx.env().to_vec();
    for value in &defaults.env {
        let Some((key, _)) = value.split_once('=') else {
            continue;
        };
        if !env.iter().any(|item| {
            item.strip_prefix(key.as_bytes())
                .is_some_and(|suffix| suffix.starts_with(b"="))
        }) {
            env.push(value.as_bytes().to_vec());
        }
    }
    (argv, env)
}

struct CommandError(i32, &'static [u8]);

impl CommandError {
    const INVALID: Self = Self(2, b"wasmer: invalid package source\n");
    const NOT_FOUND: Self = Self(127, b"wasmer: target not found\n");
    const NOT_EXECUTABLE: Self = Self(126, b"wasmer: target is not executable\n");

    fn resolve(error: io::Error) -> Self {
        tracing::debug!(%error, "runtime package resolution failed");
        match error.kind() {
            io::ErrorKind::NotFound => Self::NOT_FOUND,
            io::ErrorKind::PermissionDenied => Self::NOT_EXECUTABLE,
            _ => Self(1, b"wasmer: could not resolve package\n"),
        }
    }

    fn install(error: io::Error) -> Self {
        tracing::debug!(%error, "runtime package import failed");
        if error.raw_os_error() == Some(Errno::ENOSPC.0) {
            Self(1, b"wasmer: package limit reached\n")
        } else {
            Self(1, b"wasmer: could not import package\n")
        }
    }

    async fn print(self, cx: &CommandContext<'_>) -> CommandOutcome {
        message(cx, Fd(2), self.1, self.0).await
    }
}

async fn message(cx: &CommandContext<'_>, fd: Fd, text: &[u8], status: i32) -> CommandOutcome {
    match cx.write_all(fd, text).await {
        Err(_) if status == 0 => CommandOutcome::Exit(1),
        _ => CommandOutcome::Exit(status),
    }
}

struct ImageBytes {
    image: Image,
    _reservation: Option<Reservation>,
}

struct Reservation {
    budget: Arc<dyn MemoryBudget>,
    size: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release(self.size);
    }
}

impl ImageBytes {
    async fn read(
        file: &CommandFile,
        budget: Option<&Arc<dyn MemoryBudget>>,
    ) -> Result<Bytes, Errno> {
        if let Some(contents) = file.shared_contents().await {
            let image = Image::shared(contents);
            if image.bytes().len() > MAX_LOCAL_BYTES {
                return Err(Errno::EFBIG);
            }
            return Ok(Bytes::from_owner(Self {
                image,
                _reservation: None,
            }));
        }
        let size = file.size();
        if size > MAX_LOCAL_BYTES as u64 {
            return Err(Errno::EFBIG);
        }
        let reservation = budget
            .map(|budget| {
                budget.charge(size).map_err(|_| Errno::ENOMEM)?;
                Ok::<_, Errno>(Reservation {
                    budget: budget.clone(),
                    size,
                })
            })
            .transpose()?;
        let mut data = Vec::new();
        data.try_reserve_exact(size as usize)
            .map_err(|_| Errno::ENOMEM)?;
        data.resize(size as usize, 0);
        let got = read_to_end(file, &mut data).await?;
        if got == data.len() && file.read_at(&mut [0], got as u64).await? != 0 {
            return Err(Errno::EFBIG);
        }
        data.truncate(got);
        Ok(Bytes::from_owner(Self {
            image: Image::copied(data),
            _reservation: reservation,
        }))
    }
}

impl AsRef<[u8]> for ImageBytes {
    fn as_ref(&self) -> &[u8] {
        self.image.bytes()
    }
}

async fn read_to_end(file: &CommandFile, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut n = 0;
    while n < buf.len() {
        let read = file.read_at(&mut buf[n..], n as u64).await?;
        if read == 0 {
            break;
        }
        n += read;
    }
    Ok(n)
}
