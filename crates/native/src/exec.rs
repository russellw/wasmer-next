//! Native image validation and handoff for the WLK process supervisor.

use std::{
    ffi::CString,
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use wasixv2_abi::{AtFlags, Cstr, CstrArray, Errno, Fd};
use wasixv2_kernel::{Dispatch, Kernel, SyscallEntry};
use wasixv2_syscalls::{
    Binfmt, Caller, Control, Fault, Image, Layer, LocalFuture, Syscall, TaskId, UserMemory,
    UserSliceMut,
};

use crate::volumes::Volume;
use crate::{BridgeMemory, elf, platform::Request};

const MFD_CLOEXEC: u32 = 0x0001;
const MFD_EXEC: u32 = 0x0010;
// TODO: replace the faulting alias with direct errno translation if the exec translator API grows.
const INVALID_GUEST_POINTER: u32 = u32::MAX;
const MAX_NATIVE_STRINGS: usize = 4096;
const MAX_NATIVE_STRING_LEN: usize = 32 * 4096;
const MAX_NATIVE_ARG_BYTES: usize = 2 * 1024 * 1024;
const MAX_NATIVE_PATH_LEN: usize = 4096;
const MAX_INTERPRETER_BYTES: usize = 128 * 1024 * 1024;
const INTERPRETER_PATH_ADDR: u32 = 64;
const INTERPRETER_DATA_ADDR: u32 = 8192;
const INTERPRETER_CHUNK_SIZE: usize = 64 * 1024;
const INTERPRETER_MEMORY_SIZE: usize = INTERPRETER_DATA_ADDR as usize + INTERPRETER_CHUNK_SIZE;
const CSTR_READ_CHUNK: usize = 4096;
const GUEST_CSTR_CHUNK: usize = 256;

/// WLK executable format handler for bounded Linux x86_64 ELF images.
pub struct NativeBinfmt;

impl Binfmt for NativeBinfmt {
    fn probe(&self, header: &[u8]) -> Result<(), Errno> {
        elf::probe_header(header).map_err(|_| Errno::ENOEXEC)
    }

    fn check(&self, image: &Image) -> Result<(), Errno> {
        elf::validate_bytes(image.bytes()).map_err(|_| Errno::ENOEXEC)
    }
}

/// A validated WLK image copied to a supervisor-owned executable memfd.
pub struct NativeImage {
    _owned_fd: OwnedFd,
    pub path: CString,
    pub launch_argv: Option<Vec<CString>>,
}

/// Staged main image and, for dynamic ELF, its WLK-resolved interpreter image.
pub struct PreparedProgram {
    pub main: NativeImage,
    pub interpreter: Option<NativeImage>,
    pub interpreter_path: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ExecInvocation {
    pub path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
}

/// Copy native execve path and argv before the syscall replaces the tracee address space.
pub fn native_invocation(request: Request) -> io::Result<Option<ExecInvocation>> {
    let (path, argv) = match request.nr {
        libc::SYS_execve => (request.args[0], request.args[1]),
        libc::SYS_execveat => (request.args[1], request.args[2]),
        _ => return Ok(None),
    };
    let path = if path == 0 {
        Vec::new()
    } else {
        read_remote_cstr(request.pid, path, MAX_NATIVE_PATH_LEN).map_err(remote_string_error)?
    };
    let argv = read_remote_string_values(request.pid, argv)?;
    Ok(Some(ExecInvocation { path, argv }))
}

/// Resolve the main program through WLK and read its ELF interpreter through a WLK descriptor,
/// retaining the main executable as the process image and identity.
// TODO(native): the explicit loader reconstructs AT_EXECFN and `/proc/self/exe` from its own
// memfd/startup auxv; the WLK task remains identified as the main guest executable.
// TODO(native): the loader reopens the main guest pathname, so external host writes can race the
// WLK exec snapshot even though in-WLK exec write denial remains active.
pub async fn prepare_guest_program(
    kernel: &Kernel,
    task: TaskId,
    path: &[u8],
    args: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
) -> io::Result<PreparedProgram> {
    let first = kernel
        .exec(task, path, args.clone(), env.clone())
        .await
        .map_err(errno_error)?;
    let interpreter_path = elf::interpreter(first.bytes())?;
    let Some(interpreter_path) = interpreter_path else {
        return Ok(PreparedProgram {
            main: prepare(&first)?,
            interpreter: None,
            interpreter_path: None,
        });
    };

    let interpreter_bytes = read_guest_file(kernel, task, &interpreter_path).await?;
    if elf::interpreter(&interpreter_bytes)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ELF interpreter itself has a dynamic interpreter",
        ));
    }

    Ok(PreparedProgram {
        main: prepare(&first)?,
        interpreter: Some(prepare_bytes(&interpreter_bytes)?),
        interpreter_path: Some(interpreter_path),
    })
}

/// Stage a committed WLK exec image, selecting its guest interpreter when it is dynamic.
pub async fn prepare_exec_image(
    kernel: &Kernel,
    task: TaskId,
    image: &Image,
    invocation: Option<&ExecInvocation>,
) -> io::Result<NativeImage> {
    let Some(interpreter_path) = elf::interpreter(image.bytes())? else {
        return prepare(image);
    };
    let invocation = invocation.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "dynamic exec requires a pathname and argument vector",
        )
    })?;
    let interpreter_bytes = read_guest_file(kernel, task, &interpreter_path).await?;
    if elf::interpreter(&interpreter_bytes)?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ELF interpreter itself has a dynamic interpreter",
        ));
    }
    let mut interpreter = prepare_bytes(&interpreter_bytes)?;
    interpreter.launch_argv = Some(loader_argv(
        &interpreter,
        &interpreter_path,
        &invocation.path,
        &invocation.argv,
    )?);
    Ok(interpreter)
}

/// Open and read a guest path with WLK syscalls, without consulting the host filesystem.
pub async fn read_guest_file(kernel: &Kernel, task: TaskId, path: &[u8]) -> io::Result<Vec<u8>> {
    read_guest_file_at(kernel, task, Fd(libc::AT_FDCWD), path).await
}

/// Open a guest path relative to a WLK descriptor and read it without consulting host paths.
pub async fn read_guest_file_at(
    kernel: &Kernel,
    task: TaskId,
    dfd: Fd,
    path: &[u8],
) -> io::Result<Vec<u8>> {
    if path.is_empty() || path.contains(&0) || path.len() >= MAX_NATIVE_PATH_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid guest path",
        ));
    }
    let memory = LocalImageMemory::default();
    memory.write_bytes(INTERPRETER_PATH_ADDR, path)?;
    memory.write_bytes(INTERPRETER_PATH_ADDR + path.len() as u32, &[0])?;
    let fd = dispatch(
        kernel,
        task,
        &memory,
        Syscall::Openat {
            dfd,
            filename: Cstr::new(INTERPRETER_PATH_ADDR),
            flags: wasixv2_abi::OpenFlags::O_RDONLY,
            mode: 0,
        },
    )
    .await?;
    if fd < 0 || fd > i32::MAX as i64 {
        return Err(io::Error::from_raw_os_error((-fd) as i32));
    }
    let fd = Fd(fd as i32);
    let result = async {
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        loop {
            if offset as usize >= MAX_INTERPRETER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ELF interpreter exceeds the size limit",
                ));
            }
            let count = INTERPRETER_CHUNK_SIZE.min(MAX_INTERPRETER_BYTES - offset as usize);
            let read = dispatch(
                kernel,
                task,
                &memory,
                Syscall::Pread64 {
                    fd,
                    buf: UserSliceMut::new(INTERPRETER_DATA_ADDR, count as u32),
                    pos: offset as i64,
                },
            )
            .await? as usize;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&memory.read_bytes(INTERPRETER_DATA_ADDR, read)?);
            offset += read as u64;
        }
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ELF interpreter is empty",
            ));
        }
        Ok(bytes)
    }
    .await;
    let close = dispatch(kernel, task, &memory, Syscall::Close { fd }).await;
    match (result, close) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(bytes), Ok(_)) => Ok(bytes),
    }
}

async fn dispatch(
    kernel: &Kernel,
    task: TaskId,
    memory: &dyn UserMemory,
    call: Syscall,
) -> io::Result<i64> {
    let caller = Caller::new(task, memory);
    let raw = match SyscallEntry(Dispatch).call(&caller, call, kernel).await {
        Ok(value) => value.to_raw(),
        Err(wasixv2_syscalls::SysErr::Errno(errno)) => -(errno.0 as i64),
        Err(_) => -(libc::EINTR as i64),
    };
    kernel.run_task_work(&caller).await;
    if raw < 0 {
        Err(io::Error::from_raw_os_error((-raw) as i32))
    } else {
        Ok(raw)
    }
}

struct LocalImageMemory {
    bytes: std::sync::Mutex<Vec<u8>>,
}

impl Default for LocalImageMemory {
    fn default() -> Self {
        Self {
            bytes: std::sync::Mutex::new(vec![0; INTERPRETER_MEMORY_SIZE]),
        }
    }
}

impl LocalImageMemory {
    fn write_bytes(&self, address: u32, source: &[u8]) -> io::Result<()> {
        let mut bytes = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = address as usize + source.len();
        if end > INTERPRETER_MEMORY_SIZE {
            return Err(io::Error::other("local WLK image memory out of bounds"));
        }
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        bytes[address as usize..end].copy_from_slice(source);
        Ok(())
    }

    fn read_bytes(&self, address: u32, len: usize) -> io::Result<Vec<u8>> {
        let bytes = self
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = address as usize + len;
        if end > bytes.len() {
            return Err(io::Error::other("local WLK image memory out of bounds"));
        }
        Ok(bytes[address as usize..end].to_vec())
    }
}

impl UserMemory for LocalImageMemory {
    fn read<'a>(
        &'a self,
        address: u32,
        output: &'a mut [u8],
    ) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let bytes = self
                .bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let start = address as usize;
            let Some(source) = bytes.get(start..start.saturating_add(output.len())) else {
                return Err(Fault);
            };
            output.copy_from_slice(source);
            Ok(())
        })
    }

    fn write<'a>(&'a self, address: u32, input: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async move {
            let start = address as usize;
            let end = start.saturating_add(input.len());
            if end > INTERPRETER_MEMORY_SIZE {
                return Err(Fault);
            }
            let mut bytes = self
                .bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[start..end].copy_from_slice(input);
            Ok(())
        })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async { INTERPRETER_MEMORY_SIZE as u64 })
    }

    fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }

    fn can_duplicate(&self) -> LocalFuture<'_, bool> {
        Box::pin(async { true })
    }
}

/// Build explicit-loader argv while retaining the original guest path for `$ORIGIN` lookup.
pub fn loader_argv(
    loader_image: &NativeImage,
    interpreter_path: &[u8],
    guest_program: &[u8],
    original_argv: &[Vec<u8>],
) -> io::Result<Vec<CString>> {
    let argv0 = original_argv.first().map(Vec::as_slice).unwrap_or_default();
    let interpreter_name = interpreter_path
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    let supports_argv0 = interpreter_name.starts_with(b"ld-linux")
        || interpreter_name.starts_with(b"ld64.so")
        || interpreter_name.starts_with(b"ld-musl");

    let mut values = Vec::with_capacity(original_argv.len() + 3);
    values.push(loader_image.path.to_bytes().to_vec());
    if supports_argv0 {
        values.push(b"--argv0".to_vec());
        values.push(argv0.to_vec());
    }
    values.push(guest_program.to_vec());
    values.extend(original_argv.iter().skip(1).cloned());
    values
        .into_iter()
        .map(|value| {
            CString::new(value).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })
        .collect()
}

/// Map a host CLI program path to the guest path covered by a volume or filesystem root.
///
/// TODO(native): retain symlink spelling when translating host launch paths; canonicalizing is
/// currently used to establish that the file is visible through the configured guest view.
pub fn guest_path_for_host(
    program: &Path,
    root: &Path,
    volumes: &[Volume],
) -> io::Result<Option<Vec<u8>>> {
    let program = std::fs::canonicalize(absolute_path(program)?)?;
    let mut matches = Vec::<(usize, Vec<u8>)>::new();
    for volume in volumes {
        let host = std::fs::canonicalize(absolute_path(&volume.host)?)?;
        if let Ok(relative) = program.strip_prefix(&host) {
            matches.push((
                host.as_os_str().as_bytes().len(),
                guest_join(&volume.guest, relative),
            ));
        }
    }
    if let Some((_, path)) = matches.into_iter().max_by_key(|(length, _)| *length) {
        return Ok(Some(path));
    }

    let root = std::fs::canonicalize(absolute_path(root)?)?;
    let Ok(relative) = program.strip_prefix(root) else {
        return Ok(None);
    };
    Ok(Some(guest_join(b"/", relative)))
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn guest_join(prefix: &[u8], relative: &Path) -> Vec<u8> {
    let mut guest = prefix.to_vec();
    if guest.last() != Some(&b'/') {
        guest.push(b'/');
    }
    guest.extend_from_slice(relative.as_os_str().as_bytes());
    if guest.is_empty() {
        guest.push(b'/');
    }
    guest
}

fn errno_error(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno.0)
}

fn read_remote_string_values(pid: libc::pid_t, address: u64) -> io::Result<Vec<Vec<u8>>> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    let mut total = 0usize;
    for index in 0..=MAX_NATIVE_STRINGS {
        let slot = address
            .checked_add((index * std::mem::size_of::<u64>()) as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "argv pointer overflow"))?;
        let mut pointer = [0u8; 8];
        if !crate::read_remote(pid, slot, &mut pointer) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid argv pointer",
            ));
        }
        let pointer = u64::from_le_bytes(pointer);
        if pointer == 0 {
            return Ok(values);
        }
        if index == MAX_NATIVE_STRINGS {
            break;
        }
        let value =
            read_remote_cstr(pid, pointer, MAX_NATIVE_STRING_LEN).map_err(remote_string_error)?;
        total = total.saturating_add(value.len() + 1);
        if total > MAX_NATIVE_ARG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "argv exceeds size limit",
            ));
        }
        values.push(value);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "argv is not terminated",
    ))
}

fn remote_string_error(error: RemoteStringError) -> io::Error {
    match error {
        RemoteStringError::Fault => {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid string pointer")
        }
        RemoteStringError::TooLong => {
            io::Error::new(io::ErrorKind::InvalidInput, "string exceeds size limit")
        }
    }
}

/// Copy a validated WLK image into an executable memfd addressed through the supervisor's procfs.
pub fn prepare(image: &Image) -> io::Result<NativeImage> {
    prepare_bytes(image.bytes())
}

/// Copy validated ELF bytes into an executable memfd addressed through supervisor procfs.
pub fn prepare_bytes(bytes: &[u8]) -> io::Result<NativeImage> {
    elf::validate_bytes(bytes)?;

    // TODO: replace this memfd/procfs handoff with direct native-image ownership in the child
    // supervisor once it can consume WLK Image bytes without re-opening a path.
    let fd = create_memfd()?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } == -1 {
        return Err(io::Error::last_os_error());
    }

    let raw_fd = file.as_raw_fd();
    let path = CString::new(format!("/proc/{}/fd/{raw_fd}", unsafe { libc::getpid() }))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let owned_fd = file.into();
    Ok(NativeImage {
        _owned_fd: owned_fd,
        path,
        launch_argv: None,
    })
}

fn create_memfd() -> io::Result<OwnedFd> {
    const NAME: &[u8] = b"wlk-native-image\0";
    let fd = unsafe {
        libc::memfd_create(
            NAME.as_ptr().cast(),
            (MFD_CLOEXEC | MFD_EXEC) as libc::c_uint,
        )
    };
    if fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINVAL) {
        return Err(error);
    }

    // TODO: drop this fallback once the minimum kernel supports MFD_EXEC.
    // Older kernels reject MFD_EXEC; retry with CLOEXEC and let fchmod report noexec policy.
    let fd = unsafe { libc::memfd_create(NAME.as_ptr().cast(), MFD_CLOEXEC as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Translate native `execve` and `execveat` pointers into WLK's 32-bit pointer layout.
pub fn translate(request: Request, memory: &mut BridgeMemory) -> io::Result<Option<Syscall>> {
    let call = match request.nr {
        libc::SYS_execve => {
            let filename =
                map_remote_cstr(request.pid, request.args[0], MAX_NATIVE_PATH_LEN, memory)?;
            let (argv, envp) =
                map_native_arguments(request.pid, request.args[1], request.args[2], memory)?;
            Some(Syscall::Execve {
                filename: Cstr::new(filename),
                argv: CstrArray::new(argv),
                envp: CstrArray::new(envp),
            })
        }
        libc::SYS_execveat => {
            let filename = if request.args[1] == 0
                && (request.args[4] as u32 & AtFlags::AT_EMPTY_PATH.0) != 0
            {
                0
            } else {
                map_remote_cstr(request.pid, request.args[1], MAX_NATIVE_PATH_LEN, memory)?
            };
            let (argv, envp) =
                map_native_arguments(request.pid, request.args[2], request.args[3], memory)?;
            Some(Syscall::Execveat {
                fd: Fd(request.args[0] as i32),
                filename: Cstr::new(filename),
                argv: CstrArray::new(argv),
                envp: CstrArray::new(envp),
                flags: AtFlags(request.args[4] as u32),
            })
        }
        _ => None,
    };
    Ok(call)
}

fn map_native_arguments(
    pid: libc::pid_t,
    argv: u64,
    envp: u64,
    memory: &mut BridgeMemory,
) -> io::Result<(u32, u32)> {
    let mut limits = ArgumentLimits {
        strings: MAX_NATIVE_STRINGS,
        bytes: MAX_NATIVE_ARG_BYTES,
    };
    let argv = map_native_string_array(pid, argv, memory, &mut limits)?;
    let envp = map_native_string_array(pid, envp, memory, &mut limits)?;
    Ok((argv, envp))
}

fn map_native_string_array(
    pid: libc::pid_t,
    native_array: u64,
    memory: &mut BridgeMemory,
    limits: &mut ArgumentLimits,
) -> io::Result<u32> {
    if native_array == 0 {
        return Ok(0);
    }

    let mut guest_pointers = Vec::with_capacity(16);
    for index in 0..=MAX_NATIVE_STRINGS {
        let Some(slot) = native_array.checked_add((index * 8) as u64) else {
            guest_pointers.push(INVALID_GUEST_POINTER);
            return map_pointer_array(memory, &guest_pointers);
        };
        let mut pointer_bytes = [0u8; 8];
        if !crate::read_remote(pid, slot, &mut pointer_bytes) {
            guest_pointers.push(INVALID_GUEST_POINTER);
            return map_pointer_array(memory, &guest_pointers);
        }
        let native_string = u64::from_le_bytes(pointer_bytes);
        if native_string == 0 {
            guest_pointers.push(0);
            return map_pointer_array(memory, &guest_pointers);
        }

        if limits.strings == 0 {
            guest_pointers.push(map_too_long_sentinel(memory, MAX_NATIVE_STRING_LEN)?);
            return map_pointer_array(memory, &guest_pointers);
        }
        limits.strings -= 1;

        match read_remote_cstr(pid, native_string, MAX_NATIVE_STRING_LEN) {
            Ok(bytes) => {
                let cost = bytes.len().saturating_add(5); // string NUL plus 32-bit argv pointer
                if cost > limits.bytes {
                    guest_pointers.push(map_too_long_sentinel(memory, MAX_NATIVE_STRING_LEN)?);
                    return map_pointer_array(memory, &guest_pointers);
                }
                limits.bytes -= cost;
                guest_pointers.push(map_local_cstr(memory, &bytes, true)?);
            }
            Err(RemoteStringError::Fault) => {
                guest_pointers.push(INVALID_GUEST_POINTER);
                return map_pointer_array(memory, &guest_pointers);
            }
            Err(RemoteStringError::TooLong) => {
                guest_pointers.push(map_too_long_sentinel(memory, MAX_NATIVE_STRING_LEN)?);
                return map_pointer_array(memory, &guest_pointers);
            }
        }
    }

    guest_pointers.push(map_too_long_sentinel(memory, MAX_NATIVE_STRING_LEN)?);
    map_pointer_array(memory, &guest_pointers)
}

fn map_pointer_array(memory: &mut BridgeMemory, pointers: &[u32]) -> io::Result<u32> {
    let mut bytes = Vec::with_capacity(pointers.len() * 4);
    for pointer in pointers {
        bytes.extend_from_slice(&pointer.to_le_bytes());
    }
    memory.map_local(bytes)
}

fn map_remote_cstr(
    pid: libc::pid_t,
    address: u64,
    max_len: usize,
    memory: &mut BridgeMemory,
) -> io::Result<u32> {
    match read_remote_cstr(pid, address, max_len) {
        Ok(bytes) => map_local_cstr(memory, &bytes, true),
        Err(RemoteStringError::Fault) => Ok(INVALID_GUEST_POINTER),
        Err(RemoteStringError::TooLong) => map_too_long_sentinel(memory, max_len),
    }
}

fn map_local_cstr(memory: &mut BridgeMemory, bytes: &[u8], terminated: bool) -> io::Result<u32> {
    let len = bytes
        .len()
        .checked_add(if terminated { 1 } else { 0 })
        .ok_or_else(|| io::Error::other("native string length overflow"))?;
    let padded_len = len
        .checked_add(GUEST_CSTR_CHUNK - 1)
        .ok_or_else(|| io::Error::other("native string length overflow"))?
        / GUEST_CSTR_CHUNK
        * GUEST_CSTR_CHUNK;
    let mut local = Vec::with_capacity(padded_len);
    local.extend_from_slice(bytes);
    if terminated {
        local.push(0);
    }
    local.resize(padded_len, 0);
    memory.map_local(local)
}

fn map_too_long_sentinel(memory: &mut BridgeMemory, len: usize) -> io::Result<u32> {
    // TODO: return E2BIG/ENAMETOOLONG directly when native translation can carry immediate errno.
    let bytes = vec![b'x'; len];
    map_local_cstr(memory, &bytes, false)
}

fn read_remote_cstr(
    pid: libc::pid_t,
    address: u64,
    max_len: usize,
) -> Result<Vec<u8>, RemoteStringError> {
    if address == 0 {
        return Err(RemoteStringError::Fault);
    }

    let mut out = Vec::with_capacity(max_len.min(GUEST_CSTR_CHUNK));
    let mut chunk = [0u8; CSTR_READ_CHUNK];
    while out.len() < max_len {
        let current = address
            .checked_add(out.len() as u64)
            .ok_or(RemoteStringError::Fault)?;
        let page_remaining = CSTR_READ_CHUNK - (current as usize % CSTR_READ_CHUNK);
        let len = (max_len - out.len()).min(page_remaining);
        if !crate::read_remote(pid, current, &mut chunk[..len]) {
            return Err(RemoteStringError::Fault);
        }
        if let Some(nul) = chunk[..len].iter().position(|byte| *byte == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..len]);
    }
    Err(RemoteStringError::TooLong)
}

struct ArgumentLimits {
    strings: usize,
    bytes: usize,
}

enum RemoteStringError {
    Fault,
    TooLong,
}
