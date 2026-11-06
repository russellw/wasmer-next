//! Unofficial API for WASI integrating with the standard Wasm C API.
//!
//! This API will be superseded by a standard WASI API when/if such a standard is created.

#[cfg(feature = "sys")]
mod native;

pub use super::unstable::wasi::wasi_get_unordered_imports;
use super::{
    externals::{wasm_extern_t, wasm_extern_vec_t, wasm_func_t, wasm_memory_t},
    instance::wasm_instance_t,
    module::wasm_module_t,
    store::{StoreRef, wasm_store_t},
};
use crate::error::update_last_error;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
#[cfg(feature = "v8")]
use std::sync::Arc;
#[cfg(feature = "v8")]
use wasmer_wasix::{
    Pipe, PluggableRuntime, WasiEnv, WasiFunctionEnv, default_fs_backing,
    runtime::task_manager::{block_on, tokio::TokioTaskManager},
    virtual_fs::AsyncReadExt,
    virtual_fs::VirtualFile,
};

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct wasi_config_t {
    inherit_stdout: bool,
    inherit_stderr: bool,
    inherit_stdin: bool,
    args: Vec<String>,
    env: Vec<(String, Vec<u8>)>,
    preopens: Vec<Preopen>,
}

#[derive(Debug)]
struct Preopen {
    host: String,
    alias: Option<String>,
}

impl Preopen {
    fn announced(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.host)
    }
}

#[cfg(feature = "sys")]
#[derive(Debug, thiserror::Error)]
pub(super) enum ConfigurationError {
    #[error("bad environment variable format: `{0}`")]
    Environment(String),
    #[error("wasi filesystem creation error: `{0}`")]
    Filesystem(String),
}

#[cfg(feature = "sys")]
#[derive(Debug, thiserror::Error)]
#[error("WASI exited with code: ExitCode::{0}")]
struct Exit(u16);

#[cfg(feature = "sys")]
fn exit_trap(status: i32) -> wasmer_api::RuntimeError {
    wasmer_api::RuntimeError::user(Box::new(Exit((status % 256) as u16)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_new(
    program_name: *const c_char,
) -> Option<Box<wasi_config_t>> {
    debug_assert!(!program_name.is_null());

    let name_c_str = unsafe { CStr::from_ptr(program_name) };
    let prog_name = c_try!(name_c_str.to_str());

    Some(Box::new(wasi_config_t {
        inherit_stdout: true,
        inherit_stderr: true,
        inherit_stdin: true,
        args: vec![prog_name.to_owned()],
        env: Vec::new(),
        preopens: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_env(
    config: &mut wasi_config_t,
    key: *const c_char,
    value: *const c_char,
) {
    debug_assert!(!key.is_null());
    debug_assert!(!value.is_null());

    let key_cstr = unsafe { CStr::from_ptr(key) };
    let key_bytes = key_cstr.to_bytes();
    let value_cstr = unsafe { CStr::from_ptr(value) };
    let value_bytes = value_cstr.to_bytes();

    let key = String::from_utf8_lossy(key_bytes).into_owned();
    if let Some((_, value)) = config.env.iter_mut().find(|(existing, _)| existing == &key) {
        *value = value_bytes.to_vec();
    } else {
        config.env.push((key, value_bytes.to_vec()));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_arg(config: &mut wasi_config_t, arg: *const c_char) {
    debug_assert!(!arg.is_null());

    let arg_cstr = unsafe { CStr::from_ptr(arg) };
    let arg_bytes = arg_cstr.to_bytes();

    config
        .args
        .push(String::from_utf8_lossy(arg_bytes).into_owned());
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_preopen_dir(
    config: &mut wasi_config_t,
    dir: *const c_char,
) -> bool {
    let dir_cstr = unsafe { CStr::from_ptr(dir) };
    let dir_bytes = dir_cstr.to_bytes();
    let dir_str = match std::str::from_utf8(dir_bytes) {
        Ok(dir_str) => dir_str,
        Err(e) => {
            update_last_error(e);
            return false;
        }
    };

    config.preopens.push(Preopen {
        host: dir_str.to_owned(),
        alias: None,
    });

    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_mapdir(
    config: &mut wasi_config_t,
    alias: *const c_char,
    dir: *const c_char,
) -> bool {
    let alias_cstr = unsafe { CStr::from_ptr(alias) };
    let alias_bytes = alias_cstr.to_bytes();
    let alias_str = match std::str::from_utf8(alias_bytes) {
        Ok(alias_str) => alias_str,
        Err(e) => {
            update_last_error(e);
            return false;
        }
    };

    let dir_cstr = unsafe { CStr::from_ptr(dir) };
    let dir_bytes = dir_cstr.to_bytes();
    let dir_str = match std::str::from_utf8(dir_bytes) {
        Ok(dir_str) => dir_str,
        Err(e) => {
            update_last_error(e);
            return false;
        }
    };

    config.preopens.push(Preopen {
        host: dir_str.to_owned(),
        alias: Some(alias_str.trim_start_matches('/').to_owned()),
    });

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_config_capture_stdout(config: &mut wasi_config_t) {
    config.inherit_stdout = false;
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_config_inherit_stdout(config: &mut wasi_config_t) {
    config.inherit_stdout = true;
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_config_capture_stderr(config: &mut wasi_config_t) {
    config.inherit_stderr = false;
}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_config_inherit_stderr(config: &mut wasi_config_t) {
    config.inherit_stderr = true;
}

//#[unsafe(no_mangle)]
//pub extern "C" fn wasi_config_capture_stdin(config: &mut wasi_config_t) {
//    config.inherit_stdin = false;
//}

#[unsafe(no_mangle)]
pub extern "C" fn wasi_config_inherit_stdin(config: &mut wasi_config_t) {
    config.inherit_stdin = true;
}

#[allow(non_camel_case_types)]
pub struct wasi_env_t {
    /// cbindgen:ignore
    pub(super) inner: WasiBackend,
    pub(super) store: StoreRef,
}

pub(super) enum WasiBackend {
    #[cfg(feature = "v8")]
    Legacy(WasiFunctionEnv),
    #[cfg(feature = "sys")]
    Native(native::NativeWasi),
}

impl WasiBackend {
    pub(super) fn import_object(
        &self,
        store: &mut wasmer_api::StoreMut<'_>,
        module: &wasmer_api::Module,
    ) -> anyhow::Result<wasmer_api::Imports> {
        match self {
            #[cfg(feature = "v8")]
            Self::Legacy(env) => Ok(env.import_object(store, module)?),
            #[cfg(feature = "sys")]
            Self::Native(env) => env.import_object(store, module),
        }
    }

    fn build_memory(
        &self,
        store: &mut wasmer_api::StoreMut<'_>,
        module: &wasmer_api::Module,
    ) -> anyhow::Result<Option<wasmer_api::Memory>> {
        let ty = module
            .imports()
            .memories()
            .next()
            .map(|memory| *memory.ty());
        match self {
            #[cfg(feature = "v8")]
            Self::Legacy(env) => {
                let spawn = match ty {
                    Some(ty) => wasmer_wasix::runtime::SpawnType::CreateMemoryOfType(ty),
                    None => wasmer_wasix::runtime::SpawnType::CreateMemory,
                };
                let tasks = env.data(store).runtime.task_manager().clone();
                Ok(tasks.build_memory(store, spawn)?)
            }
            #[cfg(feature = "sys")]
            Self::Native(_) => Ok(Some(wasmer_api::Memory::new(
                store,
                ty.unwrap_or_else(|| wasmer_api::MemoryType::new(1u32, None, false)),
            )?)),
        }
    }

    pub(super) fn tag_import(&self, value: &mut wasm_extern_t) {
        match self {
            #[cfg(feature = "sys")]
            Self::Native(native) => {
                if matches!(value.inner, wasmer_api::Extern::Function(_)) {
                    value.wasi_origin = Some(native.environment().clone());
                }
            }
            #[cfg(feature = "v8")]
            Self::Legacy(_) => {}
        }
    }

    fn initialize(
        &mut self,
        store: &mut wasmer_api::StoreMut<'_>,
        instance: wasmer_api::Instance,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(feature = "v8")]
            Self::Legacy(env) => Ok(env.initialize(store, instance)?),
            #[cfg(feature = "sys")]
            Self::Native(env) => env.initialize(store, &instance),
        }
    }

    fn on_exit(&mut self, _store: &mut wasmer_api::StoreMut<'_>) {
        match self {
            #[cfg(feature = "v8")]
            Self::Legacy(env) => {
                env.on_exit(_store, None);
            }
            #[cfg(feature = "sys")]
            Self::Native(env) => env.close(),
        }
    }
}

/// Create a new WASI environment.
///
/// It take ownership over the `wasi_config_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_new(
    store: Option<&mut wasm_store_t>,
    config: Box<wasi_config_t>,
) -> Option<Box<wasi_env_t>> {
    let store = &mut store?.inner;
    #[cfg(feature = "sys")]
    if store.is_native() {
        let env = c_try!(native::NativeWasi::new(
            store,
            config.args.clone(),
            config.env.clone(),
            config
                .preopens
                .iter()
                .map(|preopen| (preopen.announced().to_owned(), preopen.host.clone()))
                .collect(),
            !config.inherit_stdout,
            !config.inherit_stderr,
        ));
        return Some(Box::new(wasi_env_t {
            inner: WasiBackend::Native(env),
            store: store.clone(),
        }));
    }

    #[cfg(feature = "v8")]
    {
        let env = c_try!(legacy_environment(store, *config));
        return Some(Box::new(wasi_env_t {
            inner: WasiBackend::Legacy(env),
            store: store.clone(),
        }));
    }
    #[cfg(not(feature = "v8"))]
    {
        update_last_error("this C API build has no WASI backend for the Store");
        None
    }
}

#[cfg(feature = "v8")]
fn legacy_environment(store: &StoreRef, config: wasi_config_t) -> anyhow::Result<WasiFunctionEnv> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();
    let _guard = handle.enter();
    let mut builder = WasiEnv::builder(&config.args[0]).fs(default_fs_backing());
    builder.add_args(config.args.iter().skip(1));
    builder.add_envs(config.env);
    for preopen in config.preopens {
        match preopen.alias {
            Some(alias) => builder.add_map_dir(&alias, preopen.host)?,
            None => builder.add_preopen_dir(preopen.host)?,
        }
    }
    let mut rt = PluggableRuntime::new(Arc::new(TokioTaskManager::new(runtime)));
    rt.set_engine(store.with_mut(|store| store.engine().clone())?);
    if !config.inherit_stdout {
        builder.set_stdout(Box::new(Pipe::new()));
    }
    if !config.inherit_stderr {
        builder.set_stderr(Box::new(Pipe::new()));
    }
    Ok(store.with_mut(|store| builder.runtime(Arc::new(rt)).finalize(store))??)
}

/// Delete a [`wasi_env_t`].
#[unsafe(no_mangle)]
pub extern "C" fn wasi_env_delete(state: Option<Box<wasi_env_t>>) {
    if let Some(mut env) = state {
        let store = env.store.clone();
        c_try!(store.with_mut(|store| env.inner.on_exit(store)); otherwise ());
    }
}

/// Set the memory on a [`wasi_env_t`].
// NOTE: Only here to not break the C API.
// This was previously supported, but is no longer possible due to WASIX changes.
// Customizing memories should be done through the builder or the runtime.
#[unsafe(no_mangle)]
#[deprecated(since = "4.0.0")]
pub unsafe extern "C" fn wasi_env_set_memory(_env: &mut wasi_env_t, _memory: &wasm_memory_t) {
    panic!("wasmer_env_set_memory() is not supported");
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_read_stdout(
    env: &mut wasi_env_t,
    buffer: *mut c_char,
    buffer_len: usize,
) -> isize {
    let inner_buffer = unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len) };

    match &env.inner {
        #[cfg(feature = "sys")]
        WasiBackend::Native(native) => native.read(false, inner_buffer),
        #[cfg(feature = "v8")]
        WasiBackend::Legacy(legacy) => {
            let stdout =
                c_try!(env.store.with_mut(|store| legacy.data(store).stdout()); otherwise -1);

            if let Ok(mut stdout) = stdout {
                if let Some(stdout) = stdout.as_mut() {
                    read_inner(stdout, inner_buffer)
                } else {
                    update_last_error("could not find a file handle for `stdout`");
                    -1
                }
            } else {
                update_last_error("could not find a file handle for `stdout`");
                -1
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_read_stderr(
    env: &mut wasi_env_t,
    buffer: *mut c_char,
    buffer_len: usize,
) -> isize {
    let inner_buffer = unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len) };
    match &env.inner {
        #[cfg(feature = "sys")]
        WasiBackend::Native(native) => native.read(true, inner_buffer),
        #[cfg(feature = "v8")]
        WasiBackend::Legacy(legacy) => {
            let stderr =
                c_try!(env.store.with_mut(|store| legacy.data(store).stderr()); otherwise -1);
            if let Ok(mut stderr) = stderr {
                if let Some(stderr) = stderr.as_mut() {
                    read_inner(stderr, inner_buffer)
                } else {
                    update_last_error("could not find a file handle for `stderr`");
                    -1
                }
            } else {
                update_last_error("could not find a file handle for `stderr`");
                -1
            }
        }
    }
}

#[cfg(feature = "v8")]
fn read_inner(
    wasi_file: &mut Box<dyn VirtualFile + Send + Sync + 'static>,
    inner_buffer: &mut [u8],
) -> isize {
    block_on(async {
        match wasi_file.read(inner_buffer).await {
            Ok(a) => a as isize,
            Err(err) => {
                update_last_error(format!("failed to read wasi_file: {err}"));
                -1
            }
        }
    })
}

/// The version of WASI. This is determined by the imports namespace
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum wasi_version_t {
    /// An invalid version.
    INVALID_VERSION = -1,

    /// Latest version.
    ///
    /// It's a “floating” version, i.e. it's an alias to the latest
    /// version (for the moment, `Snapshot1`). Using this version is a
    /// way to ensure that modules will run only if they come with the
    /// latest WASI version (in case of security issues for instance),
    /// by just updating the runtime.
    ///
    /// Note that this version is never returned by an API. It is
    /// provided only by the user.
    LATEST = 0,

    /// `wasi_unstable`.
    SNAPSHOT0 = 1,

    /// `wasi_snapshot_preview1`.
    SNAPSHOT1 = 2,

    /// `wasix_32v1`.
    WASIX32V1 = 3,

    /// `wasix_64v1`.
    WASIX64V1 = 4,
}

fn get_wasi_version(module: &wasmer_api::Module) -> Option<wasi_version_t> {
    module
        .imports()
        .functions()
        .find_map(|import| match import.module() {
            "wasi_unstable" => Some(wasi_version_t::SNAPSHOT0),
            "wasi_snapshot_preview1" => Some(wasi_version_t::SNAPSHOT1),
            "wasix_32v1" => Some(wasi_version_t::WASIX32V1),
            "wasix_64v1" => Some(wasi_version_t::WASIX64V1),
            _ => None,
        })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_get_wasi_version(module: &wasm_module_t) -> wasi_version_t {
    get_wasi_version(&module.inner).unwrap_or(wasi_version_t::INVALID_VERSION)
}

/// Non-standard function to get the imports needed for the WASI
/// implementation ordered as expected by the `wasm_module_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_get_imports(
    _store: Option<&wasm_store_t>,
    wasi_env: Option<&mut wasi_env_t>,
    module: Option<&wasm_module_t>,
    imports: &mut wasm_extern_vec_t,
) -> bool {
    unsafe { wasi_get_imports_inner(wasi_env, module, imports) }.is_some()
}

unsafe fn wasi_get_imports_inner(
    wasi_env: Option<&mut wasi_env_t>,
    module: Option<&wasm_module_t>,
    imports: &mut wasm_extern_vec_t,
) -> Option<()> {
    let wasi_env = wasi_env?;
    let store = &mut wasi_env.store;
    let module = module?;

    let mut import_object =
        c_try!(c_try!(store.with_mut(|store| {
            wasi_env.inner.import_object(store, &module.inner)
        })));

    let memory =
        c_try!(store.with_mut(|store| wasi_env.inner.build_memory(store, &module.inner))).unwrap();

    if let Some(memory) = memory {
        import_object.define("env", "memory", memory);
    }

    imports_set_buffer(store, &module.inner, import_object, imports)?;
    let values = imports
        .take()
        .into_iter()
        .map(|value| {
            value.map(|mut value| {
                wasi_env.inner.tag_import(&mut value);
                value
            })
        })
        .collect::<Vec<_>>();
    imports.set_buffer(values);
    Some(())
}

pub(crate) fn imports_set_buffer(
    store: &StoreRef,
    module: &wasmer_api::Module,
    import_object: wasmer_api::Imports,
    imports: &mut wasm_extern_vec_t,
) -> Option<()> {
    imports.set_buffer(c_try!(
        module
            .imports()
            .map(|import_type| {
                let ext = import_object
                    .get_export(import_type.module(), import_type.name())
                    .ok_or_else(|| {
                        format!(
                            "Failed to resolve import \"{}\" \"{}\"",
                            import_type.module(),
                            import_type.name()
                        )
                    })?;

                Ok(Some(Box::new(wasm_extern_t::new(store.clone(), ext))))
            })
            .collect::<Result<Vec<_>, String>>()
    ));

    Some(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_initialize_instance(
    wasi_env: &mut wasi_env_t,
    store: &mut wasm_store_t,
    instance: &mut wasm_instance_t,
) -> bool {
    c_try!(c_try!(store.inner.with_mut(|store| wasi_env.inner.initialize(store, instance.inner.clone())); otherwise false); otherwise false);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_get_start_function(
    instance: &mut wasm_instance_t,
) -> Option<Box<wasm_func_t>> {
    let start = c_try!(instance.inner.exports.get_function("_start"));

    Some(Box::new(wasm_func_t {
        extern_: wasm_extern_t::new(instance.store.clone(), start.clone().into()),
    }))
}

#[cfg(test)]
mod tests {
    use inline_c::assert_c;

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_get_wasi_version_snapshot0() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasmer_funcenv_t* env = wasmer_funcenv_new(store, 0);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(&wat, "(module (import \"wasi_unstable\" \"args_get\" (func (param i32 i32) (result i32))))");
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);

                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                assert(wasi_get_wasi_version(module) == SNAPSHOT0);

                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasmer_funcenv_delete(env);
                wasm_store_delete(store);
                wasm_engine_delete(engine);

                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_get_wasi_version_snapshot1() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasmer_funcenv_t* env = wasmer_funcenv_new(store, 0);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(&wat, "(module (import \"wasi_snapshot_preview1\" \"args_get\" (func (param i32 i32) (result i32))))");
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);

                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                assert(wasi_get_wasi_version(module) == SNAPSHOT1);

                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasmer_funcenv_delete(env);
                wasm_store_delete(store);
                wasm_engine_delete(engine);

                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_get_wasi_version_invalid() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasmer_funcenv_t* env = wasmer_funcenv_new(store, 0);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(&wat, "(module (import \"wasi_snpsht_prvw1\" \"args_get\" (func (param i32 i32) (result i32))))");
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);

                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                assert(wasi_get_wasi_version(module) == INVALID_VERSION);

                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasmer_funcenv_delete(env);
                wasm_store_delete(store);
                wasm_engine_delete(engine);

                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_instance_initialization_is_host_only_and_reactor_calls_return() {
        (assert_c! {
            #include "tests/wasmer.h"

            static int name_is(const wasm_name_t* name, const char* expected) {
                return name && name->size == strlen(expected) &&
                    memcmp(name->data, expected, name->size) == 0;
            }

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    "  (import \"wasi_snapshot_preview1\" \"args_get\" (func (param i32 i32) (result i32)))\n"
                    "  (import \"env\" \"memory\" (memory 1 2 shared))\n"
                    "  (export \"memory\" (memory 0))\n"
                    "  (global $state (mut i32) (i32.const 0))\n"
                    "  (func (export \"_initialize\")\n"
                    "    global.get $state\n"
                    "    i32.const 10\n"
                    "    i32.add\n"
                    "    global.set $state)\n"
                    "  (func (export \"_start\") (result i32)\n"
                    "    global.get $state\n"
                    "    i32.const 1\n"
                    "    i32.add\n"
                    "    global.set $state\n"
                    "    global.get $state))"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                wasi_config_t* config = wasi_config_new("reactor");
                wasi_env_t* wasi_env = wasi_env_new(store, config);
                assert(wasi_env);

                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                wasmer_named_extern_vec_t unordered = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, wasi_env, module, &imports));
                assert(wasi_get_unordered_imports(wasi_env, module, &unordered));
                assert(imports.size == 2);
                assert(unordered.size > imports.size);

                int saw_args_get = 0;
                int saw_args_sizes_get = 0;
                int saw_wasi_thread_spawn = 0;
                int saw_env_memory = 0;
                for (size_t i = 0; i < unordered.size; ++i) {
                    const wasm_name_t* module_name = wasmer_named_extern_module(unordered.data[i]);
                    const wasm_name_t* name = wasmer_named_extern_name(unordered.data[i]);
                    saw_args_get |= name_is(module_name, "wasi_snapshot_preview1") &&
                        name_is(name, "args_get");
                    saw_args_sizes_get |= name_is(module_name, "wasi_snapshot_preview1") &&
                        name_is(name, "args_sizes_get");
                    saw_wasi_thread_spawn |= name_is(module_name, "wasi") &&
                        name_is(name, "thread-spawn");
                    saw_env_memory |= name_is(module_name, "env") && name_is(name, "memory");
                }
                assert(saw_args_get);
                assert(saw_args_sizes_get);
                assert(saw_wasi_thread_spawn);
                assert(!saw_env_memory);

                wasm_instance_t* instance = wasm_instance_new(store, module, &imports, NULL);
                assert(instance);
                assert(wasi_env_initialize_instance(wasi_env, store, instance));

                wasm_func_t* start = wasi_get_start_function(instance);
                assert(start);
                wasm_val_vec_t arguments = WASM_EMPTY_VEC;
                wasm_val_t first_result[1] = { WASM_INIT_VAL };
                wasm_val_vec_t first_results = WASM_ARRAY_VEC(first_result);
                assert(wasm_func_call(start, &arguments, &first_results) == NULL);
                assert(first_result[0].kind == WASM_I32);
                assert(first_result[0].of.i32 == 1);

                wasm_val_t second_result[1] = { WASM_INIT_VAL };
                wasm_val_vec_t second_results = WASM_ARRAY_VEC(second_result);
                assert(wasm_func_call(start, &arguments, &second_results) == NULL);
                assert(second_result[0].kind == WASM_I32);
                assert(second_result[0].of.i32 == 2);

                wasm_func_delete(start);
                wasm_instance_delete(instance);
                wasm_extern_vec_delete(&imports);
                wasmer_named_extern_vec_delete(&unordered);
                wasi_env_delete(wasi_env);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_attaches_an_ordinary_same_store_instance_and_keeps_pure_functions_alive() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasi_config_t* config = wasi_config_new("ordinary-instance");
                wasi_env_t* wasi_env = wasi_env_new(store, config);
                assert(wasi_env);

                // No WASI imports, no import getter, no _start, and no memory-name convention.
                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    "  (memory (export \"backing\") 1)\n"
                    "  (data (i32.const 0) \"\\2a\\00\\00\\00\")\n"
                    "  (func (export \"read\") (result i32) i32.const 0 i32.load))"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);
                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                wasm_instance_t* instance = wasm_instance_new(store, module, &imports, NULL);
                assert(instance);
                assert(wasi_env_initialize_instance(wasi_env, store, instance));
                assert(wasi_env_initialize_instance(wasi_env, store, instance));

                wasm_extern_vec_t exports = WASM_EMPTY_VEC;
                wasm_instance_exports(instance, &exports);
                assert(exports.size == 2);
                assert(wasm_extern_kind(exports.data[0]) == WASM_EXTERN_MEMORY);
                wasm_func_t* read = wasm_extern_as_func(exports.data[1]);
                assert(read);
                wasm_func_t* copied = wasm_func_copy(read);
                assert(copied);
                wasm_val_vec_t arguments = WASM_EMPTY_VEC;
                wasm_val_t result[1] = { WASM_INIT_VAL };
                wasm_val_vec_t results = WASM_ARRAY_VEC(result);
                assert(wasm_func_call(copied, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 42);

                wasi_env_delete(wasi_env);
                result[0].of.i32 = 0;
                assert(wasm_func_call(read, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 42);
                result[0].of.i32 = 0;
                assert(wasm_func_call(copied, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 42);

                wasm_func_delete(copied);
                wasm_extern_vec_delete(&exports);
                wasm_instance_delete(instance);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_environments_are_independent_in_one_store() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_write\" (func $fd_write (param i32 i32 i32 i32) (result i32)))\n"
                    "  (memory (export \"memory\") 1)\n"
                    "  (data (i32.const 32) \"A\")\n"
                    "  (data (i32.const 40) \"B\")\n"
                    "  (func (export \"_start\") (param $which i32) (result i32)\n"
                    "    i32.const 0\n"
                    "    local.get $which\n"
                    "    if (result i32)\n"
                    "      i32.const 40\n"
                    "    else\n"
                    "      i32.const 32\n"
                    "    end\n"
                    "    i32.store\n"
                    "    i32.const 4\n"
                    "    i32.const 1\n"
                    "    i32.store\n"
                    "    i32.const 1\n"
                    "    i32.const 0\n"
                    "    i32.const 1\n"
                    "    i32.const 8\n"
                    "    call $fd_write))"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                wasi_config_t* config_a = wasi_config_new("env-a");
                wasi_config_t* config_b = wasi_config_new("env-b");
                wasi_config_capture_stdout(config_a);
                wasi_config_capture_stdout(config_b);
                wasi_env_t* env_a = wasi_env_new(store, config_a);
                wasi_env_t* env_b = wasi_env_new(store, config_b);
                assert(env_a && env_b);

                wasm_extern_vec_t imports_a = WASM_EMPTY_VEC;
                wasm_extern_vec_t imports_b = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, env_a, module, &imports_a));
                assert(wasi_get_imports(store, env_b, module, &imports_b));
                assert(imports_a.size == 1 && imports_b.size == 1);

                wasm_instance_t* instance_a = wasm_instance_new(store, module, &imports_a, NULL);
                wasm_instance_t* instance_b = wasm_instance_new(store, module, &imports_b, NULL);
                assert(instance_a && instance_b);
                assert(wasi_env_initialize_instance(env_a, store, instance_a));
                assert(wasi_env_initialize_instance(env_b, store, instance_b));

                wasm_func_t* start_a = wasi_get_start_function(instance_a);
                wasm_func_t* start_b = wasi_get_start_function(instance_b);
                assert(start_a && start_b);
                wasm_val_t arg_a[1] = { WASM_I32_VAL(0) };
                wasm_val_t arg_b[1] = { WASM_I32_VAL(1) };
                wasm_val_t result_a[1] = { WASM_INIT_VAL };
                wasm_val_t result_b[1] = { WASM_INIT_VAL };
                wasm_val_vec_t args_a = WASM_ARRAY_VEC(arg_a);
                wasm_val_vec_t args_b = WASM_ARRAY_VEC(arg_b);
                wasm_val_vec_t results_a = WASM_ARRAY_VEC(result_a);
                wasm_val_vec_t results_b = WASM_ARRAY_VEC(result_b);
                assert(wasm_func_call(start_a, &args_a, &results_a) == NULL);
                assert(wasm_func_call(start_b, &args_b, &results_b) == NULL);
                assert(result_a[0].of.i32 == 0 && result_b[0].of.i32 == 0);

                char output_a[4] = {0};
                char output_b[4] = {0};
                assert(wasi_env_read_stdout(env_a, output_a, sizeof(output_a)) == 1);
                assert(wasi_env_read_stdout(env_b, output_b, sizeof(output_b)) == 1);
                assert(output_a[0] == 'A');
                assert(output_b[0] == 'B');

                wasm_func_delete(start_a);
                wasm_func_delete(start_b);
                wasm_instance_delete(instance_a);
                wasm_instance_delete(instance_b);
                wasm_extern_vec_delete(&imports_a);
                wasm_extern_vec_delete(&imports_b);
                wasi_env_delete(env_a);
                wasi_env_delete(env_b);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_reinitializing_one_environment_uses_the_latest_instance_memory() {
        (assert_c! {
            #include "tests/wasmer.h"

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_write\" (func $fd_write (param i32 i32 i32 i32) (result i32)))\n"
                    "  (import \"env\" \"memory\" (memory 1 2 shared))\n"
                    "  (export \"memory\" (memory 0))\n"
                    "  (data (i32.const 32) \"A\")\n"
                    "  (func (export \"_start\") (param $prepare i32) (result i32)\n"
                    "    local.get $prepare\n"
                    "    i32.eqz\n"
                    "    if\n"
                    "    else\n"
                    "      i32.const 0\n"
                    "      i32.const 32\n"
                    "      i32.store\n"
                    "      i32.const 4\n"
                    "      i32.const 1\n"
                    "      i32.store\n"
                    "    end\n"
                    "    local.get $prepare\n"
                    "    i32.const 2\n"
                    "    i32.eq\n"
                    "    if\n"
                    "      i32.const 32\n"
                    "      i32.const 90\n"
                    "      i32.store8\n"
                    "    end\n"
                    "    i32.const 1\n"
                    "    i32.const 0\n"
                    "    i32.const 1\n"
                    "    i32.const 8\n"
                    "    call $fd_write))"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                wasi_config_t* config = wasi_config_new("imports");
                wasi_config_capture_stdout(config);
                wasi_env_t* wasi_env = wasi_env_new(store, config);
                assert(wasi_env);

                wasm_extern_vec_t imports_a = WASM_EMPTY_VEC;
                wasm_extern_vec_t imports_b = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, wasi_env, module, &imports_a));
                assert(wasi_get_imports(store, wasi_env, module, &imports_b));
                assert(imports_a.size == 2 && imports_b.size == 2);

                wasm_instance_t* instance_a = wasm_instance_new(store, module, &imports_a, NULL);
                wasm_instance_t* instance_b = wasm_instance_new(store, module, &imports_b, NULL);
                assert(instance_a && instance_b);

                wasm_extern_vec_t exports_a = WASM_EMPTY_VEC;
                wasm_extern_vec_t exports_b = WASM_EMPTY_VEC;
                wasm_instance_exports(instance_a, &exports_a);
                wasm_instance_exports(instance_b, &exports_b);
                assert(exports_a.size == 2 && exports_b.size == 2);
                assert(wasm_extern_kind(exports_a.data[0]) == WASM_EXTERN_MEMORY);
                assert(wasm_extern_kind(exports_b.data[0]) == WASM_EXTERN_MEMORY);
                const wasm_memory_t* memory_a = wasm_extern_as_memory(exports_a.data[0]);
                const wasm_memory_t* memory_b = wasm_extern_as_memory(exports_b.data[0]);
                assert(memory_a && memory_b);
                assert(!wasm_memory_same(memory_a, memory_b));

                assert(wasi_env_initialize_instance(wasi_env, store, instance_a));
                wasm_func_t* start_a = wasi_get_start_function(instance_a);
                wasm_func_t* start_b = wasi_get_start_function(instance_b);
                assert(start_a && start_b);

                wasm_val_t arg[1] = { WASM_I32_VAL(1) };
                wasm_val_t result[1] = { WASM_INIT_VAL };
                wasm_val_vec_t arguments = WASM_ARRAY_VEC(arg);
                wasm_val_vec_t results = WASM_ARRAY_VEC(result);
                char output[8] = {0};
                assert(wasm_func_call(start_a, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 0);

                assert(wasi_env_initialize_instance(wasi_env, store, instance_b));
                arg[0].of.i32 = 2;
                assert(wasm_func_call(start_b, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 0);
                arg[0].of.i32 = 0;
                assert(wasm_func_call(start_a, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 0);

                // The old instance still reaches the shared env's latest memory.
                size_t received = 0;
                while (received < 3) {
                    intptr_t count = wasi_env_read_stdout(
                        wasi_env, output + received, 3 - received
                    );
                    assert(count > 0);
                    assert((size_t)count <= 3 - received);
                    received += (size_t)count;
                }
                assert(output[0] == 'A' && output[1] == 'Z' && output[2] == 'Z');

                assert(wasi_env_initialize_instance(wasi_env, store, instance_a));
                assert(wasm_func_call(start_a, &arguments, &results) == NULL);
                assert(result[0].of.i32 == 0);
                assert(wasi_env_read_stdout(wasi_env, output, sizeof(output)) == 1);
                assert(output[0] == 'A');

                wasm_extern_vec_delete(&exports_a);
                wasm_extern_vec_delete(&exports_b);

                wasm_func_delete(start_a);
                wasm_func_delete(start_b);
                wasm_instance_delete(instance_a);
                wasm_instance_delete(instance_b);
                wasm_extern_vec_delete(&imports_a);
                wasm_extern_vec_delete(&imports_b);
                wasi_env_delete(wasi_env);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_legacy_virtual_root_and_preopen_descriptor_contract() {
        (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdlib.h>
            #include <sys/stat.h>
            #include <unistd.h>

            static uint32_t load_u32(const uint8_t* data, size_t offset) {
                return (uint32_t)data[offset] |
                    ((uint32_t)data[offset + 1] << 8) |
                    ((uint32_t)data[offset + 2] << 16) |
                    ((uint32_t)data[offset + 3] << 24);
            }

            static uint64_t load_u64(const uint8_t* data, size_t offset) {
                return (uint64_t)load_u32(data, offset) |
                    ((uint64_t)load_u32(data, offset + 4) << 32);
            }

            static void assert_guest_probe(
                wasm_store_t* store,
                wasm_module_t* module,
                wasi_env_t* wasi_env,
                int configured
            ) {
                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, wasi_env, module, &imports));
                wasm_instance_t* instance = wasm_instance_new(
                    store, module, &imports, NULL
                );
                assert(instance);
                assert(wasi_env_initialize_instance(wasi_env, store, instance));

                wasm_func_t* start = wasi_get_start_function(instance);
                assert(start);
                wasm_val_vec_t arguments = WASM_EMPTY_VEC;
                wasm_val_vec_t results = WASM_EMPTY_VEC;
                assert(wasm_func_call(start, &arguments, &results) == NULL);

                wasm_extern_vec_t exports = WASM_EMPTY_VEC;
                wasm_instance_exports(instance, &exports);
                assert(exports.size == 2);
                assert(wasm_extern_kind(exports.data[0]) == WASM_EXTERN_MEMORY);
                wasm_memory_t* memory = wasm_extern_as_memory(exports.data[0]);
                assert(memory);
                const uint8_t* data = (const uint8_t*)wasm_memory_data(memory);
                assert(data);

                /* fd 3 is the legacy virtual root, with its historical broad rights. */
                assert(load_u32(data, 0) == 0);
                assert(load_u32(data, 4) == 0);
                assert(load_u32(data, 8) == 0);
                assert(load_u32(data, 12) == 0);
                assert(configured ? load_u32(data, 16) > 0 : load_u32(data, 16) == 0);
                assert(load_u32(data, 120) == 1);
                assert(data[320] == '/');
                assert(load_u64(data, 72) == ((UINT64_C(1) << 39) - 1));
                assert(load_u64(data, 80) == ((UINT64_C(1) << 39) - 1));

                if (configured) {
                    const char* first_alias = "same//path";
                    const char* second_alias = "same/path";
                    const uint64_t mapped_rights = (UINT64_C(1) << 29) - 1;

                    /* The builder strips only leading slashes. These remain two names. */
                    assert(load_u32(data, 20) == 0);
                    assert(load_u32(data, 24) == 0);
                    assert(load_u32(data, 28) == 0);
                    assert(load_u32(data, 32) == 0);
                    assert(load_u32(data, 36) == 0);
                    assert(load_u32(data, 40) == 0);
                    assert(load_u32(data, 124) == strlen(first_alias));
                    assert(load_u32(data, 128) == strlen(second_alias));
                    assert(memcmp(data + 336, first_alias, strlen(first_alias)) == 0);
                    assert(memcmp(data + 352, second_alias, strlen(second_alias)) == 0);
                    assert(load_u64(data, 88) == mapped_rights);
                    assert(load_u64(data, 96) == mapped_rights);
                    assert(load_u64(data, 104) == mapped_rights);
                    assert(load_u64(data, 112) == mapped_rights);
                    assert(load_u32(data, 56) == 0);
                    assert(load_u32(data, 60) == 0);
                    assert(data[64] == 'A');
                    assert(data[65] == 'B');
                } else {
                    /* With no configured preopens, fd 4 and fd 5 do not exist. */
                    assert(load_u32(data, 20) == 8);
                    assert(load_u32(data, 24) == 8);
                    assert(load_u32(data, 28) == 8);
                    assert(load_u32(data, 32) == 8);
                    assert(load_u32(data, 36) == 8);
                    assert(load_u32(data, 40) == 8);
                    assert(load_u32(data, 44) == 76);
                    assert(load_u32(data, 48) == 76);
                    assert(load_u32(data, 52) == 76);
                    assert(load_u32(data, 56) == 8);
                    assert(load_u32(data, 60) == 8);
                }

                wasm_extern_vec_delete(&exports);
                wasm_func_delete(start);
                wasm_instance_delete(instance);
                wasm_extern_vec_delete(&imports);
            }

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);

                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_prestat_get\" (func $prestat_get (param i32 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_prestat_dir_name\" (func $prestat_name (param i32 i32 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_fdstat_get\" (func $fdstat_get (param i32 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_readdir\" (func $readdir (param i32 i32 i32 i64 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"path_open\" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_read\" (func $fd_read (param i32 i32 i32 i32) (result i32)))\n"
                    "  (import \"wasi_snapshot_preview1\" \"fd_close\" (func $fd_close (param i32) (result i32)))\n"
                    "  (memory (export \"memory\") 1)\n"
                    "  (data (i32.const 800) \"proc\")\n"
                    "  (data (i32.const 810) \"dev\")\n"
                    "  (data (i32.const 820) \"tmp\")\n"
                    "  (data (i32.const 830) \"marker\")\n"
                    "  (func $path_status (param $path i32) (param $len i32) (result i32)\n"
                    "    (local $error i32)\n"
                    "    i32.const 3 i32.const 0\n"
                    "    local.get $path local.get $len\n"
                    "    i32.const 0 i64.const 0 i64.const 0 i32.const 0\n"
                    "    i32.const 560 call $path_open\n"
                    "    local.tee $error\n"
                    "    if (result i32)\n"
                    "      local.get $error\n"
                    "    else\n"
                    "      i32.const 560 i32.load call $fd_close\n"
                    "    end)\n"
                    "  (func $read_marker (param $dir i32) (param $out i32) (result i32)\n"
                    "    (local $error i32)\n"
                    "    local.get $dir i32.const 0\n"
                    "    i32.const 830 i32.const 6 i32.const 0\n"
                    "    i64.const 2 i64.const 0 i32.const 0\n"
                    "    i32.const 560 call $path_open\n"
                    "    local.tee $error\n"
                    "    if\n"
                    "      local.get $error return\n"
                    "    end\n"
                    "    i32.const 496 i32.const 640 i32.store\n"
                    "    i32.const 500 i32.const 1 i32.store\n"
                    "    i32.const 564 i32.const 0 i32.store\n"
                    "    i32.const 560 i32.load i32.const 496 i32.const 1 i32.const 564\n"
                    "    call $fd_read local.tee $error\n"
                    "    if\n"
                    "      local.get $error return\n"
                    "    end\n"
                    "    local.get $out i32.const 640 i32.load8_u i32.store8\n"
                    "    i32.const 560 i32.load call $fd_close)\n"
                    "  (func (export \"_start\")\n"
                    "    i32.const 0 i32.const 3 i32.const 256 call $prestat_get i32.store\n"
                    "    i32.const 4 i32.const 3 i32.const 320 i32.const 64 call $prestat_name i32.store\n"
                    "    i32.const 8 i32.const 3 i32.const 400 call $fdstat_get i32.store\n"
                    "    i32.const 72 i32.const 400 i64.load offset=8 i64.store\n"
                    "    i32.const 80 i32.const 400 i64.load offset=16 i64.store\n"
                    "    i32.const 12 i32.const 3 i32.const 700 i32.const 256 i64.const 0 i32.const 544\n"
                    "    call $readdir i32.store\n"
                    "    i32.const 16 i32.const 544 i32.load i32.store\n"
                    "    i32.const 120 i32.const 256 i32.load offset=4 i32.store\n"
                    "    i32.const 20 i32.const 4 i32.const 272 call $prestat_get i32.store\n"
                    "    i32.const 24 i32.const 4 i32.const 336 i32.const 64 call $prestat_name i32.store\n"
                    "    i32.const 28 i32.const 4 i32.const 432 call $fdstat_get i32.store\n"
                    "    i32.const 88 i32.const 432 i64.load offset=8 i64.store\n"
                    "    i32.const 96 i32.const 432 i64.load offset=16 i64.store\n"
                    "    i32.const 124 i32.const 272 i32.load offset=4 i32.store\n"
                    "    i32.const 32 i32.const 5 i32.const 288 call $prestat_get i32.store\n"
                    "    i32.const 36 i32.const 5 i32.const 352 i32.const 64 call $prestat_name i32.store\n"
                    "    i32.const 40 i32.const 5 i32.const 464 call $fdstat_get i32.store\n"
                    "    i32.const 104 i32.const 464 i64.load offset=8 i64.store\n"
                    "    i32.const 112 i32.const 464 i64.load offset=16 i64.store\n"
                    "    i32.const 128 i32.const 288 i32.load offset=4 i32.store\n"
                    "    i32.const 44 i32.const 800 i32.const 4 call $path_status i32.store\n"
                    "    i32.const 48 i32.const 810 i32.const 3 call $path_status i32.store\n"
                    "    i32.const 52 i32.const 820 i32.const 3 call $path_status i32.store\n"
                    "    i32.const 56 i32.const 4 i32.const 64 call $read_marker i32.store\n"
                    "    i32.const 60 i32.const 5 i32.const 65 call $read_marker i32.store))"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                wasi_config_t* empty_config = wasi_config_new("empty");
                wasi_env_t* empty_env = wasi_env_new(store, empty_config);
                assert(empty_env);
                assert_guest_probe(store, module, empty_env, 0);

                char temp_root[] = "/tmp/wasmer-capi-preopens-XXXXXX";
                char* root = mkdtemp(temp_root);
                assert(root);
                char dir_a[512], dir_b[512], file_a[512], file_b[512];
                assert(snprintf(dir_a, sizeof(dir_a), "%s/a", root) > 0);
                assert(snprintf(dir_b, sizeof(dir_b), "%s/b", root) > 0);
                assert(mkdir(dir_a, 0700) == 0);
                assert(mkdir(dir_b, 0700) == 0);
                assert(snprintf(file_a, sizeof(file_a), "%s/marker", dir_a) > 0);
                assert(snprintf(file_b, sizeof(file_b), "%s/marker", dir_b) > 0);
                FILE* marker_a = fopen(file_a, "wb");
                FILE* marker_b = fopen(file_b, "wb");
                assert(marker_a && marker_b);
                assert(fputc('A', marker_a) == 'A');
                assert(fputc('B', marker_b) == 'B');
                assert(fclose(marker_a) == 0);
                assert(fclose(marker_b) == 0);

                wasi_config_t* config = wasi_config_new("mapped");
                /* Legacy normalization strips leading slashes only. */
                assert(wasi_config_mapdir(config, "/same//path", dir_a));
                assert(wasi_config_mapdir(config, "same/path", dir_b));
                wasi_env_t* mapped_env = wasi_env_new(store, config);
                assert(mapped_env);
                assert_guest_probe(store, module, mapped_env, 1);

                wasi_config_t* duplicate = wasi_config_new("duplicate");
                assert(wasi_config_mapdir(duplicate, "duplicate", dir_a));
                assert(wasi_config_mapdir(duplicate, "/duplicate", dir_b));
                assert(wasi_env_new(store, duplicate) == NULL);

                wasi_env_delete(mapped_env);
                wasi_env_delete(empty_env);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);

                assert(unlink(file_a) == 0);
                assert(unlink(file_b) == 0);
                assert(rmdir(dir_a) == 0);
                assert(rmdir(dir_b) == 0);
                assert(rmdir(root) == 0);
                return 0;
            }
        })
        .success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_v2_configured_namespace_keeps_capabilities_private_and_root_errors_exact() {
        (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/stat.h>
            #include <unistd.h>

            typedef struct {
                wasi_env_t* env;
                wasm_instance_t* instance;
                wasm_extern_vec_t imports;
                wasm_extern_vec_t exports;
                uint8_t* data;
                wasm_func_t* functions[9];
            } guest;

            static uint32_t u32(const uint8_t* p) {
                return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            }
            static uint64_t u64(const uint8_t* p) {
                return (uint64_t)u32(p) | ((uint64_t)u32(p + 4) << 32);
            }
            static int invoke(wasm_func_t* function, size_t count, const int32_t* values) {
                wasm_val_t args[6];
                assert(count <= 6);
                for (size_t i = 0; i < count; ++i) args[i] = (wasm_val_t)WASM_I32_VAL(values[i]);
                wasm_val_vec_t arguments = WASM_EMPTY_VEC;
                arguments.size = count;
                arguments.data = args;
                wasm_val_t value[1] = { WASM_INIT_VAL };
                wasm_val_vec_t results = WASM_ARRAY_VEC(value);
                assert(wasm_func_call(function, &arguments, &results) == NULL);
                return value[0].of.i32;
            }
            static int path(guest* g, int function, int fd, const char* name, int option) {
                size_t len = strlen(name);
                assert(len < 192);
                memcpy(g->data + 256, name, len);
                int32_t values[] = { fd, 256, (int32_t)len, option, 0 };
                size_t count = function == 4 ? 3 : 4;
                return invoke(g->functions[function], count, values);
            }
            static int open_path(guest* g, int fd, const char* name, int follow, int flags) {
                size_t len = strlen(name);
                assert(len < 192);
                memcpy(g->data + 256, name, len);
                int32_t values[] = { fd, 256, (int32_t)len, follow, flags };
                return invoke(g->functions[0], 5, values);
            }
            static int pair(guest* g, int function, int oldfd, const char* old,
                            int newfd, const char* new_name) {
                size_t oldlen = strlen(old), newlen = strlen(new_name);
                assert(oldlen < 192 && newlen < 192);
                memcpy(g->data + 256, old, oldlen);
                memcpy(g->data + 512, new_name, newlen);
                int32_t values[] = { oldfd, 256, (int32_t)oldlen, newfd, 512, (int32_t)newlen };
                return invoke(g->functions[function], 6, values);
            }
            static int symlink_status(guest* g, const char* name) {
                size_t len = strlen(name);
                assert(len < 192);
                memcpy(g->data + 256, "marker", 6);
                memcpy(g->data + 512, name, len);
                int32_t values[] = { 256, 6, 3, 512, (int32_t)len };
                return invoke(g->functions[8], 5, values);
            }
            static size_t listing(guest* g, int fd, uint64_t cookie, int limit) {
                wasm_val_t args[] = { WASM_I32_VAL(fd), WASM_I64_VAL(cookie), WASM_I32_VAL(limit) };
                wasm_val_vec_t arguments = WASM_ARRAY_VEC(args);
                wasm_val_t result[] = { WASM_INIT_VAL };
                wasm_val_vec_t results = WASM_ARRAY_VEC(result);
                assert(wasm_func_call(g->functions[2], &arguments, &results) == NULL);
                assert(result[0].of.i32 == 0);
                return u32(g->data + 996);
            }
            static void assert_listing(guest* g, int fd, const char* const* names, size_t count) {
                size_t size = listing(g, fd, 0, 2048), cursor = 0;
                assert(size <= 2048);
                for (size_t i = 0; i < count; ++i) {
                    size_t len = strlen(names[i]);
                    assert(cursor + 24 + len <= size);
                    const uint8_t* record = g->data + 4096 + cursor;
                    assert(u64(record) == i + 1);
                    assert(u32(record + 16) == len && record[20] == 3);
                    assert(memcmp(record + 24, names[i], len) == 0);
                    cursor += 24 + len;
                }
                assert(cursor == size); /* no dots, default mounts or private anchors */
                uint8_t saved[2048];
                memcpy(saved, g->data + 4096, size);
                assert(listing(g, fd, 0, 7) == 7);
                assert(memcmp(saved, g->data + 4096, 7) == 0);
                size_t first = 24 + strlen(names[0]);
                assert(listing(g, fd, 1, 2048) == size - first);
                assert(memcmp(saved + first, g->data + 4096, size - first) == 0);
            }
            static guest attach(wasm_store_t* store, wasm_module_t* module, wasi_config_t* config) {
                guest g = {0};
                g.env = wasi_env_new(store, config);
                assert(g.env);
                assert(wasi_get_imports(store, g.env, module, &g.imports));
                g.instance = wasm_instance_new(store, module, &g.imports, NULL);
                assert(g.instance);
                assert(wasi_env_initialize_instance(g.env, store, g.instance));
                wasm_instance_exports(g.instance, &g.exports);
                assert(g.exports.size == 10);
                g.data = (uint8_t*)wasm_memory_data(wasm_extern_as_memory(g.exports.data[0]));
                assert(g.data);
                for (size_t i = 0; i < 9; ++i) {
                    g.functions[i] = wasm_extern_as_func(g.exports.data[i + 1]);
                    assert(g.functions[i]);
                }
                return g;
            }
            static void retire(guest* g) {
                wasm_extern_vec_delete(&g->exports);
                wasm_instance_delete(g->instance);
                wasm_extern_vec_delete(&g->imports);
                wasi_env_delete(g->env);
            }
            static void write_marker(const char* dir, char value) {
                char name[512];
                assert(snprintf(name, sizeof(name), "%s/marker", dir) > 0);
                FILE* file = fopen(name, "wb");
                assert(file && fputc(value, file) == value && fclose(file) == 0);
            }
            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(&wat,
                "(module\n"
                " (import \"wasi_snapshot_preview1\" \"path_open\" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"fd_read\" (func $read (param i32 i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"fd_close\" (func $close (param i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"fd_readdir\" (func $list (param i32 i32 i32 i64 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_create_directory\" (func $mkdir (param i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_remove_directory\" (func $rmdir (param i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_unlink_file\" (func $unlink (param i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_link\" (func $link (param i32 i32 i32 i32 i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_rename\" (func $rename (param i32 i32 i32 i32 i32 i32) (result i32)))\n"
                " (import \"wasi_snapshot_preview1\" \"path_symlink\" (func $symlink (param i32 i32 i32 i32 i32) (result i32)))\n"
                " (memory (export \"memory\") 1)\n"
                " (func (export \"open\") (param $fd i32) (param $path i32) (param $len i32) (param $follow i32) (param $flags i32) (result i32)\n"
                "   local.get $fd local.get $follow local.get $path local.get $len local.get $flags\n"
                "   i64.const 536870911 i64.const 536870911 i32.const 0 i32.const 768 call $open)\n"
                " (func (export \"read\") (param $fd i32) (param $path i32) (param $len i32) (param $follow i32) (result i32)\n"
                "   (local $err i32) (local $file i32)\n"
                "   local.get $fd local.get $follow local.get $path local.get $len i32.const 0\n"
                "   i64.const 2 i64.const 0 i32.const 0 i32.const 768 call $open local.tee $err\n"
                "   if local.get $err return end\n"
                "   i32.const 768 i32.load local.set $file\n"
                "   i32.const 800 i32.const 820 i32.store\n"
                "   i32.const 804 i32.const 1 i32.store\n"
                "   i32.const 820 i32.const 0 i32.store8\n"
                "   local.get $file i32.const 800 i32.const 1 i32.const 824 call $read local.set $err\n"
                "   local.get $file call $close drop\n"
                "   local.get $err)\n"
                " (func (export \"list\") (param $fd i32) (param $cookie i64) (param $limit i32) (result i32)\n"
                "   local.get $fd i32.const 4096 local.get $limit local.get $cookie i32.const 996 call $list)\n"
                " (func (export \"close\") (param $fd i32) (result i32) local.get $fd call $close)\n"
                " (func (export \"mkdir\") (param $fd i32) (param $path i32) (param $len i32) (result i32)\n"
                "   local.get $fd local.get $path local.get $len call $mkdir)\n"
                " (func (export \"unlink\") (param $fd i32) (param $path i32) (param $len i32) (param $directory i32) (result i32)\n"
                "   local.get $directory if (result i32)\n"
                "     local.get $fd local.get $path local.get $len call $rmdir\n"
                "   else local.get $fd local.get $path local.get $len call $unlink end)\n"
                " (func (export \"link\") (param $oldfd i32) (param $old i32) (param $oldlen i32) (param $newfd i32) (param $new i32) (param $newlen i32) (result i32)\n"
                "   local.get $oldfd i32.const 0 local.get $old local.get $oldlen local.get $newfd local.get $new local.get $newlen call $link)\n"
                " (func (export \"rename\") (param $oldfd i32) (param $old i32) (param $oldlen i32) (param $newfd i32) (param $new i32) (param $newlen i32) (result i32)\n"
                "   local.get $oldfd local.get $old local.get $oldlen local.get $newfd local.get $new local.get $newlen call $rename)\n"
                " (func (export \"symlink\") (param $target i32) (param $targetlen i32) (param $fd i32) (param $path i32) (param $len i32) (result i32)\n"
                "   local.get $target local.get $targetlen local.get $fd local.get $path local.get $len call $symlink))\n"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);
                char base[] = "/tmp/wasmer-capi-private-XXXXXX";
                assert(mkdtemp(base));
                char a[512], b[512], name[512];
                assert(snprintf(a, sizeof(a), "%s/a", base) > 0 && mkdir(a, 0700) == 0);
                assert(snprintf(b, sizeof(b), "%s/b", base) > 0 && mkdir(b, 0700) == 0);
                write_marker(a, 'A');
                write_marker(b, 'B');
                const char* links[] = { "abs-out", "parent-out", "absolute-marker", "relative-marker", "hidden-guess" };
                const char* targets[] = { "/proc/self/status", "../b/marker", "/visible/marker", "marker", "/.wasmer-c-api/preopens/0/marker" };
                for (size_t i = 0; i < 5; ++i) {
                    assert(snprintf(name, sizeof(name), "%s/%s", a, links[i]) > 0);
                    assert(symlink(targets[i], name) == 0);
                }
                wasi_config_t* first = wasi_config_new("private-a");
                assert(wasi_config_mapdir(first, "visible", a));
                assert(wasi_config_mapdir(first, "/same//path", a));
                assert(wasi_config_mapdir(first, "same/path", b));
                guest ga = attach(store, module, first);
                wasi_config_t* second = wasi_config_new("private-b");
                assert(wasi_config_mapdir(second, "other", b));
                guest gb = attach(store, module, second);
                const char* names_a[] = { "/same//path", "/same/path", "/visible" };
                const char* names_b[] = { "/other" };
                assert_listing(&ga, 3, names_a, 3);
                assert_listing(&gb, 3, names_b, 1);
                assert(path(&ga, 1, 5, "marker", 0) == 0 && ga.data[820] == 'A');
                assert(path(&ga, 1, 6, "marker", 0) == 0 && ga.data[820] == 'B');
                assert(path(&gb, 1, 4, "marker", 0) == 0 && gb.data[820] == 'B');
                assert(path(&ga, 1, 4, "missing", 0) == 44);
                const char* denied[] = { "proc", "dev", "tmp", "other/marker", "same/path/marker",
                    ".wasmer-c-api", ".wasmer-c-api/preopens/0", "__wasix_namespace_0", ".namespace/0", "0", "1" };
                for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i)
                    assert(open_path(&ga, 3, denied[i], 1, 0) == 76);
                assert(path(&ga, 1, 4, "../other/marker", 1) == 76);
                assert(path(&ga, 1, 4, "/other/marker", 1) == 76);
                assert(path(&ga, 1, 4, "abs-out", 1) == 76);
                assert(path(&ga, 1, 4, "parent-out", 1) == 76);
                assert(path(&ga, 1, 4, "hidden-guess", 1) == 76);
                assert(path(&ga, 1, 4, "absolute-marker", 1) == 0 && ga.data[820] == 'A');
                assert(path(&ga, 1, 4, "relative-marker", 1) == 0 && ga.data[820] == 'A');
                assert(open_path(&ga, 4, "..", 1, 2) == 0);
                int root_alias = (int)u32(ga.data + 768);
                assert(root_alias > 6);
                assert_listing(&ga, root_alias, names_a, 3);
                int32_t close_arg[] = { root_alias };
                assert(invoke(ga.functions[3], 1, close_arg) == 0);
                /* Structural mutation and an intermediate lookup denial are different verdicts. */
                assert(path(&ga, 4, 3, "new", 0) == 2);
                assert(path(&ga, 5, 3, "visible", 0) == 2);
                assert(path(&ga, 5, 3, "visible", 1) == 2);
                assert(pair(&ga, 6, 4, "marker", 3, "new") == 28);
                assert(pair(&ga, 7, 3, "visible", 3, "renamed") == 76);
                assert(symlink_status(&ga, "new") == 76);
                assert(open_path(&ga, 3, "new", 0, 1) == 76);
                assert(path(&ga, 4, 3, "absent/child", 0) == 76);
                assert(path(&ga, 5, 3, "absent/child", 0) == 76);
                assert(path(&ga, 5, 3, "absent/child", 1) == 76);
                assert(pair(&ga, 6, 4, "marker", 3, "absent/child") == 76);
                assert(pair(&ga, 7, 4, "marker", 3, "absent/child") == 76);
                assert(symlink_status(&ga, "absent/child") == 76);
                assert(open_path(&ga, 3, "visible/created", 0, 1) == 0);
                close_arg[0] = (int32_t)u32(ga.data + 768);
                assert(invoke(ga.functions[3], 1, close_arg) == 0);
                assert(snprintf(name, sizeof(name), "%s/created", a) > 0);
                assert(access(name, F_OK) == 0 && unlink(name) == 0);
                assert_listing(&ga, 3, names_a, 3);
                assert(open_path(&gb, 3, "visible/marker", 1, 0) == 76);
                retire(&ga);
                assert_listing(&gb, 3, names_b, 1);
                assert(path(&gb, 1, 4, "marker", 0) == 0 && gb.data[820] == 'B');
                retire(&gb);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                for (size_t i = 0; i < 5; ++i) {
                    assert(snprintf(name, sizeof(name), "%s/%s", a, links[i]) > 0);
                    assert(unlink(name) == 0);
                }
                assert(snprintf(name, sizeof(name), "%s/marker", a) > 0 && unlink(name) == 0);
                assert(snprintf(name, sizeof(name), "%s/marker", b) > 0 && unlink(name) == 0);
                assert(rmdir(a) == 0 && rmdir(b) == 0 && rmdir(base) == 0);
                return 0;
            }
        }).success();
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_legacy_root_mapping_and_path_resolution_contract() {
        let output = (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/stat.h>
            #include <unistd.h>

            static uint32_t read_u32(const uint8_t* data, size_t offset) {
                return (uint32_t)data[offset] |
                    ((uint32_t)data[offset + 1] << 8) |
                    ((uint32_t)data[offset + 2] << 16) |
                    ((uint32_t)data[offset + 3] << 24);
            }

            static uint64_t read_u64(const uint8_t* data, size_t offset) {
                return (uint64_t)read_u32(data, offset) |
                    ((uint64_t)read_u32(data, offset + 4) << 32);
            }

            static void write_byte(const char* path, char value) {
                FILE* file = fopen(path, "wb");
                assert(file);
                assert(fputc(value, file) == value);
                assert(fclose(file) == 0);
            }

            static void assert_preopen_name(
                const uint8_t* data,
                uint32_t fd,
                uint32_t status,
                const char* expected
            ) {
                size_t record = 4000 + (size_t)(fd - 3) * 80;
                assert(read_u32(data, record) == status);
                if (status != 0) {
                    return;
                }
                size_t expected_len = strlen(expected);
                assert(read_u32(data, record + 4) == 0);
                assert(read_u32(data, record + 8) == expected_len);
                assert(memcmp(data + record + 12, expected, expected_len) == 0);
            }

            static void assert_open_record(
                const uint8_t* data,
                uint32_t index,
                uint32_t status,
                uint64_t inode
            ) {
                size_t record = 10000 + (size_t)index * 32;
                assert(read_u32(data, record) == status);
                if (status == 0) {
                    assert(read_u32(data, record + 4) == 0);
                    assert(read_u64(data, record + 8) == inode);
                }
            }

            static void assert_read_record(
                const uint8_t* data,
                uint32_t index,
                uint32_t open_status,
                char value
            ) {
                size_t record = 12000 + (size_t)index * 32;
                assert(read_u32(data, record) == open_status);
                if (open_status == 0) {
                    assert(read_u32(data, record + 4) == 0);
                    assert(read_u32(data, record + 16) == 0);
                    assert(read_u32(data, record + 20) == 1);
                    assert(data[record + 24] == (uint8_t)value);
                }
            }

            static void run_probe(
                wasm_store_t* store,
                wasm_module_t* module,
                wasi_config_t* config,
                int map_root_alias,
                const char* root_path
            ) {
                wasi_env_t* wasi_env = wasi_env_new(store, config);
                assert(wasi_env);

                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, wasi_env, module, &imports));
                wasm_instance_t* instance = wasm_instance_new(
                    store, module, &imports, NULL
                );
                assert(instance);
                assert(wasi_env_initialize_instance(wasi_env, store, instance));

                wasm_extern_vec_t exports = WASM_EMPTY_VEC;
                wasm_instance_exports(instance, &exports);
                assert(exports.size == 2);
                assert(wasm_extern_kind(exports.data[0]) == WASM_EXTERN_MEMORY);
                wasm_memory_t* memory = wasm_extern_as_memory(exports.data[0]);
                assert(memory);
                uint8_t* data = (uint8_t*)wasm_memory_data(memory);
                assert(data);

                char root_marker[512];
                char root_named_marker[512];
                char missing_path[512];
                char relative_root_marker[512];
                char relative_named_marker[512];
                const char* root_leaf = strrchr(root_path, '/');
                assert(root_leaf);
                root_leaf++;
                assert(snprintf(root_marker, sizeof(root_marker), "%s/marker", root_path) > 0);
                assert(snprintf(
                    root_named_marker,
                    sizeof(root_named_marker),
                    "%s/named/marker",
                    root_path
                ) > 0);
                assert(snprintf(
                    missing_path,
                    sizeof(missing_path),
                    "%s/missing-for-root-contract",
                    root_path
                ) > 0);
                assert(snprintf(
                    relative_root_marker,
                    sizeof(relative_root_marker),
                    "tmp/%s/marker",
                    root_leaf
                ) > 0);
                assert(snprintf(
                    relative_named_marker,
                    sizeof(relative_named_marker),
                    "tmp/%s/named/marker",
                    root_leaf
                ) > 0);

                const char* dynamic_paths[] = {
                    root_marker,
                    root_named_marker,
                    missing_path,
                    relative_root_marker,
                    relative_named_marker,
                };
                const size_t dynamic_offsets[] = { 3000, 3200, 3400, 3600, 3800 };
                const size_t dynamic_lengths[] = { 3500, 3504, 3508, 3512, 3516 };
                for (size_t i = 0; i < sizeof(dynamic_offsets) / sizeof(dynamic_offsets[0]); ++i) {
                    size_t length = strlen(dynamic_paths[i]);
                    assert(length < 180);
                    memcpy(data + dynamic_offsets[i], dynamic_paths[i], length);
                    data[dynamic_offsets[i] + length] = 0;
                    data[dynamic_lengths[i]] = (uint8_t)length;
                    data[dynamic_lengths[i] + 1] = (uint8_t)(length >> 8);
                    data[dynamic_lengths[i] + 2] = (uint8_t)(length >> 16);
                    data[dynamic_lengths[i] + 3] = (uint8_t)(length >> 24);
                }
                data[3520] = (uint8_t)(map_root_alias != 0);

                wasm_func_t* start = wasi_get_start_function(instance);
                assert(start);
                wasm_val_vec_t arguments = WASM_EMPTY_VEC;
                wasm_val_vec_t results = WASM_EMPTY_VEC;
                assert(wasm_func_call(start, &arguments, &results) == NULL);

                fprintf(stderr, "root-probe mode=%s\n", map_root_alias ? "mapdir-root" : "preopen-root");
                for (uint32_t fd = 3; fd <= 6; ++fd) {
                    size_t record = 4000 + (size_t)(fd - 3) * 80;
                    uint32_t status = read_u32(data, record);
                    uint32_t name_len = read_u32(data, record + 8);
                    fprintf(stderr, "prestat fd=%u status=%u name=%.*s len=%u\n",
                        fd, status, (int)name_len, data + record + 12, name_len);
                }
                size_t root_ino = read_u64(data, 4808);
                size_t map_ino = read_u64(data, 4840);
                size_t named_ino = read_u64(data, 4872);
                fprintf(stderr, "fd-inodes root=%llu fd4=%llu fd5=%llu\n",
                    (unsigned long long)root_ino,
                    (unsigned long long)map_ino,
                    (unsigned long long)named_ino);
                uint32_t listing_error = read_u32(data, 4700);
                uint32_t listing_size = read_u32(data, 4704);
                assert(listing_error == 0);
                assert(listing_size <= 2048);
                fprintf(stderr, "root-listing bytes=%u\n", listing_size);
                size_t cursor = 20000;
                size_t end = 20000 + listing_size;
                char previous[256] = {0};
                char listed_names[2][256] = {{0}};
                size_t entries = 0;
                while (cursor < end) {
                    assert(end - cursor >= 24);
                    uint32_t name_len = read_u32(data, cursor + 16);
                    assert(cursor + 24 + name_len <= end);
                    char name[256];
                    assert(name_len < sizeof(name));
                    memcpy(name, data + cursor + 24, name_len);
                    name[name_len] = 0;
                    if (entries != 0) {
                        assert(strcmp(previous, name) < 0);
                    }
                    fprintf(stderr, "root-entry[%zu]=%s\n", entries, name);
                    assert(entries < 2);
                    strcpy(listed_names[entries], name);
                    strcpy(previous, name);
                    entries++;
                    cursor += 24 + name_len;
                }
                assert(cursor == end);
                assert(entries == 2);
                assert(strcmp(listed_names[0], map_root_alias ? "/" : "//") == 0);
                assert(strcmp(listed_names[1], "/named") == 0);

                static const char* open_names[] = {
                    "/", "//", "///", "/.", "/..", ".", "fd4/..", "fd4/.",
                    "/named", "sub/abs-root", "sub/abs-dot", "sub/abs-parent",
                    "sub/rel-dot", "sub/rel-parent", "fd5/sub", "missing",
                };
                for (uint32_t i = 0; i < 16; ++i) {
                    size_t record = 10000 + (size_t)i * 32;
                    fprintf(stderr, "open[%u]=%s errno=%u stat_errno=%u ino=%llu type=%u\n",
                        i,
                        open_names[i],
                        read_u32(data, record),
                        read_u32(data, record + 4),
                        (unsigned long long)read_u64(data, record + 8),
                        data[record + 16]);
                }
                static const char* read_names[] = {
                    "fallback-R", "fallback-named-F", "/named/marker", "fd4/marker",
                    "fd4/named/marker", "fd4/tmp-R", "fd4/tmp-F",
                    "sub/rel-dot/marker", "sub/rel-parent/marker",
                };
                for (uint32_t i = 0; i < 9; ++i) {
                    size_t record = 12000 + (size_t)i * 32;
                    fprintf(stderr, "read[%u]=%s errno=%u stat_errno=%u ino=%llu read_errno=%u count=%u byte=%c\n",
                        i,
                        read_names[i],
                        read_u32(data, record),
                        read_u32(data, record + 4),
                        (unsigned long long)read_u64(data, record + 8),
                        read_u32(data, record + 16),
                        read_u32(data, record + 20),
                        data[record + 24] ? data[record + 24] : '-');
                }

                assert_preopen_name(data, 3, 0, "/");
                assert_preopen_name(data, 4, 0, map_root_alias ? "" : "/");
                assert_preopen_name(data, 5, 0, "named");
                assert_preopen_name(data, 6, 8, "");

                assert(read_u32(data, 4800) == 0);
                assert(read_u32(data, 4832) == 0);
                assert(read_u32(data, 4864) == 0);
                uint64_t virtual_root = read_u64(data, 4808);
                uint64_t root_grant = read_u64(data, 4840);
                uint64_t named_grant = read_u64(data, 4872);
                assert(virtual_root != root_grant);
                assert(virtual_root != named_grant);
                assert(root_grant != named_grant);
                if (map_root_alias) {
                    assert_open_record(data, 0, 0, virtual_root);
                    assert_open_record(data, 1, 0, virtual_root);
                    assert_open_record(data, 2, 0, virtual_root);
                    assert_open_record(data, 3, 0, virtual_root);
                    assert_open_record(data, 4, 0, virtual_root);
                    assert_open_record(data, 5, 0, virtual_root);
                    assert_open_record(data, 6, 0, virtual_root);
                    assert_open_record(data, 7, 0, root_grant);
                    assert_open_record(data, 8, 0, named_grant);
                    assert_open_record(data, 9, 0, virtual_root);
                    assert_open_record(data, 10, 0, virtual_root);
                    assert_open_record(data, 11, 0, virtual_root);
                    assert_open_record(data, 12, 76, 0);
                    assert_open_record(data, 13, 76, 0);
                    assert_open_record(data, 15, 76, 0);
                    assert_read_record(data, 0, 76, 0);
                    assert_read_record(data, 1, 76, 0);
                    assert_read_record(data, 2, 0, 'N');
                    assert_read_record(data, 3, 0, 'R');
                    assert_read_record(data, 4, 0, 'F');
                    assert_read_record(data, 7, 76, 0);
                    assert_read_record(data, 8, 76, 0);
                } else {
                    assert_open_record(data, 0, 0, root_grant);
                    assert_open_record(data, 1, 0, root_grant);
                    assert_open_record(data, 2, 0, root_grant);
                    assert_open_record(data, 3, 0, virtual_root);
                    assert_open_record(data, 4, 0, virtual_root);
                    assert_open_record(data, 5, 0, virtual_root);
                    assert_open_record(data, 6, 0, virtual_root);
                    assert_open_record(data, 7, 0, root_grant);
                    assert_open_record(data, 8, 0, named_grant);
                    assert_open_record(data, 9, 0, root_grant);
                    assert_open_record(data, 10, 0, root_grant);
                    assert_open_record(data, 11, 0, virtual_root);
                    assert_open_record(data, 12, 0, read_u64(data, 10456));
                    assert_open_record(data, 13, 0, named_grant);
                    assert_open_record(data, 14, 0, read_u64(data, 10456));
                    assert_open_record(data, 15, 44, 0);
                    assert_read_record(data, 0, 0, 'R');
                    assert_read_record(data, 1, 0, 'F');
                    assert_read_record(data, 2, 0, 'N');
                    assert_read_record(data, 5, 0, 'R');
                    assert_read_record(data, 6, 0, 'F');
                    assert_read_record(data, 7, 0, 'S');
                    assert_read_record(data, 8, 0, 'N');
                }

                wasm_func_delete(start);
                wasm_instance_delete(instance);
                wasm_extern_vec_delete(&imports);
                wasm_extern_vec_delete(&exports);
                wasi_env_delete(wasi_env);
            }

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                wasm_byte_vec_t wat;
                wasmer_byte_vec_new_from_string(
                    &wat,
                    "(module\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_prestat_get\" (func $prestat_get (param i32 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_prestat_dir_name\" (func $prestat_name (param i32 i32 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_readdir\" (func $readdir (param i32 i32 i32 i64 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"path_open\" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_filestat_get\" (func $filestat (param i32 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_read\" (func $read (param i32 i32 i32 i32) (result i32)))\n"
                    " (import \"wasi_snapshot_preview1\" \"fd_close\" (func $close (param i32) (result i32)))\n"
                    " (memory (export \"memory\") 1)\n"
                    " (data (i32.const 800) \"/\")\n"
                    " (data (i32.const 804) \"//\")\n"
                    " (data (i32.const 808) \"///\")\n"
                    " (data (i32.const 812) \"/.\")\n"
                    " (data (i32.const 816) \"/..\")\n"
                    " (data (i32.const 820) \".\")\n"
                    " (data (i32.const 824) \"..\")\n"
                    " (data (i32.const 832) \"/named\")\n"
                    " (data (i32.const 840) \"/named/marker\")\n"
                    " (data (i32.const 856) \"named/marker\")\n"
                    " (data (i32.const 872) \"marker\")\n"
                    " (data (i32.const 888) \"sub/abs-root\")\n"
                    " (data (i32.const 904) \"sub/abs-dot\")\n"
                    " (data (i32.const 920) \"sub/abs-parent\")\n"
                    " (data (i32.const 936) \"sub/rel-dot\")\n"
                    " (data (i32.const 952) \"sub/rel-parent\")\n"
                    " (data (i32.const 968) \"sub\")\n"
                    " (data (i32.const 976) \"sub/rel-dot/marker\")\n"
                    " (data (i32.const 1000) \"sub/rel-parent/marker\")\n"
                    " (func $record_fd (param $fd i32) (param $out i32) (local $err i32)\n"
                    "  local.get $fd i32.const 5000 call $filestat local.set $err\n"
                    "  local.get $out local.get $err i32.store\n"
                    "  local.get $out i32.const 8 i32.add i32.const 5000 i64.load offset=8 i64.store)\n"
                    " (func $record_pre (param $fd i32) (param $out i32) (local $err i32)\n"
                    "  local.get $fd i32.const 5000 call $prestat_get local.set $err\n"
                    "  local.get $out local.get $err i32.store\n"
                    "  local.get $err if else\n"
                    "   local.get $out i32.const 8 i32.add i32.const 5000 i32.load offset=4 i32.store\n"
                    "   local.get $fd local.get $out i32.const 12 i32.add i32.const 64 call $prestat_name\n"
                    "   local.set $err\n"
                    "   local.get $out i32.const 4 i32.add local.get $err i32.store\n"
                    "  end)\n"
                    " (func $record_open (param $dir i32) (param $lookup i32) (param $path i32) (param $len i32) (param $oflags i32) (param $out i32) (local $err i32) (local $fd i32)\n"
                    "  local.get $dir local.get $lookup local.get $path local.get $len local.get $oflags\n"
                    "  i64.const 2097154 i64.const 0 i32.const 0 i32.const 5300 call $path_open local.set $err\n"
                    "  local.get $out local.get $err i32.store\n"
                    "  local.get $err if else\n"
                    "   i32.const 5300 i32.load local.tee $fd i32.const 5400 call $filestat local.set $err\n"
                    "   local.get $out i32.const 4 i32.add local.get $err i32.store\n"
                    "   local.get $out i32.const 8 i32.add i32.const 5400 i64.load offset=8 i64.store\n"
                    "   local.get $out i32.const 16 i32.add i32.const 5400 i32.load8_u offset=16 i32.store8\n"
                    "   local.get $fd call $close drop\n"
                    "  end)\n"
                    " (func $record_read (param $dir i32) (param $lookup i32) (param $path i32) (param $len i32) (param $out i32) (local $err i32) (local $fd i32)\n"
                    "  local.get $dir local.get $lookup local.get $path local.get $len i32.const 0\n"
                    "  i64.const 2097154 i64.const 0 i32.const 0 i32.const 5300 call $path_open local.set $err\n"
                    "  local.get $out local.get $err i32.store\n"
                    "  local.get $err if else\n"
                    "   i32.const 5300 i32.load local.tee $fd i32.const 5400 call $filestat local.set $err\n"
                    "   local.get $out i32.const 4 i32.add local.get $err i32.store\n"
                    "   local.get $out i32.const 8 i32.add i32.const 5400 i64.load offset=8 i64.store\n"
                    "   i32.const 7000 i32.const 7100 i32.store\n"
                    "   i32.const 7004 i32.const 1 i32.store\n"
                    "   i32.const 7100 i32.const 0 i32.store8\n"
                    "   i32.const 7200 i32.const 0 i32.store\n"
                    "   local.get $fd i32.const 7000 i32.const 1 i32.const 7200 call $read local.set $err\n"
                    "   local.get $out i32.const 16 i32.add local.get $err i32.store\n"
                    "   local.get $out i32.const 20 i32.add i32.const 7200 i32.load i32.store\n"
                    "   local.get $out i32.const 24 i32.add i32.const 7100 i32.load8_u i32.store8\n"
                    "   local.get $fd call $close drop\n"
                    "  end)\n"
                    " (func (export \"_start\")\n"
                    "  i32.const 3 i32.const 4800 call $record_fd\n"
                    "  i32.const 4 i32.const 4832 call $record_fd\n"
                    "  i32.const 5 i32.const 4864 call $record_fd\n"
                    "  i32.const 3 i32.const 4000 call $record_pre\n"
                    "  i32.const 4 i32.const 4080 call $record_pre\n"
                    "  i32.const 5 i32.const 4160 call $record_pre\n"
                    "  i32.const 6 i32.const 4240 call $record_pre\n"
                    "  i32.const 4700\n"
                    "  i32.const 3 i32.const 20000 i32.const 2048 i64.const 0 i32.const 4704 call $readdir i32.store\n"
                    "  i32.const 3 i32.const 0 i32.const 800 i32.const 1 i32.const 2 i32.const 10000 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 804 i32.const 2 i32.const 2 i32.const 10032 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 808 i32.const 3 i32.const 2 i32.const 10064 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 812 i32.const 2 i32.const 2 i32.const 10096 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 816 i32.const 3 i32.const 2 i32.const 10128 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 820 i32.const 1 i32.const 2 i32.const 10160 call $record_open\n"
                    "  i32.const 4 i32.const 0 i32.const 824 i32.const 2 i32.const 2 i32.const 10192 call $record_open\n"
                    "  i32.const 4 i32.const 0 i32.const 820 i32.const 1 i32.const 2 i32.const 10224 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 832 i32.const 6 i32.const 2 i32.const 10256 call $record_open\n"
                    "  i32.const 5 i32.const 1 i32.const 888 i32.const 12 i32.const 2 i32.const 10288 call $record_open\n"
                    "  i32.const 5 i32.const 1 i32.const 904 i32.const 11 i32.const 2 i32.const 10320 call $record_open\n"
                    "  i32.const 5 i32.const 1 i32.const 920 i32.const 14 i32.const 2 i32.const 10352 call $record_open\n"
                    "  i32.const 5 i32.const 1 i32.const 936 i32.const 11 i32.const 2 i32.const 10384 call $record_open\n"
                    "  i32.const 5 i32.const 1 i32.const 952 i32.const 14 i32.const 2 i32.const 10416 call $record_open\n"
                    "  i32.const 5 i32.const 0 i32.const 968 i32.const 3 i32.const 2 i32.const 10448 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 3400 i32.const 3508 i32.load i32.const 0 i32.const 10480 call $record_open\n"
                    "  i32.const 3 i32.const 0 i32.const 3000 i32.const 3500 i32.load i32.const 12000 call $record_read\n"
                    "  i32.const 3 i32.const 0 i32.const 3200 i32.const 3504 i32.load i32.const 12032 call $record_read\n"
                    "  i32.const 3 i32.const 0 i32.const 840 i32.const 13 i32.const 12064 call $record_read\n"
                    "  i32.const 4 i32.const 0 i32.const 872 i32.const 6 i32.const 12096 call $record_read\n"
                    "  i32.const 4 i32.const 0 i32.const 856 i32.const 12 i32.const 12128 call $record_read\n"
                    "  i32.const 4 i32.const 0 i32.const 3600 i32.const 3512 i32.load i32.const 12160 call $record_read\n"
                    "  i32.const 4 i32.const 0 i32.const 3800 i32.const 3516 i32.load i32.const 12192 call $record_read\n"
                    "  i32.const 5 i32.const 1 i32.const 976 i32.const 18 i32.const 12224 call $record_read\n"
                    "  i32.const 5 i32.const 1 i32.const 1000 i32.const 21 i32.const 12256 call $record_read))\n"
                );
                wasm_byte_vec_t wasm;
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);

                char root_template[] = "/tmp/wasmer-capi-root-contract-XXXXXX";
                char grant_template[] = "/tmp/wasmer-capi-named-grant-XXXXXX";
                char* root_path = mkdtemp(root_template);
                char* grant_path = mkdtemp(grant_template);
                assert(root_path && grant_path);
                char path[512];
                assert(snprintf(path, sizeof(path), "%s/named", root_path) > 0);
                assert(mkdir(path, 0700) == 0);
                char root_marker[512], fallback_named_marker[512], grant_marker[512];
                assert(snprintf(root_marker, sizeof(root_marker), "%s/marker", root_path) > 0);
                assert(snprintf(fallback_named_marker, sizeof(fallback_named_marker), "%s/named/marker", root_path) > 0);
                assert(snprintf(grant_marker, sizeof(grant_marker), "%s/marker", grant_path) > 0);
                write_byte(root_marker, 'R');
                write_byte(fallback_named_marker, 'F');
                write_byte(grant_marker, 'N');
                assert(snprintf(path, sizeof(path), "%s/sub", grant_path) > 0);
                assert(mkdir(path, 0700) == 0);
                char sub_marker[512];
                assert(snprintf(sub_marker, sizeof(sub_marker), "%s/sub/marker", grant_path) > 0);
                write_byte(sub_marker, 'S');
                char link_path[512];
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-root", grant_path) > 0);
                assert(symlink("/", link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-dot", grant_path) > 0);
                assert(symlink("/.", link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-parent", grant_path) > 0);
                assert(symlink("/..", link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/rel-dot", grant_path) > 0);
                assert(symlink(".", link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/rel-parent", grant_path) > 0);
                assert(symlink("..", link_path) == 0);

                wasi_config_t* map_root_config = wasi_config_new("map-root");
                assert(map_root_config);
                assert(wasi_config_mapdir(map_root_config, "/", root_path));
                assert(wasi_config_mapdir(map_root_config, "named", grant_path));
                run_probe(store, module, map_root_config, 1, root_path);

                wasi_config_t* preopen_root_config = wasi_config_new("preopen-root");
                assert(preopen_root_config);
                assert(wasi_config_preopen_dir(preopen_root_config, "/"));
                assert(wasi_config_mapdir(preopen_root_config, "named", grant_path));
                run_probe(store, module, preopen_root_config, 0, root_path);

                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);

                assert(unlink(root_marker) == 0);
                assert(unlink(fallback_named_marker) == 0);
                assert(snprintf(path, sizeof(path), "%s/named", root_path) > 0);
                assert(rmdir(path) == 0);
                assert(rmdir(root_path) == 0);
                assert(unlink(grant_marker) == 0);
                assert(unlink(sub_marker) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-root", grant_path) > 0);
                assert(unlink(link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-dot", grant_path) > 0);
                assert(unlink(link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/abs-parent", grant_path) > 0);
                assert(unlink(link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/rel-dot", grant_path) > 0);
                assert(unlink(link_path) == 0);
                assert(snprintf(link_path, sizeof(link_path), "%s/sub/rel-parent", grant_path) > 0);
                assert(unlink(link_path) == 0);
                assert(snprintf(path, sizeof(path), "%s/sub", grant_path) > 0);
                assert(rmdir(path) == 0);
                assert(rmdir(grant_path) == 0);
                return 0;
            }
        })
        .success();
        eprintln!("{}", String::from_utf8_lossy(&output.get_output().stderr));
    }
    // Measured original reference: child completion succeeds, then shared fd1
    // removal makes its public capture lookup fail. Keep the body unchanged.
    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    #[ignore = "legacy reference: native intentionally retains the original configured capture consumer"]
    fn test_wasi_public_exec_preserves_namespace_and_reports_an_exit_trap() {
        let output = (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/stat.h>
            #include <unistd.h>

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                assert(engine && store);
                char directory[] = "/tmp/wasmer-capi-exec-contract-XXXXXX";
                assert(mkdtemp(directory));
                char child_path[512], result_path[512];
                assert(snprintf(child_path, sizeof(child_path), "%s/child.wasm", directory) > 0);
                assert(snprintf(result_path, sizeof(result_path), "%s/result", directory) > 0);
                wasm_byte_vec_t child_wat, child_wasm;
                wasmer_byte_vec_new_from_string(&child_wat, "(module\n"
                    "(import \"wasix_32v1\" \"args_sizes_get\" (func $argc (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"args_get\" (func $argv (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"environ_sizes_get\" (func $envc (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"environ_get\" (func $env (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_prestat_get\" (func $prestat (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_prestat_dir_name\" (func $name (param i32 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdstat_get\" (func $stat (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdflags_get\" (func $flags (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_readdir\" (func $readdir (param i32 i32 i32 i64 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"path_open\" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_write\" (func $write (param i32 i32 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_close\" (func $close (param i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"proc_exit2\" (func $exit (param i32)))\n"
                    "(memory (export \"memory\") 1)\n"
                    "(data (i32.const 3000) \"/opaque//alias/prog\")\n"
                    "(data (i32.const 3040) \"result\")\n"
                    "(data (i32.const 3080) \"donefail\")\n"
                    "(func $fail\n"
                    " (i32.store (i32.const 200) (i32.const 3084))\n"
                    " (i32.store (i32.const 204) (i32.const 4))\n"
                    " (drop (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)))\n"
                    " (call $exit (i32.const 2)) unreachable)\n"
                    "(func $check (param $actual i32) (param $expected i32)\n"
                    " (if (i32.ne (local.get $actual) (local.get $expected)) (then (call $fail))))\n"
                    "(func $bytes (param $actual i32) (param $expected i32) (param $len i32) (local $i i32)\n"
                    " (loop $next (if (i32.lt_u (local.get $i) (local.get $len)) (then\n"
                    "  (call $check (i32.load8_u (i32.add (local.get $actual) (local.get $i)))\n"
                    "               (i32.load8_u (i32.add (local.get $expected) (local.get $i))))\n"
                    "  (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))))\n"
                    "(func (export \"_start\")\n"
                    " (call $check (call $argc (i32.const 0) (i32.const 4)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 1))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 6))\n"
                    " (call $check (call $argv (i32.const 8) (i32.const 64)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 64)) (i32.const 0x6c696863))\n"
                    " (call $check (i32.load8_u (i32.const 68)) (i32.const 100))\n"
                    " (call $check (call $envc (i32.const 0) (i32.const 4)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 2))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 19))\n"
                    " (call $check (call $env (i32.const 8) (i32.const 64)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 8)) (i32.const 64))\n"
                    " (call $check (i32.load (i32.const 12)) (i32.const 75))\n"
                    " (call $check (i32.load (i32.const 64)) (i32.const 0x3d444c4f))\n"
                    " (call $check (i32.load (i32.const 68)) (i32.const 0x65726170))\n"
                    " (call $check (i32.load16_u (i32.const 72)) (i32.const 0x746e))\n"
                    " (call $check (i32.load8_u (i32.const 74)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 75)) (i32.const 0x3d57454e))\n"
                    " (call $check (i32.load (i32.const 79)) (i32.const 0x00736579))\n"
                    " (call $check (call $prestat (i32.const 20) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 13))\n"
                    " (call $check (call $name (i32.const 20) (i32.const 64) (i32.const 13)) (i32.const 0))\n"
                    " (call $bytes (i32.const 64) (i32.const 3001) (i32.const 13))\n"
                    " (call $check (call $stat (i32.const 20) (i32.const 128)) (i32.const 0))\n"
                    " (if (i64.ne (i64.load (i32.const 136)) (i64.const 2097160)) (then (call $fail)))\n"
                    " (if (i64.ne (i64.load (i32.const 144)) (i64.const 0)) (then (call $fail)))\n"
                    " (call $check (call $flags (i32.const 20) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load16_u (i32.const 0)) (i32.const 1))\n"
                    " (call $check (call $readdir (i32.const 3) (i32.const 1000) (i32.const 256) (i64.const 0) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 67))\n"
                    " (call $check (i32.load (i32.const 1016)) (i32.const 14))\n"
                    " (call $bytes (i32.const 1024) (i32.const 3000) (i32.const 14))\n"
                    " (call $check (i32.load (i32.const 1054)) (i32.const 5))\n"
                    " (call $bytes (i32.const 1062) (i32.const 3014) (i32.const 5))\n"
                    " (call $check (call $open (i32.const 5) (i32.const 1) (i32.const 3040) (i32.const 6)\n"
                    "    (i32.const 1) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 256)) (i32.const 0))\n"
                    " (i32.store (i32.const 200) (i32.const 3080))\n"
                    " (i32.store (i32.const 204) (i32.const 4))\n"
                    " (call $check (call $write (i32.load (i32.const 256)) (i32.const 200) (i32.const 1) (i32.const 208)) (i32.const 0))\n"
                    " (call $check (call $close (i32.load (i32.const 256))) (i32.const 0))\n"
                    " (call $check (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)) (i32.const 0))))\n");
                wat2wasm(&child_wat, &child_wasm);
                assert(child_wasm.size > 0);
                FILE* child = fopen(child_path, "wb");
                assert(child);
                assert(fwrite(child_wasm.data, 1, child_wasm.size, child) == child_wasm.size);
                assert(fclose(child) == 0 && chmod(child_path, 0755) == 0);
                wasm_byte_vec_t wat, wasm;
                wasmer_byte_vec_new_from_string(&wat, "(module\n"
                    "(import \"wasix_32v1\" \"fd_renumber\" (func $renumber (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdstat_set_rights\" (func $reduce (param i32 i64 i64) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdflags_set\" (func $flags (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"proc_exec3\" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))\n"
                    "(memory (export \"memory\") 1)\n"
                    "(data (i32.const 1000) \"/prog/child.wasm\")\n"
                    "(data (i32.const 1040) \"child\\n\")\n"
                    "(data (i32.const 1080) \"NEW=yes\\n\")\n"
                    "(func (export \"run\") (result i64)\n"
                    "(if (call $renumber (i32.const 4) (i32.const 20)) (then unreachable))\n"
                    "(if (call $reduce (i32.const 20) (i64.const 2097160) (i64.const 0)) (then unreachable))\n"
                    "(if (call $flags (i32.const 20) (i32.const 1)) (then unreachable))\n"
                    "(drop (call $exec (i32.const 1000) (i32.const 16) (i32.const 1040) (i32.const 6)\n"
                    " (i32.const 1080) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0)))\n"
                    "i64.const -1))\n");
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);
                wasi_config_t* config = wasi_config_new("old-parent");
                assert(config);
                wasi_config_env(config, "OLD", "parent");
                wasi_config_capture_stdout(config);
                assert(wasi_config_mapdir(config, "opaque//alias", directory));
                assert(wasi_config_mapdir(config, "prog", directory));
                wasi_env_t* env = wasi_env_new(store, config);
                assert(env);
                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, env, module, &imports));
                wasm_instance_t* instance = wasm_instance_new(store, module, &imports, NULL);
                assert(instance && wasi_env_initialize_instance(env, store, instance));
                wasm_extern_vec_t exports = WASM_EMPTY_VEC;
                wasm_instance_exports(instance, &exports);
                assert(exports.size == 2);
                wasm_func_t* original = wasm_extern_as_func(exports.data[1]);
                assert(original);
                wasm_func_t* copied = wasm_func_copy(original);
                assert(copied);
                wasm_val_vec_t args = WASM_EMPTY_VEC, results;
                wasm_val_vec_new_uninitialized(&results, 1);
                results.data[0] = (wasm_val_t)WASM_I64_VAL(0x123456789);
                wasm_trap_t* trap = wasm_func_call(copied, &args, &results);
                assert(trap);
                assert(results.data[0].kind == WASM_I64);
                assert(results.data[0].of.i64 == 0x123456789);
                wasm_message_t message;
                wasm_trap_message(trap, &message);
                const char expected_exit[] = "WASI exited with code: ExitCode::0";
                assert(message.size == sizeof(expected_exit));
                assert(memcmp(message.data, expected_exit, sizeof(expected_exit)) == 0);
                fprintf(stderr, "public-exec-trap: %.*s\n", (int)message.size, message.data);
                // A missing completion must fail before any potentially blocking stream read.
                FILE* result = fopen(result_path, "rb");
                assert(result);
                char bytes[4];
                assert(fread(bytes, 1, sizeof(bytes), result) == sizeof(bytes));
                assert(memcmp(bytes, "done", sizeof(bytes)) == 0);
                assert(fclose(result) == 0);
                // The legacy child's on_exit closes shared fd1. The public
                // reader therefore fails even though the positive host marker
                // above proves the child completed and wrote its captured output.
                assert(wasi_env_read_stdout(env, bytes, sizeof(bytes)) == -1);
                wasm_byte_vec_delete(&message);
                wasm_trap_delete(trap);
                wasm_val_vec_delete(&results);
                wasm_func_delete(copied);
                wasm_extern_vec_delete(&exports);
                wasm_instance_delete(instance);
                wasm_extern_vec_delete(&imports);
                wasi_env_delete(env);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_byte_vec_delete(&child_wasm);
                wasm_byte_vec_delete(&child_wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                assert(unlink(result_path) == 0 && unlink(child_path) == 0);
                assert(rmdir(directory) == 0);
                return 0;
            }
        }).success();
        eprintln!("{}", String::from_utf8_lossy(&output.get_output().stderr));
    }

    // Intentional native correction: drain the original configured capture and EOF
    // after fd1 redirection/closure; the redirected host file is a distinct consumer.
    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_native_exec_retains_configured_capture_after_child_fd1_closes() {
        let output = (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/stat.h>
            #include <unistd.h>

            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                assert(engine && store);
                char directory[] = "/tmp/wasmer-capi-exec-contract-XXXXXX";
                assert(mkdtemp(directory));
                char child_path[512], result_path[512], redirect_path[512];
                assert(snprintf(child_path, sizeof(child_path), "%s/child.wasm", directory) > 0);
                assert(snprintf(result_path, sizeof(result_path), "%s/result", directory) > 0);
                assert(snprintf(redirect_path, sizeof(redirect_path), "%s/redirect", directory) > 0);
                wasm_byte_vec_t child_wat, child_wasm;
                wasmer_byte_vec_new_from_string(&child_wat, "(module\n"
                    "(import \"wasix_32v1\" \"args_sizes_get\" (func $argc (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"args_get\" (func $argv (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"environ_sizes_get\" (func $envc (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"environ_get\" (func $env (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_prestat_get\" (func $prestat (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_prestat_dir_name\" (func $name (param i32 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdstat_get\" (func $stat (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdflags_get\" (func $flags (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_readdir\" (func $readdir (param i32 i32 i32 i64 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"path_open\" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_write\" (func $write (param i32 i32 i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_close\" (func $close (param i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_renumber\" (func $renumber (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"proc_exit2\" (func $exit (param i32)))\n"
                    "(memory (export \"memory\") 1)\n"
                    "(data (i32.const 3000) \"/opaque//alias/prog\")\n"
                    "(data (i32.const 3040) \"result\")\n"
                    "(data (i32.const 3080) \"donefail\")\n"
                    "(data (i32.const 3120) \"redirect\")\n"
                    "(data (i32.const 3160) \"file\")\n"
                    "(func $fail\n"
                    " (i32.store (i32.const 200) (i32.const 3084))\n"
                    " (i32.store (i32.const 204) (i32.const 4))\n"
                    " (drop (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)))\n"
                    " (call $exit (i32.const 2)) unreachable)\n"
                    "(func $check (param $actual i32) (param $expected i32)\n"
                    " (if (i32.ne (local.get $actual) (local.get $expected)) (then (call $fail))))\n"
                    "(func $bytes (param $actual i32) (param $expected i32) (param $len i32) (local $i i32)\n"
                    " (loop $next (if (i32.lt_u (local.get $i) (local.get $len)) (then\n"
                    "  (call $check (i32.load8_u (i32.add (local.get $actual) (local.get $i)))\n"
                    "               (i32.load8_u (i32.add (local.get $expected) (local.get $i))))\n"
                    "  (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))))\n"
                    "(func (export \"_start\")\n"
                    " (call $check (call $argc (i32.const 0) (i32.const 4)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 1))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 6))\n"
                    " (call $check (call $argv (i32.const 8) (i32.const 64)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 64)) (i32.const 0x6c696863))\n"
                    " (call $check (i32.load8_u (i32.const 68)) (i32.const 100))\n"
                    " (call $check (call $envc (i32.const 0) (i32.const 4)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 2))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 19))\n"
                    " (call $check (call $env (i32.const 8) (i32.const 64)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 8)) (i32.const 64))\n"
                    " (call $check (i32.load (i32.const 12)) (i32.const 75))\n"
                    " (call $check (i32.load (i32.const 64)) (i32.const 0x3d444c4f))\n"
                    " (call $check (i32.load (i32.const 68)) (i32.const 0x65726170))\n"
                    " (call $check (i32.load16_u (i32.const 72)) (i32.const 0x746e))\n"
                    " (call $check (i32.load8_u (i32.const 74)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 75)) (i32.const 0x3d57454e))\n"
                    " (call $check (i32.load (i32.const 79)) (i32.const 0x00736579))\n"
                    " (call $check (call $prestat (i32.const 20) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 4)) (i32.const 13))\n"
                    " (call $check (call $name (i32.const 20) (i32.const 64) (i32.const 13)) (i32.const 0))\n"
                    " (call $bytes (i32.const 64) (i32.const 3001) (i32.const 13))\n"
                    " (call $check (call $stat (i32.const 20) (i32.const 128)) (i32.const 0))\n"
                    " (if (i64.ne (i64.load (i32.const 136)) (i64.const 2097160)) (then (call $fail)))\n"
                    " (if (i64.ne (i64.load (i32.const 144)) (i64.const 0)) (then (call $fail)))\n"
                    " (call $check (call $flags (i32.const 20) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load16_u (i32.const 0)) (i32.const 1))\n"
                    " (call $check (call $readdir (i32.const 3) (i32.const 1000) (i32.const 256) (i64.const 0) (i32.const 0)) (i32.const 0))\n"
                    " (call $check (i32.load (i32.const 0)) (i32.const 67))\n"
                    " (call $check (i32.load (i32.const 1016)) (i32.const 14))\n"
                    " (call $bytes (i32.const 1024) (i32.const 3000) (i32.const 14))\n"
                    " (call $check (i32.load (i32.const 1054)) (i32.const 5))\n"
                    " (call $bytes (i32.const 1062) (i32.const 3014) (i32.const 5))\n"
                    " (call $check (call $open (i32.const 5) (i32.const 1) (i32.const 3040) (i32.const 6)\n"
                    "    (i32.const 1) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 256)) (i32.const 0))\n"
                    " (i32.store (i32.const 200) (i32.const 3080))\n"
                    " (i32.store (i32.const 204) (i32.const 4))\n"
                    " (call $check (call $write (i32.load (i32.const 256)) (i32.const 200) (i32.const 1) (i32.const 208)) (i32.const 0))\n"
                    " (call $check (call $close (i32.load (i32.const 256))) (i32.const 0))\n"
                    " (call $check (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)) (i32.const 0))\n"
                    " (call $check (call $open (i32.const 5) (i32.const 1) (i32.const 3120) (i32.const 8)\n"
                    "    (i32.const 1) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 256)) (i32.const 0))\n"
                    " (call $check (call $renumber (i32.load (i32.const 256)) (i32.const 1)) (i32.const 0))\n"
                    " (i32.store (i32.const 200) (i32.const 3160))\n"
                    " (call $check (call $write (i32.const 1) (i32.const 200) (i32.const 1) (i32.const 208)) (i32.const 0))\n"
                    " (call $check (call $close (i32.load (i32.const 256))) (i32.const 0))))\n");
                wat2wasm(&child_wat, &child_wasm);
                assert(child_wasm.size > 0);
                FILE* child = fopen(child_path, "wb");
                assert(child);
                assert(fwrite(child_wasm.data, 1, child_wasm.size, child) == child_wasm.size);
                assert(fclose(child) == 0 && chmod(child_path, 0755) == 0);
                wasm_byte_vec_t wat, wasm;
                wasmer_byte_vec_new_from_string(&wat, "(module\n"
                    "(import \"wasix_32v1\" \"fd_renumber\" (func $renumber (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdstat_set_rights\" (func $reduce (param i32 i64 i64) (result i32)))\n"
                    "(import \"wasix_32v1\" \"fd_fdflags_set\" (func $flags (param i32 i32) (result i32)))\n"
                    "(import \"wasix_32v1\" \"proc_exec3\" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))\n"
                    "(memory (export \"memory\") 1)\n"
                    "(data (i32.const 1000) \"/prog/child.wasm\")\n"
                    "(data (i32.const 1040) \"child\\n\")\n"
                    "(data (i32.const 1080) \"NEW=yes\\n\")\n"
                    "(func (export \"run\") (result i64)\n"
                    "(if (call $renumber (i32.const 4) (i32.const 20)) (then unreachable))\n"
                    "(if (call $reduce (i32.const 20) (i64.const 2097160) (i64.const 0)) (then unreachable))\n"
                    "(if (call $flags (i32.const 20) (i32.const 1)) (then unreachable))\n"
                    "(drop (call $exec (i32.const 1000) (i32.const 16) (i32.const 1040) (i32.const 6)\n"
                    " (i32.const 1080) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0)))\n"
                    "i64.const -1))\n");
                wat2wasm(&wat, &wasm);
                wasm_module_t* module = wasm_module_new(store, &wasm);
                assert(module);
                wasi_config_t* config = wasi_config_new("old-parent");
                assert(config);
                wasi_config_env(config, "OLD", "parent");
                wasi_config_capture_stdout(config);
                assert(wasi_config_mapdir(config, "opaque//alias", directory));
                assert(wasi_config_mapdir(config, "prog", directory));
                wasi_env_t* env = wasi_env_new(store, config);
                assert(env);
                wasm_extern_vec_t imports = WASM_EMPTY_VEC;
                assert(wasi_get_imports(store, env, module, &imports));
                wasm_instance_t* instance = wasm_instance_new(store, module, &imports, NULL);
                assert(instance && wasi_env_initialize_instance(env, store, instance));
                wasm_extern_vec_t exports = WASM_EMPTY_VEC;
                wasm_instance_exports(instance, &exports);
                assert(exports.size == 2);
                wasm_func_t* original = wasm_extern_as_func(exports.data[1]);
                assert(original);
                wasm_func_t* copied = wasm_func_copy(original);
                assert(copied);
                wasm_val_vec_t args = WASM_EMPTY_VEC, results;
                wasm_val_vec_new_uninitialized(&results, 1);
                results.data[0] = (wasm_val_t)WASM_I64_VAL(0x123456789);
                wasm_trap_t* trap = wasm_func_call(copied, &args, &results);
                assert(trap);
                assert(results.data[0].kind == WASM_I64);
                assert(results.data[0].of.i64 == 0x123456789);
                wasm_message_t message;
                wasm_trap_message(trap, &message);
                const char expected_exit[] = "WASI exited with code: ExitCode::0";
                assert(message.size == sizeof(expected_exit));
                assert(memcmp(message.data, expected_exit, sizeof(expected_exit)) == 0);
                fprintf(stderr, "public-exec-trap: %.*s\n", (int)message.size, message.data);
                // A missing completion must fail before any potentially blocking stream read.
                FILE* result = fopen(result_path, "rb");
                assert(result);
                char bytes[4];
                assert(fread(bytes, 1, sizeof(bytes), result) == sizeof(bytes));
                assert(memcmp(bytes, "done", sizeof(bytes)) == 0);
                assert(fclose(result) == 0);
                // The original configured consumer remains readable even after
                // the child redirects fd1 to a file and then closes all its fds.
                size_t count = 0;
                while (count < sizeof(bytes)) {
                    intptr_t read = wasi_env_read_stdout(env, bytes + count, sizeof(bytes) - count);
                    assert(read > 0 && (size_t)read <= sizeof(bytes) - count);
                    count += (size_t)read;
                }
                assert(memcmp(bytes, "done", sizeof(bytes)) == 0);
                assert(wasi_env_read_stdout(env, bytes, sizeof(bytes)) == 0);
                assert(wasi_env_read_stdout(env, bytes, 0) == 0);
                assert(wasi_env_read_stderr(env, bytes, sizeof(bytes)) == -1);
                FILE* redirected = fopen(redirect_path, "rb");
                assert(redirected);
                assert(fread(bytes, 1, sizeof(bytes), redirected) == sizeof(bytes));
                assert(memcmp(bytes, "file", sizeof(bytes)) == 0);
                assert(fclose(redirected) == 0);
                wasm_byte_vec_delete(&message);
                wasm_trap_delete(trap);
                wasm_val_vec_delete(&results);
                wasm_func_delete(copied);
                wasm_extern_vec_delete(&exports);
                wasm_instance_delete(instance);
                wasm_extern_vec_delete(&imports);
                wasi_env_delete(env);
                wasm_module_delete(module);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                wasm_byte_vec_delete(&child_wasm);
                wasm_byte_vec_delete(&child_wat);
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                assert(unlink(result_path) == 0 && unlink(child_path) == 0 && unlink(redirect_path) == 0);
                assert(rmdir(directory) == 0);
                return 0;
            }
        }).success();
        eprintln!("{}", String::from_utf8_lossy(&output.get_output().stderr));
    }

    #[allow(
        unexpected_cfgs,
        reason = "tools like cargo-llvm-coverage pass --cfg coverage"
    )]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_wasi_public_host_attachment_spawns_threads_without_process_entry_and_preflights_selected_exports()
     {
        (assert_c! {
            #include "tests/wasmer.h"
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            static uint32_t read32(const uint8_t* p) {
                return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            }
            static void write32(uint8_t* p, uint32_t value) {
                for (size_t i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (i * 8));
            }
            static int32_t invoke(wasm_func_t* function, size_t argc, int32_t value) {
                wasm_val_t input[] = { WASM_I32_VAL(value) };
                wasm_val_vec_t args, results;
                wasm_val_vec_new(&args, argc, input);
                wasm_val_vec_new_uninitialized(&results, 1);
                results.data[0] = (wasm_val_t)WASM_I32_VAL(-999);
                wasm_trap_t* trap = wasm_func_call(function, &args, &results);
                if (trap) {
                    wasm_message_t message;
                    wasm_trap_message(trap, &message);
                    fprintf(stderr, "thread fixture trap: %.*s\n", (int)message.size, message.data);
                }
                assert(!trap && results.data[0].kind == WASM_I32);
                int32_t result = results.data[0].of.i32;
                wasm_val_vec_delete(&results);
                wasm_val_vec_delete(&args);
                return result;
            }
            static wasm_module_t* module(wasm_store_t* store, const char* source) {
                wasm_byte_vec_t wat, wasm;
                wasmer_byte_vec_new_from_string(&wat, source);
                wat2wasm(&wat, &wasm);
                assert(wasm.size);
                wasm_module_t* result = wasm_module_new(store, &wasm);
                assert(result);
                wasm_byte_vec_delete(&wasm);
                wasm_byte_vec_delete(&wat);
                return result;
            }
            static void spawn_join(
                wasm_func_t* spawn, wasm_func_t* join, uint8_t* memory, uint32_t expected
            ) {
                write32(memory + 104, 12345);
                write32(memory + 200, 0);
                assert(invoke(spawn, 0, 0) == 0);
                uint32_t tid = read32(memory + 104);
                assert(tid > 0 && tid != 12345);
                assert(invoke(join, 1, (int32_t)tid) == 0);
                assert(read32(memory + 200) == expected);
            }
            int main() {
                wasm_engine_t* engine = wasm_engine_new();
                wasm_store_t* store = wasm_store_new(engine);
                const char* entries[] = {
                    "(func (export \"wasi_thread_start\") (param i32 i32) "
                    " i32.const 212 i32.atomic.load if "
                    "  i32.const 204 i32.const 1 i32.atomic.store "
                    "  i32.const 204 i32.const 1 memory.atomic.notify drop "
                    "  block $done loop $wait "
                    "   i32.const 208 i32.atomic.load br_if $done "
                    "   i32.const 208 i32.const 0 i64.const -1 memory.atomic.wait32 drop "
                    "   br $wait end end end "
                    " i32.const 200 i32.const 37 i32.store)",
                    "",
                    "(func (export \"wasi_thread_start\") (param i64))",
                    "(func (export \"wasi_thread_start\") (param i32 i32))"
                };
                const char* gates =
                    "(func (export \"hold_begin\") (result i32) "
                    " i32.const 200 i32.const 0 i32.atomic.store "
                    " i32.const 204 i32.const 0 i32.atomic.store "
                    " i32.const 208 i32.const 0 i32.atomic.store "
                    " i32.const 212 i32.const 1 i32.atomic.store i32.const 0)"
                    "(func (export \"await_started\") (result i32) "
                    " block $done loop $wait "
                    "  i32.const 204 i32.atomic.load br_if $done "
                    "  i32.const 204 i32.const 0 i64.const -1 memory.atomic.wait32 drop "
                    "  br $wait end end i32.const 0)"
                    "(func (export \"release\") (result i32) "
                    " i32.const 208 i32.const 1 i32.atomic.store "
                    " i32.const 208 i32.const 1 memory.atomic.notify drop "
                    " i32.const 212 i32.const 0 i32.atomic.store i32.const 0)";
                for (size_t profile = 0; profile < 4; ++profile) {
                    char source[4096];
                    int length = snprintf(source, sizeof(source),
                        "(module (import \"env\" \"memory\" (memory 1 1 %s))\n"
                        "(import \"wasix_32v1\" \"thread_spawn_v2\" (func $spawn (param i32 i32) (result i32)))\n"
                        "(import \"wasi\" \"thread-spawn\" (func $wasi_spawn (param i32) (result i32)))\n"
                        "(import \"wasix_32v1\" \"thread_join\" (func $join (param i32) (result i32)))\n"
                        "(import \"wasix_32v1\" \"proc_id\" (func $pid (param i32) (result i32)))\n"
                        "(export \"memory\" (memory 0))\n"
                        "(func (export \"spawn\") (result i32) i32.const 36 i32.const 104 call $spawn)\n"
                        "(func (export \"join\") (param i32) (result i32) local.get 0 call $join)\n"
                        "(func (export \"pid\") (result i32) i32.const 108 call $pid drop i32.const 108 i32.load)\n"
                        "(func (export \"answer\") (result i32) i32.const 19)\n"
                        "(func (export \"_initialize\") unreachable)\n"
                        "(func (export \"wasi_spawn\") (result i32) i32.const 36 call $wasi_spawn)\n%s%s)",
                        profile == 3 ? "" : "shared", entries[profile], profile == 0 ? gates : "");
                    assert(length > 0 && (size_t)length < sizeof(source));
                    wasm_module_t* a = module(store, source);
                    wasi_config_t* config = wasi_config_new("host-thread");
                    assert(config);
                    wasi_env_t* env = wasi_env_new(store, config);
                    assert(env);
                    wasm_extern_vec_t imports = WASM_EMPTY_VEC, exports = WASM_EMPTY_VEC;
                    assert(wasi_get_imports(store, env, a, &imports));
                    wasm_instance_t* instance = wasm_instance_new(store, a, &imports, NULL);
                    // No _start exists, and _initialize traps if called. Selection
                    // must still succeed for every shared/private/entry profile.
                    assert(instance && wasi_env_initialize_instance(env, store, instance));
                    wasm_instance_exports(instance, &exports);
                    assert(exports.size == (profile == 0 ? 11 : profile == 1 ? 7 : 8));
                    wasm_memory_t* memory = wasm_extern_as_memory(exports.data[0]);
                    assert(memory && wasm_memory_data_size(memory) >= 256);
                    uint8_t* bytes = wasm_memory_data(memory);
                    wasm_func_t* spawn = wasm_extern_as_func(exports.data[1]);
                    wasm_func_t* join = wasm_extern_as_func(exports.data[2]);
                    wasm_func_t* pid = wasm_extern_as_func(exports.data[3]);
                    wasm_func_t* answer = wasm_extern_as_func(exports.data[4]);
                    wasm_func_t* wasi_spawn = wasm_extern_as_func(exports.data[6]);
                    int32_t original_pid = invoke(pid, 0, 0);
                    assert(original_pid > 0 && invoke(answer, 0, 0) == 19);
                    if (profile == 0) {
                        spawn_join(spawn, join, bytes, 37);
                        // Pure B has only an imported shared memory and its actual
                        // thread entry. It must not be rejected by ABI import matching.
                        wasm_module_t* b = module(store,
                            "(module (import \"env\" \"memory\" (memory 1 1 shared))\n"
                            "(export \"memory\" (memory 0))\n"
                            "(func (export \"wasi_thread_start\") (param i32 i32)\n"
                            " i32.const 200 i32.const 73 i32.store))");
                        wasm_extern_t* shared = wasm_extern_copy(imports.data[0]);
                        wasm_extern_vec_t b_imports;
                        wasm_extern_vec_new(&b_imports, 1, &shared);
                        wasm_instance_t* instance_b = wasm_instance_new(store, b, &b_imports, NULL);
                        assert(instance_b);
                        wasm_func_t* hold = wasm_extern_as_func(exports.data[8]);
                        wasm_func_t* started = wasm_extern_as_func(exports.data[9]);
                        wasm_func_t* release = wasm_extern_as_func(exports.data[10]);
                        assert(invoke(hold, 0, 0) == 0);
                        write32(bytes + 104, 12345);
                        assert(invoke(spawn, 0, 0) == 0);
                        uint32_t held_tid = read32(bytes + 104);
                        assert(held_tid > 0 && held_tid != 12345);
                        assert(invoke(started, 0, 0) == 0);
                        assert(read32(bytes + 200) == 0);
                        // A is physically executing and held before its final
                        // store. Selecting B affects future thread images only.
                        assert(wasi_env_initialize_instance(env, store, instance_b));
                        assert(invoke(release, 0, 0) == 0);
                        assert(invoke(join, 1, (int32_t)held_tid) == 0);
                        assert(read32(bytes + 200) == 37);
                        // Invoke A's old functions while B is explicitly selected:
                        // its thread image must use B, with the same process/mm.
                        spawn_join(spawn, join, bytes, 73);
                        assert(invoke(pid, 0, 0) == original_pid);
                        assert(wasi_env_initialize_instance(env, store, instance));
                        spawn_join(spawn, join, bytes, 37);
                        assert(invoke(pid, 0, 0) == original_pid);
                        wasm_instance_delete(instance_b);
                        wasm_extern_vec_delete(&b_imports);
                        wasm_module_delete(b);
                    } else {
                        write32(bytes + 104, 12345);
                        int32_t expected = profile == 3 ? 78 : 76;
                        assert(invoke(spawn, 0, 0) == expected);
                        assert(invoke(wasi_spawn, 0, 0) == -expected);
                        assert(read32(bytes + 104) == 12345);
                        assert(invoke(pid, 0, 0) == original_pid);
                        assert(invoke(answer, 0, 0) == 19);
                    }
                    wasi_env_delete(env);
                    assert(invoke(answer, 0, 0) == 19);
                    wasm_extern_vec_delete(&exports);
                    wasm_instance_delete(instance);
                    wasm_extern_vec_delete(&imports);
                    wasm_module_delete(a);
                }
                wasm_store_delete(store);
                wasm_engine_delete(engine);
                return 0;
            }
        }).success();
    }
}
