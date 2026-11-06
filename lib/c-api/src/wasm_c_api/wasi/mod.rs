//! Unofficial API for WASI integrating with the standard Wasm C API.
//!
//! This API will be superseded by a standard WASI API when/if such a standard is created.

pub use super::unstable::wasi::wasi_get_unordered_imports;
use super::{
    externals::{wasm_extern_t, wasm_extern_vec_t, wasm_func_t, wasm_memory_t},
    instance::wasm_instance_t,
    module::wasm_module_t,
    store::{StoreRef, wasm_store_t},
};
use crate::error::update_last_error;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
use std::sync::Arc;
use wasmer_wasix::{
    Pipe, PluggableRuntime, WasiEnv, WasiEnvBuilder, WasiFunctionEnv, WasiVersion,
    default_fs_backing, get_wasi_version,
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
    builder: WasiEnvBuilder,
    runtime: Option<tokio::runtime::Runtime>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_new(
    program_name: *const c_char,
) -> Option<Box<wasi_config_t>> {
    debug_assert!(!program_name.is_null());

    let name_c_str = unsafe { CStr::from_ptr(program_name) };
    let prog_name = c_try!(name_c_str.to_str());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();

    Some(Box::new(wasi_config_t {
        inherit_stdout: true,
        inherit_stderr: true,
        inherit_stdin: true,
        builder: WasiEnv::builder(prog_name).fs(default_fs_backing()),
        runtime: Some(runtime),
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

    config.builder.add_env(key_bytes, value_bytes);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_config_arg(config: &mut wasi_config_t, arg: *const c_char) {
    debug_assert!(!arg.is_null());

    let arg_cstr = unsafe { CStr::from_ptr(arg) };
    let arg_bytes = arg_cstr.to_bytes();

    config.builder.add_arg(arg_bytes);
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

    if let Err(e) = config.builder.add_preopen_dir(dir_str) {
        update_last_error(e);
        return false;
    }

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

    if let Err(e) = config.builder.add_map_dir(alias_str, dir_str) {
        update_last_error(e);
        return false;
    }

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
    pub(super) inner: WasiFunctionEnv,
    pub(super) store: StoreRef,
}

/// Create a new WASI environment.
///
/// It take ownership over the `wasi_config_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_new(
    store: Option<&mut wasm_store_t>,
    mut config: Box<wasi_config_t>,
) -> Option<Box<wasi_env_t>> {
    let store = &mut store?.inner;
    let mut store_mut = unsafe { store.store_mut() };

    let runtime = config.runtime.take();

    let runtime = runtime.unwrap_or_else(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    let handle = runtime.handle().clone();
    let _guard = handle.enter();
    let mut rt = PluggableRuntime::new(Arc::new(TokioTaskManager::new(runtime)));
    rt.set_engine(store_mut.engine().clone());

    if !config.inherit_stdout {
        config.builder.set_stdout(Box::new(Pipe::channel().0));
    }

    if !config.inherit_stderr {
        config.builder.set_stderr(Box::new(Pipe::channel().0));
    }

    // TODO: impl capturer for stdin

    let env = c_try!(
        config
            .builder
            .runtime(Arc::new(rt))
            .finalize(&mut store_mut)
    );

    Some(Box::new(wasi_env_t {
        inner: env,
        store: store.clone(),
    }))
}

/// Delete a [`wasi_env_t`].
#[unsafe(no_mangle)]
pub extern "C" fn wasi_env_delete(state: Option<Box<wasi_env_t>>) {
    if let Some(mut env) = state {
        let mut store = unsafe { env.store.store_mut() };
        env.inner.on_exit(&mut store, None);
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
    let store = unsafe { env.store.store() };

    let stdout = {
        let data = env.inner.data(&store);
        data.stdout()
    };

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_env_read_stderr(
    env: &mut wasi_env_t,
    buffer: *mut c_char,
    buffer_len: usize,
) -> isize {
    let inner_buffer = unsafe { slice::from_raw_parts_mut(buffer as *mut _, buffer_len) };
    let store = unsafe { env.store.store() };
    let stderr = {
        let data = env.inner.data(&store);
        data.stderr()
    };
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

impl From<WasiVersion> for wasi_version_t {
    fn from(other: WasiVersion) -> Self {
        match other {
            WasiVersion::Snapshot0 => wasi_version_t::SNAPSHOT0,
            WasiVersion::Snapshot1 => wasi_version_t::SNAPSHOT1,
            WasiVersion::Wasix32v1 => wasi_version_t::WASIX32V1,
            WasiVersion::Wasix64v1 => wasi_version_t::WASIX64V1,
            WasiVersion::Latest => wasi_version_t::LATEST,
        }
    }
}

impl TryFrom<wasi_version_t> for WasiVersion {
    type Error = &'static str;

    fn try_from(other: wasi_version_t) -> Result<Self, Self::Error> {
        Ok(match other {
            wasi_version_t::INVALID_VERSION => return Err("Invalid WASI version cannot be used"),
            wasi_version_t::SNAPSHOT0 => WasiVersion::Snapshot0,
            wasi_version_t::SNAPSHOT1 => WasiVersion::Snapshot1,
            wasi_version_t::WASIX32V1 => WasiVersion::Wasix32v1,
            wasi_version_t::WASIX64V1 => WasiVersion::Wasix64v1,
            wasi_version_t::LATEST => WasiVersion::Latest,
        })
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasi_get_wasi_version(module: &wasm_module_t) -> wasi_version_t {
    get_wasi_version(&module.inner, false)
        .map(Into::into)
        .unwrap_or(wasi_version_t::INVALID_VERSION)
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

    let mut import_object = {
        let mut store_mut = unsafe { store.store_mut() };
        c_try!(wasi_env.inner.import_object(&mut store_mut, &module.inner))
    };

    let shared_memory = module.inner.imports().memories().next().map(|a| *a.ty());

    let spawn_type = match shared_memory {
        Some(ty) => wasmer_wasix::runtime::SpawnType::CreateMemoryOfType(ty),
        None => wasmer_wasix::runtime::SpawnType::CreateMemory,
    };

    let tasks = {
        let store_ref = unsafe { store.store() };
        wasi_env
            .inner
            .data(&store_ref)
            .runtime
            .task_manager()
            .clone()
    };
    let memory = {
        let mut store_mut = unsafe { store.store_mut() };
        tasks.build_memory(&mut store_mut, spawn_type).unwrap()
    };

    if let Some(memory) = memory {
        import_object.define("env", "memory", memory);
    }

    imports_set_buffer(store, &module.inner, import_object, imports)?;

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
    let mut store_mut = unsafe { store.inner.store_mut() };
    wasi_env
        .inner
        .initialize(&mut store_mut, instance.inner.clone())
        .unwrap();
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
                assert(wasi_env_read_stdout(wasi_env, output, sizeof(output)) == 3);
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
}
