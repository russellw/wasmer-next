//! Checks generated Wasmer and WLK bindings against the owned canonical generator
//! and annotated WIT in `lib/wasix/codegen`.
//!
//! Set `WASIXV2_CODEGEN_BLESS=1` to regenerate them.

use std::path::{Path, PathBuf};

use anyhow::Result;
use wasixv2_codegen::{
    Target, generate_abi, generate_exec, generate_syscalls, rust::source_from_header,
};

const ABI_RS: &str = "lib/wasix/abi/src/generated.rs";
const SYSCALLS_RS: &str = "lib/wasix/syscalls/src/generated.rs";
const EXEC_RS: &str = "lib/wasix/exec/src/generated.rs";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn generated_path(path: &str) -> PathBuf {
    for name in ["abi", "syscalls"] {
        if let Some(suffix) = path.strip_prefix(&format!("lib/wasix/{name}/")) {
            return repo_root()
                .join("wlk")
                .join("crates")
                .join(name)
                .join(suffix);
        }
    }
    repo_root().join(path)
}

fn bless() -> bool {
    std::env::var_os("WASIXV2_CODEGEN_BLESS").is_some()
}

/// Regenerates the checked-in `path` from the WIT source recorded in its header.
fn check_generated(
    path: &str,
    generate: fn(&Path, &str, Target) -> Result<String>,
    subcommand: &str,
) {
    let root = repo_root();
    let current = std::fs::read_to_string(generated_path(path)).unwrap();
    let source = source_from_header(&current).expect("generated header names its source");
    let fresh = generate(&root.join(source), source, Target::WASM32).unwrap();
    if bless() {
        std::fs::write(generated_path(path), &fresh).unwrap();
        return;
    }
    assert!(
        fresh == current,
        "{path} is stale; from the repo root run:\n  \
         WASIXV2_CODEGEN_BLESS=1 cargo test -p wasixv2-exec --test generated\n\
         or: cargo run -p wasixv2-codegen -- {subcommand} --wit {source} --out {path}"
    );
}

#[test]
fn abi_is_up_to_date() {
    check_generated(ABI_RS, generate_abi, "abi");
}

#[test]
fn syscalls_is_up_to_date() {
    check_generated(SYSCALLS_RS, generate_syscalls, "syscalls");
}

#[test]
fn exec_is_up_to_date() {
    check_generated(EXEC_RS, generate_exec, "exec");
}
