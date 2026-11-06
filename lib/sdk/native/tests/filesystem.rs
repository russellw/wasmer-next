//! Canonical guest append flags through the public SDK Directory provider.
//! WAT syscall imports follow lib/wasix/api/tests/package.rs and the owned WIT.
use wasmer_sdk::{CacheConfig, PackageSource, Result, Wasmer, WasmerConfig};

const APPEND_FLAGS: &str = r#"(module
  (import "wasixv2" "openat" (func $open(param i32 i32 i32 i32)(result i32)))
  (import "wasixv2" "fcntl64" (func $fcntl(param i32 i32 i32)(result i32)))
  (import "wasixv2" "lseek" (func $seek(param i32 i64 i32)(result i64)))
  (import "wasixv2" "write" (func $write(param i32 i32 i32)(result i32)))
  (import "wasixv2" "read" (func $read(param i32 i32 i32)(result i32)))
  (import "wasixv2" "pwritev2" (func $pwrite(param i32 i32 i32 i64 i32)(result i32)))
  (import "wasixv2" "exit_group" (func $exit(param i32)))
  (memory(export "memory")1)
  (data(i32.const 16)"append\00")
  (data(i32.const 32)"ABCDEFGH")
  (func $zero(param $n i32)(if(local.get $n)(then(call $exit(i32.const 99)))))
  (func $one(param $n i32)(call $zero(i32.ne(local.get $n)(i32.const 1))))
  (func(export "_start")(local $fd i32)(local $append i32)
    (local.set $fd(call $open(i32.const -100)(i32.const 16)(i32.const 2)(i32.const 0)))
    (call $zero(i32.lt_s(local.get $fd)(i32.const 0)))
    (call $one(call $write(local.get $fd)(i32.const 32)(i32.const 1)))
    ;; F_SETFL adds append to a handle originally opened without it.
    (call $zero(call $fcntl(local.get $fd)(i32.const 4)(i32.const 1024)))
    (call $one(call $write(local.get $fd)(i32.const 33)(i32.const 1)))
    (call $zero(call $fcntl(local.get $fd)(i32.const 4)(i32.const 0)))
    (call $zero(i64.ne(call $seek(local.get $fd)(i64.const 0)(i32.const 0))(i64.const 0)))
    (call $one(call $write(local.get $fd)(i32.const 34)(i32.const 1)))
    (call $zero(call $fcntl(local.get $fd)(i32.const 4)(i32.const 1024)))
    (i32.store(i32.const 80)(i32.const 35))
    (i32.store(i32.const 84)(i32.const 1))
    ;; RWF_NOAPPEND and RWF_APPEND use explicit offsets, preserving the fd cursor.
    (call $one(call $pwrite(local.get $fd)(i32.const 80)(i32.const 1)(i64.const 1)(i32.const 32)))
    (i32.store(i32.const 80)(i32.const 36))
    (call $one(call $pwrite(local.get $fd)(i32.const 80)(i32.const 1)(i64.const 0)(i32.const 16)))
    (call $zero(call $fcntl(local.get $fd)(i32.const 4)(i32.const 0)))
    (call $one(call $write(local.get $fd)(i32.const 37)(i32.const 1)))
    ;; A handle born with O_APPEND must still support positioned overrides.
    (local.set $append(call $open(i32.const -100)(i32.const 16)(i32.const 1026)(i32.const 0)))
    (call $zero(i32.lt_s(local.get $append)(i32.const 0)))
    (i32.store(i32.const 80)(i32.const 38))
    (call $one(call $pwrite(local.get $append)(i32.const 80)(i32.const 1)(i64.const 2)(i32.const 32)))
    (call $zero(call $fcntl(local.get $append)(i32.const 4)(i32.const 0)))
    (call $zero(i64.ne(call $seek(local.get $append)(i64.const 0)(i32.const 0))(i64.const 0)))
    (call $one(call $write(local.get $append)(i32.const 39)(i32.const 1)))
    (call $zero(i64.ne(call $seek(local.get $fd)(i64.const 0)(i32.const 0))(i64.const 0)))
    (call $zero(i32.ne(call $read(local.get $fd)(i32.const 128)(i32.const 32))(i32.const 6)))
    (drop(call $write(i32.const 1)(i32.const 128)(i32.const 6)))
    (call $exit(i32.const 0))))"#;

#[tokio::test(flavor = "multi_thread")]
async fn canonical_guest_append_flags_use_real_offsets_without_sdk_cursor_state() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            ..Default::default()
        })?;
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(wat::parse_str(APPEND_FLAGS).unwrap()))
            .await?;
        sandbox.fs().write_text("append", "seed").await?;
        assert_eq!(sandbox.command("main").run().await?.text()?, "HFGdBE");
        assert_eq!(sandbox.fs().read_text("append").await?, "HFGdBE");
        sandbox.close().await?;
        client.shutdown().await?;
        Ok(())
    })
    .await
    .expect("guest append/positioned operations must retire")
}
