//! Synchronous native construction owns the same runtime used by its services.
use wasmer_sdk::{CacheConfig, PackageSource, Result, Wasmer, WasmerConfig};
#[test]
fn native_client_constructs_outside_tokio_then_runs_and_closes() -> Result<()> {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let state = tempfile::TempDir::new()?;
    let client = Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().join("cache"),
        },
        output_bytes: 1024,
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // tokio::spawn also checks the public native futures remain Send even
        // though the retained service executor and guest Store are local.
        tokio::spawn(async move {
            let bytes = wat::parse_str(
                r#"(module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit(param i32)))
          (memory(export "memory")1)
          (func(export "_start")(call $exit(i32.const 0))))"#,
            )
            .unwrap();
            let sandbox = client
                .sandboxes()
                .create()
                .package(PackageSource::bytes(bytes))
                .await?;
            assert!(sandbox.command("main").run().await?.ok());
            client.shutdown().await
        })
        .await
        .expect("native public SDK operation did not panic")
    })
}
