//! The SDK's import-free initial command uses the ordinary protected run owner.
use std::time::Duration;
use tempfile::TempDir;
use wasmer_sdk::{
    CacheConfig, Error, ExitReason, Output, PackageCommandDefinition, PackageDefinition, Result,
    Wasmer, WasmerConfig,
};

const MEMORY_COMMAND: &str = r#"(module
  (memory (export "memory") 1 2)
  (data (i32.const 0) "raw")
  (func (export "_initialize")
    i32.const 4 i32.const 73 i32.store)
  (func (export "_start")
    i32.const 0 i32.load8_u i32.const 114 i32.ne
    if unreachable end
    i32.const 4 i32.load i32.const 73 i32.ne
    if unreachable end
    i32.const 1 memory.grow i32.const 1 i32.ne
    if unreachable end
    i32.const 65536 i32.const 91 i32.store
    i32.const 65536 i32.load i32.const 91 i32.ne
    if unreachable end))"#;

fn client() -> (Wasmer, TempDir) {
    let state = TempDir::new().unwrap();
    let client = Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().to_owned(),
        },
        ..WasmerConfig::default()
    })
    .unwrap();
    (client, state)
}

fn definition(wasm: Vec<u8>) -> PackageDefinition {
    PackageDefinition {
        modules: [("atom".into(), wasm.into())].into(),
        commands: [(
            "raw".into(),
            PackageCommandDefinition {
                module: "atom".into(),
            },
        )]
        .into(),
        ..PackageDefinition::default()
    }
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), 0);
    assert_eq!(output.reason, ExitReason::Exited);
    assert!(output.stdout.bytes().is_empty());
    assert!(output.stderr.bytes().is_empty());
    assert!(!output.stdout.truncated());
    assert!(!output.stderr.truncated());
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_bytes_and_defined_commands_initialize_memory_and_return_zero() -> Result<()> {
    let (client, _state) = client();
    let wasm = wat::parse_str(MEMORY_COMMAND).unwrap();
    let raw = client.packages().load(wasm.clone()).await?;
    let defined = client.packages().create(definition(wasm)).await?;
    let sandbox = client.sandboxes().create().package(raw.clone()).await?;
    sandbox.install_package(defined.clone()).await?;
    // Repeat both source forms through the same client/cache and private run owners.
    for package in [raw.clone(), defined.clone(), raw, defined] {
        let output =
            tokio::time::timeout(Duration::from_secs(10), sandbox.command(package).output())
                .await
                .expect("import-free command did not complete")?;
        assert_success(&output);
    }
    sandbox.close().await?;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn entry_return_values_preserve_the_original_untyped_call_contract() -> Result<()> {
    let (client, _state) = client();
    // The original runner calls both exports with [] and ignores successful Values.
    let package = client
        .packages()
        .create(definition(
            wat::parse_str(
                r#"(module (memory (export "memory") 1)
                (func (export "_initialize") (result i32) i32.const 9)
                (func (export "_start") (result i32) i32.const 7))"#,
            )
            .unwrap(),
        ))
        .await?;
    let sandbox = client.sandboxes().create().package(package.clone()).await?;
    let output = tokio::time::timeout(Duration::from_secs(10), sandbox.command(package).output())
        .await
        .expect("entry return did not complete")?;
    assert_success(&output);
    sandbox.close().await?;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_entry_memory_and_traps_remain_failures_and_do_not_poison_siblings() -> Result<()>
{
    let (client, _state) = client();
    let healthy = client
        .packages()
        .create(definition(wat::parse_str(MEMORY_COMMAND).unwrap()))
        .await?;
    let sandbox = client.sandboxes().create().package(healthy.clone()).await?;
    // Bind/format failures use Error::Execution. Once entry runs, the canonical
    // executor reports traps as process statuses: SIGSEGV for a bad call shape,
    // SIGILL for unreachable. These are not legacy runner error-code mappings.
    for (source, guest_status) in [
        (r#"(module (func (export "_start")))"#, None),
        (
            r#"(module (memory (export "memory") 1)
            (func (export "_start") (param i32)))"#,
            Some(139),
        ),
        (
            r#"(module (memory (export "memory") 1)
            (func (export "_initialize") (param i32)) (func (export "_start")))"#,
            Some(139),
        ),
        (
            r#"(module (memory (export "memory") 1)
            (func (export "_initialize") unreachable) (func (export "_start")))"#,
            Some(132),
        ),
        (
            r#"(module (memory (export "memory") 1)
            (func (export "_start") unreachable))"#,
            Some(132),
        ),
        // An original imported helper does not opt in, even if it spoofs the
        // instrumenter's namespace and the expected preempt signature.
        (
            r#"(module (import "wasixv2-exec" "preempt" (func (result i32)))
            (memory (export "memory") 1) (func (export "_start")))"#,
            None,
        ),
        (
            r#"(module (import "foreign" "callback" (func))
            (memory (export "memory") 1) (func (export "_start")))"#,
            None,
        ),
    ] {
        let package = client
            .packages()
            .create(definition(wat::parse_str(source).unwrap()))
            .await?;
        sandbox.install_package(package.clone()).await?;
        let outcome =
            tokio::time::timeout(Duration::from_secs(10), sandbox.command(package).output())
                .await
                .expect("failed initial command did not retire");
        if let Some(status) = guest_status {
            let output = outcome.expect("guest entry must run before reporting its fault");
            assert_eq!(output.status.code(), status, "{source}");
            assert_eq!(output.reason, ExitReason::Exited, "{source}");
        } else {
            assert!(
                matches!(&outcome, Err(Error::Execution { .. })),
                "expected startup/format failure for {source}: {outcome:?}"
            );
        }
        assert_success(&sandbox.command(healthy.clone()).output().await?);
    }
    sandbox.close().await?;
    client.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_import_free_commands_keep_preemption_cached_wait_and_sibling_owners() -> Result<()> {
    let (client, _state) = client();
    let busy = client
        .packages()
        .create(definition(
            wat::parse_str(
                r#"(module (memory (export "memory") 1)
                (func (export "_start") (loop $busy br $busy)))"#,
            )
            .unwrap(),
        ))
        .await?;
    let healthy = client
        .packages()
        .create(definition(wat::parse_str(MEMORY_COMMAND).unwrap()))
        .await?;
    let sandbox = client.sandboxes().create().package(busy.clone()).await?;
    let sibling = client.sandboxes().create().package(healthy.clone()).await?;
    let mut process = sandbox.command(busy.clone()).spawn().await?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_success(&sibling.command(healthy.clone()).output().await?);
    process.kill()?;
    let output = tokio::time::timeout(Duration::from_secs(10), process.wait())
        .await
        .expect("busy initial command did not join after kill")?;
    assert_eq!(output.reason, ExitReason::Terminated);
    assert_eq!(output.status.code(), 137);
    let cached = process.wait().await?;
    assert_eq!(cached.reason, output.reason);
    assert_eq!(cached.status.code(), output.status.code());
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        sandbox
            .command(busy)
            .timeout(Duration::from_millis(25))
            .output(),
    )
    .await
    .expect("busy initial command did not join after timeout")?;
    assert_eq!(output.reason, ExitReason::TimedOut);
    assert_eq!(output.status.code(), 137);
    assert_success(&sibling.command(healthy).output().await?);
    sandbox.close().await?;
    sibling.close().await?;
    client.shutdown().await?;
    Ok(())
}
