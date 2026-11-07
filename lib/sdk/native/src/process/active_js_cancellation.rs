//! Actual public SDK runs; private context access observes cleanup only.
use crate::{
    CacheConfig, ExitReason, Output, PackageCommandDefinition, PackageDefinition, Process, Result,
    Sandbox, Stdio, Wasmer, WasmerConfig,
};
use std::{path::PathBuf, time::Duration};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wasmer_napi::NapiCtx;

const ACTIVE: &str = "test_sdk_js_active_loop";
const ENTERED: &[u8] = b"SDK_JS_ACTIVE_LOOP_ENTERED\n";
const DEADLINE: Duration = Duration::from_secs(60);

fn produced_fixtures() -> PackageDefinition {
    let directory = PathBuf::from(std::env::var_os("NAPI_WASIX_TEST_OUT_DIR").expect(
        "set NAPI_WASIX_TEST_OUT_DIR to build-test-wasix.sh outputs, including test_sdk_js_active_loop",
    ));
    let mut definition = PackageDefinition::default();
    for name in [ACTIVE, "test_callback", "run_script_test"] {
        let path = directory.join(format!("{name}.wasm"));
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("required produced NAPI fixture {}: {error}", path.display())
        });
        definition.modules.insert(name.into(), bytes.into());
        definition.commands.insert(
            name.into(),
            PackageCommandDefinition {
                module: name.into(),
            },
        );
    }
    definition
}

async fn healthy(sandbox: &Sandbox, name: &str, marker: &str) -> Result<(Process, Output)> {
    let mut process = sandbox
        .command(name)
        .stdout(Stdio::Capture)
        .stderr(Stdio::Capture)
        .spawn()
        .await?;
    let output = tokio::time::timeout(DEADLINE, process.wait())
        .await
        .expect("healthy NAPI sibling did not complete")?;
    assert_eq!(output.reason, ExitReason::Exited, "{output:?}");
    assert_eq!(output.status.code(), 0, "{output:?}");
    assert_eq!(output.stdout.text()?, format!("{marker}\n"));
    assert!(!output.stderr.text()?.contains("FAIL"), "{output:?}");
    assert!(!output.stdout.truncated());
    assert!(!output.stderr.truncated());
    assert_eq!(process.wait().await?, output);
    Ok((process, output))
}

fn assert_live(context: &NapiCtx) {
    let usage = context.budget().snapshot();
    assert!(context.active_sessions() > 0);
    assert!(usage.live_isolates > 0, "{usage:?}");
    assert!(usage.wasm_linear > 0, "{usage:?}");
    // The public default context is unlimited, so it owns no finite V8 heap
    // ceiling reservation. Session/isolate and Wasm charges still prove use.
    assert_eq!(usage.mem_total, u64::MAX, "{usage:?}");
    assert_eq!(usage.v8_heap_reserved, 0, "{usage:?}");
    assert!(usage.mem_charged > 0, "{usage:?}");
}

fn assert_retired(context: &NapiCtx) {
    // The cloned context retains only accounting/control metadata, not its
    // Store, NativeLoader or a session. Native isolate retirement uncharges
    // these counters after the physical native destruction acknowledgement.
    let usage = context.budget().snapshot();
    assert_eq!(context.active_sessions(), 0);
    assert_eq!(usage.live_isolates, 0, "{usage:?}");
    assert_eq!(usage.wasm_linear, 0, "{usage:?}");
    assert_eq!(usage.v8_heap_reserved, 0, "{usage:?}");
    assert_eq!(usage.v8_external, 0, "{usage:?}");
    assert_eq!(usage.mem_charged, 0, "{usage:?}");
}

async fn cancel_active_js(close_sandbox: bool) -> Result<()> {
    // No missing-fixture skip or implicit producer invocation.
    let definition = produced_fixtures();
    let state = TempDir::new()?;
    let client = Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().to_owned(),
        },
        ..WasmerConfig::default()
    })?;
    let package = client.packages().create(definition).await?;
    let primary = client.sandboxes().create().package(package.clone()).await?;
    let sibling = client.sandboxes().create().package(package).await?;
    let mut process = primary
        .command(ACTIVE)
        .stdin(Stdio::Piped)
        .stdout(Stdio::Piped)
        .stderr(Stdio::Piped)
        .spawn()
        .await?;
    // Observability only: launch and all control still use public SDK methods.
    let context = process
        .control()
        .napi
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    let mut stdout = process.take_stdout().expect("active JS stdout");
    let mut stderr = process.take_stderr().expect("active JS stderr");
    let mut stdin = process.take_stdin().expect("active JS stdin");
    let mut marker = vec![0; ENTERED.len()];
    tokio::time::timeout(DEADLINE, stdout.read_exact(&mut marker))
        .await
        .expect("evaluated JS did not reach its loop callback")?;
    assert_eq!(marker, ENTERED);
    assert_live(&context);
    assert!(process.try_wait()?.is_none());
    {
        let pending = process.wait();
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
    }
    let mut sibling_process = sibling
        .command(ACTIVE)
        .stdin(Stdio::Piped)
        .stdout(Stdio::Piped)
        .stderr(Stdio::Piped)
        .spawn()
        .await?;
    let sibling_context = sibling_process
        .control()
        .napi
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    let mut sibling_stdout = sibling_process.take_stdout().expect("sibling JS stdout");
    let mut sibling_stderr = sibling_process.take_stderr().expect("sibling JS stderr");
    let mut sibling_stdin = sibling_process.take_stdin().expect("sibling JS stdin");
    tokio::time::timeout(DEADLINE, sibling_stdout.read_exact(&mut marker))
        .await
        .expect("sibling evaluated JS did not reach its loop callback")?;
    assert_eq!(marker, ENTERED);
    assert_live(&sibling_context);
    assert!(sibling_process.try_wait()?.is_none());
    // Waiting-subscription drop must not kill the owner. Independent original
    // NAPI commands complete while that original evaluation remains pending.
    let mut completed = vec![
        healthy(&primary, "test_callback", "TEST_CALLBACK_OK=1").await?,
        healthy(&sibling, "run_script_test", "RUN_SCRIPT_TEST_OK=1").await?,
    ];
    assert_live(&context);
    assert!(process.try_wait()?.is_none());

    if close_sandbox {
        tokio::time::timeout(DEADLINE, primary.close())
            .await
            .expect("sandbox close did not join active JS")?;
    } else {
        process.kill()?;
    }
    let output = tokio::time::timeout(DEADLINE, process.wait())
        .await
        .expect("public wait did not join active JS cancellation")?;
    // Do not convert a primary execution error into a requested status.
    assert_eq!(output.reason, ExitReason::Terminated, "{output:?}");
    assert_eq!(output.status.code(), 137, "{output:?}");
    assert!(!output.stdout.truncated());
    assert!(!output.stderr.truncated());
    assert!(output.stdout.bytes().starts_with(ENTERED), "{output:?}");
    assert!(!output.stdout.text()?.contains("FAIL"), "{output:?}");
    assert!(!output.stderr.text()?.contains("FAIL"), "{output:?}");
    assert_retired(&context);
    let mut rest = Vec::new();
    tokio::time::timeout(DEADLINE, stdout.read_to_end(&mut rest))
        .await
        .expect("joined active JS stdout did not reach EOF")?;
    assert_eq!([ENTERED, rest.as_slice()].concat(), output.stdout.bytes());
    rest.clear();
    tokio::time::timeout(DEADLINE, stderr.read_to_end(&mut rest))
        .await
        .expect("joined active JS stderr did not reach EOF")?;
    assert_eq!(rest, output.stderr.bytes());
    assert_eq!(
        stdin.write_all(b"closed").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(process.wait().await?, output);
    completed.push((process, output));

    // A global terminate-existing-isolates bug could still allow fresh finite
    // admissions. The already-live sibling must survive both the primary
    // cancellation and an independent finite callback run.
    assert_live(&sibling_context);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sibling_process.wait())
            .await
            .is_err()
    );
    completed.push(healthy(&sibling, "test_callback", "TEST_CALLBACK_OK=1").await?);
    assert_live(&sibling_context);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sibling_process.wait())
            .await
            .is_err()
    );
    // Dropping those wait subscriptions must not cancel this owning run.
    assert_live(&sibling_context);
    sibling_process.kill()?;
    let sibling_output = tokio::time::timeout(DEADLINE, sibling_process.wait())
        .await
        .expect("public kill did not join the live sibling JS")?;
    assert_eq!(
        sibling_output.reason,
        ExitReason::Terminated,
        "{sibling_output:?}"
    );
    assert_eq!(sibling_output.status.code(), 137, "{sibling_output:?}");
    assert!(!sibling_output.stdout.truncated());
    assert!(!sibling_output.stderr.truncated());
    assert!(
        sibling_output.stdout.bytes().starts_with(ENTERED),
        "{sibling_output:?}"
    );
    assert!(
        !sibling_output.stdout.text()?.contains("FAIL"),
        "{sibling_output:?}"
    );
    assert!(
        !sibling_output.stderr.text()?.contains("FAIL"),
        "{sibling_output:?}"
    );
    assert_retired(&sibling_context);
    rest.clear();
    tokio::time::timeout(DEADLINE, sibling_stdout.read_to_end(&mut rest))
        .await
        .expect("joined sibling JS stdout did not reach EOF")?;
    assert_eq!(
        [ENTERED, rest.as_slice()].concat(),
        sibling_output.stdout.bytes()
    );
    rest.clear();
    tokio::time::timeout(DEADLINE, sibling_stderr.read_to_end(&mut rest))
        .await
        .expect("joined sibling JS stderr did not reach EOF")?;
    assert_eq!(rest, sibling_output.stderr.bytes());
    assert_eq!(
        sibling_stdin.write_all(b"closed").await.unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(sibling_process.wait().await?, sibling_output);
    completed.push((sibling_process, sibling_output));
    completed.push(healthy(&sibling, "run_script_test", "RUN_SCRIPT_TEST_OK=1").await?);
    primary.close().await?;
    primary.close().await?;
    sibling.close().await?;
    client.shutdown().await?;
    client.shutdown().await?;
    for (mut process, output) in completed {
        assert_eq!(process.wait().await?, output);
    }
    assert_retired(&context);
    assert_retired(&sibling_context);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn public_kill_joins_active_js_and_releases_its_budget() -> Result<()> {
    cancel_active_js(false).await
}

#[tokio::test(flavor = "multi_thread")]
async fn public_sandbox_close_joins_active_js_and_preserves_siblings() -> Result<()> {
    cancel_active_js(true).await
}
