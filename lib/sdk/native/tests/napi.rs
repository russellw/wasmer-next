//! Original produced NAPI guests through the public Linux native SDK.
//! Set NAPI_WASIX_TEST_OUT_DIR to the existing output of
//! lib/napi/tests/build-test-wasix.sh; this target never builds or skips fixtures.
//! These finite success cases do not prove cancellation of already executing JS.

#![cfg(all(feature = "napi-v8", target_os = "linux"))]

use std::{path::PathBuf, time::Duration};

use tempfile::TempDir;
use wasmer_sdk::{
    CacheConfig, ExitReason, Output, PackageCommandDefinition, PackageDefinition, Process, Result,
    Sandbox, Stdio, Wasmer, WasmerConfig,
};

const CASES: [(&str, &str); 3] = [
    ("hello_napi_test", "HELLO_NAPI_TEST_OK=1"),
    ("test_callback", "TEST_CALLBACK_OK=1"),
    ("run_script_test", "RUN_SCRIPT_TEST_OK=1"),
];

fn original_fixture_package() -> PackageDefinition {
    let directory = PathBuf::from(std::env::var_os("NAPI_WASIX_TEST_OUT_DIR").expect(
        "set NAPI_WASIX_TEST_OUT_DIR to already-produced lib/napi/tests/build-test-wasix.sh assets",
    ));
    let mut definition = PackageDefinition::default();
    for (name, _) in CASES {
        let path = directory.join(format!("{name}.wasm"));
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!("required original fixture {}: {error}", path.display())
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

async fn completed_fixture(
    sandbox: &Sandbox,
    name: &str,
    marker: &str,
) -> Result<(Process, Output)> {
    let mut process = sandbox
        .command(name)
        .stdin(Stdio::Null)
        .stdout(Stdio::Capture)
        .stderr(Stdio::Capture)
        .spawn()
        .await?;
    let output = tokio::time::timeout(Duration::from_secs(60), process.wait())
        .await
        .unwrap_or_else(|_| panic!("original NAPI fixture {name} did not finish"))?;
    assert_eq!(output.status.code(), 0, "{name}: {output:?}");
    assert_eq!(output.reason, ExitReason::Exited, "{name}: {output:?}");
    assert!(!output.stdout.truncated(), "{name}: {output:?}");
    assert!(!output.stderr.truncated(), "{name}: {output:?}");
    let stdout = output.stdout.text()?;
    let stderr = output.stderr.text()?;
    assert_eq!(stdout, format!("{marker}\n"), "{name}");
    assert!(!stdout.contains("FAIL"), "{name}: {output:?}");
    assert!(!stderr.contains("FAIL"), "{name}: {output:?}");
    assert_eq!(process.wait().await?, output, "cached wait for {name}");
    Ok((process, output))
}

#[tokio::test(flavor = "multi_thread")]
async fn original_napi_success_fixtures_repeat_across_public_sandboxes() -> Result<()> {
    // Read every required asset before creating any runtime owner.
    let definition = original_fixture_package();
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
    let mut completed = Vec::new();
    // Retain the public completed owners while later admissions reuse the same
    // client, package and sandbox. Each NAPI context still belongs to its run.
    for index in [0, 1, 2, 2, 1] {
        let (name, marker) = CASES[index];
        completed.push(completed_fixture(&primary, name, marker).await?);
    }
    primary.close().await?;
    // Closing one sandbox must leave the independently owned sibling healthy.
    for (name, marker) in CASES {
        completed.push(completed_fixture(&sibling, name, marker).await?);
    }
    sibling.close().await?;
    client.shutdown().await?;
    // Successful waits remain cached after all service and sandbox owners close.
    for (mut process, output) in completed {
        assert_eq!(process.wait().await?, output);
    }
    Ok(())
}
