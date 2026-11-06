//! Runs an externally built, unchanged C consumer on the v1 compatibility adapter.
//!
//! Keep compiler flags and source hashes with the artifact. This harness does not
//! rebuild or substitute fixtures; original-v1 and rebuilt-v2 runs are separate evidence.

#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;
use wasixv2::{Machine, ProcessConfig, Stdio};

// Uses the same host-directory/Machine entry path as tests/dynamic.rs.
#[test]
#[ignore = "requires an explicitly built consumer artifact and producer provenance"]
fn externally_built_consumer() {
    let artifact = PathBuf::from(
        std::env::var_os("WASIXV2_CONSUMER").expect("set WASIXV2_CONSUMER to the guest artifact"),
    )
    .canonicalize()
    .expect("consumer artifact exists");
    let profile = std::env::var("WASIXV2_CONSUMER_PROFILE")
        .expect("label WASIXV2_CONSUMER_PROFILE as original-v1 or rebuilt-v2");
    assert!(matches!(profile.as_str(), "original-v1" | "rebuilt-v2"));
    eprintln!("consumer profile={profile} artifact={}", artifact.display());
    let name = artifact.file_name().unwrap().to_str().unwrap();
    let guest_path = format!("/consumer/{name}");
    let expected: i32 = std::env::var("WASIXV2_CONSUMER_STATUS")
        .expect("set WASIXV2_CONSUMER_STATUS to the original expected exit status")
        .parse()
        .unwrap();
    let mut args = vec![guest_path.clone()];
    if let Ok(extra) = std::env::var("WASIXV2_CONSUMER_ARGS") {
        args.extend(extra.lines().map(str::to_owned));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let status = tokio::task::LocalSet::new().block_on(&runtime, async {
        let mut machine = Machine::new();
        // Original fixture subprocesses resolve siblings such as ./main.wasm.
        machine.set_working_dir("/consumer");
        machine
            .mount_host_dir("/consumer", artifact.parent().unwrap(), false)
            .await
            .unwrap();
        machine
            .run_file(
                &wasmer::Engine::default(),
                &guest_path,
                ProcessConfig {
                    args,
                    env: vec!["LD_LIBRARY_PATH=/consumer".into()],
                    stdio: Stdio::from_fns(
                        |bytes| print!("{}", String::from_utf8_lossy(bytes)),
                        |bytes| eprint!("{}", String::from_utf8_lossy(bytes)),
                    ),
                },
            )
            .await
            .expect("original consumer loads and runs")
    });
    assert_eq!(status, expected, "consumer {}", artifact.display());
}
