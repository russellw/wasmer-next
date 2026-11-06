//! Per-run provider custody follows the public SDK rather than a shared Net owner.
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use virtual_net::{VirtualNetworking, VirtualTcpSocket};
use wasmer_sdk::{CacheConfig, ExitReason, PackageSource, Result, Wasmer, WasmerConfig};

// Linux ABI sockaddr and connect sequence follows api/tests/net.rs.
const CONNECT_WAT: &str = r#"(module
  (import "wasixv2" "socket" (func $socket(param i32 i32 i32)(result i32)))
  (import "wasixv2" "connect" (func $connect(param i32 i32 i32)(result i32)))
  (memory(export "memory")1)
  (data(i32.const 16)"\02\00\01\bb\c6\33\64\50\00\00\00\00\00\00\00\00")
  (func(export "_start")
    (drop(call $connect(call $socket(i32.const 2)(i32.const 1)(i32.const 0))(i32.const 16)(i32.const 16)))))"#;
#[derive(Debug)]
struct PendingProvider {
    started: Semaphore,
    canceled: Arc<AtomicUsize>,
}
struct Canceled(Arc<AtomicUsize>);
impl Drop for Canceled {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl VirtualNetworking for PendingProvider {
    async fn connect_tcp(
        &self,
        _local: SocketAddr,
        _peer: SocketAddr,
    ) -> virtual_net::Result<Box<dyn VirtualTcpSocket + Sync>> {
        let _canceled = Canceled(self.canceled.clone());
        self.started.add_permits(1);
        std::future::pending().await
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn killed_run_joins_its_network_admission_without_canceling_a_sibling() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            output_bytes: 1024,
        })?;
        let provider = Arc::new(PendingProvider {
            started: Semaphore::new(0),
            canceled: Arc::new(AtomicUsize::new(0)),
        });
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(wat::parse_str(CONNECT_WAT).unwrap()))
            .network_provider(provider.clone())
            .await?;
        let mut first = sandbox.command("main").spawn().await?;
        let mut second = sandbox.command("main").spawn().await?;
        provider.started.acquire_many(2).await.unwrap().forget();
        first.kill()?;
        let result = first.wait().await?;
        assert_eq!(result.reason, ExitReason::Terminated);
        assert_eq!(
            provider.canceled.load(Ordering::SeqCst),
            1,
            "wait joins the killed run's actual provider future"
        );
        assert!(
            second.try_wait()?.is_none(),
            "a private network cutoff must not cancel a sibling run"
        );
        second.kill()?;
        second.wait().await?;
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 2);
        client.shutdown().await?;
        Ok(())
    })
    .await
    .expect("private run network cleanup made progress")
}
#[tokio::test(flavor = "multi_thread")]
async fn disabled_networking_denies_even_private_loopback_bind() -> Result<()> {
    let state = tempfile::TempDir::new()?;
    let client = Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().join("cache"),
        },
        output_bytes: 1024,
    })?;
    let bytes=wat::parse_str(r#"(module
      (import "wasixv2" "socket" (func $socket(param i32 i32 i32)(result i32)))
      (import "wasixv2" "bind" (func $bind(param i32 i32 i32)(result i32)))
      (import "wasixv2" "exit_group" (func $exit(param i32)))
      (memory(export "memory")1)
      (data(i32.const 16)"\02\00\1f\90\7f\00\00\01\00\00\00\00\00\00\00\00")
      (func(export "_start")
        (if(i32.ge_s(call $bind(call $socket(i32.const 2)(i32.const 1)(i32.const 0))(i32.const 16)(i32.const 16))(i32.const 0))
          (then(call $exit(i32.const 99))))))"#).unwrap();
    let sandbox = client
        .sandboxes()
        .create()
        .package(PackageSource::bytes(bytes))
        .await?;
    assert!(sandbox.command("main").run().await?.ok());
    client.shutdown().await
}
