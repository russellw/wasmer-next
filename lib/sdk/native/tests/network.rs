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
use wasmer_sdk::network_api::{NetworkError, NetworkProvider, NetworkResult, TcpStream, WaitQueue};
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
impl NetworkProvider for PendingProvider {
    async fn connect_tcp(
        &self,
        _local: SocketAddr,
        _peer: SocketAddr,
        _queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
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
          (then(call $exit(i32.const 99))))
        (call $exit(i32.const 0))))"#).unwrap();
    let sandbox = client
        .sandboxes()
        .create()
        .package(PackageSource::bytes(bytes))
        .await?;
    assert!(sandbox.command("main").run().await?.ok());
    client.shutdown().await
}

type ResolveCall = (String, Option<u16>, Option<std::net::IpAddr>);

/// Resolver fixture uses the retained public provider API; no direct Kernel/Instance path.
#[derive(Debug)]
struct DnsProvider {
    calls: std::sync::Mutex<Vec<ResolveCall>>,
    error: Option<NetworkError>,
    pending: bool,
    started: Semaphore,
    canceled: Arc<AtomicUsize>,
}
impl DnsProvider {
    fn new(error: Option<NetworkError>, pending: bool) -> Self {
        Self {
            calls: std::sync::Mutex::default(),
            error,
            pending,
            started: Semaphore::new(0),
            canceled: Arc::new(AtomicUsize::new(0)),
        }
    }
}
#[async_trait]
impl NetworkProvider for DnsProvider {
    async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        dns_server: Option<std::net::IpAddr>,
    ) -> NetworkResult<Vec<std::net::IpAddr>> {
        self.calls
            .lock()
            .unwrap()
            .push((host.into(), port, dns_server));
        if self.pending {
            let _canceled = Canceled(self.canceled.clone());
            self.started.add_permits(1);
            std::future::pending::<()>().await;
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        Ok(vec![
            "192.0.2.9".parse().unwrap(),
            "2001:db8::9".parse().unwrap(),
        ])
    }
}
fn resolve_guest(port: i32, expected_errno: u32) -> Vec<u8> {
    wat::parse_str(format!(r#"(module
      (import "wasix_32v1" "resolve" (func $resolve(param i32 i32 i32 i32 i32 i32)(result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit(param i32)))
      (memory(export "memory")1)
      (data(i32.const 16)"MiXeD.Invalid.")
      (func(export "_start")
        (if(i32.ne(call $resolve(i32.const 16)(i32.const 14)(i32.const {port})(i32.const 64)(i32.const 1)(i32.const 100))(i32.const {expected_errno}))
          (then(call $exit(i32.const 91))))
        {check}
        (call $exit(i32.const 0))))"#,
        check = if expected_errno == 0 { r#"
        (if(i32.ne(i32.load(i32.const 100))(i32.const 1))(then(call $exit(i32.const 92))))
        (if(i32.ne(i32.load8_u(i32.const 64))(i32.const 1))(then(call $exit(i32.const 93))))
        (if(i32.ne(i32.load align=1(i32.const 66))(i32.const 0x090200c0))(then(call $exit(i32.const 94))))"# } else { "" }
    )).unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn v1_resolve_preserves_custom_provider_original_name_port_and_authoritative_errors()
-> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            output_bytes: 1024,
        })?;
        let provider = Arc::new(DnsProvider::new(None, false));
        for port in [443, 0, 65536 + 443, -1, 65536] {
            let sandbox = client
                .sandboxes()
                .create()
                .package(PackageSource::bytes(resolve_guest(port, 0)))
                .network_provider(provider.clone())
                .await?;
            let output = sandbox.command("main").output().await?;
            assert_eq!(output.status.code(), 0);
            assert_eq!(output.reason, ExitReason::Exited);
            sandbox.close().await?;
        }
        assert_eq!(
            *provider.calls.lock().unwrap(),
            vec![
                ("MiXeD.Invalid.".into(), Some(443), None),
                ("MiXeD.Invalid.".into(), None, None),
                ("MiXeD.Invalid.".into(), Some(443), None),
                ("MiXeD.Invalid.".into(), Some(65535), None),
                ("MiXeD.Invalid.".into(), None, None),
            ]
        );
        for (error, errno) in [(NetworkError::EOPNOTSUPP, 58), (NetworkError::EACCES, 2)] {
            let denied = Arc::new(DnsProvider::new(Some(error), false));
            let sandbox = client
                .sandboxes()
                .create()
                .package(PackageSource::bytes(resolve_guest(443, errno)))
                .network_provider(denied.clone())
                .await?;
            assert_eq!(sandbox.command("main").run().await?.status.code(), 0);
            assert_eq!(
                denied.calls.lock().unwrap().len(),
                1,
                "a selected provider error never falls back to wire DNS"
            );
            sandbox.close().await?;
        }
        client.shutdown().await
    })
    .await
    .expect("public SDK contextual DNS completed")
}
#[tokio::test(flavor = "multi_thread")]
async fn killed_v1_resolver_joins_its_provider_future_and_keeps_sibling_live() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let state = tempfile::TempDir::new()?;
        let client = Wasmer::with_config(WasmerConfig {
            cache: CacheConfig {
                root: state.path().join("cache"),
            },
            output_bytes: 1024,
        })?;
        let provider = Arc::new(DnsProvider::new(None, true));
        let sandbox = client
            .sandboxes()
            .create()
            .package(PackageSource::bytes(resolve_guest(443, 0)))
            .network_provider(provider.clone())
            .await?;
        let mut first = sandbox.command("main").spawn().await?;
        let mut second = sandbox.command("main").spawn().await?;
        provider.started.acquire_many(2).await.unwrap().forget();
        first.kill()?;
        assert_eq!(first.wait().await?.reason, ExitReason::Terminated);
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 1);
        assert!(second.try_wait()?.is_none());
        second.kill()?;
        second.wait().await?;
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 2);
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("public SDK DNS cancellation joined provider ownership")
}
