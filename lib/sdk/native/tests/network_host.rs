//! Public SDK socket calls against the native host provider.
use async_trait::async_trait;
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use std::{
    fmt,
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as HostTcpListener,
        TcpStream as HostTcpStream, UdpSocket as HostUdpSocket,
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, Semaphore},
};
use wasixv2_abi::{GuestLayout, IpMreqn};
use wasixv2_vnet::{Shutdown, StreamState};
use wasmer_sdk::{
    CacheConfig, ExitReason, NetworkResult, PackageSource, Result, Sandbox, Stdio, Wasmer,
    WasmerConfig,
    network_api::{
        BackendDatagram, BackendStream, BoundTcp, DatagramInfo, DatagramReceiveLease,
        DatagramReceiver, DynNetworkProvider, HostNetwork, NetworkCloseMode, NetworkProvider,
        PollMask, PollTable, Pollable, TcpListener, TcpStream, UdpSocket, WaitQueue,
    },
};

const SOCKET_HELPERS: &str = r#"
  (func $fail (param $step i32) (param $error i32)
    (call $exit
      (i32.or
        (i32.shl (local.get $step) (i32.const 8))
        (local.get $error)))
    unreachable)

  (func $check (param $value i32) (param $step i32) (result i32)
    (if (i32.lt_s (local.get $value) (i32.const 0))
      (then
        (call $fail
          (local.get $step)
          (i32.sub (i32.const 0) (local.get $value)))))
    (local.get $value))

  (func $read_all (param $fd i32) (param $buffer i32) (param $length i32) (param $step i32)
    (local $done i32)
    (local $count i32)
    (block $complete
      (loop $again
        (br_if $complete
          (i32.ge_u (local.get $done) (local.get $length)))
        (local.set $count
          (call $check
            (call $read
              (local.get $fd)
              (i32.add (local.get $buffer) (local.get $done))
              (i32.sub (local.get $length) (local.get $done)))
            (local.get $step)))
        (if (i32.eqz (local.get $count))
          (then (call $fail (local.get $step) (i32.const 254))))
        (local.set $done
          (i32.add (local.get $done) (local.get $count)))
        (br $again))))

  (func $write_all (param $fd i32) (param $buffer i32) (param $length i32) (param $step i32)
    (local $done i32)
    (local $count i32)
    (block $complete
      (loop $again
        (br_if $complete
          (i32.ge_u (local.get $done) (local.get $length)))
        (local.set $count
          (call $check
            (call $write
              (local.get $fd)
              (i32.add (local.get $buffer) (local.get $done))
              (i32.sub (local.get $length) (local.get $done)))
            (local.get $step)))
        (if (i32.eqz (local.get $count))
          (then (call $fail (local.get $step) (i32.const 253))))
        (local.set $done
          (i32.add (local.get $done) (local.get $count)))
        (br $again))))
"#;

const SOCKET_IMPORTS: &str = r#"
  (import "wasixv2" "socket" (func $socket (param i32 i32 i32) (result i32)))
  (import "wasixv2" "bind" (func $bind (param i32 i32 i32) (result i32)))
  (import "wasixv2" "listen" (func $listen (param i32 i32) (result i32)))
  (import "wasixv2" "accept" (func $accept (param i32 i32 i32) (result i32)))
  (import "wasixv2" "connect" (func $connect (param i32 i32 i32) (result i32)))
  (import "wasixv2" "getsockname" (func $getsockname (param i32 i32 i32) (result i32)))
  (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "sendto" (func $sendto (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "recvfrom" (func $recvfrom (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "setsockopt" (func $setsockopt (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "close" (func $close (param i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit (param i32)))
"#;

fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02x}")).collect()
}

fn sockaddr_bytes(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(if address.is_ipv4() { 16 } else { 28 });
    match address {
        SocketAddr::V4(address) => {
            bytes.extend_from_slice(&[2, 0]);
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&[0; 8]);
        }
        SocketAddr::V6(address) => {
            bytes.extend_from_slice(&[10, 0]);
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.scope_id().to_le_bytes());
        }
    }
    bytes
}

fn data_segment(offset: u32, bytes: &[u8]) -> String {
    format!("(data (i32.const {offset}) \"{}\")", wat_bytes(bytes))
}

fn module(imports: &str, data: &str, body: &str) -> Vec<u8> {
    wat::parse_str(format!(
        "(module {SOCKET_IMPORTS} {imports} (memory (export \"memory\") 1) \
         {data} {SOCKET_HELPERS} (func (export \"_start\") {body}))"
    ))
    .expect("network WAT fixture parses")
}

fn tcp_client_wat(peer: SocketAddr, local_bind: Option<SocketAddr>, reuse_addr: bool) -> Vec<u8> {
    tcp_client_wat_with_source(peer, local_bind, reuse_addr, false)
}

fn tcp_client_wat_with_source(
    peer: SocketAddr,
    local_bind: Option<SocketAddr>,
    reuse_addr: bool,
    publish_source: bool,
) -> Vec<u8> {
    let peer_bytes = sockaddr_bytes(peer);
    let peer_len = peer_bytes.len();
    let family = if peer.is_ipv4() { 2 } else { 10 };
    let mut data = data_segment(16, &peer_bytes);
    data.push_str(&data_segment(160, b"ping"));
    data.push_str(&data_segment(168, b"pong"));
    data.push_str(&data_segment(140, &1_i32.to_le_bytes()));

    let bind = if let Some(local) = local_bind {
        let local_bytes = sockaddr_bytes(local);
        let local_len = local_bytes.len();
        let local_family = if local.is_ipv4() { 2 } else { 10 };
        data.push_str(&data_segment(48, &local_bytes));
        format!(
            r#"
            (if (i32.ne (i32.const {family}) (i32.const {local_family}))
              (then (call $fail (i32.const 21) (i32.const 1))))
            {reuse}
            (drop (call $check
              (call $bind (local.get $fd) (i32.const 48) (i32.const {local_len}))
              (i32.const 22)))
            (i32.store (i32.const 128) (i32.const {local_len}))
            (drop (call $check
              (call $getsockname (local.get $fd) (i32.const 80) (i32.const 128))
              (i32.const 23)))
            (call $write_all (i32.const 1) (i32.const 82) (i32.const 2) (i32.const 24))
            "#,
            family = family,
            local_family = local_family,
            local_len = local_len,
            reuse = if reuse_addr {
                r#"(drop (call $check
                  (call $setsockopt (local.get $fd) (i32.const 1) (i32.const 2)
                    (i32.const 140) (i32.const 4))
                  (i32.const 20)))"#
            } else {
                ""
            }
        )
    } else {
        String::new()
    };

    let source = if publish_source {
        r#"(i32.store (i32.const 128) (i32.const 16))
        (drop (call $check
          (call $getsockname (local.get $fd) (i32.const 80) (i32.const 128))
          (i32.const 26)))
        (call $write_all (i32.const 1) (i32.const 80) (i32.const 16) (i32.const 27))"#
    } else {
        ""
    };
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local.set $fd
              (call $check (call $socket (i32.const {family}) (i32.const 1) (i32.const 0))
                (i32.const 1)))
            {bind}
            (drop (call $check
              (call $connect (local.get $fd) (i32.const 16) (i32.const {peer_len}))
              (i32.const 2)))
            {source}
            (call $write_all (local.get $fd) (i32.const 160) (i32.const 4) (i32.const 3))
            (call $read_all (local.get $fd) (i32.const 168) (i32.const 4) (i32.const 4))
            (if (i32.ne (i32.load (i32.const 168)) (i32.const 0x676e6f70))
              (then (call $fail (i32.const 5) (i32.const 1))))
            (drop (call $check (call $close (local.get $fd)) (i32.const 6)))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn tcp_linger_exit_wat(peer: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let peer_bytes = sockaddr_bytes(peer);
    let peer_len = peer_bytes.len();
    let family = if peer.is_ipv4() { 2 } else { 10 };
    let payload_len = payload.len();
    let mut data = data_segment(16, &peer_bytes);
    data.push_str(&data_segment(
        140,
        &[1, 0, 0, 0, 2, 0, 0, 0], // enabled SO_LINGER, two seconds
    ));
    data.push_str(&data_segment(160, payload));
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local.set $fd
              (call $check (call $socket (i32.const {family}) (i32.const 1) (i32.const 0))
                (i32.const 1)))
            (drop (call $check
              (call $setsockopt (local.get $fd) (i32.const 1) (i32.const 13)
                (i32.const 140) (i32.const 8))
              (i32.const 2)))
            (drop (call $check
              (call $connect (local.get $fd) (i32.const 16) (i32.const {peer_len}))
              (i32.const 3)))
            (call $write_all (local.get $fd) (i32.const 160) (i32.const {payload_len})
              (i32.const 4))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn listener_wat(
    local: SocketAddr,
    bind_first: bool,
    reuse_addr: bool,
    consume_probe: bool,
) -> Vec<u8> {
    let local_bytes = sockaddr_bytes(local);
    let local_len = local_bytes.len();
    let family = if local.is_ipv4() { 2 } else { 10 };
    let mut data = data_segment(16, &local_bytes);
    data.push_str(&data_segment(64, b"ping"));
    data.push_str(&data_segment(72, b"pong"));
    data.push_str(&data_segment(140, &1_i32.to_le_bytes()));

    let bind = if bind_first {
        format!(
            r#"
            {reuse}
            (drop (call $check
              (call $bind (local.get $fd) (i32.const 16) (i32.const {local_len}))
              (i32.const 2)))
            "#,
            reuse = if reuse_addr {
                r#"(drop (call $check
                  (call $setsockopt (local.get $fd) (i32.const 1) (i32.const 2)
                    (i32.const 140) (i32.const 4))
                  (i32.const 19)))"#
            } else {
                ""
            }
        )
    } else {
        String::new()
    };
    let probe = if consume_probe {
        r#"
        (local.set $conn
          (call $check (call $accept (local.get $fd) (i32.const 0) (i32.const 0))
            (i32.const 5)))
        (local.set $count
          (call $check
            (call $read (local.get $conn) (i32.const 64) (i32.const 1))
            (i32.const 6)))
        (if (i32.ne (local.get $count) (i32.const 0))
          (then (call $fail (i32.const 6) (i32.const 1))))
        (drop (call $check (call $close (local.get $conn)) (i32.const 7)))
        "#
    } else {
        ""
    };

    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local $conn i32)
            (local $count i32)
            (local.set $fd
              (call $check (call $socket (i32.const {family}) (i32.const 1) (i32.const 0))
                (i32.const 1)))
            {bind}
            (drop (call $check
              (call $listen (local.get $fd) (i32.const 8))
              (i32.const 3)))
            (i32.store (i32.const 128) (i32.const {local_len}))
            (drop (call $check
              (call $getsockname (local.get $fd) (i32.const 80) (i32.const 128))
              (i32.const 4)))
            (call $write_all (i32.const 1) (i32.const 82) (i32.const 2) (i32.const 9))
            {probe}
            (block $stop
              (loop $serve
                (local.set $conn
                  (call $check
                    (call $accept (local.get $fd) (i32.const 0) (i32.const 0))
                    (i32.const 10)))
                (call $read_all (local.get $conn) (i32.const 64) (i32.const 4) (i32.const 11))
                (if (i32.ne (i32.load (i32.const 64)) (i32.const 0x676e6970))
                  (then (call $fail (i32.const 12) (i32.const 1))))
                (call $write_all (local.get $conn) (i32.const 72) (i32.const 4) (i32.const 13))
                (drop (call $check (call $close (local.get $conn)) (i32.const 14)))
                (br $serve)))
            unreachable
            "#
        ),
    )
}

fn udp_echo_wat(local: SocketAddr, peer: SocketAddr) -> Vec<u8> {
    udp_echo_wat_with_source(local, peer, false)
}

fn udp_echo_wat_with_source(local: SocketAddr, peer: SocketAddr, publish_source: bool) -> Vec<u8> {
    let local_bytes = sockaddr_bytes(local);
    let local_len = local_bytes.len();
    let peer_bytes = sockaddr_bytes(peer);
    let peer_len = peer_bytes.len();
    let family = if local.is_ipv4() { 2 } else { 10 };
    let mut data = data_segment(16, &local_bytes);
    data.push_str(&data_segment(48, &peer_bytes));
    data.push_str(&data_segment(80, b"ping"));
    data.push_str(&data_segment(96, b"zero"));
    data.push_str(&data_segment(104, b"done"));
    let source = if publish_source {
        r#"(i32.store (i32.const 128) (i32.const 16))
        (drop (call $check
          (call $getsockname (local.get $fd) (i32.const 176) (i32.const 128))
          (i32.const 16)))
        (call $write_all (i32.const 1) (i32.const 176) (i32.const 16) (i32.const 17))"#
    } else {
        ""
    };
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local $count i32)
            (local.set $fd
              (call $check (call $socket (i32.const {family}) (i32.const 2) (i32.const 0))
                (i32.const 1)))
            (drop (call $check
              (call $bind (local.get $fd) (i32.const 16) (i32.const {local_len}))
              (i32.const 3)))
            {source}
            (drop (call $check
              (call $sendto (local.get $fd) (i32.const 80) (i32.const 4)
                (i32.const 0) (i32.const 48) (i32.const {peer_len}))
              (i32.const 4)))
            (i32.store (i32.const 384) (i32.const {peer_len}))
            (local.set $count
              (call $check
                (call $recvfrom (local.get $fd) (i32.const 320) (i32.const 16)
                  (i32.const 0) (i32.const 352) (i32.const 384))
                (i32.const 5)))
            (if (i32.ne (local.get $count) (i32.const 4))
              (then (call $fail (i32.const 6) (i32.const 1))))
            (if (i32.ne (i32.load (i32.const 320)) (i32.const 0x676e6f70))
              (then (call $fail (i32.const 7) (i32.const 1))))
            (drop (call $check
              (call $sendto (local.get $fd) (i32.const 96) (i32.const 0)
                (i32.const 0) (i32.const 48) (i32.const {peer_len}))
              (i32.const 8)))
            (i32.store (i32.const 384) (i32.const {peer_len}))
            (local.set $count
              (call $check
                (call $recvfrom (local.get $fd) (i32.const 320) (i32.const 16)
                  (i32.const 0) (i32.const 352) (i32.const 384))
                (i32.const 9)))
            (if (i32.ne (local.get $count) (i32.const 0))
              (then (call $fail (i32.const 10) (i32.const 1))))
            (drop (call $check
              (call $sendto (local.get $fd) (i32.const 96) (i32.const 4)
                (i32.const 0) (i32.const 48) (i32.const {peer_len}))
              (i32.const 11)))
            (i32.store (i32.const 384) (i32.const {peer_len}))
            (local.set $count
              (call $check
                (call $recvfrom (local.get $fd) (i32.const 320) (i32.const 16)
                  (i32.const 0) (i32.const 352) (i32.const 384))
                (i32.const 12)))
            (if (i32.ne (local.get $count) (i32.const 4))
              (then (call $fail (i32.const 13) (i32.const 1))))
            (if (i32.ne (i32.load (i32.const 320)) (i32.const 0x656e6f64))
              (then (call $fail (i32.const 14) (i32.const 1))))
            (drop (call $check (call $close (local.get $fd)) (i32.const 15)))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn broadcast_send_wat(local: SocketAddr, enable_broadcast: bool) -> Vec<u8> {
    let local_bytes = sockaddr_bytes(local);
    let target = sockaddr_bytes(SocketAddr::from(([255, 255, 255, 255], 9)));
    let mut data = data_segment(16, &local_bytes);
    data.push_str(&data_segment(48, &target));
    data.push_str(&data_segment(64, b"x"));
    data.push_str(&data_segment(140, &1_i32.to_le_bytes()));
    let enable = if enable_broadcast {
        r#"(drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 1) (i32.const 6)
            (i32.const 140) (i32.const 4))
          (i32.const 2)))"#
    } else {
        ""
    };
    let send = if enable_broadcast {
        r#"
        (local.set $count
          (call $check
            (call $sendto (local.get $fd) (i32.const 64) (i32.const 1)
              (i32.const 0) (i32.const 48) (i32.const 16))
            (i32.const 4)))
        (if (i32.ne (local.get $count) (i32.const 1))
          (then (call $fail (i32.const 5) (i32.const 1))))
        "#
    } else {
        r#"
        (local.set $count
          (call $sendto (local.get $fd) (i32.const 64) (i32.const 1)
            (i32.const 0) (i32.const 48) (i32.const 16)))
        (if (i32.ne (local.get $count) (i32.const -13))
          (then (call $fail (i32.const 4) (i32.const 1))))
        "#
    };
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local $count i32)
            (local.set $fd
              (call $check (call $socket (i32.const 2) (i32.const 2) (i32.const 0))
                (i32.const 1)))
            {enable}
            (drop (call $check
              (call $bind (local.get $fd) (i32.const 16) (i32.const 16))
              (i32.const 3)))
            {send}
            (drop (call $check (call $close (local.get $fd)) (i32.const 6)))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn multicast_echo_wat() -> Vec<u8> {
    let local = sockaddr_bytes(SocketAddr::from(([0, 0, 0, 0], 0)));
    let group = sockaddr_bytes(SocketAddr::from(([239, 255, 77, 19], 0)));
    let mut membership = Vec::with_capacity(8);
    membership.extend_from_slice(&[239, 255, 77, 19]);
    membership.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    let mut data = data_segment(16, &local);
    data.push_str(&data_segment(48, &group));
    data.push_str(&data_segment(64, b"mcast"));
    data.push_str(&data_segment(128, &Ipv4Addr::LOCALHOST.octets()));
    data.push_str(&data_segment(144, &membership));
    data.push_str(&data_segment(160, &1_i32.to_le_bytes()));
    module(
        "",
        &data,
        r#"
        (local $fd i32)
        (local $count i32)
        (local.set $fd
          (call $check (call $socket (i32.const 2) (i32.const 2) (i32.const 0))
            (i32.const 1)))
        (drop (call $check
          (call $bind (local.get $fd) (i32.const 16) (i32.const 16))
          (i32.const 2)))
        (i32.store (i32.const 192) (i32.const 16))
        (drop (call $check
          (call $getsockname (local.get $fd) (i32.const 176) (i32.const 192))
          (i32.const 3)))
        (i32.store16 (i32.const 50) (i32.load16_u (i32.const 178)))
        (call $write_all (i32.const 1) (i32.const 178) (i32.const 2) (i32.const 4))
        ;; Select loopback, enable multicast loopback, and set a local TTL.
        (drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 0) (i32.const 32)
            (i32.const 128) (i32.const 4))
          (i32.const 5)))
        (drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 0) (i32.const 34)
            (i32.const 160) (i32.const 4))
          (i32.const 6)))
        (drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 0) (i32.const 33)
            (i32.const 160) (i32.const 4))
          (i32.const 7)))
        (drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 0) (i32.const 35)
            (i32.const 144) (i32.const 8))
          (i32.const 8)))
        (drop (call $check
          (call $sendto (local.get $fd) (i32.const 64) (i32.const 5)
            (i32.const 0) (i32.const 48) (i32.const 16))
          (i32.const 9)))
        (i32.store (i32.const 192) (i32.const 16))
        (local.set $count
          (call $check
            (call $recvfrom (local.get $fd) (i32.const 96) (i32.const 16)
              (i32.const 0) (i32.const 112) (i32.const 192))
            (i32.const 10)))
        (if (i32.ne (local.get $count) (i32.const 5))
          (then (call $fail (i32.const 11) (i32.const 1))))
        (if (i32.ne (i32.load (i32.const 96)) (i32.const 0x7361636d))
          (then (call $fail (i32.const 12) (i32.const 1))))
        (if (i32.ne (i32.load8_u (i32.const 100)) (i32.const 116))
          (then (call $fail (i32.const 13) (i32.const 1))))
        (drop (call $check
          (call $setsockopt (local.get $fd) (i32.const 0) (i32.const 36)
            (i32.const 144) (i32.const 8))
          (i32.const 14)))
        (drop (call $check (call $close (local.get $fd)) (i32.const 15)))
        (call $exit (i32.const 0))
        unreachable
        "#,
    )
}

fn lifecycle_wat() -> Vec<u8> {
    let peer = sockaddr_bytes(SocketAddr::from(([127, 0, 0, 1], 9)));
    let mut data = data_segment(16, &peer);
    data.push_str(&data_segment(64, b"ping"));
    data.push_str(&data_segment(72, b"pong"));
    let listen = listener_body_unbound();
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local $conn i32)
            (call $read_all (i32.const 0) (i32.const 150) (i32.const 1) (i32.const 30))
            (if (i32.eq (i32.load8_u (i32.const 150)) (i32.const 76))
              (then {listen})
              (else
                (local.set $fd
                  (call $check
                    (call $socket (i32.const 2) (i32.const 1) (i32.const 0))
                    (i32.const 31)))
                (drop (call $check
                  (call $connect (local.get $fd) (i32.const 16) (i32.const 16))
                  (i32.const 32)))))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn close_gate_lifecycle_wat(peer: SocketAddr) -> Vec<u8> {
    let peer_bytes = sockaddr_bytes(peer);
    let peer_len = peer_bytes.len();
    let family = if peer.is_ipv4() { 2 } else { 10 };
    let mut data = data_segment(16, &peer_bytes);
    data.push_str(&data_segment(64, b"ping"));
    data.push_str(&data_segment(72, b"pong"));
    data.push_str(&data_segment(140, &[1, 0, 0, 0, 2, 0, 0, 0]));
    let listen = listener_body_unbound();
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local $conn i32)
            (call $read_all (i32.const 0) (i32.const 150) (i32.const 1) (i32.const 30))
            (if (i32.eq (i32.load8_u (i32.const 150)) (i32.const 76))
              (then {listen})
              (else
                (local.set $fd
                  (call $check
                    (call $socket (i32.const {family}) (i32.const 1) (i32.const 0))
                    (i32.const 31)))
                (drop (call $check
                  (call $setsockopt (local.get $fd) (i32.const 1) (i32.const 13)
                    (i32.const 140) (i32.const 8))
                  (i32.const 32)))
                (drop (call $check
                  (call $connect (local.get $fd) (i32.const 16) (i32.const {peer_len}))
                  (i32.const 33)))
                (call $write_all (local.get $fd) (i32.const 64) (i32.const 4)
                  (i32.const 34))
                (drop (call $check (call $close (local.get $fd)) (i32.const 35)))
                (call $read_all (i32.const 0) (i32.const 151) (i32.const 1) (i32.const 36))))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn listener_body_unbound() -> &'static str {
    r#"
      (local.set $fd
        (call $check (call $socket (i32.const 2) (i32.const 1) (i32.const 0))
          (i32.const 33)))
      (drop (call $check
        (call $listen (local.get $fd) (i32.const 8))
        (i32.const 34)))
      (i32.store (i32.const 128) (i32.const 16))
      (drop (call $check
        (call $getsockname (local.get $fd) (i32.const 80) (i32.const 128))
        (i32.const 35)))
      (call $write_all (i32.const 1) (i32.const 82) (i32.const 2) (i32.const 36))
      (block $stop
        (loop $serve
          (local.set $conn
            (call $check
              (call $accept (local.get $fd) (i32.const 0) (i32.const 0))
              (i32.const 37)))
          (call $read_all (local.get $conn) (i32.const 64) (i32.const 4) (i32.const 38))
          (if (i32.ne (i32.load (i32.const 64)) (i32.const 0x676e6970))
            (then (call $fail (i32.const 39) (i32.const 1))))
          (call $write_all (local.get $conn) (i32.const 72) (i32.const 4) (i32.const 40))
          (drop (call $check (call $close (local.get $conn)) (i32.const 41)))
          (br $serve)))
      unreachable
    "#
}

fn pending_bind_wat(local: SocketAddr) -> Vec<u8> {
    let bytes = sockaddr_bytes(local);
    let len = bytes.len();
    let family = if local.is_ipv4() { 2 } else { 10 };
    let data = data_segment(16, &bytes);
    module(
        "",
        &data,
        &format!(
            r#"
            (local $fd i32)
            (local.set $fd
              (call $check (call $socket (i32.const {family}) (i32.const 1) (i32.const 0))
                (i32.const 50)))
            (drop (call $check
              (call $bind (local.get $fd) (i32.const 16) (i32.const {len}))
              (i32.const 51)))
            (call $exit (i32.const 0))
            unreachable
            "#
        ),
    )
}

fn client(state: &TempDir) -> Result<Wasmer> {
    Wasmer::with_config(WasmerConfig {
        cache: CacheConfig {
            root: state.path().join("cache"),
        },
        output_bytes: 1024,
    })
}

async fn create_sandbox(
    client: &Wasmer,
    provider: DynNetworkProvider,
    wasm: Vec<u8>,
) -> Result<Sandbox> {
    client
        .sandboxes()
        .create()
        .package(PackageSource::bytes(wasm))
        .network_provider(provider)
        .await
}

fn host_network() -> Arc<HostNetwork> {
    HostNetwork::new().expect("construct the canonical native host network")
}

fn tcp_echo_server(address: SocketAddr) -> (SocketAddr, JoinHandle<SocketAddr>) {
    let listener = HostTcpListener::bind(address).expect("bind host-side TCP peer");
    let local = listener.local_addr().expect("read host listener address");
    listener
        .set_nonblocking(true)
        .expect("bound host accept is nonblocking");
    let task = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, peer) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept guest TCP connection before deadline: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bound host read");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("bound host write");
        let mut request = [0; 4];
        std::io::Read::read_exact(&mut stream, &mut request).expect("read guest request");
        assert_eq!(&request, b"ping");
        std::io::Write::write_all(&mut stream, b"pong").expect("reply to guest");
        peer
    });
    (local, task)
}

fn udp_echo_server(address: SocketAddr) -> (SocketAddr, JoinHandle<SocketAddr>) {
    let socket = HostUdpSocket::bind(address).expect("bind host-side UDP peer");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound host UDP receive");
    let local = socket.local_addr().expect("read host UDP address");
    let task = std::thread::spawn(move || {
        let mut peer = None;
        for (request, reply) in [
            (&b"ping"[..], &b"pong"[..]),
            (&b""[..], &b""[..]),
            (&b"zero"[..], &b"done"[..]),
        ] {
            let mut buffer = [0; 16];
            let (count, from) = socket
                .recv_from(&mut buffer)
                .expect("receive guest UDP request before deadline");
            assert_eq!(&buffer[..count], request);
            if let Some(first) = peer {
                assert_eq!(from, first, "the guest uses one retained UDP endpoint");
            } else {
                peer = Some(from);
            }
            assert_eq!(
                socket
                    .send_to(reply, from)
                    .expect("reply to guest UDP request"),
                reply.len()
            );
        }
        peer.expect("guest sent its first UDP request")
    });
    (local, task)
}

type DeferredTcpReadServer = (
    SocketAddr,
    mpsc::Receiver<SocketAddr>,
    mpsc::Sender<()>,
    JoinHandle<(SocketAddr, Vec<u8>)>,
);

fn tcp_read_after_release_server(address: SocketAddr) -> DeferredTcpReadServer {
    let listener = HostTcpListener::bind(address).expect("bind host-side TCP reader");
    let local = listener.local_addr().expect("read host reader address");
    listener
        .set_nonblocking(true)
        .expect("bound host accept is nonblocking");
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let task = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, peer) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept guest TCP connection before deadline: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bound host read");
        accepted_tx
            .send(peer)
            .expect("test still observes the accepted TCP peer");
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("test releases host reading after guest exit");
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut stream, &mut bytes)
            .expect("read all guest bytes through FIN");
        (peer, bytes)
    });
    (local, accepted_rx, release_tx, task)
}

fn host_stream_round_trip(address: SocketAddr) -> HostTcpStream {
    let mut stream = HostTcpStream::connect_timeout(&address, Duration::from_secs(5))
        .expect("connect to guest listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound host read");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bound host write");
    std::io::Write::write_all(&mut stream, b"ping").expect("send host request");
    let mut response = [0; 4];
    std::io::Read::read_exact(&mut stream, &mut response).expect("read guest response");
    assert_eq!(&response, b"pong");
    stream
}

fn published_port(bytes: [u8; 2]) -> u16 {
    let port = u16::from_be_bytes(bytes);
    assert_ne!(port, 0, "the guest must publish its actual ephemeral port");
    port
}

fn published_output_port(bytes: &[u8]) -> u16 {
    let port_bytes: [u8; 2] = bytes
        .get(..2)
        .expect("guest published both port bytes")
        .try_into()
        .expect("two-byte port output");
    published_port(port_bytes)
}

#[tokio::test(flavor = "multi_thread")]
async fn host_tcp_round_trip_works_on_ipv4_and_ipv6_loopback() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let (peer, host) = tcp_echo_server(SocketAddr::new(ip, 0));
            let provider: DynNetworkProvider = host_network();
            let sandbox =
                create_sandbox(&client, provider, tcp_client_wat(peer, None, false)).await?;
            let output = sandbox.command("main").output().await?;
            assert_eq!(output.reason, ExitReason::Exited);
            assert_eq!(output.status.code(), 0);
            let source = host.join().expect("host TCP peer completed");
            assert_eq!(source.ip(), ip);
            assert_ne!(source.port(), 0);
            sandbox.close().await?;
        }
        client.shutdown().await
    })
    .await
    .expect("guest TCP loopback exchange completed")
}

#[tokio::test(flavor = "multi_thread")]
async fn normal_guest_exit_with_positive_linger_preserves_accepted_bytes() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let payload = b"write accepted before normal exit";
        let (peer, accepted, release_reader, host) =
            tcp_read_after_release_server(SocketAddr::from(([127, 0, 0, 1], 0)));
        let sandbox =
            create_sandbox(&client, host_network(), tcp_linger_exit_wat(peer, payload)).await?;

        let output = sandbox.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);
        let accepted_peer = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match accepted.try_recv() {
                    Ok(peer) => break peer,
                    Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("host TCP reader stopped before accepting the guest")
                    }
                }
            }
        })
        .await
        .expect("host accepted the guest TCP connection");
        assert_eq!(accepted_peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        release_reader
            .send(())
            .expect("release host read after normal guest exit");
        let (source, bytes) = host.join().expect("host read task completed");
        assert_eq!(source, accepted_peer);
        assert_eq!(bytes, payload);
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("normal guest close drained accepted TCP bytes")
}

#[tokio::test(flavor = "multi_thread")]
async fn run_owner_cancel_escalates_pending_positive_linger_and_keeps_sibling_live() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let (peer, host) = tcp_echo_server(SocketAddr::from(([127, 0, 0, 1], 0)));
        let provider = CloseGateProvider::new(host_network());
        let provider_trait: DynNetworkProvider = provider.clone();
        let sandbox =
            create_sandbox(&client, provider_trait, close_gate_lifecycle_wat(peer)).await?;

        let mut listener_command = sandbox.command("main");
        listener_command.stdin(Stdio::Piped);
        listener_command.stdout(Stdio::Piped);
        let mut listener = listener_command.spawn().await?;
        let mut listener_input = listener.take_stdin().expect("piped listener input");
        listener_input.write_all(b"L").await?;
        listener_input.shutdown().await?;
        let mut stdout = listener
            .take_stdout()
            .expect("sibling listener publishes its port");
        let mut port_bytes = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), stdout.read_exact(&mut port_bytes))
            .await
            .expect("sibling listener did not publish a port")
            .expect("read sibling listener port");
        let sibling_port = published_port(port_bytes);

        let mut close_command = sandbox.command("main");
        close_command.stdin(Stdio::Piped);
        close_command.stdout(Stdio::Null).stderr(Stdio::Null);
        let mut close_pending = close_command.spawn().await?;
        let mut close_input = close_pending.take_stdin().expect("piped close input");
        close_input.write_all(b"C").await?;
        // Withhold the second byte and EOF so the guest stays live after its FD close.
        provider
            .close_started
            .acquire()
            .await
            .expect("positive-linger normal close started")
            .forget();
        let client_peer = host
            .join()
            .expect("host observed the guest's accepted bytes");
        assert_eq!(client_peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        close_pending.kill()?;
        assert_eq!(close_pending.wait().await?.reason, ExitReason::Terminated);
        drop(close_input);
        assert_eq!(provider.cancel_closes.load(Ordering::SeqCst), 1);
        assert_eq!(provider.normal_waiters_retired.load(Ordering::SeqCst), 1);

        let _stream = host_stream_round_trip(SocketAddr::from(([127, 0, 0, 1], sibling_port)));
        sandbox.close().await?;
        assert_eq!(listener.wait().await?.reason, ExitReason::Terminated);
        client.shutdown().await
    })
    .await
    .expect("run owner escalated close and sibling network remained live")
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_listener_publishes_port_waits_for_probe_and_serves_host_connection() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider: DynNetworkProvider = host_network();
        let sandbox = create_sandbox(
            &client,
            provider,
            listener_wat(SocketAddr::from(([127, 0, 0, 1], 0)), false, false, true),
        )
        .await?;

        let mut command = sandbox.command("main");
        command.stdout(Stdio::Piped);
        let mut process = command.spawn().await?;
        let mut stdout = process
            .take_stdout()
            .expect("guest publishes its port on stdout");
        let mut bytes = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), stdout.read_exact(&mut bytes))
            .await
            .expect("guest did not publish its bound port")
            .expect("read guest port");
        let port = published_port(bytes);

        tokio::time::timeout(
            Duration::from_secs(5),
            sandbox.ports().wait(port, Duration::from_secs(4)),
        )
        .await
        .expect("port readiness timed out")
        .expect("guest listener accepted the readiness probe");

        let _stream = host_stream_round_trip(SocketAddr::from(([127, 0, 0, 1], port)));
        process.kill()?;
        let result = process.wait().await?;
        assert_eq!(result.reason, ExitReason::Terminated);
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("guest listener and port probe completed")
}

#[tokio::test(flavor = "multi_thread")]
async fn host_udp_echo_works_on_both_loopbacks_and_preserves_empty_datagrams() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let (host_address, host) = udp_echo_server(SocketAddr::new(ip, 0));
            let provider = RecordingProvider::new(host_network());
            let provider_trait: DynNetworkProvider = provider.clone();
            let unspecified = match ip {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            let sandbox = create_sandbox(
                &client,
                provider_trait,
                udp_echo_wat(SocketAddr::new(unspecified, 0), host_address),
            )
            .await?;
            let output = sandbox.command("main").output().await?;
            assert_eq!(output.reason, ExitReason::Exited);
            assert_eq!(output.status.code(), 0);
            let peer = host.join().expect("host UDP peer completed");
            {
                let received = provider.calls.received_datagrams.lock().unwrap();
                assert_eq!(received.len(), 3);
                let provider_local = provider
                    .calls
                    .udp_local_addresses
                    .lock()
                    .unwrap()
                    .first()
                    .copied()
                    .expect("host provider socket was bound");
                assert!(provider_local.ip().is_unspecified());
                assert_ne!(provider_local.port(), 0);
                assert_eq!(peer.ip(), ip);
                assert_eq!(peer.port(), provider_local.port());
                for packet in received.iter() {
                    assert_eq!(packet.source, host_address);
                    assert_eq!(packet.destination.ip(), ip);
                    assert_eq!(packet.destination.port(), provider_local.port());
                    assert_ne!(
                        packet.interface, 0,
                        "host receive reports the actual interface"
                    );
                }
                assert_eq!(
                    provider.calls.udp_sends.lock().unwrap().as_slice(),
                    &[
                        (b"ping".to_vec(), host_address),
                        (Vec::new(), host_address),
                        (b"zero".to_vec(), host_address),
                    ]
                );
            }
            sandbox.close().await?;
        }
        client.shutdown().await
    })
    .await
    .expect("guest UDP loopback exchanges completed")
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_permission_is_checked_before_provider_send() -> Result<()> {
    let state = TempDir::new().expect("create SDK state");
    let client = client(&state)?;
    let provider = RecordingProvider::suppressing_broadcast(host_network());
    let provider_trait: DynNetworkProvider = provider.clone();
    let local = SocketAddr::from(([127, 0, 0, 1], 0));

    let sandbox = create_sandbox(
        &client,
        provider_trait.clone(),
        broadcast_send_wat(local, false),
    )
    .await?;
    let output = sandbox.command("main").output().await?;
    assert_eq!(output.reason, ExitReason::Exited);
    assert_eq!(output.status.code(), 0);
    assert!(
        provider.calls.udp_sends.lock().unwrap().is_empty(),
        "the denied broadcast must not reach the provider data plane"
    );
    sandbox.close().await?;

    let sandbox = create_sandbox(&client, provider_trait, broadcast_send_wat(local, true)).await?;
    let output = sandbox.command("main").output().await?;
    assert_eq!(output.reason, ExitReason::Exited);
    assert_eq!(output.status.code(), 0);
    assert_eq!(
        provider.calls.udp_options.lock().unwrap().as_slice(),
        &[(1, 6, 1_i32.to_le_bytes().to_vec())],
        "the enabled guest option reaches its selected provider"
    );
    assert_eq!(
        provider.calls.udp_sends.lock().unwrap().as_slice(),
        &[(b"x".to_vec(), SocketAddr::from(([255, 255, 255, 255], 9)))]
    );
    sandbox.close().await?;
    client.shutdown().await
}

#[tokio::test(flavor = "multi_thread")]
async fn multicast_options_and_join_leave_reach_the_provider_and_loopback() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider = RecordingProvider::new(host_network());
        let provider_trait: DynNetworkProvider = provider.clone();
        let sandbox = create_sandbox(&client, provider_trait, multicast_echo_wat()).await?;
        let output = sandbox.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);

        let destination = SocketAddr::from((
            [239, 255, 77, 19],
            published_output_port(output.stdout.bytes()),
        ));
        assert_eq!(
            provider.calls.udp_sends.lock().unwrap().as_slice(),
            &[(b"mcast".to_vec(), destination)]
        );
        {
            let options = provider.calls.udp_options.lock().unwrap();
            let mut interface_requests = 0;
            for (_, _, bytes) in options
                .iter()
                .filter(|(level, name, _)| (*level, *name) == (0, 32))
            {
                assert_eq!(
                    bytes.len(),
                    IpMreqn::SIZE,
                    "normalized IP_MULTICAST_IF layout"
                );
                let request =
                    IpMreqn::read_from(bytes).expect("decode normalized interface request");
                assert_eq!(request.imr_multiaddr.s_addr, 0);
                assert_eq!(
                    Ipv4Addr::from(request.imr_address.s_addr.to_le_bytes()),
                    Ipv4Addr::LOCALHOST
                );
                assert_eq!(
                    request.imr_ifindex, 0,
                    "retain literal zero, not resolved namespace ifindex"
                );
                interface_requests += 1;
            }
            assert_ne!(interface_requests, 0, "missing IP_MULTICAST_IF request");
            for option in [
                (0, 34, 1_i32.to_le_bytes().to_vec()),
                (0, 33, 1_i32.to_le_bytes().to_vec()),
                (
                    0,
                    35,
                    [
                        Ipv4Addr::new(239, 255, 77, 19).octets(),
                        Ipv4Addr::LOCALHOST.octets(),
                    ]
                    .concat(),
                ),
                (
                    0,
                    36,
                    [
                        Ipv4Addr::new(239, 255, 77, 19).octets(),
                        Ipv4Addr::LOCALHOST.octets(),
                    ]
                    .concat(),
                ),
            ] {
                assert!(
                    options.contains(&option),
                    "missing multicast option {option:?}"
                );
            }
        }

        {
            let received = provider.calls.received_datagrams.lock().unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].source,
                SocketAddr::from(([127, 0, 0, 1], destination.port()))
            );
            assert_eq!(received[0].destination, destination);
            assert_ne!(received[0].interface, 0);
        }
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("loopback multicast remained local and completed")
}

#[tokio::test(flavor = "multi_thread")]
async fn physical_nonloopback_source_bind_round_trips_tcp_and_udp_without_namespace_rewrite()
-> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        // UDP connect selects a local route/address only. Never send a payload or external
        // probe: both actual data exchanges below terminate on this host's selected address.
        let route = HostUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .expect("non-loopback IPv4 source unavailable: cannot create local route lookup socket");
        route.connect(SocketAddr::from(([192, 0, 2, 1], 9)))
            .expect("non-loopback IPv4 source unavailable: local route lookup failed (no payload sent)");
        let source = route.local_addr()
            .expect("non-loopback IPv4 source unavailable: local getsockname failed").ip();
        assert!(source.is_ipv4() && !source.is_loopback() && !source.is_unspecified(),
            "non-loopback IPv4 source unavailable: selected {source}; this gate must not silently skip");
        drop(route);
        let namespace = wasixv2_vnet::NetConfig::host_default();
        let synthetic = namespace.uplink.as_ref().and_then(|up| up.v4).map(|(ip, _, _)| IpAddr::V4(ip));
        assert_ne!(Some(source), synthetic,
            "selected host address coincides with synthetic namespace; unavailable discrimination");
        let literal = SocketAddr::new(source, 0);
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider = RecordingProvider::new(host_network());
        let provider_trait: DynNetworkProvider = provider.clone();

        let (tcp_peer, tcp_host) = tcp_echo_server(literal);
        let tcp = create_sandbox(&client, provider_trait.clone(),
            tcp_client_wat_with_source(tcp_peer, Some(literal), false, true)).await?;
        let output = tcp.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);
        let tcp_source = tcp_host.join().expect("non-loopback TCP exchange completed");
        assert_eq!(tcp_source.ip(), source);
        assert_ne!(tcp_source.port(), 0);
        assert_eq!(published_output_port(output.stdout.bytes()), tcp_source.port());
        assert_eq!(&output.stdout.bytes()[2..], sockaddr_bytes(tcp_source),
            "guest post-connect getsockname must equal the host-observed actual source");
        assert!(provider.calls.unbound_connects.lock().unwrap().is_empty(),
            "literal bind must not be rewritten into the unbound-connect callback");
        let binds = provider.calls.binds.lock().unwrap().clone();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].requested, literal);
        assert_eq!(binds[0].requested.port(), 0);
        assert_eq!(binds[0].actual, tcp_source);
        assert!(!binds[0].v6only && !binds[0].reuse_port && !binds[0].reuse_addr);
        assert_eq!(*provider.calls.bound_actions.lock().unwrap(),
            [(binds[0].id, BoundAction::Connect(tcp_peer))]);
        tcp.close().await?;

        let (udp_peer, udp_host) = udp_echo_server(literal);
        let udp = create_sandbox(&client, provider_trait,
            udp_echo_wat_with_source(literal, udp_peer, true)).await?;
        let output = udp.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);
        let udp_source = udp_host.join().expect("non-loopback UDP exchanges completed");
        assert_eq!(udp_source.ip(), source);
        assert_ne!(udp_source.port(), 0);
        assert_eq!(output.stdout.bytes(), sockaddr_bytes(udp_source),
            "guest UDP getsockname must equal the actual source of every echo request");
        assert_eq!(*provider.calls.udp_binds.lock().unwrap(), [(literal, udp_source)]);
        assert_eq!(*provider.calls.udp_local_addresses.lock().unwrap(), [udp_source]);
        assert_eq!(*provider.calls.udp_sends.lock().unwrap(),
            [(b"ping".to_vec(), udp_peer), (Vec::new(), udp_peer), (b"zero".to_vec(), udp_peer)]);
        let received = provider.calls.received_datagrams.lock().unwrap().clone();
        assert_eq!(received.len(), 3);
        for packet in received {
            assert_eq!(packet.source, udp_peer);
            assert_eq!(packet.destination, udp_source);
            assert_ne!(packet.interface, 0);
        }
        udp.close().await?;
        client.shutdown().await
    }).await.expect("physical non-loopback provider round trips completed")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BindRecord {
    id: u64,
    requested: SocketAddr,
    actual: SocketAddr,
    v6only: bool,
    reuse_port: bool,
    reuse_addr: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundAction {
    Connect(SocketAddr),
    Listen,
}

#[derive(Default, Debug)]
struct ProviderCalls {
    unbound_connects: Mutex<Vec<(SocketAddr, SocketAddr)>>,
    binds: Mutex<Vec<BindRecord>>,
    bound_actions: Mutex<Vec<(u64, BoundAction)>>,
    udp_sends: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    udp_options: Mutex<Vec<(i32, i32, Vec<u8>)>>,
    received_datagrams: Mutex<Vec<DatagramInfo>>,
    udp_local_addresses: Mutex<Vec<SocketAddr>>,
    udp_binds: Mutex<Vec<(SocketAddr, SocketAddr)>>,
}

struct RecordingProvider {
    host: Arc<HostNetwork>,
    calls: Arc<ProviderCalls>,
    next_id: AtomicU64,
    suppress_broadcast: bool,
}

impl fmt::Debug for RecordingProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingProvider").finish_non_exhaustive()
    }
}

impl RecordingProvider {
    fn new(host: Arc<HostNetwork>) -> Arc<Self> {
        Arc::new(Self {
            host,
            calls: Arc::new(ProviderCalls::default()),
            next_id: AtomicU64::new(1),
            suppress_broadcast: false,
        })
    }

    fn suppressing_broadcast(host: Arc<HostNetwork>) -> Arc<Self> {
        Arc::new(Self {
            host,
            calls: Arc::new(ProviderCalls::default()),
            next_id: AtomicU64::new(1),
            suppress_broadcast: true,
        })
    }
}

struct RecordingBound {
    id: u64,
    inner: Arc<dyn BoundTcp>,
    calls: Arc<ProviderCalls>,
}

struct RecordingUdp {
    inner: Arc<dyn UdpSocket>,
    calls: Arc<ProviderCalls>,
    suppress_broadcast: bool,
}

struct RecordingReceiver {
    inner: Arc<dyn DatagramReceiver>,
    calls: Arc<ProviderCalls>,
}
impl DatagramReceiver for RecordingReceiver {
    fn ready(&self) {
        self.inner.ready();
    }
    fn failed(&self, error: wasmer_sdk::NetworkError) {
        self.inner.failed(error);
    }
    fn received(
        &self,
        info: DatagramInfo,
        bytes: &[u8],
    ) -> wasixv2_vnet::endpoint::DatagramDelivery {
        self.calls.received_datagrams.lock().unwrap().push(info);
        self.inner.received(info, bytes)
    }
}

impl fmt::Debug for RecordingUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingUdp").finish_non_exhaustive()
    }
}

impl Pollable for RecordingBound {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.inner.poll(table)
    }
}

impl Pollable for RecordingUdp {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.inner.poll(table)
    }
}

impl BackendDatagram for RecordingUdp {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> NetworkResult<usize> {
        self.calls
            .udp_sends
            .lock()
            .unwrap()
            .push((data.to_vec(), to));
        if self.suppress_broadcast && matches!(to.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST)
        {
            return Ok(data.len());
        }
        self.inner.send_to(data, to)
    }

    fn connect(&self, peer: Option<SocketAddr>) -> NetworkResult<()> {
        self.inner.connect(peer)
    }

    fn take_error(&self) -> Option<wasmer_sdk::NetworkError> {
        self.inner.take_error()
    }

    fn recv_from(&self, buf: &mut [u8], peek: bool) -> NetworkResult<(usize, usize, SocketAddr)> {
        self.inner.recv_from(buf, peek)
    }

    fn input_len(&self) -> usize {
        self.inner.input_len()
    }

    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.calls
            .udp_options
            .lock()
            .unwrap()
            .push((level, name, value.to_vec()));
        self.inner.set_socket_option(level, name, value)
    }

    fn take_queued_error(&self) -> Option<wasixv2_vnet::QueuedError> {
        self.inner.take_queued_error()
    }

    fn attach(&self, queue: Option<WaitQueue>) -> NetworkResult<()> {
        self.inner.attach(queue)
    }
}

#[async_trait]
impl UdpSocket for RecordingUdp {
    fn install_receiver(
        &self,
        receiver: Arc<dyn DatagramReceiver>,
    ) -> NetworkResult<Arc<dyn DatagramReceiveLease>> {
        self.inner.install_receiver(Arc::new(RecordingReceiver {
            inner: receiver,
            calls: self.calls.clone(),
        }))
    }

    fn peer_addr(&self) -> NetworkResult<Option<SocketAddr>> {
        self.inner.peer_addr()
    }

    fn recv_packet(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> NetworkResult<wasmer_sdk::network_api::ReceivedDatagram> {
        let packet = self.inner.recv_packet(buf, peek)?;
        self.calls.received_datagrams.lock().unwrap().push(packet.2);
        Ok(packet)
    }

    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.calls
            .udp_options
            .lock()
            .unwrap()
            .push((level, name, value.to_vec()));
        self.inner.set_socket_option(level, name, value)
    }

    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
        self.inner.close(mode).await
    }
}

#[async_trait]
impl BoundTcp for RecordingBound {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.inner.set_socket_option(level, name, value)
    }

    async fn connect(
        &self,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        self.calls
            .bound_actions
            .lock()
            .unwrap()
            .push((self.id, BoundAction::Connect(peer)));
        self.inner.connect(peer, queue).await
    }

    async fn listen(&self, backlog: u32, queue: WaitQueue) -> NetworkResult<Arc<dyn TcpListener>> {
        self.calls
            .bound_actions
            .lock()
            .unwrap()
            .push((self.id, BoundAction::Listen));
        self.inner.listen(backlog, queue).await
    }

    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
        self.inner.close(mode).await
    }
}

#[async_trait]
impl NetworkProvider for RecordingProvider {
    async fn connect_tcp(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        self.calls
            .unbound_connects
            .lock()
            .unwrap()
            .push((local, peer));
        self.host.connect_tcp(local, peer, queue).await
    }

    async fn bind_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetworkResult<Arc<dyn BoundTcp>> {
        let inner = self
            .host
            .bind_tcp(local, v6only, reuse_port, reuse_addr)
            .await?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.calls.binds.lock().unwrap().push(BindRecord {
            id,
            requested: local,
            actual: inner.local_addr()?,
            v6only,
            reuse_port,
            reuse_addr,
        });
        Ok(Arc::new(RecordingBound {
            id,
            inner,
            calls: self.calls.clone(),
        }))
    }

    async fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        self.host
            .listen_tcp(local, v6only, reuse_port, reuse_addr, backlog, queue)
            .await
    }

    async fn bind_udp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn UdpSocket>> {
        let inner = self
            .host
            .bind_udp(local, v6only, reuse_port, reuse_addr, queue)
            .await?;
        let actual = inner.local_addr()?;
        self.calls.udp_binds.lock().unwrap().push((local, actual));
        self.calls.udp_local_addresses.lock().unwrap().push(actual);
        Ok(Arc::new(RecordingUdp {
            inner,
            calls: self.calls.clone(),
            suppress_broadcast: self.suppress_broadcast,
        }))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_keeps_unbound_connect_and_explicit_bound_connect_listen_distinct() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider = RecordingProvider::new(host_network());
        let provider_trait: DynNetworkProvider = provider.clone();

        let (peer, host) = tcp_echo_server(SocketAddr::from(([127, 0, 0, 1], 0)));
        let sandbox = create_sandbox(
            &client,
            provider_trait.clone(),
            tcp_client_wat(peer, None, false),
        )
        .await?;
        let output = sandbox.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);
        let source = host.join().expect("unbound host peer completed");
        assert_eq!(
            provider.calls.unbound_connects.lock().unwrap().as_slice(),
            &[(SocketAddr::from(([0, 0, 0, 0], 0)), peer)]
        );
        assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        sandbox.close().await?;

        let (peer, host) = tcp_echo_server(SocketAddr::from(([127, 0, 0, 1], 0)));
        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let sandbox = create_sandbox(
            &client,
            provider_trait.clone(),
            tcp_client_wat(peer, Some(local), false),
        )
        .await?;
        let output = sandbox.command("main").output().await?;
        assert_eq!(output.reason, ExitReason::Exited);
        assert_eq!(output.status.code(), 0);
        let source = host.join().expect("explicitly bound host peer completed");
        let local_port = published_output_port(output.stdout.bytes());
        assert_eq!(source.port(), local_port);
        let connect_record = provider
            .calls
            .binds
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("explicit bind was recorded");
        assert_eq!(connect_record.requested, local);
        assert_eq!(connect_record.actual.port(), local_port);
        assert!(!connect_record.v6only);
        assert!(!connect_record.reuse_addr);
        assert!(
            provider
                .calls
                .bound_actions
                .lock()
                .unwrap()
                .contains(&(connect_record.id, BoundAction::Connect(peer)))
        );
        sandbox.close().await?;

        let local = SocketAddr::from(([127, 0, 0, 1], 0));
        let sandbox = create_sandbox(
            &client,
            provider_trait,
            listener_wat(local, true, true, true),
        )
        .await?;
        let mut command = sandbox.command("main");
        command.stdout(Stdio::Piped);
        let mut process = command.spawn().await?;
        let mut stdout = process
            .take_stdout()
            .expect("listener publishes actual address");
        let mut port_bytes = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), stdout.read_exact(&mut port_bytes))
            .await
            .expect("listener did not publish a port")
            .expect("read listener port");
        let port = published_port(port_bytes);
        let listen_record = provider
            .calls
            .binds
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("explicit listener bind was recorded");
        assert_eq!(listen_record.requested, local);
        assert_eq!(listen_record.actual.port(), port);
        assert!(listen_record.reuse_addr);
        assert!(
            provider
                .calls
                .bound_actions
                .lock()
                .unwrap()
                .contains(&(listen_record.id, BoundAction::Listen))
        );

        sandbox.ports().wait(port, Duration::from_secs(4)).await?;
        let _stream = host_stream_round_trip(SocketAddr::from(([127, 0, 0, 1], port)));
        process.kill()?;
        process.wait().await?;
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("legacy guest socket paths completed through the canonical provider")
}

struct DropMark(Arc<AtomicUsize>);

impl Drop for DropMark {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct CloseGateProvider {
    host: Arc<HostNetwork>,
    close_started: Arc<Semaphore>,
    normal_waiters_retired: Arc<AtomicUsize>,
    cancel_closes: Arc<AtomicUsize>,
    close_completed: Arc<Notify>,
}

impl fmt::Debug for CloseGateProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloseGateProvider").finish_non_exhaustive()
    }
}

impl CloseGateProvider {
    fn new(host: Arc<HostNetwork>) -> Arc<Self> {
        Arc::new(Self {
            host,
            close_started: Arc::new(Semaphore::new(0)),
            normal_waiters_retired: Arc::new(AtomicUsize::new(0)),
            cancel_closes: Arc::new(AtomicUsize::new(0)),
            close_completed: Arc::new(Notify::new()),
        })
    }
}

struct CloseGateStream {
    inner: Arc<dyn TcpStream>,
    close_started: Arc<Semaphore>,
    normal_waiters_retired: Arc<AtomicUsize>,
    cancel_closes: Arc<AtomicUsize>,
    close_completed: Arc<Notify>,
}

impl Pollable for CloseGateStream {
    fn poll(&self, table: Option<&mut PollTable<'_>>) -> PollMask {
        self.inner.poll(table)
    }
}

impl BackendStream for CloseGateStream {
    fn provider_local_addr(&self) -> Option<NetworkResult<SocketAddr>> {
        self.inner.provider_local_addr()
    }
    fn state(&self) -> StreamState {
        self.inner.state()
    }
    fn tcp_established(&self) -> bool {
        self.inner.tcp_established()
    }
    fn read(&self, buf: &mut [u8], peek: bool) -> NetworkResult<usize> {
        self.inner.read(buf, peek)
    }
    fn write(&self, data: &[u8]) -> NetworkResult<usize> {
        self.inner.write(data)
    }
    fn write_more(&self, data: &[u8], more: bool, mss: usize) -> NetworkResult<usize> {
        self.inner.write_more(data, more, mss)
    }
    fn push(&self) {
        self.inner.push();
    }
    fn corked_len(&self) -> usize {
        self.inner.corked_len()
    }
    fn write_urgent(&self, data: &[u8]) -> NetworkResult<usize> {
        self.inner.write_urgent(data)
    }
    fn read_urgent(&self, peek: bool) -> NetworkResult<u8> {
        self.inner.read_urgent(peek)
    }
    fn at_mark(&self) -> bool {
        self.inner.at_mark()
    }
    fn shutdown(&self, how: Shutdown) -> NetworkResult<()> {
        self.inner.shutdown(how)
    }
    fn take_error(&self) -> Option<wasmer_sdk::NetworkError> {
        self.inner.take_error()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }
    fn input_len(&self) -> usize {
        self.inner.input_len()
    }
    fn output_len(&self) -> usize {
        self.inner.output_len()
    }
    fn set_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.inner.set_option(level, name, value)
    }
}

#[async_trait]
impl TcpStream for CloseGateStream {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.inner.local_addr()
    }
    fn flush(&self) -> NetworkResult<()> {
        self.inner.flush()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.inner.set_socket_option(level, name, value)
    }
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
        match mode {
            NetworkCloseMode::Normal => {
                let completed = self.close_completed.notified();
                tokio::pin!(completed);
                completed.as_mut().enable();
                let _retired = DropMark(self.normal_waiters_retired.clone());
                self.close_started.add_permits(1);
                completed.await;
                Ok(())
            }
            NetworkCloseMode::Cancel => {
                self.cancel_closes.fetch_add(1, Ordering::SeqCst);
                let result = self.inner.close(NetworkCloseMode::Cancel).await;
                self.close_completed.notify_waiters();
                result
            }
        }
    }
}

#[async_trait]
impl NetworkProvider for CloseGateProvider {
    async fn connect_tcp(
        &self,
        local: SocketAddr,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        let inner = self.host.connect_tcp(local, peer, queue).await?;
        Ok(Arc::new(CloseGateStream {
            inner,
            close_started: self.close_started.clone(),
            normal_waiters_retired: self.normal_waiters_retired.clone(),
            cancel_closes: self.cancel_closes.clone(),
            close_completed: self.close_completed.clone(),
        }))
    }

    async fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        self.host
            .listen_tcp(local, v6only, reuse_port, reuse_addr, backlog, queue)
            .await
    }
}

struct PendingConnectProvider {
    host: Arc<HostNetwork>,
    started: Semaphore,
    canceled: Arc<AtomicUsize>,
}

impl fmt::Debug for PendingConnectProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingConnectProvider")
            .finish_non_exhaustive()
    }
}

impl PendingConnectProvider {
    fn new(host: Arc<HostNetwork>) -> Arc<Self> {
        Arc::new(Self {
            host,
            started: Semaphore::new(0),
            canceled: Arc::new(AtomicUsize::new(0)),
        })
    }
}

#[async_trait]
impl NetworkProvider for PendingConnectProvider {
    async fn connect_tcp(
        &self,
        _local: SocketAddr,
        _peer: SocketAddr,
        _queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        let _drop = DropMark(self.canceled.clone());
        self.started.add_permits(1);
        std::future::pending().await
    }

    async fn listen_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
        backlog: u32,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpListener>> {
        self.host
            .listen_tcp(local, v6only, reuse_port, reuse_addr, backlog, queue)
            .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn run_cancel_joins_connect_without_closing_sibling_listener_and_sandbox_close_joins_all()
-> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider = PendingConnectProvider::new(host_network());
        let provider_trait: DynNetworkProvider = provider.clone();
        let sandbox = create_sandbox(&client, provider_trait, lifecycle_wat()).await?;

        let mut listener_command = sandbox.command("main");
        listener_command.stdin(Stdio::Piped);
        listener_command.stdout(Stdio::Piped);
        let mut listener = listener_command.spawn().await?;
        let mut listener_input = listener.take_stdin().expect("piped listener input");
        listener_input.write_all(b"L").await?;
        listener_input.shutdown().await?;
        let mut stdout = listener
            .take_stdout()
            .expect("guest listener publishes port");
        let mut port_bytes = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), stdout.read_exact(&mut port_bytes))
            .await
            .expect("listener did not publish a port")
            .expect("read listener port");
        let port = published_port(port_bytes);
        let address = SocketAddr::from(([127, 0, 0, 1], port));

        let mut first_command = sandbox.command("main");
        first_command.stdin(Stdio::Piped);
        first_command.stdout(Stdio::Null).stderr(Stdio::Null);
        let mut first_connect = first_command.spawn().await?;
        let mut first_input = first_connect
            .take_stdin()
            .expect("piped first connect input");
        first_input.write_all(b"C").await?;
        first_input.shutdown().await?;
        provider
            .started
            .acquire()
            .await
            .expect("provider connect started")
            .forget();
        first_connect.kill()?;
        assert_eq!(first_connect.wait().await?.reason, ExitReason::Terminated);
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 1);

        let _stream = host_stream_round_trip(address);

        let mut second_command = sandbox.command("main");
        second_command.stdin(Stdio::Piped);
        second_command.stdout(Stdio::Null).stderr(Stdio::Null);
        let mut second_connect = second_command.spawn().await?;
        let mut second_input = second_connect
            .take_stdin()
            .expect("piped second connect input");
        second_input.write_all(b"C").await?;
        second_input.shutdown().await?;
        provider
            .started
            .acquire()
            .await
            .expect("second provider connect started")
            .forget();

        tokio::time::timeout(Duration::from_secs(8), sandbox.close())
            .await
            .expect("sandbox close did not join its network owners")?;
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 2);
        assert!(HostTcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
        assert_eq!(listener.wait().await?.reason, ExitReason::Terminated);
        assert_eq!(second_connect.wait().await?.reason, ExitReason::Terminated);
        assert!(sandbox.command("main").spawn().await.is_err());
        client.shutdown().await
    })
    .await
    .expect("per-run and sandbox network retirement completed")
}

#[derive(Default)]
struct PendingBindState {
    ready: bool,
    canceled: bool,
    closed: bool,
    late_rejected: usize,
}
struct PendingBindStatus {
    state: Mutex<PendingBindState>,
    queue: WaitQueue,
    canceled: Arc<AtomicUsize>,
    close_started: Semaphore,
    release_close: Semaphore,
    closed: Notify,
}
impl PendingBindStatus {
    fn cancel(&self) {
        let first = {
            let mut state = self.state.lock().unwrap();
            let first = !state.canceled;
            state.canceled = true;
            first
        };
        if first {
            self.canceled.fetch_add(1, Ordering::SeqCst);
        }
        self.queue.wake(PollMask::ERR | PollMask::HUP);
    }
    fn usable(&self) -> NetworkResult<()> {
        let state = self.state.lock().unwrap();
        if state.canceled || state.closed {
            Err(wasmer_sdk::NetworkError::ECANCELED)
        } else if state.ready {
            Ok(())
        } else {
            Err(wasmer_sdk::NetworkError::EAGAIN)
        }
    }
    fn complete_late(&self) -> bool {
        let accepted = {
            let mut state = self.state.lock().unwrap();
            if state.canceled || state.closed {
                state.late_rejected += 1;
                false
            } else {
                state.ready = true;
                true
            }
        };
        self.queue.wake(PollMask::OUT | PollMask::ERR);
        accepted
    }
}

type PendingClose = Shared<BoxFuture<'static, NetworkResult<()>>>;
/// This returned owner holds the real binding even while its public metadata is Pending.
/// Its one close future owns the gate and actual native close; Drop spawns no cleanup task.
struct PendingBound {
    inner: Arc<dyn BoundTcp>,
    status: Arc<PendingBindStatus>,
    close: Mutex<Option<PendingClose>>,
}
impl Drop for PendingBound {
    fn drop(&mut self) {
        self.status.cancel();
    }
}
impl Pollable for PendingBound {
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        if let Some(table) = &mut table {
            table.wait_on(&self.status.queue);
        }
        match self.status.usable() {
            Ok(()) => self.inner.poll(table),
            Err(wasmer_sdk::NetworkError::EAGAIN) => PollMask::empty(),
            Err(_) => PollMask::ERR | PollMask::HUP,
        }
    }
}
#[async_trait]
impl BoundTcp for PendingBound {
    fn local_addr(&self) -> NetworkResult<SocketAddr> {
        self.status.usable()?;
        self.inner.local_addr()
    }
    fn set_socket_option(&self, level: i32, name: i32, value: &[u8]) -> NetworkResult<()> {
        self.status.usable()?;
        self.inner.set_socket_option(level, name, value)
    }
    async fn connect(
        &self,
        peer: SocketAddr,
        queue: WaitQueue,
    ) -> NetworkResult<Arc<dyn TcpStream>> {
        self.status.usable()?;
        self.inner.connect(peer, queue).await
    }
    async fn listen(&self, backlog: u32, queue: WaitQueue) -> NetworkResult<Arc<dyn TcpListener>> {
        self.status.usable()?;
        self.inner.listen(backlog, queue).await
    }
    async fn close(&self, mode: NetworkCloseMode) -> NetworkResult<()> {
        let waiting = {
            let mut close = self.close.lock().unwrap();
            close
                .get_or_insert_with(|| {
                    let inner = self.inner.clone();
                    let status = self.status.clone();
                    async move {
                        status.cancel();
                        status.close_started.add_permits(1);
                        status
                            .release_close
                            .acquire()
                            .await
                            .expect("test releases actual pending-owner close")
                            .forget();
                        // No child has been transferred from this pending binding. Both modes
                        // retire this same descriptor, after any late same-owner result.
                        let result = inner.close(mode).await;
                        status.state.lock().unwrap().closed = true;
                        status.closed.notify_one();
                        result
                    }
                    .boxed()
                    .shared()
                })
                .clone()
        };
        waiting.await
    }
}

struct PendingBindProvider {
    host: Arc<HostNetwork>,
    started: Semaphore,
    canceled: Arc<AtomicUsize>,
    requested: Mutex<Option<SocketAddr>>,
    actual: Mutex<Option<SocketAddr>>,
    owner: Mutex<std::sync::Weak<PendingBound>>,
    status: Arc<PendingBindStatus>,
}
impl fmt::Debug for PendingBindProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingBindProvider")
            .finish_non_exhaustive()
    }
}
impl PendingBindProvider {
    fn new(host: Arc<HostNetwork>) -> Arc<Self> {
        let canceled = Arc::new(AtomicUsize::new(0));
        Arc::new(Self {
            host,
            started: Semaphore::new(0),
            canceled: canceled.clone(),
            requested: Mutex::new(None),
            actual: Mutex::new(None),
            owner: Mutex::new(std::sync::Weak::new()),
            status: Arc::new(PendingBindStatus {
                state: Mutex::default(),
                queue: WaitQueue::new(),
                canceled,
                close_started: Semaphore::new(0),
                release_close: Semaphore::new(0),
                closed: Notify::new(),
            }),
        })
    }
    fn complete_late(&self) -> (bool, SocketAddr) {
        // The completion belongs to the already-returned owner and its SAME prepared fd.
        // It never creates a replacement descriptor or publishes after cancellation/ACK.
        let actual = self
            .actual
            .lock()
            .unwrap()
            .expect("pending bound address recorded");
        if !self.status.state.lock().unwrap().closed {
            let owner = self
                .owner
                .lock()
                .unwrap()
                .upgrade()
                .expect("accepted result retains its SAME owner until close ACK");
            assert!(Arc::ptr_eq(&owner.status, &self.status));
            assert_eq!(
                owner
                    .inner
                    .local_addr()
                    .expect("actual resource remains owned"),
                actual
            );
        }
        (self.status.complete_late(), actual)
    }
}
#[async_trait]
impl NetworkProvider for PendingBindProvider {
    async fn bind_tcp(
        &self,
        local: SocketAddr,
        v6only: bool,
        reuse_port: bool,
        reuse_addr: bool,
    ) -> NetworkResult<Arc<dyn BoundTcp>> {
        *self.requested.lock().unwrap() = Some(local);
        let inner = self
            .host
            .bind_tcp(local, v6only, reuse_port, reuse_addr)
            .await?;
        *self.actual.lock().unwrap() = Some(inner.local_addr()?);
        let owner = Arc::new(PendingBound {
            inner,
            status: self.status.clone(),
            close: Mutex::new(None),
        });
        *self.owner.lock().unwrap() = Arc::downgrade(&owner);
        self.started.add_permits(1);
        // Host bind is synchronous when polled. No suspension follows accepted work: return
        // the existing Pollable owner now, and represent ongoing readiness with EAGAIN.
        Ok(owner)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn killing_pending_bind_closes_prepared_and_late_bound_handles() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let state = TempDir::new().expect("create SDK state");
        let client = client(&state)?;
        let provider = PendingBindProvider::new(host_network());
        struct ReleaseClose(Arc<PendingBindStatus>);
        impl Drop for ReleaseClose {
            fn drop(&mut self) {
                self.0.release_close.add_permits(1);
            }
        }
        // Unwind releases the existing tracked close future; Drop starts no work.
        let _release_on_exit = ReleaseClose(provider.status.clone());
        let provider_trait: DynNetworkProvider = provider.clone();
        let requested = SocketAddr::from(([127, 0, 0, 1], 0));
        let sandbox = create_sandbox(&client, provider_trait, pending_bind_wat(requested)).await?;
        let mut process = sandbox.command("main").spawn().await?;
        provider
            .started
            .acquire()
            .await
            .expect("pending owner returned")
            .forget();
        assert_eq!(*provider.requested.lock().unwrap(), Some(requested));
        let actual = provider
            .actual
            .lock()
            .unwrap()
            .expect("bound address recorded");
        assert_ne!(actual.port(), 0);
        let owner = provider
            .owner
            .lock()
            .unwrap()
            .upgrade()
            .expect("SDK retains the returned pending owner");
        assert_eq!(owner.local_addr(), Err(wasmer_sdk::NetworkError::EAGAIN));
        assert!(owner.poll(None).is_empty());

        process.kill()?;
        provider
            .status
            .close_started
            .acquire()
            .await
            .expect("tracked pending-owner close started")
            .forget();
        let mut waiting = Box::pin(process.wait());
        assert!(
            futures::poll!(waiting.as_mut()).is_pending(),
            "process wait must join the actual close ACK"
        );
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 1);
        assert!(
            matches!(
                provider.host.bind_tcp(actual, false, false, false).await,
                Err(wasmer_sdk::NetworkError::EADDRINUSE)
            ),
            "actual prepared fd remains reserved before ACK"
        );

        let (delivered, late_address) = provider.complete_late();
        assert!(
            !delivered,
            "a canceled owner must reject its late completion"
        );
        assert_eq!(late_address, actual);
        assert_eq!(owner.local_addr(), Err(wasmer_sdk::NetworkError::ECANCELED));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        assert!(
            matches!(
                provider.host.bind_tcp(actual, false, false, false).await,
                Err(wasmer_sdk::NetworkError::EADDRINUSE)
            ),
            "late completion does not release or replace the owned fd"
        );
        provider.status.release_close.add_permits(1);
        assert_eq!(waiting.await?.reason, ExitReason::Terminated);
        tokio::time::timeout(Duration::from_secs(5), provider.status.closed.notified())
            .await
            .expect("actual native close acknowledgement was not recorded");
        assert!(provider.status.state.lock().unwrap().closed);

        let (delivered, late_address) = provider.complete_late();
        assert!(!delivered, "closed owner cannot resurrect after ACK");
        assert_eq!(late_address, actual);
        assert_eq!(provider.status.state.lock().unwrap().late_rejected, 2);
        // Retain the public owner Arc: retirement must be physical, not delayed until Drop.
        let rebound = provider
            .host
            .bind_tcp(actual, false, false, false)
            .await
            .expect("retired actual binding can be reused");
        assert_eq!(
            rebound.local_addr().expect("rebound actual address"),
            actual
        );
        rebound
            .close(NetworkCloseMode::Normal)
            .await
            .expect("close rebound binding");
        owner
            .close(NetworkCloseMode::Normal)
            .await
            .expect("repeat normal close joins the same acknowledgement");
        owner
            .close(NetworkCloseMode::Cancel)
            .await
            .expect("repeat cancel joins the same acknowledgement");
        assert_eq!(provider.canceled.load(Ordering::SeqCst), 1);
        sandbox.close().await?;
        client.shutdown().await
    })
    .await
    .expect("pending owner and same-owner late completion were retired")
}
