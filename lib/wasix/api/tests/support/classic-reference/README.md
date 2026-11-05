# Original classic relay reference, tests only

This unpublished fixture retains the original Wasmer v1 networking record, server,
MPSC transport and host socket implementation at commit
`427c4cbfc5b805b109f0fba93ad26573cf6c3774`. It is an independent test dependency;
no production crate depends on it, `virtual-net` or `virtual-mio` through these tests.
The sibling `classic-io-reference` retains the original IO selector/interest code.
Both retain the original MIT license and copyright notice in `LICENSE`.

`SOURCES.json` records original and retained SHA-256 values. `meta.rs`, `server.rs`,
`rx_tx.rs` and every IO source file are byte-for-byte originals. The retained
`lib.rs` omits only unused module/export declarations (client, composite, loopback,
ruleset, tcp_pair and their unit-test module). The retained `host.rs` selects the
original `LocalNetworking::new()` profile: it removes the unused `with_ruleset`
constructor, optional ruleset storage and its conditional policy branches, which
are unreachable in that profile. All socket/TCP/UDP/DNS/selector behavior is
retained. No wire tag, serialization layout, server dispatch, asynchronous task,
ACK, socket readiness, queue or EOF behavior has been replaced with a mock.

The test-only manifests keep only dependencies and features needed for that
profile. Original disabled optional transport/archive cfgs remain in the source
and are declared as expected cfg names without offering those fixture features.
This fixture deliberately preserves original protocol defects so the existing
reference tests continue to expose them. It permits retiring the old production
network crates without deleting or rewriting compatibility evidence.
