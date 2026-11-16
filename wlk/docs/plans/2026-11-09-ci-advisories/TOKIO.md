# Tokio 1.53.3 advisory correction

The baseline is WLK `7ec3347a564ed5eb1c9acf2bb75b64e709dba61d`.
The manifest now requires Tokio 1.53.3; the lock changes only Tokio's version
and checksum from 1.53.1. No Tokio feature or unrelated package changes.

[RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html)
identifies unsafe descriptor registration through the former safe `AsyncFd`
constructors. The patched 1.53.3 line introduces unsafe `register` and
`register_with_interest`: the descriptor must remain valid, open, unchanged and
refer to the same file description throughout registration. It deprecates the
old constructors; it does not make arbitrary raw-fd ownership safe.

WLK contains no `AsyncFd` use. Its Tokio host enables io-std, io-util, rt, sync
and time, not net; direct host operations use LocalSet, spawn_local,
spawn_blocking, Handle/runtime flavor, stdout/stderr and channels. This audit
does not certify external callers or feature-unified Next consumers. No new
unsafe registration call or assumed raw-fd ownership is introduced here.

The exact cached 1.53.1/1.53.3 sources were compared against the
[upstream patch changelog](https://github.com/tokio-rs/tokio/blob/tokio-1.53.3/tokio/CHANGELOG.md).
`task/local.rs`, `runtime/task/harness.rs` and the multi-thread worker are
byte-identical. JoinHandle polling, Sleep and I/O registration pass the current
Context into trace_leaf. Current-thread scheduling now unparks its own driver;
unstable task-dump changes are not an enabled WLK profile. Rejected blocking
tasks are shut down after dropping the blocking-pool mutex. These changes do not
transfer task, output, panic or runtime ownership to a different owner. Existing
runtime/LocalSet/guard ownership remains the consumer's responsibility.

After independent source review, the focused gate is the existing
`tokio_host::tests` on the Tokio host profile (excluding the explicitly ignored
timer measurement), its timer tests, and affected strict Clippy. These cover
Ready/Pending timing, local/blocking execution and panic propagation, and both
current-thread and multi-thread guest execution. Record actual counts and source
identity; this document is not a test receipt or renewed CAPI acceptance.

Next composition is ROOT-owned: raise its Tokio minimum to 1.53.3 if it separately
declares Tokio, resolve the same 1.53.3 package without unrelated registry updates,
and preserve its coherent 21 WLK Git identities. This WLK lock alone does not
update a downstream consumer's lockfile. Any source-specific consumer assumptions
must be checked against that composed lock, not inferred from this repository.

OpenAI Codex authored this source audit and correction. Human maintainers remain
responsible for integration.
