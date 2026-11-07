# Native execution follow-ups

Keep the MVP in `crates/native`. These are execution-adapter gaps and possible
future WLK additions, not a request to refactor the core kernel now. Update this
list as the native implementation and tests establish the supported subset.

This is an inventory of known gaps, not a claim to enumerate every possible
Linux feature or undiscovered bug. It includes source-level workarounds and
explicitly unsupported cases from [README.md](README.md). Add adapters in response
to concrete workloads and preserve predictable errors for unsupported variants.
Namespaces, host cgroups, and additional isolation remain outside this MVP's
scope; this list does not silently expand that scope.

## Execution model and memory

- [ ] **Native address width.** WLK's guest pointers and retained memory addresses
  are 32-bit. The native adapter translates 64-bit pointers and uses stable aliases
  for addresses retained between calls. Consider an execution-neutral native
  address-space capability before expanding this adapter indefinitely.
- [ ] **Native memory management.** Startup `brk`, anonymous mappings, protection
  changes, and TLS currently execute in Linux. They are not represented fully in
  WLK's memory accounting and mapping model. Retained pointer aliases also need
  lifecycle coverage across threads, fork, exec, and native mapping changes.
  Sources: [main.rs](src/main.rs), [memory.rs](src/memory.rs).
- [ ] **Mapping and injection completeness.** Extend unsupported mmap flags and
  mapping types as workloads need them. A fixed mapping that covers the current
  syscall instruction is rejected; a dedicated injection trampoline would remove
  that restriction. Unexpected signal stops during injection currently fail the
  run: restore the original context and deliver/defer the signal correctly.
  Test failures during allocation, copying, protection changes, and unmap cleanup;
  cleanup failures currently leave pages until process teardown. Preserve Linux's
  handling of legacy `MAP_DENYWRITE`/`MAP_EXECUTABLE` hints when extending flags;
  their current ignore behavior is intentional.
  Sources: [mapping.rs](src/mapping.rs), [injection.rs](src/injection.rs).
- [ ] **Bootstrap and host capability baseline.** Replace the dynamic launch's
  post-Tokio fork with a pre-runtime launch handshake. Until then, keep the child
  path allocation-free and limited to syscall-level setup before exec. Establish
  and test the minimum host-kernel capability set, including syscall-stop
  inspection, procfs handoff, and executable memfds. Retain the `MFD_EXEC` fallback
  until the supported baseline permits removing it; test host noexec/permission
  failures rather than assuming all Linux environments allow the same operations.
  Sources: [platform.rs](src/platform.rs), [exec.rs](src/exec.rs).
- [ ] **Dynamic ELF fidelity.** Dynamic musl/glibc loading, transitive `$ORIGIN`
  libraries, constructors, `dlopen`, pthread TLS, root/volume lookup, and guest
  exec/fork pass acceptance tests. The adapter uses the existing guest-resolved
  loader and private snapshot mappings of WLK-owned descriptors. Add shared
  mappings, backing-file write visibility, and truncation/SIGBUS fidelity when
  needed. Core WLK currently rejects executable mappings, so native execution
  mappings remain explicit in the adapter rather than stripping `PROT_EXEC`.
  Explicit loader invocation leaves native `AT_EXECFN` and `/proc/self/exe`
  identifying the loader memfd, although WLK retains the main process image.
  Reopening the main guest path differs from executing the exact committed image
  if that file changes during handoff. Empty-path `execveat` and dynamic targets
  named relative to a custom dirfd are rejected before commit; add descriptor-aware
  resolution, including execute-only static targets the current read probe cannot
  inspect. Canonicalizing CLI host paths also loses symlink spelling and can change
  `$ORIGIN` for symlinked programs.
  Sources: [exec.rs](src/exec.rs), [main.rs](src/main.rs).
- [ ] **Futex atomics and robust lists.** The default `UserMemory` compare-exchange
  is a read followed by a write, which is unsuitable for concurrent native
  threads. Keep unsupported PI/`FUTEX_WAKE_OP` operations explicit until there is
  a real atomic backend. Native 64-bit robust-list layouts also need translation.
- [ ] **Native clock deadlines.** Native vDSO monotonic time uses the host clock's
  origin, while `TokioHost::monotonic` uses its own elapsed-time origin. Normalize
  absolute monotonic futex deadlines before supporting timed bitset waits; do not
  silently interpret one clock's absolute deadline in the other clock's domain.
  Source: [sync.rs](src/sync.rs).

## Processes, signals, and terminals

- [ ] **vfork and process-spawn variants.** Ordinary fork support does not establish
  shared-memory vfork or musl `posix_spawn` compatibility. Add `clone3`, wider clone
  flags, process clones sharing `CLONE_VM`, custom child-stack handoff, and other
  rejected combinations only with lifecycle tests. Thread creation currently
  supports the pthread-style subset rather than every Linux clone combination.
  Sources: [main.rs](src/main.rs), [scheduler.rs](src/scheduler.rs).
- [ ] **wait4 details and host reaping.** Convert non-null native `rusage` outputs;
  the first adapter explicitly returns `ENOSYS` for them. The MVP runs native
  process creation with `CLONE_PARENT` (rewriting fork to clone) so the supervisor
  is the real host parent and can reap its tracees. WLK retains the guest-visible
  parent/child hierarchy. This avoids unreaped host children but changes the
  hierarchy visible through host `/proc`; replace it if that distinction matters.
- [ ] **Exec handover.** The MVP executes WLK-resolved image bytes using a native
  memfd/temporary-stack handover. Replace that workaround with direct native image
  ownership and a dedicated scratch mapping rather than borrowing space below the
  native stack pointer. Multithreaded exec needs Linux `de_thread` semantics.
  Currently a host-exec failure after WLK commits terminates the task; a future
  prepare/commit protocol should allow rollback without resuming a mismatched image.
  Sources: [platform.rs](src/platform.rs), [runtime.rs](src/runtime.rs).
- [ ] **Signals and native exits.** Native signal delivery, WLK pending actions,
  clear-TID teardown, and native ptrace exits must stay consistent. Implement the
  remaining WLK signal/stop/continue actions, including actions encountered during
  teardown. Native `SIGCHLD` is currently suppressed; synthesize virtual child
  notifications from WLK lifecycle events. Reconcile native signal dispositions
  with WLK state rather than treating startup passthrough as complete signal support.
  Sources: [runtime.rs](src/runtime.rs), [main.rs](src/main.rs).
- [ ] **Interactive terminal and job control.** `-i` forces a Bash prompt but does
  not provide terminal job control. The current stdio bridge exposes streams,
  not a controlling WLK terminal. Bind terminal descriptors with provenance-aware
  attachments or an existing WLK console, supply device nodes without privileged
  host mknod, and restore host termios on every exit. Native signal dispositions,
  foreground groups, and WLK signal/stop/continue actions must be integrated before
  claiming `fg`, `bg`, Ctrl-C, or Ctrl-Z compatibility. Do not fake successful
  terminal ioctls or forward virtual process-group IDs to host TIOCSPGRP.

## Filesystem and networking ABI

- [ ] **Additional ABI translations.** Add native structure and syscall adapters
  as concrete programs need them. The statx-to-native-stat conversion is present;
  wider socket message structures still need explicit 64-bit layout conversion.
  Keep conversion tests for native `stat`, iovecs, time structures, and socket
  layouts. If WLK later exposes a native stat ABI, reassess the existing Statx
  adapter instead of maintaining duplicate conversions unnecessarily.
- [ ] **Descriptor-control ABI.** Translate native `flock` structures and other
  `fcntl` commands beyond the six supported scalar commands. Add explicit layouts
  for further pointerful ioctls, keeping scalar arguments distinct from 32-bit
  guest pointers and preserving `EBADF` precedence for invalid descriptors.
  Sources: [newfd.rs](src/newfd.rs), [ioctl.rs](src/ioctl.rs).
- [ ] **Kernel `dup2` semantics.** Add a WLK `Dup2` operation that owns Linux's
  `oldfd == newfd` validation/no-op behavior. The native adapter currently maps
  different descriptors to `Dup3(flags=0)` and handles the same-descriptor case
  by checking the WLK descriptor table first.
- [ ] **Readiness APIs.** Add native `poll`/`ppoll`, `select`/`pselect6`, and epoll
  adapters, including native layouts, timeouts, and signal-mask semantics. These
  currently lack translations and block broader shell/server workloads even when
  basic sockets work. Use WLK virtual descriptors and concurrent pending calls;
  passing those descriptor numbers to host readiness syscalls is not valid.
  Source boundary: [main.rs](src/main.rs); pending-call model: [runtime.rs](src/runtime.rs).
- [ ] **Networking adapter follow-ups.** Translate `sendmsg`/`recvmsg` and the mmsg
  family, including 64-bit iovecs and control messages. Narrow the `getsockopt`
  output alias to the tracee's requested length. The current host backend owns
  its reactor/resolver rather than consuming the WLK `Host` capability; consider
  an adapter only when a concrete host-service requirement needs one. The current
  gateway alias (`10.0.2.2`) and localhost publication policy are documented in the
  native README; broader host-network compatibility needs separate work.
  Source: [net.rs](src/net.rs).

## Error handling and I/O

- [ ] **Direct translator errno results.** Let translators return immediate errno
  values consistently instead of manufacturing faulting pointers or unterminated
  strings. Preserve `EFAULT`, `E2BIG`, and `ENAMETOOLONG` distinctions for exec
  arguments and paths. Unaligned futex addresses currently fall back to `ENOSYS`;
  return Linux's `EINVAL` directly. Add regressions for boundary lengths, invalid
  arrays, alignment, and descriptor-error precedence.
  Sources: [exec.rs](src/exec.rs), [sync.rs](src/sync.rs).
- [ ] **Copy and I/O edge cases.** The bounded adapter can return faults on short
  cross-process memory copies rather than reproducing every Linux partial-copy
  case. Standard-output sinks also need proper error propagation for broken pipes
  and failed writes. Document and test short counts at the adapter's transfer cap,
  including vectored I/O, rather than relying on accidental truncation behavior.
  Source: [main.rs](src/main.rs).

## Validation and maintenance

- [ ] **Failure-path lifecycle coverage.** Add bounded regressions for native
  crashes/signals, supervisor termination, failed native clone after WLK approval,
  failed exec after WLK commit, and interruption/failure during mapping injection.
  Check that native children are killed/reaped as appropriate, pending futures are
  cancelled, clear-TID happens while memory exists, and WLK tasks release once.
  Existing acceptance success paths do not establish those guarantees for every
  failure path. Sources: [tests/smoke.rs](tests/smoke.rs), [runtime.rs](src/runtime.rs).
- [ ] **Required acceptance tiers.** Make enabled/skipped fixture tiers explicit in
  CI. Missing musl compilers or optional Bash/BusyBox binaries currently cause some
  tests to return early; a green test count alone does not prove those workloads
  ran. Provide a job that requires the libc, dynamic-loader, shell, and network
  tiers intended as release gates.
  Sources: [tests/smoke.rs](tests/smoke.rs), [network_listener.rs](tests/network_listener.rs).
- [ ] **Fixture pin upkeep and download failures.** Keep the pinned cache paths,
  NAR hashes, executable checksums, and source/build instructions in sync. Exercise
  a cold-cache download and unavailable-cache/hash-mismatch failures, confirming
  installed fixtures stay intact. Generated assets must remain ignored.
  Source: [download-fixtures.sh](tests/fixtures/download-fixtures.sh).
- [ ] **Revalidate the historical terminal-test flake.** Before native changes,
  `cargo test -p wasixv2-kernel --lib --locked` passed 1,181 tests but failed
  `tests::tty::finite_console_empty_eof_does_not_hang_up_the_terminal` with
  `None` instead of `Some(Ok(0))` at `crates/kernel/src/tests/tty.rs:667`.
  The isolated rerun passed. Check whether it still reproduces against the current
  core before treating it as an active issue; no native-related core fix was attempted.

Every temporary workaround should have a nearby `// TODO` comment identifying
its limitation and, where useful, referring back to this file. When adding a new
unsupported variant or workaround, update this inventory and the README boundary,
and record the regression needed to close it. When resolving one, update all three
rather than leaving stale comments behind. Audit starting point:

```sh
rg -n 'TODO|FIXME|ENOSYS|unsupported' crates/native/src
```
