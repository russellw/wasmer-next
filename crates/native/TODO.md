# Native execution follow-ups

Keep the MVP in `crates/native`. These are execution-adapter gaps and possible
future WLK additions, not a request to refactor the core kernel now. Update this
list as the native implementation and tests establish the supported subset.

- [ ] **Native address width.** WLK's guest pointers and retained memory addresses
  are 32-bit. The native adapter translates 64-bit pointers and uses stable aliases
  for addresses retained between calls. Consider an execution-neutral native
  address-space capability before expanding this adapter indefinitely.
- [ ] **Native memory management.** Startup `brk`, anonymous mappings, protection
  changes, and TLS currently execute in Linux. They are not represented fully in
  WLK's memory accounting and mapping model.
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
  if that file changes during handoff. Dynamic `execveat` directory-relative
  custom-dirfd and empty-path operands currently return `ENOSYS` before commit;
  add descriptor-aware resolution when needed. Canonicalizing CLI host paths
  also loses symlink spelling and can change `$ORIGIN` for symlinked programs.
- [ ] **Futex atomics and robust lists.** The default `UserMemory` compare-exchange
  is a read followed by a write, which is unsuitable for concurrent native
  threads. Keep unsupported PI/atomic operations explicit until there is a real
  atomic backend. Native 64-bit robust-list layouts also need translation.
- [ ] **Native clock deadlines.** Native vDSO monotonic time uses the host clock's
  origin, while `TokioHost::monotonic` uses its own elapsed-time origin. Normalize
  absolute monotonic futex deadlines before supporting timed bitset waits; do not
  silently interpret one clock's absolute deadline in the other clock's domain.
- [ ] **vfork and process-spawn variants.** Ordinary fork support does not establish
  shared-memory vfork or musl `posix_spawn` compatibility. Record rejected clone
  combinations and add them only with lifecycle tests.
- [ ] **wait4 details and host reaping.** Convert non-null native `rusage` outputs;
  the first adapter explicitly returns `ENOSYS` for them. The MVP runs native
  process creation with `CLONE_PARENT` (rewriting fork to clone) so the supervisor
  is the real host parent and can reap its tracees. WLK retains the guest-visible
  parent/child hierarchy. This avoids unreaped host children but changes the
  hierarchy visible through host `/proc`; replace it if that distinction matters.
- [ ] **Exec handover.** The MVP executes WLK-resolved image bytes using a native
  memfd/temporary-stack handover. Replace that workaround with direct native image
  ownership when needed. Multithreaded exec remains unsupported; a host-exec
  failure after WLK commits must terminate the task instead of resuming stale code.
- [ ] **Signals and native exits.** Native signal delivery, WLK pending actions,
  clear-TID teardown, and native ptrace exits must stay consistent. Expand beyond
  the tested subset with fatal-exit and job-control regressions.
- [ ] **Interactive terminal and job control.** `-i` forces a Bash prompt but does
  not provide terminal job control. The current stdio bridge exposes streams,
  not a controlling WLK terminal. Bind terminal descriptors with provenance-aware
  attachments or an existing WLK console, supply device nodes without privileged
  host mknod, and restore host termios on every exit. Native signal dispositions,
  foreground groups, and WLK signal/stop/continue actions must be integrated before
  claiming `fg`, `bg`, Ctrl-C, or Ctrl-Z compatibility. Do not fake successful
  terminal ioctls or forward virtual process-group IDs to host TIOCSPGRP.
- [ ] **Additional ABI translations.** Add native structure and syscall adapters
  as concrete programs need them. The statx-to-native-stat conversion is present;
  wider socket message structures still need explicit 64-bit layout conversion.
- [ ] **Kernel `dup2` semantics.** Add a WLK `Dup2` operation that owns Linux's
  `oldfd == newfd` validation/no-op behavior. The native adapter currently maps
  different descriptors to `Dup3(flags=0)` and handles the same-descriptor case
  by checking the WLK descriptor table first.
- [ ] **Networking adapter follow-ups.** Translate `sendmsg`/`recvmsg` and the mmsg
  family, including 64-bit iovecs and control messages. Narrow the `getsockopt`
  output alias to the tracee's requested length. The current host backend owns
  its reactor/resolver rather than consuming the WLK `Host` capability; consider
  an adapter only when a concrete host-service requirement needs one. The current
  gateway alias (`10.0.2.2`) and localhost publication policy are documented in the
  native README; broader host-network compatibility needs separate work.
- [ ] **Copy and I/O edge cases.** The bounded adapter can return faults on short
  cross-process memory copies rather than reproducing every Linux partial-copy
  case. Standard-output sinks also need proper error propagation for broken pipes
  and failed writes.
- [ ] **Existing terminal-test flake.** Before native implementation changes,
  `cargo test -p wasixv2-kernel --lib --locked` passed 1,181 tests but failed
  `tests::tty::finite_console_empty_eof_does_not_hang_up_the_terminal` with
  `None` instead of `Some(Ok(0))` at `crates/kernel/src/tests/tty.rs:667`.
  The isolated rerun passed. Investigate separately; no core fix was attempted.

Every temporary workaround should have a nearby `// TODO` comment identifying
its limitation and, where useful, referring back to this file.
