# Native Linux applications on WLK

Date: 2026-11-05

Status: research only. No prototype, execution experiment, benchmark, or security
validation was performed. A Sol 6.1 high subagent produced the conceptual analysis
without using tools; the parent checked the referenced public documentation.
This is a separate possible project, not an expansion of the current WASIX v1
compatibility delivery.

## Decision and objective

Explore running unmodified native Linux applications against WLK as their
guest-visible kernel, with an enforced boundary around hostile native code.
WLK should own the supported guest syscall semantics and resource identities.
Host services should be reached through controlled implementations of WLK's host
interfaces, rather than by generally allowing the application's syscalls through.

**The Firejail approach is discarded for this project.** A launcher that configures
host namespaces and syscall restrictions, then lets host Linux implement allowed
application operations, does not meet this objective. This is a scope decision,
not a claim that host-kernel confinement is never useful. Namespaces, seccomp,
capability restrictions and resource controls can still provide defense in depth
around the proposed runtime.

The closest architectural precedent is a gVisor-style application kernel:
guest-visible kernel behavior runs in userspace, supported by a separate execution
platform and a narrow host-service boundary. This does not propose embedding
gVisor or copying its implementation. See the [gVisor architecture description](https://gvisor.dev/docs/architecture_guide/intro/).

## Feasibility

This is feasible in principle, but requires a substantial native execution backend.
WLK's engine-independent kernel is a useful starting point; interception and native
execution control are additional responsibilities, not consequences of moving its
crates out of Wasmer.

Conceptually, the application encounters an enforced interception boundary, a native
backend translates the operation into WLK semantics, and WLK performs any necessary
host operations through restricted services. Responses return to the original
native thread with the appropriate Linux ABI result.

The trusted supervisor must be isolated from the application's address space.
Arbitrary native code can overwrite an in-process supervisor's memory regardless
of whether that supervisor is written in Rust. An interposed libc or an
LD_PRELOAD library is therefore not the proposed security boundary.

Host Linux remains responsible for underlying address-space isolation, CPU
scheduling and other platform services. Guest operations and supervisor host
operations must be distinguished: mediation through WLK does not mean the
supervisor itself stops making Linux syscalls.

## Execution-platform options

| Option | Useful role | Main limitation |
| --- | --- | --- |
| ptrace | Initial execution bridge: inspect syscall entry, suppress the original operation and supply a WLK result. | Thread-by-thread control, signal/restart semantics and repeated tracing stops complicate compatibility and performance. |
| Seccomp user notification | Selected emulation and supervisor-owned resource operations within a larger confined platform. | Notifications and return values alone cannot create native mappings, threads or execution contexts. Pointer races require careful handling. |
| Syscall User Dispatch | Cooperative compatibility experiments. | Application-controlled dispatch can be bypassed by malicious code; unsuitable as the security boundary. |
| Dynamic binary translation | Control native syscall instructions and, if needed, additional execution behavior. | Introduces a large translation/runtime project, including executable mappings, signals, threading and self-modifying code. |
| Restricted native platform with WLK supervision | Production architectural direction, combining interception, isolated execution and narrow host services. | Requires an explicit threat model and substantial compatibility/security engineering. |

Ptrace exposes control over individual threads, registers and memory; observing a
process does not automatically cover every thread. A backend must establish and
maintain control across creation, exec and exit. Its suitability as a first bridge
does not establish production security or acceptable throughput.
See [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Seccomp user notification can delegate handling to a supervisor and can transfer
descriptors. Its own documentation cautions against treating it as a general
security-policy mechanism. In particular, inspecting mutable pointer arguments and
then using CONTINUE is not an authorization boundary: another writer can change
the inputs before Linux consumes them. Prefer copied inputs and supervisor-owned
operations where the semantics permit, with explicit rules for outputs and atomic
operations. See [seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).

Syscall User Dispatch is explicitly described as a compatibility facility rather
than a sandbox mechanism. It must not become a shortcut around the external
boundary. See its [security notes](https://docs.kernel.org/admin-guide/syscall-user-dispatch.html#security-notes).

## Required boundary and semantics

### Complete mediation and lifecycle

Confinement must be active before untrusted instructions run and remain active
across all supported syscall entry conventions, threads, fork, clone and exec.
Inherited descriptors and shared mappings are capabilities that need deliberate
handling. Unsupported indirect interfaces should initially be denied explicitly.

Returning a virtual PID does not create a native child. The backend must coordinate
actual execution contexts, registers, stack/TLS setup, confinement and WLK task
registration. Exec must replace execution state without opening an unconfined
window or confusing the old and new address-space owners.

### Memory and pointer arguments

Native memory instructions need real mappings and protections in the target
address space. Reporting success for mmap does not establish those mappings.
Mapping changes, sharing, executable memory and faults need an explicit division
of responsibility between WLK and the platform.

Native UserMemory access must handle inaccessible pages, checked arithmetic,
partial copies and races. Stopping one thread does not stop every writer to shared
memory. Nested argument structures need bounded copying and validation; copying
alone does not solve every atomicity requirement.

### Descriptors, waits and signals

WLK descriptor identities must remain distinct from supervisor/host descriptors.
Duplication, inheritance, close/reuse, polling and descriptor passing must agree
with the selected guest model. Broad host-descriptor injection could undermine
WLK's resource ownership and cannot be the default implementation strategy.

Futexes require correct atomic interaction with application memory, timeouts,
wakeups and signals. Signal delivery requires native masks, frames, alternate
stacks, interrupted-call behavior and register restoration. These are not merely
translations of Wasm callbacks.

### Execution outside syscalls

Syscall mediation does not control every CPU instruction or memory interaction.
vDSO paths and direct CPU instructions can bypass a syscall-based time or feature
virtualization scheme. The threat model must separate resource confinement from
deterministic execution or complete behavioral virtualization.

## WLK reuse and interface audit

The described kernel, VFS/VNet, task, descriptor, signal and host abstractions may
provide substantial reusable semantics. This analysis did not audit their current
source or establish native Linux ABI compatibility.

Before estimating implementation scope, audit:

- Guest pointer/address-width assumptions, layouts, syscall numbers and flags.
  WASIX compatibility is not evidence of complete Linux native ABI compatibility.
- The split between internal kernel semantics and generated Wasmer/WASIX bindings.
- UserMemory contracts for cross-process access, races, faults and ownership.
- Task control that currently relies on cooperative engine safepoints.
- Memory, native signal/TLS state and execution-context ownership across exec/fork.
- Blocking operations, cancellation and worker retirement without supervisor
  deadlocks or premature release of a live execution context.
- Unsupported syscalls and interactions exposed by actual target applications.

The native backend should consume WLK interfaces without introducing Wasmer
dependencies into the pure kernel. If those interfaces need generalization, that
requires a separately reviewed design; do not guess a large generic abstraction
from this conceptual report alone.

## Proposed research stages

1. **Threat model and interface audit.** Define hostile-code assumptions, trusted
   components, supported architecture, resource boundaries and initial syscall
   subset. Audit WLK's relevant contracts and choose the execution-platform model.
2. **Limited execution bridge.** A ptrace-based experiment is a plausible first
   vehicle: a static, single-threaded executable, a small explicit syscall set and
   WLK-owned filesystem behavior. Reject unsupported operations. This establishes
   feasibility, not a production security claim.
3. **Containment validation.** Exercise direct syscalls, alternative entry paths,
   inherited capabilities, pointer races, supervisor access attempts, lifecycle
   changes and cancellation. Verify that no unchecked pass-through substitutes
   host Linux semantics for the promised WLK operations.
4. **Named application compatibility.** Add dynamic loading, threads, signals,
   memory and networking against specific programs and documented profiles.
   Preserve unsupported behavior explicitly instead of claiming arbitrary Linux.
5. **Production platform evaluation.** Measure interception costs, supervisor
   scheduling, contention and memory consumption. Select a defensible platform,
   subject it to independent security review and determine the supported Linux ABI.

No stage is authorized for execution by this research document. Performance,
kernel-version requirements, privileges, host configuration and security claims
remain to be verified before selecting an implementation.

## Conclusion

WLK could form the reusable kernel component of a native Linux sandbox. The missing
piece is a secure native execution platform, plus the ABI and lifecycle integration
that connects actual native execution to WLK's virtual resources. The intended
direction is a userspace application kernel, with the host-confinement-only
approach excluded. Supporting arbitrary hostile Linux applications would be a
separate runtime, compatibility and security program.
