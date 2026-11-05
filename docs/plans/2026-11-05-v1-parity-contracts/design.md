# Remaining v1 compatibility contracts

Status: proposed; independently reviewed by Sol 6.1 high subagents. Production
implementation of the changes below awaits user agreement. This is bounded
compatibility work, not a commitment to the complete Linux surface.

## macOS pathname metadata and inode capabilities

Required behavior: on macOS 13+, pathname metadata for an existing mode-000 file
must work when host `lstat` works, even when opening that file is denied. The old
host filesystem performs metadata and readlink by pathname. Data handles, truncate
and file times use retained descriptors.

The current driver needs an inode-pinning descriptor during lookup. Public Darwin
open modes examined do not provide an unprivileged equivalent of Linux `O_PATH`
for arbitrary regular files. `O_EVTONLY` still encounters access restrictions;
private/process-wide opt-ins and temporary permission changes are excluded.

The pure VFS must distinguish a pathname observation from a retained inode:

- Add `Node::lookup_entry`, defaulting to the existing lookup and a pinned result.
  Its alternate result describes an anchored parent capability, one final name and
  observed attributes. It is operation-scoped and does not implement `Node`.
- Add parent-relative existing-file acquisition, analogous to `create_open`.
  Darwin opens the selected object without truncation, obtains its fd attributes,
  and validates guest permission, mount, type and security policy before data I/O,
  truncation or canonical inode publication.
- Extend terminal name resolution and pathname-stat/access operations to consume
  observations. Keep `Path`, `Inode`, `File` and descriptor operations pinned.
- Never put observations in inode/dentry caches, aliases, locks, leases, exports,
  seals or descriptor tables. Persistent-object requests must acquire a genuine
  capability or fail explicitly.
- Preserve directory traversal through pinned search capabilities. Directory-read
  grants remain separate from search; final-directory metadata need not acquire a
  traversal grant.
- Carry observations through overlay selection and creation/existence checks,
  unlink/rename and their security hooks. Do not fabricate a dentry to satisfy an
  existing hook signature.

An observation's inode number is informational. Matching later stat fields cannot
prove identity across unlink/reuse; a successful open selects its own object.
Already-pinned reopens keep their stronger identity checks. Inode mutations require
a verified capability and checks on that object, with no pathname chmod/chown/times
fallback or cached authorization.

Host namespace mutations retain their parent/name operation semantics and parent
locking. The observation API does not assert atomic authorization against arbitrary
external host namespace replacement. That boundary must remain explicit in the
implementation review; observations must not introduce an authorization bypass.

The newly proposed post-unlink symlink-body guarantee is not an old v1 requirement
and has been withdrawn. Preserve actual Darwin readlink errors, current MAC/DAC
checks, original fixtures, supported rename/replacement behavior, metadata/times
and granted file-handle lifetime.

Expected affected concerns: VFS driver/namei/open/stat/security operations, overlay
selection, kernel pathname attributes and the macOS host driver. Existing drivers
default to the pinned path. Review and test the core interfaces before the Darwin
implementation, then run real macOS mode-000 metadata and open/mutation cases.

## Configured guest parallelism

Required behavior: the retained SDK accepts integer parallelism values from 1
through `u32::MAX`, rejects zero/nonintegers, and returns the configured value to
the guest. Browser default is 2. Host worker capacity is a separate limit.

Add optional `MachineBuilder::cpu_count(NonZeroU32)` and consuming
`Kernel::with_cpu_count`, applied before init and preserved across Machine root
rebuilds. Omission retains the existing host-derived behavior. No `Host` method or
worker topology changes are required.

- Use one immutable per-kernel CPU domain and compact affinity: all configured
  CPUs, or an explicit fallibly allocated mask. Derive cardinality, first CPU and
  mask words from that state; do not allocate proportional to a large default count.
- Add manual Rust `Control::affinity_count(TaskId) -> Result<u32, Errno>`, default
  `ENOSYS`, with canonical generated layered forwarding. The compatibility call
  uses actual kernel affinity cardinality and retains its existing syscall fallback
  only on `ENOSYS`. No WIT or numeric guest syscall is added.
- Preserve affinity through thread/fork cloning and exec. Update initial-task,
  scheduler reset/base-slice/deadline and getcpu consumers consistently; all-CPU
  representations must compare semantically with full explicit masks.
- Keep executor budgets, futex hashing and internal storage allowances tied to
  bounded physical resources. In particular, do not multiply AIO ring allocation
  by an arbitrarily large configured CPU count.
- Avoid eager CPU-sized procfs buffers. Use existing `Handle::read_at` semantics
  with open-time snapshots and bounded window formatting. Skip repeated CPU records
  arithmetically using decimal-width bands; do not replay billions of records to
  service a small read at a large offset. Index hex-mask words directly and render
  an all-CPU list as a range. Keep offsets and bit arithmetic wide enough.

The original SDK did not generate `/proc`; this work does not add a full-Linux
compatibility requirement. It must nevertheless avoid introducing unbounded memory
or CPU work for a valid configuration. Existing read-chunk limits are not total-file
size caps and must not be repurposed as arbitrary rejection limits.

Required focused cases: 1, 2, 1024, 1025 and `u32::MAX`; distinct machines; narrowing
affinity; partial mask words; inheritance and root rebuild; bounded first/offset
procfs reads; unaffected native defaults and executor admission. Independent code
review and serialized Luna validation precede integration.
