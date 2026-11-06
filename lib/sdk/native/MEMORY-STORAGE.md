# Private memory storage boundary

`memory.rs` owns the complete implementation behind `Directory`. Its only
constructor creates a `wasixv2_vfs_mem::MemFs`, a private `Vfs`, `Cred::user(1, 1)`
and a private `SystemTimeClock`. Explicit `Limits::UNLIMITED` preserves the old
unbounded standalone storage; the guest tmpfs default quota is not imposed.
It has no constructor from an external VFS,
filesystem, clock or node. Neither storage nor its canonical files/guards escape
through the public SDK types.

The following restrictions are part of the implementation, not caller promises:

- No mounts, shared pages, watchers, leases, security callbacks or user clocks
  are installed. Only regular files and directories can be created.
- Lookup, permissions, opens, directory creation, timestamp changes, rename and
  unlink use the canonical VFS. Recursive removal keeps raw canonical entry
  names; the public lossy display name never selects an inode.
- Open data operations use the canonical `Vfs::File`, including its write guard,
  append operation and retained inode after rename/unlink. Public reads/writes
  enforce the original open rights. Close takes the private file exactly once
  under its mutex and releases it after unlocking.
- The private `complete` function pins ONE future, polls with parking 2.2's real
  unparker, and parks/re-polls that SAME future. It does not call an executor,
  spin on Pending, create a thread/runtime, or invoke a caller callback. A wake
  between poll and park is retained by the parker.
- Every production future passed to `complete` is constructed inside this
  module and reaches only that closed storage. Pending can only wait for a
  canonical memory lock held by another fully driven OS thread. There is no
  LocalSet task, external provider, user timer or callback required to release it.
  The cfg(test) park-gap hook only coordinates actual canonical lock tests.
- Public async-trait methods return Send futures without awaiting a canonical
  VFS future. They complete their private memory operation inside their poll;
  no canonical guard escapes to a public future or user callback.

An append-open public `File::write_at` keeps its previous append behavior.
The optional `write_positioned_at` method defaults to existing providers'
`write_at`; Directory overrides it to honor the offset regardless of append-open.
The guest adapter uses that seam for the kernel's positioned writes, including
F_SETFL/RWF_NOAPPEND changes. Atomic append is available on every writable
Directory handle. Its start/count comes from the canonical append result under
the same inode lock, without querying size afterward or maintaining an SDK cursor.
Existing custom providers keep their original unknown-offset append fallback.

User filesystem providers use `ProviderRuntime`, not this memory driver.
One existing Services callback submission owns the lease, runtime task, result
delivery and abandoned-result cleanup. Async callers use a oneshot subscriber;
synchronous workspace calls use a capacity-one completion subscriber and recv,
with the existing service-thread rejection and MultiThread block_in_place wait.
No second provider queue, executor or pool is introduced.

Stdio uses the existing PipeWriter and capture storage directly through ByteSink.
Capture records only the accepted prefix of a successful pipe write. Pending,
failed and canceled writes add nothing. Capture and Null do not create live pipes.
The original pipe admission, close ordering, EOF, wake and public Tokio streams
remain in place.

Source gates cover nested futures, no/current/multi-thread Tokio, existing
Services callbacks, real directory inode and cross-directory rename-lock
contention, append/rename races, direct positioned overrides, timestamps and
retained unlinked files. The public guest fixture drives actual F_SETFL,
RWF_APPEND and RWF_NOAPPEND through the kernel. Callback cancellation/late open
cleanup and accepted-prefix pipe retention have focused gates. The reviewed
tuple passed 41 library and 40 integration tests, plus eight original N-API guest
executions, on the coherent WLK 049156e0 dependency.

This slice removes the native SDK's filesystem/stdio use of virtual-fs. Its public
network provider still uses virtual-net and, transitively, virtual-io; their
separate nominal migration is not implemented here. No root kernel policy,
C API/Python code, WLK pin or original fixture bytes are changed.
