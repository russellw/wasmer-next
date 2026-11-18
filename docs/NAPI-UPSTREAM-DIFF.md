# NAPI source ownership

`lib/napi` is a submodule of public [wasmerio/napi](https://github.com/wasmerio/napi),
branch `edge-wasixv2`. The gitlink pins the exact revision; initialize it and its nested
QuickJS dependency with `git submodule update --init --recursive -- lib/napi`.

The branch starts from upstream `82b328f50ddaac78de388b67b4707f21864b9245` and
merges the product's `git subtree split --prefix=lib/napi main` history, also
preserving the pre-existing remote `next` history as a merge parent. Its extraction tree is identical to the previously vendored product tree, including
the relative QuickJS `.gitmodules` entry. The root no longer owns that entry.
`lib/napi/SOURCE.md` records the earlier import provenance; its references to
vendored ownership and root QuickJS registration describe that earlier layout.

The branch preserves WASIX v2 execution/instantiation hooks, protected memory
leases, pending-call/refill/cancellation tests, native frame and GC repairs,
native/JSPI continuation ownership, CLI package/mount integration, memory budgets,
and browser adaptations. It does not revert to upstream's legacy WASIX integration.
Relative path dependencies such as `../wasix/*` continue to resolve in-tree.

CI checkouts must use recursive submodules to fetch NAPI and QuickJS. NAPI is
public and needs no additional private-repository credentials. The runtime is
public too. CI retains its separate GitHub App authentication setup.
