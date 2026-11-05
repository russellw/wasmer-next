# Legacy CLI terminal reference

`legacy_cli_terminal.rs` preserves the exact original CLI terminal implementation and
its panic/suspend regression, without changing the test body.

- Repository: `wasmerio/wasmer-next`
- Source commit: `c399d1cdc19659278775a32f0c7d25900489bfb4`
- Source path: `lib/cli/src/commands/run/terminal.rs`
- Git blob: `490741297434bef6e7be0902abfa019b5e73360f`
- SHA-256: `fd89c9c14621e008cdcf845e0258ff96dc6190f1ae8ef08467a1e31ec37c2546`

This is a historical source fixture, not a compiled test or a passing-test claim.
The old CLI installed a process-wide panic hook that restored its terminal before
the previous hook printed the panic, even when a surrounding `catch_unwind` retained
the raw-mode guard. That process policy cannot belong to a reusable driver: it would
cook live sibling terminals after an embedder catches an unrelated panic.

Current driver leases restore their terminal only when their last owner releases
them, including through unwinding. Embedders may retain a lease through caught-panic
cleanup. The CLI explicitly catches guest unwinding, retires its forwarders, releases
its raw lease, then resumes unwinding. Its former restore-before-report timing is
preserved here as a reference, not imposed on other consumers.
