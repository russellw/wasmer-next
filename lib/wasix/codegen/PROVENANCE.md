# Generator source ownership

This directory is tracked source in public `wasmerio/wasmer-next`. It preserves
the canonical annotated WIT and generator from `wasix-org/wasixv2-abi`, baseline
`c2c28b95e0c403b224f9cf83fa0e6d56a5a2f3a0`, with the engine-context emitter
changes recovered from `2e57ab00aec6aef0a95df339f2bbc244f11aae7d`. The only
upstream source difference between those revisions is `src/exec.rs`; guest WIT,
ABI/syscall/C generators and tests are unchanged. Original MIT license retained
in `LICENSE`. No foreign repository commit is required to obtain this source.

Wasmer owns the canonical WIT and generator here. Generated equality tests in
`../exec/tests/generated.rs` check exec and the local `wlk/crates/{abi,syscalls}`
outputs. `WASIXV2_CODEGEN_BLESS=1` writes directly into this checkout. Review ABI,
kernel, import-shim and `guest/libc` output changes in the same commit.
