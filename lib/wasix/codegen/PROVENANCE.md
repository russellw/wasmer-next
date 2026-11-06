# Generator source ownership

This directory is tracked source in private `wasmerio/wasmer-next`. It preserves
the canonical annotated WIT and generator from `wasix-org/wasixv2-abi`, baseline
`c2c28b95e0c403b224f9cf83fa0e6d56a5a2f3a0`, with the engine-context emitter
changes recovered from `2e57ab00aec6aef0a95df339f2bbc244f11aae7d`. The only
upstream source difference between those revisions is `src/exec.rs`; guest WIT,
ABI/syscall/C generators and tests are unchanged. Original MIT license retained
in `LICENSE`. No foreign repository commit is required to obtain this source.

Wasmer owns engine-specific import generation here. Generated equality tests in
`../exec/tests/generated.rs` check exec locally and ABI/syscalls against the one
locked WLK source. Use `WLK_ROOT` for explicit writable WLK regeneration; never
bless files into Cargo caches. WLK changes and Wasmer outputs must be reviewed
and validated together before updating Wasmer's locked WLK revision.
