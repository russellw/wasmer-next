# Context and function compatibility sources

This directory owns the small public `wasix/` C interface for contexts,
packed function calls, reflection and closures on **wasm32-wasixv2**. It is
hand-written producer source alongside the canonical WIT and generator, not
generator output. [PROVENANCE.md](PROVENANCE.md) records its origin and local
adaptations; the original MIT terms are in [LICENSE](LICENSE).

The six public headers preserve the libc2 wrapper names, signatures, value
type bytes and reflection layout. `src/wasix_context.c` and
`src/wasix_function.c` call the eight `wasixv2` imports declared in
`src/wasixv2_ext.h`. They translate the syscall error range `-4095..-1` to
`-1` and public `errno`, leaving `errno` unchanged on success. They require
only public libc headers, without musl's internal `syscall.h` or symbols.

For a separately labelled rebuilt-v2 consumer, compile these two C files
with the same wasm32-wasixv2 compiler, sysroot and profile flags as that
consumer. Add this directory's `include` ahead of the sysroot include path,
and link the resulting objects directly into the consumer. For example,
from this directory, with a compiler and matching EH/PIC sysroot already
selected in the environment:

```sh
wasixcc --target=wasm32-wasixv2 -sPIC=1 -sWASM_EXCEPTIONS=yes \
  -Iinclude -c src/wasix_context.c -o /private/build/wasix_context.o
wasixcc --target=wasm32-wasixv2 -sPIC=1 -sWASM_EXCEPTIONS=yes \
  -Iinclude -c src/wasix_function.c -o /private/build/wasix_function.o
```

Use a private output directory that already exists. Select static EH or
asyncify flags instead when that is the consumer's original profile; only
link the context object when function wrappers are unnecessary. There is
no install step and no modification to an installed sysroot. Do not link
these objects alongside a libc that already defines the same public
functions. They supply neither `__wasi_*` imports nor the remainder of libc.

Original linked v1 fixtures remain in `lib/wasix-legacy/tests/wasm_tests`
with their original producers and flags. A v2 rebuild using these objects
is separate evidence. Context support still depends on the engine, and
closure support requires the dynamic-loader profile: static v1 images
already returned `NOTSUP`. Providing these sources does not establish
runtime, compiler, NAPI or browser acceptance.

The generator's existing integration test target checks these raw import
signatures and public type bytes against canonical WIT:

```sh
cargo test -p wasixv2-codegen --test generated compat_libc
```

The C sources retain compile-time checks for the wasm32 data model and
reflection record layout. Actual C compilation, original fixture execution
and separately labelled v2 execution are additional validation gates.
