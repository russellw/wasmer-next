# Producer source ownership

This directory is owned source in public `wasmerio/wasmer-next`. Its six
`include/wasix/*.h` files and two wrapper implementations originate from
[`wasix-org/libc2` commit
`71ccfb3879d9eae8984f917219d703c70e285789`](https://github.com/wasix-org/libc2/commit/71ccfb3879d9eae8984f917219d703c70e285789):

- `include/wasix/{call_dynamic,closure,context,function_pointer,reflection,value_type}.h`
- `src/misc/wasm32/{wasix_context,wasix_function}.c`
- The eight context/function declarations in `arch/wasm32/wasixv2_ext.h`

The public interfaces and import declarations retain those source
signatures. The wrappers replace the internal `syscall.h` / `__syscall_ret`
dependency with `src/errno_result.h`, using public `errno` and the same
negative errno range as libc2's `src/internal/syscall_ret.c`. Only the eight
needed import declarations are retained, with wasm32 width assertions.
Formatting follows the enclosing repository. The original musl MIT notice
is retained in `LICENSE`; the rest of libc is not copied.

These are hand-written sources, distinct from the generator's C output.
The owned canonical ABI is `../wit/{ext,types}.wit`; changes to either side
must preserve the reviewed producer contract. Generator tests compare the
import wire signatures and public value type bytes with that ABI. No
foreign source commit, repository pin, toolchain change or sysroot install
is required to obtain these files from Wasmer.
