#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "$0")" && pwd)"
src="$here/src"
out="$here"
cc="${CC:-gcc}"

common=( -m64 -O2 -Wall -Wextra -ffreestanding -fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables -nostdlib )
link=( -static -no-pie -Wl,-e,_start -Wl,--build-id=none )

for name in argv bad_pointer exit fd_ops file_io file_mmap file_mmap_shared getpid process_groups tty_ioctl unsupported_syscall; do
    "$cc" "${common[@]}" "${link[@]}" -I "$src" "$src/start.S" "$src/$name.c" -o "$out/$name"
done

# This raw ELF intentionally has PT_INTERP; the smoke test hides its interpreter in an isolated guest root.
"$cc" "${common[@]}" -fPIE -pie -Wl,-e,_start -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -Wl,--build-id=none -I "$src" "$src/start.S" "$src/dynamic.c" -o "$out/dynamic"

# Optional normal libc-backed static tests. Set MUSL_CC (or provide musl-gcc) to enable them.
libc_cc="${MUSL_CC:-}"
if [[ -z "$libc_cc" ]]; then
    for candidate in musl-gcc x86_64-linux-musl-gcc x86_64-unknown-linux-musl-gcc; do
        if command -v "$candidate" >/dev/null 2>&1; then
            libc_cc="$candidate"
            break
        fi
    done
fi
if [[ -n "$libc_cc" ]]; then
    libc_flags=( -m64 -O2 -Wall -Wextra -static -fno-stack-protector -Wl,--build-id=none )
    for name in libc_smoke fs_lifecycle fork_wait fork_exec_busybox dynamic_fork_exec exec_child exec_parent tcp_echo tcp_listener udp_echo volume volume_ro; do
        "$libc_cc" "${libc_flags[@]}" "$src/$name.c" -o "$out/$name"
    done
    "$libc_cc" "${libc_flags[@]}" -pthread "$src/pthread.c" -o "$out/pthread"
else
    printf '%s\n' 'Skipping libc-backed fixtures: set MUSL_CC to a static musl compiler.' >&2
fi
