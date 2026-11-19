# WASIX v1 C and C++ guest fixtures

These sources come from the legacy WASIX guest suite at `577676bd47^`.
The adapter crate's `c_suite` integration test builds each case with the v1
compiler and runs it through `wasixv2::Machine`. See the [test guide](../../../../../docs/TEST.md)
for the compiler, filter and bless commands.

A fixture uses its shell build scripts, or a standalone `main.c` or
`main.cpp`. Build scripts must produce an executable named `main`. Cases live
in temporary directories so they can build and modify files without changing
the checkout. The runner uses the legacy arguments, environment, stdio and
filesystem assertions. It checks the default exit status of zero unless the
fixture specifies `ExpectedExitCode` or `MustFail`.

Case names are the directory and configuration joined by `/`. A shell script
other than `build.sh` adds its stem between them. Keep one reason per entry in
`expected-failures.txt` and `excluded.txt`. Build failures always fail the
suite. Keep compiler artifacts out of the repository.

The legacy `dynamic_runtime_hooks` host-side smoke test was dropped because
it injected hooks into the removed runtime's internal runner. The legacy
Rust-only guest sources and WebC host-runner tests are outside this C/C++
suite.
