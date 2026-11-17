# Real registry package smoke tests

Run `make test-real-packages` from the repository root to build the debug CLI
and test Bash, PHPix, static-web-server, and WordPress through the WASIX v2
adapter. Use `ENABLE_LLVM=0` if LLVM is unavailable. Override `WASMER_BIN` to
select another binary and `REAL_PACKAGES_ARGS` to select `bash`, `php` (alias
`phpix`), `static`, or `wordpress` instead of `all`.

To use an already built CLI without rebuilding:

```sh
WASMER_BIN="$PWD/target/debug/wasmer" bash tests/integration/real-packages/run.sh all
```

Requires Bash, curl, Python 3, GNU timeout, and network access to the Wasmer
registry. WordPress additionally requires a working Docker daemon and the
`mysql:8.4` image (downloaded when absent). It verifies installation against a
temporary MySQL database and serves the login page. Containers and servers are
stopped on exit; logs and generated files remain in the printed temporary
directory for diagnosis.

Individual server subcommands keep serving after their assertions pass; press
Ctrl+C to stop them. `all` stops each server and exits after the checks.
