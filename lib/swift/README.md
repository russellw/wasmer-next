# Swift bindings

`run_package` runs a package's declared entrypoint on WASIX v2, including WASI
preview1 and WASIX v1 guests. Package dependencies use the default public Wasmer
registry. Native macOS support targets macOS 13 and newer.

The function captures stdout and supplies empty stdin and discarded stderr.
It preserves the existing Swift result policy: guest failures and execution
worker panics return captured output after managed teardown. Invalid package
input and invalid UTF-8 output use `WasmerError`; acquisition failures retain
the existing panic behavior. A package without a declared entrypoint returns
the existing informational message.
