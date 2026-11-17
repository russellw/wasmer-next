/*
 * Freestanding Wasm command for opted-in Machines. Regenerate runtime-command.wasm with:
 * clang --target=wasm32-unknown-unknown -Os -nostdlib -fno-builtin \
 *   -Wl,--entry=_start -Wl,--export-memory -Wl,--strip-all \
 *   runtime-command.c -o runtime-command.wasm
 */

#define IMPORT(module, name) __attribute__((import_module(module), import_name(name)))
#define WASIX(name) IMPORT("wasixv2", name)

WASIX("startup_size") int startup_size(void);
WASIX("startup_get") int startup_get(void *, unsigned);
WASIX("openat") int openat(int, const char *, int, unsigned);
WASIX("close") int close(int);
WASIX("write") int write(int, const char *, unsigned);
WASIX("execve") int execve(const char *, char **, char **);
WASIX("exit_group") __attribute__((noreturn)) void exit_group(int);
IMPORT("wasmer_runtime_package", "resolve") int resolve(const char *, int, void *, unsigned);

enum {
    AT_FDCWD = -100,
    O_NONBLOCK = 0x800,
    O_CLOEXEC = 0x80000,
    ENOENT = 2,
    ENOTDIR = 20,
    ENOSPC = 28,
    PAGE_SIZE = 65536,
    METADATA_SIZE = 128 * 1024,
};

static unsigned length(const char *s) {
    unsigned n = 0;
    while (s[n])
        ++n;
    return n;
}

static void fail(const char *message, int status) {
    write(2, message, length(message));
    exit_group(status);
}

static void *allocate(unsigned bytes) {
    unsigned pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    unsigned previous = __builtin_wasm_memory_grow(0, pages);
    if (previous == (unsigned)-1)
        fail("wasmer: insufficient memory\n", 126);
    return (void *)(previous * PAGE_SIZE);
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

static int same_key(const char *a, const char *b) {
    while (*a && *a != '=' && *a == *b) {
        ++a;
        ++b;
    }
    return *a == '=' && *b == '=';
}

static char *next_string(char **cursor) {
    char *value = *cursor;
    *cursor += length(value) + 1;
    return value;
}

void _start(void) {
    int size = startup_size();
    if (size < 0)
        fail("wasmer: could not read process arguments\n", 126);
    unsigned *startup = allocate((unsigned)size);
    if (startup_get(startup, (unsigned)size) < 0)
        fail("wasmer: could not read process arguments\n", 126);

    unsigned argc = *startup;
    char **argv = (char **)(startup + 1);
    char **envp = argv + argc + 1;
    if (argc < 3 || !same(argv[1], "run"))
        fail("usage: wasmer run <package-or-file> [--] [args...]\n", 2);

    char *target = argv[2];
    unsigned first = 2;
    if (argc > 3 && same(argv[3], "--"))
        argv[++first] = target;

    int fd = openat(AT_FDCWD, target, O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0 && fd != -ENOENT && fd != -ENOTDIR)
        fail("wasmer: cannot open guest file\n", 126);

    unsigned *data = allocate(METADATA_SIZE);
    int result = resolve(target, fd, data, METADATA_SIZE);
    if (fd >= 0)
        close(fd);
    if (result == -ENOSPC)
        fail("wasmer: runtime package limit reached\n", 126);
    if (result == -ENOENT)
        fail("wasmer: package not found\n", 127);
    if (result < 0)
        fail("wasmer: cannot import package\n", 126);

    unsigned extra_args = data[0];
    unsigned defaults = data[1];
    char *strings = (char *)(data + 3);
    char *path = next_string(&strings);
    char *name = next_string(&strings);

    unsigned envc = 0;
    while (envp[envc])
        ++envc;

    unsigned user_args = argc - first - 1;
    char **new_argv = allocate((2 + extra_args + user_args + 1 + envc + defaults) * sizeof(char *));
    char **new_env = new_argv + 2 + extra_args + user_args;
    new_argv[0] = data[2] ? name : target;
    for (unsigned i = 0; i < extra_args; ++i)
        new_argv[i + 1] = next_string(&strings);
    for (unsigned i = 0; i < user_args; ++i)
        new_argv[1 + extra_args + i] = argv[first + 1 + i];
    new_argv[1 + extra_args + user_args] = 0;

    for (unsigned i = 0; i < envc; ++i)
        new_env[i] = envp[i];
    for (unsigned i = 0; i < defaults; ++i) {
        char *value = next_string(&strings);
        if (!same_key(value, value))
            continue;
        unsigned existing = 0;
        while (existing < envc && !same_key(new_env[existing], value))
            ++existing;
        if (existing == envc)
            new_env[envc++] = value;
    }
    new_env[envc] = 0;

    execve(path, new_argv, new_env);
    fail("wasmer: cannot execute package command\n", 126);
}
