#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int dynamic_chain_value(void);

static __thread int dynamic_tls = 5;

static void *dynamic_tls_worker(void *unused) {
    (void)unused;
    dynamic_tls = 43;
    return (void *)(intptr_t)dynamic_tls;
}

static int plugin_path(char *out, size_t capacity, const char *program,
                       const char *explicit_path) {
    if (explicit_path != NULL && strcmp(explicit_path, "started") != 0) {
        size_t path_length = strlen(explicit_path);
        if (path_length + 1 > capacity) return -1;
        memcpy(out, explicit_path, path_length + 1);
        return 0;
    }
    const char *slash = strrchr(program, '/');
    if (slash == NULL) return -1;
    size_t directory_length = (size_t)(slash - program);
    static const char suffix[] = "/../lib/libdynamic_plugin.so";
    if (directory_length + sizeof(suffix) > capacity) return -1;
    memcpy(out, program, directory_length);
    memcpy(out + directory_length, suffix, sizeof(suffix));
    return 0;
}

int main(int argc, char **argv) {
    if (dynamic_chain_value() != 42) return 70;

    int main_tls = dynamic_tls;
    pthread_t thread;
    void *thread_result = NULL;
    if (pthread_create(&thread, NULL, dynamic_tls_worker, NULL) != 0) return 71;
    if (pthread_join(thread, &thread_result) != 0) return 72;
    if ((intptr_t)thread_result != 43 || dynamic_tls != main_tls) return 73;

    char path[4096];
    if (plugin_path(path, sizeof(path), argv[0], argc > 1 ? argv[1] : NULL) != 0) return 74;
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 75;
    }
    dlerror();
    int (*plugin_value)(void) = (int (*)(void))dlsym(handle, "dynamic_plugin_value");
    const char *error = dlerror();
    if (error != NULL || plugin_value == NULL || plugin_value() != 86) {
        fprintf(stderr, "dlsym: %s\n", error == NULL ? "bad plugin value" : error);
        return 76;
    }
    if (dlclose(handle) != 0) {
        fprintf(stderr, "dlclose: %s\n", dlerror());
        return 77;
    }

    printf("dynamic=ok chain=42 tls=%ld main_tls=%d plugin=86\n",
           (long)(intptr_t)thread_result, main_tls);
    if (fflush(stdout) != 0) return 78;
    return 0;
}
