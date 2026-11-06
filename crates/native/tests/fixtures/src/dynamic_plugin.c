#include <unistd.h>

static int dynamic_plugin_ready;

__attribute__((constructor)) static void dynamic_plugin_constructor(void) {
    dynamic_plugin_ready = 1;
    static const char marker[] = "plugin-ctor\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

__attribute__((destructor)) static void dynamic_plugin_destructor(void) {
    static const char marker[] = "plugin-dtor\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

int dynamic_plugin_value(void) {
    return dynamic_plugin_ready ? 86 : -1;
}
