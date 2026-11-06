#include <unistd.h>

int dynamic_leaf_ready;

__attribute__((constructor)) static void dynamic_leaf_constructor(void) {
    dynamic_leaf_ready = 1;
    static const char marker[] = "leaf-ctor\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

int dynamic_leaf_value(void) {
    return dynamic_leaf_ready ? 19 : -1;
}
