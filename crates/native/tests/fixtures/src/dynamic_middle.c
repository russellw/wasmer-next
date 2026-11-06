#include <unistd.h>

extern int dynamic_leaf_value(void);

static int dynamic_middle_ready;

__attribute__((constructor)) static void dynamic_middle_constructor(void) {
    dynamic_middle_ready = dynamic_leaf_value() == 19;
    static const char marker[] = "middle-ctor\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

int dynamic_chain_value(void) {
    return dynamic_middle_ready ? dynamic_leaf_value() + 23 : -1;
}
