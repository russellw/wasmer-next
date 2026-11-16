#include <pthread.h>
#include <stdio.h>

static int worker_value;

static void *worker(void *arg) {
    worker_value = *(int *)arg + 1;
    return &worker_value;
}

int main(void) {
    int input = 40;
    pthread_t thread;
    void *result = 0;
    if (pthread_create(&thread, 0, worker, &input) != 0) return 70;
    if (pthread_join(thread, &result) != 0) return 71;
    if (result != &worker_value || worker_value != 41) return 72;
    printf("pthread=%d\n", worker_value);
    return 0;
}
