// CVE-2026-40200, fixed by musl 228da39e: smoothsort tracks its Leonardo heaps
// in a two-word bit vector, and pntz miscounted once the low word was empty. On
// wasm32 a heap of more than L(34) = 18454929 elements reaches the high word,
// and qsort then accessed memory outside the array. The heap's shape depends
// only on the count, so ascending input reaches it in linear time.
//#ExpectedStdout: ok
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int compare(const void* a, const void* b) {
  uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
  return (x > y) - (x < y);
}

int main(void) {
  const size_t n = 18454930;
  uint32_t* a = malloc(n * sizeof(*a));
  if (!a) {
    perror("malloc");
    return 1;
  }
  for (size_t i = 0; i < n; i++) a[i] = i;
  qsort(a, n, sizeof(*a), compare);
  for (size_t i = 0; i < n; i++) {
    if (a[i] != i) {
      printf("a[%zu] = %u\n", i, (unsigned)a[i]);
      return 1;
    }
  }
  puts("ok");
  return 0;
}
