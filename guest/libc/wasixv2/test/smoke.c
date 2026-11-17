/* Smoke test for a wasixv2 sysroot. wasixv2/test/run.sh compiles and links it;
 * running it is done by the wasmer repo. argv[1] is a directory the test may
 * write to (/tmp).
 * Prints one line per check and exits with the number of failed checks. */
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond) check(!!(cond), #cond, __LINE__)
static void check(int ok, const char *what, int line)
{
	checks++;
	if (!ok) failures++;
	printf("%s %d: %s (line %d)\n", ok ? "ok" : "FAIL", checks, what, line);
	if (!ok) printf("  errno=%d (%s)\n", errno, strerror(errno));
}

static void test_args(int argc, char **argv)
{
	CHECK(argc == 2);
	CHECK(argv[argc] == NULL);
	const char *e = getenv("WASIXV2_SMOKE");
	CHECK(e && !strcmp(e, "1"));
}

static void test_file_io(const char *dir)
{
	char path[256], buf[16];
	const off_t big = (off_t)1 << 33; /* needs the full i64 offset path */

	snprintf(path, sizeof path, "%s/smoke.dat", dir);
	int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	CHECK(fd >= 3);
	CHECK(write(fd, "hello\n", 6) == 6);
	CHECK(lseek(fd, 0, SEEK_CUR) == 6);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, buf, sizeof buf) == 6 && !memcmp(buf, "hello\n", 6));
	CHECK(pwrite(fd, "X", 1, big) == 1);
	CHECK(lseek(fd, 0, SEEK_END) == big + 1);
	CHECK(pread(fd, buf, 1, big) == 1 && buf[0] == 'X');
	CHECK(pread(fd, buf, 5, 0) == 5 && !memcmp(buf, "hello", 5));
	CHECK(close(fd) == 0);

	FILE *f = fopen(path, "r");
	CHECK(f != NULL);
	if (f) {
		CHECK(fgets(buf, sizeof buf, f) && !strcmp(buf, "hello\n"));
		CHECK(fclose(f) == 0);
	}

	CHECK(unlink(path) == 0);
	errno = 0;
	CHECK(open(path, O_RDONLY) == -1 && errno == ENOENT);
}

static void test_clock(void)
{
	struct timespec rt, t0, t1;
	CHECK(clock_gettime(CLOCK_REALTIME, &rt) == 0 && rt.tv_sec > 1600000000);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
	CHECK(nanosleep(&(struct timespec){ .tv_nsec = 5000000 }, NULL) == 0);
	CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
	long long ns = (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
	CHECK(ns >= 5000000);
	CHECK(time(NULL) >= rt.tv_sec);
}

static jmp_buf jb;
static sigjmp_buf sjb;
static volatile int jumps;

static void jump_back(int v) { jumps++; longjmp(jb, v); }

static void test_setjmp(void)
{
	int r = setjmp(jb);
	if (r == 0) jump_back(42);
	CHECK(r == 42 && jumps == 1);

	r = setjmp(jb);
	if (r == 0) jump_back(0);
	CHECK(r == 1 && jumps == 2); /* longjmp(jb, 0) returns 1 */

	r = sigsetjmp(sjb, 1);
	if (r == 0) siglongjmp(sjb, 7);
	CHECK(r == 7);
}

static _Thread_local int tls_counter = 7;
static _Thread_local char tls_buf[32] = "tls-init";

static void test_tls(void)
{
	CHECK(tls_counter == 7);
	tls_counter++;
	CHECK(tls_counter == 8);
	CHECK(!strcmp(tls_buf, "tls-init"));
	errno = 0;
	CHECK(close(12345) == -1 && errno == EBADF);
}

/* long double (IEEE binary128) and __int128 come from compiler-rt builtins. */
static void test_builtins(void)
{
	char buf[64];
	volatile long double third = 1.0L / 3;
	snprintf(buf, sizeof buf, "%.6Lf", third * 3);
	CHECK(!strcmp(buf, "1.000000"));
	CHECK(sizeof(long double) == 16);

	volatile unsigned __int128 x = (unsigned __int128)1 << 100;
	CHECK(x % 7 == 2);
	CHECK((x / 7) * 7 + 2 == x);
}

static void test_malloc(void)
{
	char *big = malloc(1 << 20);
	CHECK(big != NULL);
	if (big) {
		memset(big, 0xab, 1 << 20);
		CHECK((unsigned char)big[(1 << 20) - 1] == 0xab);
	}
	void *small[64];
	int ok = 1;
	for (int i = 0; i < 64; i++) {
		small[i] = malloc(16 + i * 8);
		if (!small[i]) ok = 0;
		else memset(small[i], i, 16 + i * 8);
	}
	CHECK(ok);
	for (int i = 0; i < 64; i++) free(small[i]);
	free(big);
}

int main(int argc, char **argv)
{
	printf("wasixv2 smoke test\n");
	test_args(argc, argv);
	if (argc >= 2) test_file_io(argv[1]);
	test_clock();
	test_setjmp();
	test_tls();
	test_builtins();
	test_malloc();
	if (failures)
		printf("smoke: %d of %d checks FAILED\n", failures, checks);
	else
		printf("smoke: all %d checks passed\n", checks);
	return failures;
}
