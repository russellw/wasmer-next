#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include "dynlink.h"
#include "pthread_impl.h"
#include "wasixv2_ext.h"

/* Like musl ldso/dynlink.c:do_init_fini/dlopen: serialize completion, not
 * merely dequeueing. The host gate is released before any constructor runs. */
static pthread_mutex_t loader_lock = { ._m_type = PTHREAD_MUTEX_RECURSIVE };
static int search_failed;
static const char *search_path = "/lib:/usr/local/lib:/usr/lib";

static void capture_search_path(void)
{
	const char *env = libc.secure ? 0 : getenv("LD_LIBRARY_PATH");
	if (!env || !*env) return;
	size_t n = strlen(env), m = strlen(search_path);
	if (n > SIZE_MAX-m-2) { search_failed = 1; return; }
	char *copy = __libc_malloc(n+m+2);
	if (!copy) { search_failed = 1; return; }
	memcpy(copy, env, n);
	copy[n] = ':';
	memcpy(copy+n+1, search_path, m+1);
	search_path = copy;
}

hidden int __wasixv2_dl_lock(void)
{
	int cs;
	__pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	__pthread_mutex_lock(&loader_lock);
	return cs;
}

hidden void __wasixv2_dl_unlock(int cs)
{
	__pthread_mutex_unlock(&loader_lock);
	__pthread_setcancelstate(cs, 0);
}

hidden void __wasixv2_dl_error(long r, char *message, size_t n)
{
	message[n-1] = 0;
	__dl_seterr("%s", *message ? message : strerror(-r));
}

static void call_initializers(void)
{
	for (;;) {
		void (*ctor)(void) = 0;
		long r = __wasixv2_ext_dl_next_init((void **)&ctor);
		/* Publication has succeeded. An internal queue failure cannot be
		 * reported as a recoverable failed load or undo guest effects. */
		if (r < 0) a_crash();
		if (!r) break;
		if (ctor) ctor();
	}
}

hidden void __wasixv2_dl_startup(void)
{
	capture_search_path();
	/* __libc_start_main has initialized main TLS/SSP and secure state.
	 * Match ldso/dynlink.c:__libc_start_init: dependencies precede main
	 * constructors, and guest code runs only after host publication. */
	int cs = __wasixv2_dl_lock();
	call_initializers();
	__wasixv2_dl_unlock(cs);
}

void *dlopen(const char *file, int mode)
{
	char error[1024] = {0};
	void *handle = 0;
	if (!(mode & (RTLD_NOW | RTLD_LAZY))) {
		__dl_seterr("WASIX v2 dynamic loading requires RTLD_NOW or RTLD_LAZY");
		return 0;
	}
	if (search_failed) {
		__dl_seterr("Cannot allocate dynamic loader search path");
		return 0;
	}
	int cs = __wasixv2_dl_lock();
	long r = __wasixv2_ext_dl_open(file, mode, search_path, 0, &handle,
		error, sizeof error);
	if (r < 0) {
		__wasixv2_dl_error(r, error, sizeof error);
		handle = 0;
	} else {
		call_initializers();
	}
	__wasixv2_dl_unlock(cs);
	return handle;
}
