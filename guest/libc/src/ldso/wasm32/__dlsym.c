#include <dlfcn.h>
#include "dynlink.h"
#include "wasixv2_ext.h"

hidden int __wasixv2_dl_lock(void);
hidden void __wasixv2_dl_unlock(int);
hidden void __wasixv2_dl_error(long, char *, size_t);

hidden void *__dlsym(void *restrict handle, const char *restrict name, void *restrict ra)
{
	(void)ra;
	char error[1024] = {0};
	void *address = 0;
	if (handle == RTLD_NEXT) {
		__dl_seterr("WASIX v2 RTLD_NEXT requires caller provenance");
		return 0;
	}
	int cs = __wasixv2_dl_lock();
	long r = __wasixv2_ext_dl_sym(handle, name, 0, &address, error, sizeof error);
	if (r < 0) {
		__wasixv2_dl_error(r, error, sizeof error);
		address = 0;
	}
	__wasixv2_dl_unlock(cs);
	return address;
}

#if _REDIR_TIME64
weak_alias(__dlsym, __dlsym_redir_time64);
#endif
