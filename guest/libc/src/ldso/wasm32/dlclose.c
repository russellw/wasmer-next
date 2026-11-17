#include <dlfcn.h>
#include "dynlink.h"
#include "wasixv2_ext.h"

hidden int __wasixv2_dl_lock(void);
hidden void __wasixv2_dl_unlock(int);

int dlclose(void *handle)
{
	int cs = __wasixv2_dl_lock();
	long r = __wasixv2_ext_dl_close(handle);
	if (r < 0) __dl_seterr("Invalid library handle %p", handle);
	__wasixv2_dl_unlock(cs);
	return r < 0 ? -1 : 0;
}
