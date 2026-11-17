#include <unistd.h>
#include <sys/statvfs.h>

long pathconf(const char *path, int name)
{
	/* Linux fs/statfs.c:user_statfs resolves the path before reporting the
	 * name limit; glibc sysdeps/posix/pathconf.c uses the same statvfs field. */
	if (name == _PC_NAME_MAX) {
		struct statvfs st;
		if (statvfs(path, &st)) return -1;
		return st.f_namemax;
	}
	return fpathconf(-1, name);
}
