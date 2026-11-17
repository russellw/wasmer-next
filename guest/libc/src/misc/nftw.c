#define _GNU_SOURCE
#include <ftw.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <search.h>
#include <stdlib.h>

struct history
{
	struct history *chain;
	dev_t dev;
	ino_t ino;
	int level;
	int base;
};

#undef dirfd
#define dirfd(d) (*(int *)d)

/* glibc io/ftw.c:find_object/add_object remember every followed directory,
 * not only the ancestors of the current path. */
struct visited_dir {
	dev_t dev;
	ino_t ino;
};

static int compare_dir(const void *a, const void *b)
{
	const struct visited_dir *x = a, *y = b;
	if (x->dev != y->dev) return x->dev < y->dev ? -1 : 1;
	return x->ino < y->ino ? -1 : x->ino != y->ino;
}

static int remember_dir(const struct stat *st, void **visited)
{
	struct visited_dir key = { st->st_dev, st->st_ino };
	if (tfind(&key, visited, compare_dir)) return 1;
	struct visited_dir *entry = malloc(sizeof *entry);
	if (!entry) return -1;
	*entry = key;
	if (!tsearch(entry, visited, compare_dir)) {
		free(entry);
		return -1;
	}
	return 0;
}

/* With FTW_CHDIR, callbacks see the containing directory. Anchor the original
 * cwd so relative traversal paths and the caller's cwd survive each callback,
 * including a callback that stops the walk (glibc io/ftw.c:ftw_startup/ftw_dir;
 * Linux fs/open.c:fchdir). */
static int call_nftw(char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), const struct stat *st, int type, struct FTW *lev, int cwd)
{
	if (cwd < 0) return fn(path, st, type, lev);
	if (lev->base) {
		size_t at = lev->base - 1;
		char saved = path[at];
		path[at] = 0;
		int r = chdir(at ? path : "/");
		path[at] = saved;
		if (r) return -1;
	} else if (path[0] == '/' && chdir("/")) return -1;
	int r = fn(path, st, type, lev);
	int err = errno;
	if (fchdir(cwd)) return -1;
	errno = err;
	return r;
}

static int do_nftw(char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags, struct history *h, int cwd, void **visited)
{
	size_t l = strlen(path), j = l && path[l-1]=='/' ? l-1 : l;
	struct stat st;
	struct history new;
	int type;
	int r;
	int dfd = -1;
	int err;
	struct FTW lev;

	st.st_dev = st.st_ino = 0;

	if ((flags & FTW_PHYS) ? lstat(path, &st) : stat(path, &st) < 0) {
		if (!(flags & FTW_PHYS) && errno==ENOENT && !lstat(path, &st))
			type = FTW_SLN;
		else if (errno != EACCES) return -1;
		else type = FTW_NS;
	} else if (S_ISDIR(st.st_mode)) {
		if (flags & FTW_DEPTH) type = FTW_DP;
		else type = FTW_D;
	} else if (S_ISLNK(st.st_mode)) {
		if (flags & FTW_PHYS) type = FTW_SL;
		else type = FTW_SLN;
	} else {
		type = FTW_F;
	}

	if ((flags & FTW_MOUNT) && h && type != FTW_NS && st.st_dev != h->dev)
		return 0;
	
	if (!(flags & FTW_PHYS) && (type == FTW_D || type == FTW_DP)) {
		int seen = remember_dir(&st, visited);
		if (seen) return seen > 0 ? 0 : -1;
	}

	new.chain = h;
	new.dev = st.st_dev;
	new.ino = st.st_ino;
	new.level = h ? h->level+1 : 0;
	new.base = j+1;
	
	lev.level = new.level;
	if (h) {
		lev.base = h->base;
	} else {
		size_t k;
		for (k=j; k && path[k]=='/'; k--);
		for (; k && path[k-1]!='/'; k--);
		lev.base = k;
	}

	if (type == FTW_D || type == FTW_DP) {
		dfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		err = errno;
		if (dfd < 0 && err == EACCES) type = FTW_DNR;
	}

	if (!(flags & FTW_DEPTH) && (r=call_nftw(path, fn, &st, type, &lev, cwd))) {
		if ((type == FTW_D || type == FTW_DP) && dfd >= 0) {
			int saved = errno;
			close(dfd);
			errno = saved;
		}
		return r;
	}

	for (; h; h = h->chain)
		if (h->dev == st.st_dev && h->ino == st.st_ino) {
			if ((type == FTW_D || type == FTW_DP) && dfd >= 0) close(dfd);
			return 0;
		}

	if ((type == FTW_D || type == FTW_DP) && fd_limit) {
		if (dfd < 0) {
			errno = err;
			return -1;
		}
		DIR *d = fdopendir(dfd);
		if (d) {
			struct dirent *de;
			while ((de = readdir(d))) {
				if (de->d_name[0] == '.'
				 && (!de->d_name[1]
				  || (de->d_name[1]=='.'
				   && !de->d_name[2]))) continue;
				if (strlen(de->d_name) >= PATH_MAX-l) {
					errno = ENAMETOOLONG;
					closedir(d);
					return -1;
				}
				path[j]='/';
				strcpy(path+j+1, de->d_name);
				/* The budget limits open directory streams, not tree depth.
				 * Reopen this directory at its cookie after visiting the child. */
				long pos = 0;
				if (fd_limit == 1) {
					pos = telldir(d);
					closedir(d);
					d = 0;
				}
				r = do_nftw(path, fn, fd_limit > 1 ? fd_limit-1 : 1, flags, &new, cwd, visited);
				if (r) {
					int saved = errno;
					if (d) closedir(d);
					errno = saved;
					return r;
				}
				if (!d) {
					path[j] = 0;
					d = opendir(j ? path : "/");
					path[j] = '/';
					if (!d) return -1;
					seekdir(d, pos);
				}
			}
			closedir(d);
		} else {
			close(dfd);
			return -1;
		}
	}

	path[l] = 0;
	if ((flags & FTW_DEPTH) && (r=call_nftw(path, fn, &st, type, &lev, cwd)))
		return r;

	return 0;
}

int nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags)
{
	int r, cs;
	size_t l;
	char pathbuf[PATH_MAX+1];

	if (fd_limit <= 0) return 0;

	l = strlen(path);
	if (l > PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(pathbuf, path, l+1);
	
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	int cwd = -1;
	if (flags & FTW_CHDIR) {
		cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (cwd < 0) {
			pthread_setcancelstate(cs, 0);
			return -1;
		}
	}
	void *visited = 0;
	r = do_nftw(pathbuf, fn, fd_limit, flags, NULL, cwd, &visited);
	int err = errno;
	tdestroy(visited, free);
	if (cwd >= 0) close(cwd);
	pthread_setcancelstate(cs, 0);
	errno = err;
	return r;
}
