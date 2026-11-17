#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <sched.h>
#include "syscall.h"
#include "wasixv2_vfork.h"

/* vfork on wasixv2 (see the vfork macro in unistd.h). clone with CLONE_VM |
 * CLONE_VFORK returns 0 and the instance keeps running as the child task.
 * When the child's execve succeeds, or it exits or is killed, the host
 * switches the instance back to the parent and calls the exported
 * wasixv2_vfork_return(child), which longjmps to the vfork point; vfork then
 * returns the child's pid.
 *
 * The points form a stack, since a vfork child may vfork again. The stack is
 * per thread: each thread is its own instance, and a jmp_buf only unwinds the
 * call stack of the instance that set it. A vfork child runs in its parent's
 * instance with the parent's thread pointer, so it pushes onto the same
 * stack, and wasixv2_vfork_return, which the host calls in that instance,
 * pops it. Only one task runs in an instance at a time, so the stack needs no
 * lock. */

#define MAX_DEPTH 16

static _Thread_local struct {
	jmp_buf jb;
	pid_t pid;
} points[MAX_DEPTH];

static _Thread_local int depth;

/* What the vfork macro's setjmp writes when the stack is full: the clone
 * fails with EAGAIN before anything longjmps to it, and the live points
 * stay intact. */
static _Thread_local jmp_buf overflow;

struct __jmp_buf_tag *__wasixv2_vfork_point(void)
{
	return depth < MAX_DEPTH ? points[depth].jb : overflow;
}

static long vfork_clone(unsigned long flags)
{
	if (depth >= MAX_DEPTH) return -EAGAIN;
	long r = __syscall(SYS_clone, flags, 0, 0, 0, 0);
	if (r == 0) depth++;
	return r;
}

pid_t __wasixv2_vfork_child(void)
{
	return __syscall_ret(vfork_clone(CLONE_VM | CLONE_VFORK | SIGCHLD));
}

pid_t __wasixv2_vfork_parent(void)
{
	return points[depth].pid;
}

__attribute__((__export_name__("wasixv2_vfork_return")))
_Noreturn void __wasixv2_vfork_return(int child)
{
	depth--;
	points[depth].pid = child;
	longjmp(points[depth].jb, 1);
}

/* The vfork function, for calls that bypass the macro: a fork without the
 * atfork handlers, as musl's generic vfork is, since only the macro can
 * return twice. It is there so that link tests such as autoconf's
 * AC_FUNC_FORK find vfork; without it the program defines vfork as fork and
 * loses the macro. Without asyncify it fails with ENOSYS, as fork does, which
 * the deprecated declaration in <unistd.h> warns about. */
pid_t (vfork)(void)
{
	return _Fork();
}

hidden long __wasixv2_vfork_call(int (*func)(void *), void *arg, unsigned long flags)
{
	if (depth >= MAX_DEPTH) return -EAGAIN;
	if (setjmp(points[depth].jb))
		return points[depth].pid;
	long r = vfork_clone(flags);
	if (r) return r;
	_exit(func(arg));
}

