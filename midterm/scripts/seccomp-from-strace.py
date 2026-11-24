#!/usr/bin/env python3
"""Build section3/seccomp-profile.json from a list of traced syscalls.

Usage: python3 scripts/seccomp-from-strace.py section3/seccomp-traced-syscalls.txt section3/seccomp-profile.json
Regenerate the traced list with scripts/trace-syscalls.sh.
"""
import json, sys
traced = open(sys.argv[1]).read().split()
# Syscalls the container runtime (runc) and the Python HEALTHCHECK need around
# exec time, plus close relatives of traced calls that glibc/CPython pick at runtime.
runtime = """capget capset prctl setgroups setuid setgid setresuid setresgid getresuid getresgid
execveat faccessat faccessat2 statx fstatfs statfs dup dup2 dup3 fchdir fchmod fchown
ftruncate fsync fdatasync getpeername recvmsg sendmsg sendfile select pselect6 ppoll
epoll_pwait epoll_create eventfd2 mremap nanosleep sched_yield sched_getaffinity getrusage
sysinfo tgkill tkill rt_sigsuspend rt_sigtimedwait sigaltstack pause getpgrp getpgid getsid
setsid alarm membarrier restart_syscall rename renameat renameat2 unlinkat mkdirat rmdir
readv writev pwrite64 getitimer setitimer timerfd_create timerfd_settime clock_gettime
clock_getres gettimeofday time times get_robust_list futex_waitv pipe getxattr lgetxattr
fgetxattr fadvise64 mincore getgroups vfork
close_range waitid epoll_pwait2 openat2 pidfd_open pidfd_send_signal fchmodat fchmodat2 getcpu""".split()
names = sorted(set(traced) | set(runtime))
profile = {
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "archMap": [
    {"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]},
    {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": ["SCMP_ARCH_ARM"]}
  ],
  "syscalls": [
    {"names": names, "action": "SCMP_ACT_ALLOW",
     "comment": "Allow-list from strace of gunicorn+Flask (section3/seccomp-traced-syscalls.txt) plus runc/CPython/docker-exec needs"}
  ]
}
json.dump(profile, open(sys.argv[2], "w"), indent=2)
print(len(names), "syscalls allowed")
