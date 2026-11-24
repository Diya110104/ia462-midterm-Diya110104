# Section 3 — Docker Hardened Build + Runtime Controls

| Requirement | Where it is met |
|---|---|
| Multi-stage build | `Dockerfile`: `FROM … AS builder` installs the hashed lock into `/opt/venv`; `FROM … AS runtime` copies only the venv + `app/` |
| Digest-pinned base | Both stages use `python:3.13-slim-trixie@sha256:e48f59cd…` (multi-arch index digest) |
| Non-root | `USER appuser` (uid/gid 10001, `nologin` shell, no home) |
| `--read-only`, `--cap-drop ALL`, `no-new-privileges` | `run-command.sh` (plus `--tmpfs /tmp`, pids/memory/CPU limits, loopback-only port) |
| Custom seccomp | `seccomp-profile.json` + `--security-opt seccomp=…` in `run-command.sh` |
| Daemon hardening | `daemon.json.sample` (`icc:false`, `no-new-privileges:true`, `userns-remap:default`, `log-driver:json-file` with rotation) |

> `Dockerfile` in this folder is a copy of `midterm/Dockerfile` (the one CI builds). Keep them identical with `scripts/sync-copies.sh`; CI fails if they drift.

## Build and run

```bash
cd midterm
docker build -t ia462-midterm:hardened .
./section3/run-command.sh
```

## How the seccomp profile was built

- **Default deny.** `defaultAction: SCMP_ACT_ERRNO` with `defaultErrnoRet: 1` (EPERM). Any syscall not on the list fails instead of running. Docker's default profile allows roughly 350 syscalls. This one allows about 160.
- **Derived from tracing, not guessed.** `scripts/trace-syscalls.sh` runs the app under gunicorn with `strace -f`, hits every route (GET, POST, 404) and runs the HEALTHCHECK command. The distinct syscalls are saved to `seccomp-traced-syscalls.txt`.
- **Runtime additions.** `scripts/seccomp-from-strace.py` adds a small, documented set on top of the trace:
  - what runc needs around `execve` (`capget`, `capset`, `prctl`, `set*id`)
  - what the `docker exec id` / `whoami` / `sh` demo commands need (`getgroups`, `vfork`)
  - close relatives that glibc or CPython can pick at runtime, such as `statx` vs `newfstatat` and `epoll_pwait` vs `epoll_wait`
- **Arch map.** Covers x86_64 and aarch64, so the profile also works on Apple-silicon Docker Desktop. Names that don't exist on an architecture are ignored.
- **Verified.** The app was run under the compiled filter (libseccomp, default ERRNO). All routes returned 200/201/404, the healthcheck passed, and these syscalls were blocked with EPERM: `unshare`, `ptrace`, `mount`, `keyctl`, `bpf`. They are the usual container-escape and privilege-escalation primitives.

If the container exits immediately with `Operation not permitted`, a syscall your environment needs is missing. Run the container once with `"defaultAction": "SCMP_ACT_LOG"`, check `dmesg`/`journalctl -k` for `type=SECCOMP` lines to find the syscall number, add it, and switch back to `SCMP_ACT_ERRNO`.
