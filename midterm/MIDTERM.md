# IA 462 Midterm — Threat Model & Cross-Platform Comparison

> Before submitting, replace every *[slide: …]* marker with the exact slide title from
> that week's deck, and the objective names in §4 with the syllabus wording.

## 1. What this repo is

This repository holds one small Python/Flask web service and the evidence that it was
built, hardened, scanned and defended end-to-end. The hosts come first: an Ubuntu
system is hardened and audited with Lynis (Section 1). A Windows host is baselined,
with Sysmon and command-line/script-block auditing producing analyzable Security
events (Section 2). The service ships as a multi-stage, digest-pinned, non-root
container. It runs read-only with all capabilities dropped and a seccomp allow-list
derived by tracing (Section 3). The image is scanned with Trivy, inventoried with a
Syft SPDX SBOM and re-scanned with Grype, and one CVE is enriched with NVD and
MITRE ATT&CK data (Section 4). Policy is enforced with the CIS Docker Benchmark and a
Sigma detection for a technique seen in the Windows logs (Section 5). Every Python
package, base image and GitHub Action is pinned. A CI pipeline plus a Dependency
Review gate, required by branch protection, blocks a known-vulnerable Flask downgrade
(Section 6).

## 2. Cross-platform hardening comparison

| Dimension | Linux (Ubuntu) | Windows 10/11 | Docker container |
|---|---|---|---|
| **Kernel model** | Monolithic kernel with loadable modules; user/kernel split through syscalls | Hybrid NT kernel (executive + HAL), with Win32 and other subsystems in user mode | **No kernel of its own.** Shares the host Linux kernel; isolation comes from namespaces and cgroups |
| **Access control** | DAC (owner/group/other + umask), sudoers, PAM stack, MAC through AppArmor/SELinux, capabilities | ACLs on securable objects, access tokens and integrity levels, UAC, GPO, privileges (`SeDebugPrivilege`, …) | Runs as a UID mapped through userns-remap; capability set (`--cap-drop ALL`), seccomp syscall filter, AppArmor/SELinux profile, `no-new-privileges` |
| **Auditing** | journald/syslog, `auditd`, `/var/log/auth.log`, `faillock` counters, Lynis | Security event log (4624/4625/4688/4720), PowerShell 4104, Sysmon, advanced audit policy (`auditpol`) | Container stdout via `json-file` log driver, `docker events`, daemon logs. Host auditd must watch the Docker files (CIS 1.1.x) |
| **Hardening standard** | CIS Ubuntu Benchmark, DISA STIG (Ubuntu), Lynis hardening index | CIS Windows Benchmark, DISA STIG (Win 10/11), Microsoft Security Baselines | CIS Docker Benchmark (docker-bench-security), NIST SP 800-190 |
| **Common attack surface** | SSH (root login, brute force), SUID binaries, world-writable paths, unneeded services, weak PAM | SMBv1/remote services, credential theft (LSASS), encoded PowerShell, local account creation, Defender exclusions | Vulnerable base-image packages, root-in-container, writable rootfs, excess capabilities, exposed Docker socket, poisoned images or actions upstream |

All three platforms follow the same idea: least privilege, a small attack surface,
and logging that can be checked. They enforce it in different layers. Linux and
Windows each protect a whole OS with their own kernel and identity model. A container
has no kernel boundary of its own, so its safety depends on the host kernel's
namespaces, capabilities and seccomp, plus the integrity of the supply chain that
built the image. That is why Sections 3–6 spend as much effort on *where the bits
came from* as on *how they run*.

## 3. Supply-chain threat model

Assets: the source in this repo, the built image, the CI runner's token, and anyone
who pulls the image. Trust boundaries: PyPI, Docker Hub, GitHub Actions Marketplace
and the developer workstation.

| # | Attacker attempt | Control that stops or limits it | Where | Source |
|---|---|---|---|---|
| 1 | Repoint a mutable Action tag (e.g. `@v0.34.2`) to credential-stealing code. This **happened** to `aquasecurity/trivy-action` in March 2026, GHSA-69fq-xp46-6x23 | All actions pinned to a 40-char commit SHA; `permissions: contents: read`; `persist-credentials: false`; Dependabot proposes reviewed SHA bumps | `.github/workflows/*.yml`, `.github/dependabot.yml` | Week 8 *[slide: …pinning actions…]* |
| 2 | Publish a malicious version of a dependency, or a typosquat, to PyPI | `requirements.lock` with `--generate-hashes`; the Docker build uses `pip install --require-hashes --no-deps`, so an unknown package or changed hash fails the build | `requirements.lock`, `Dockerfile` | Week 8 *[slide: …]* |
| 3 | Swap the contents behind a base-image tag (`python:3.13-slim`) | Base image pinned by `@sha256` digest; digest bumps arrive only as Dependabot PRs | `Dockerfile` | Week 6 *[slide: …]* |
| 4 | Sneak a known-vulnerable version in through a PR (e.g. `flask==2.0.0`, CVE-2023-30861) | `dependency-review` (`fail-on-severity: high`) + `pip-audit` as required status checks under branch protection; demonstrated by the closed PR | `dependency-review.yml`, `security-pipeline.yml`, screenshots 22–23 | Week 8 *[slide: …]* |
| 5 | Exploit a CVE in an OS package of the image | Trivy CRITICAL gate on every push/PR, weekly scheduled re-scan, SBOM for fast impact lookup, Grype second opinion | `security-pipeline.yml`, `section4/` | Week 5 *[slide: …]* |
| 6 | After RCE in the app, escalate or escape the container | Non-root `appuser`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, seccomp blocks `ptrace`/`mount`/`unshare`/`bpf`/`keyctl`, `userns-remap`, `icc:false`, pids/memory limits | `section3/` | Week 3/4 *[slide: …]*, Week 6 *[slide: …]* |
| 7 | Commit a secret, or harvest one from the public repo | No secrets in code or config; Secret scanning + push protection enabled; Windows evidence redacted (host, user, SID) | GitHub settings, `scripts/section2-windows-baseline.ps1` | Exam rules; Week 8 *[slide: …]* |
| 8 | Push straight to `main`, bypassing review and the gates | Branch protection: PR required, status checks required, force-push blocked | GitHub settings (video) | Lab 4 |
| 9 | Hide activity on the Windows host with encoded PowerShell | 4688 command-line + 4104 script-block logging, Sysmon EID 1, Sigma rule `encoded-powershell.sigma.yml` (T1059.001, T1027.010) | `section2/`, `section5/` | Week 5 *[slide: …]* |

**Residual risk:** a compromised maintainer of a pinned dependency at the moment of
pinning; zero-days with no CVE yet; the Defender exclusion on the app folder (a
deliberate blind spot, scoped to one directory); and a trust-on-first-use step for
the Sysmon binary, mitigated by checking its Authenticode signature.

## 4. Section → learning-objective crosswalk

*(Replace the objective names with the exact wording from the syllabus.)*

- **Objective: harden and administer Linux systems** → Section 1 (user/group, umask 027, SUID audit, services, sshd, pam_faillock, Lynis).
- **Objective: configure and audit Windows security baselines** → Section 2 (Defender, firewall, SMBv1, audit policy, Sysmon, event export).
- **Objective: secure containerized workloads and virtualization** → Section 3 (multi-stage, digest pin, non-root, runtime flags, seccomp, daemon.json) and Section 5 (CIS Docker Benchmark).
- **Objective: perform security analysis and apply threat intelligence** → Section 4 (Trivy/Syft/Grype, NVD CVSS, ATT&CK mapping) and Section 5 (Sigma rule with ATT&CK tags).
- **Objective: manage dependencies and version control securely with GitHub** → Section 6 (exact pins, hashed lock, Dependabot, SHA-pinned actions, Dependency Review gate, branch protection).
- **Objective: compare security models across operating systems** → Section 7, §2 table and narrative.
- **Objective: apply enterprise policy enforcement** → Section 5 (daemon policy, CIS benchmark, detection-as-code) and the branch-protection rules.
