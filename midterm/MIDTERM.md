# IA 462 Midterm — Threat Model & Cross-Platform Comparison

**Student:** Diya110104 · **Repo:** `ia462-midterm-Diya110104` · **Course:** IA 462 Advanced Operating Systems Security & Administration (Fall 2026)

## 1. What this repo is

This repository takes one small Flask web app and locks it down at every layer it touches. On the Linux side, the Ubuntu (WSL) host was hardened: a restricted lab user, a stricter umask, two unneeded services turned off, SSH tightened, and accounts that lock after five bad passwords. Lynis then measured the result (hardening index 65). On Windows, the firewall and SMBv1 were checked, detailed logging was turned on, Sysmon was installed, and suspicious activity (failed logins, a new user, encoded PowerShell) was generated so there would be real events to analyze. The app runs in a Docker container that doesn't run as root, can't write to its own filesystem, has no extra Linux capabilities, and can only make the system calls it actually needs. The image was scanned with Trivy, Syft and Grype, and one real HIGH vulnerability (a zlib bug, CVE-2026-85091) was researched in depth. Finally, every dependency and GitHub Action is pinned, and a pipeline checks every change. As proof that it works, a pull request that downgraded Flask to a known-vulnerable version was opened, and GitHub refused to merge it.

## 2. Cross-platform hardening comparison

| Dimension | Linux (Ubuntu) | Windows 11 | Docker container |
|---|---|---|---|
| **Kernel model** | Monolithic kernel with loadable modules; user/kernel boundary through system calls | Hybrid NT kernel (executive + HAL); Win32 and other subsystems run in user mode | **No kernel of its own.** Shares the host Linux kernel; isolation comes from namespaces and cgroups |
| **Access control** | DAC (owner/group/other + umask 027), sudoers, PAM (pam_faillock), MAC through AppArmor/SELinux | ACLs on securable objects, access tokens and integrity levels, UAC, Group Policy, privileges | Non-root UID (10001), capability set (`--cap-drop ALL`), seccomp syscall filter, `no-new-privileges`, userns-remap |
| **Auditing** | journald/syslog, auditd, `/var/log/auth.log`, faillock counters, Lynis | Security log (4624/4625/4688/4720), PowerShell 4104, Sysmon, advanced audit policy (`auditpol`) | `json-file` log driver, `docker events`, daemon logs; the host must audit Docker's files |
| **Hardening standard** | CIS Ubuntu Benchmark, DISA STIG, Lynis hardening index | CIS Windows Benchmark, DISA STIG, Microsoft Security Baselines | CIS Docker Benchmark (docker-bench-security), NIST SP 800-190 |
| **Common attack surface** | SSH brute force / root login, SUID binaries, world-writable paths, unneeded services, weak PAM | SMBv1 and remote services, credential theft (LSASS), encoded PowerShell, rogue local accounts, AV exclusions | Vulnerable base-image packages, root in container, writable rootfs, excess capabilities, exposed Docker socket, poisoned upstream images/actions |

All three platforms are chasing the same goals, which the Week 3 slide *"Linux vs. Windows vs. Docker: Putting It Together"* sums up well: give everything as little privilege as possible, shrink what an attacker can reach, and keep logs that can actually be checked. Where they differ is in *where* that protection lives. Linux and Windows each defend a whole operating system with their own kernel and their own way of handling users and permissions. A container has no kernel of its own, so it depends entirely on the host's kernel features (namespaces, capabilities, seccomp) and on how trustworthy the image it was built from is. That's why so much of this midterm (Sections 3 to 6) focuses on where the software came from, not just on how it runs.

## 3. Supply-chain threat model

**Assets:** the source in this repo, the built image, the CI runner's token, and anyone who runs the image. **Trust boundaries:** PyPI, Docker Hub, the GitHub Actions Marketplace, and my workstation.

| # | Attacker attempt | Control that stops or limits it | Evidence | Slide(s) I drew from |
|---|---|---|---|---|
| 1 | Repoint a mutable GitHub Action tag to malicious code. This **really happened** in March 2026, when 76 of 77 `aquasecurity/trivy-action` tags were force-pushed to a credential stealer (GHSA-69fq-xp46-6x23) | Every action pinned to a full 40-character commit SHA; `permissions: contents: read`; `persist-credentials: false`; Dependabot proposes reviewed SHA bumps | `.github/workflows/*.yml`, `.github/dependabot.yml` | Week 4 *"Docker: Supply Chain Attacks & The Trivy Incident (March 2026)"*; Week 8 *"Securing Dependencies in GitHub Actions"* |
| 2 | Publish a malicious or typosquatted package to PyPI | `requirements.lock` generated with `pip-compile --generate-hashes`; the Docker build runs `pip install --require-hashes --no-deps`, so any unknown package or changed hash fails the build | `requirements.lock`, `Dockerfile` | Week 8 *"Pinning vs. Floating Dependencies"*, *"Dependency Confusion & Supply Chain Attacks"* |
| 3 | Swap the contents behind a base-image tag (`python:3.13-slim`) | Base image pinned by `@sha256` digest; updates arrive only as Dependabot PRs | `Dockerfile` | Week 6 *"Advanced Topic: Image Scanning & Supply Chain Security"* |
| 4 | Sneak a known-vulnerable dependency in through a PR (e.g. `flask==2.0.0`, CVE-2023-30861) | `dependency-review` (`fail-on-severity: high`) and `pip-audit` as required status checks on `main`; PR #1 was blocked and closed unmerged | `dependency-review.yml`, `security-pipeline.yml`, screenshots 22–23 | Week 8 *"GitHub's Dependency Review Action"*, *"Integrating Dependency Scanning into CI/CD"* |
| 5 | Exploit a CVE in an OS package of the image (e.g. CVE-2026-85091, zlib heap overflow, CVSS 8.3) | Trivy CRITICAL gate on every push/PR, weekly scheduled re-scan, Syft SBOM for fast "are we affected?" answers, Grype second opinion | `security-pipeline.yml`, `section4/` | Week 5 *"Docker: Threat Intelligence Techniques"*; Week 6 *"Advanced Topic: Image Scanning & Supply Chain Security"* |
| 6 | After code execution in the app, escalate or escape the container | Non-root `appuser`, `--read-only`, `--cap-drop ALL` (CapEff = 0), `no-new-privileges`, custom seccomp that blocks `ptrace`/`mount`/`unshare`/`bpf`/`keyctl`, PID/memory/CPU limits, port bound to 127.0.0.1; 25 of 27 CIS runtime checks pass | `section3/`, `section5/docker-bench-report.txt` | Week 4 *"Docker: Runtime Security & Least Privilege"*, *"Docker: Seccomp, AppArmor & SELinux Profiles"*; Week 6 *"Advanced Topic: Docker Security Hardening"* |
| 7 | Weaken the Docker daemon itself | `daemon.json` sample with `icc: false`, `no-new-privileges: true`, `userns-remap: default`, log rotation; CIS Docker Benchmark run | `section3/daemon.json.sample`, `section5/` | Week 4 *"Docker: Daemon Configuration & Security Policy"*, *"Docker: CIS Benchmark & Compliance"*; Week 7 *"Docker: The Daemon Configuration Policy"* |
| 8 | Commit a secret or personal data to the public repo | No secrets in code or config; Secret scanning + push protection on; Windows exports redacted (hostname, username, SID) and checked with `grep` | GitHub settings, `section2/` | Week 8 *"GitHub Dependency Security Tools"* |
| 9 | Push straight to `main`, bypassing the gates | Branch protection on `main`: PR required, `pip-audit` and `build-and-scan` required status checks | GitHub branch protection rule (video) | Week 8 *"The Git Workflow in Practice"*; Week 7 *"Docker: Policy in the CI/CD Pipeline"* |
| 10 | Hide activity on the Windows host with encoded PowerShell | 4688 command-line logging + 4104 script-block logging, Sysmon EID 1, and a Sigma rule tagged T1059.001 / T1027.010 | `section2/`, `section5/encoded-powershell.sigma.yml` | Week 4 *"Windows: Audit Policy & Event Logging"*; Week 5 *"Windows: Event Log Analysis"* |
| 11 | Brute-force a Linux account or SSH | `pam_faillock` (lock after 5 failures, verified), SSH `PermitRootLogin no`, `MaxAuthTries 3`, `PermitEmptyPasswords no` | `section1/` | Week 4 *"Linux: PAM & Authentication Policy"*, *"Linux: SSH Hardening & Remote Access Policy"* |

**Residual risk:**
- a compromised maintainer at the moment I pinned a dependency
- zero-days that don't have a CVE yet
- 54 HIGH OS-package CVEs, most of them "won't fix" by Debian; none are in my application's Python packages, which have 0 findings
- the Sysmon download is trust-on-first-use, mitigated by checking its Authenticode signature
- AppArmor is unavailable on the WSL kernel (CIS 5.2 WARN), so seccomp carries the syscall restriction instead

**Note on Section 2 (Defender):** this host runs **Norton 360** as its registered antivirus (`root/SecurityCenter2 AntivirusProduct`). Windows automatically puts Microsoft Defender in a disabled/passive state when a third-party AV is active, so `Get-MpComputerStatus` reports False and `Add-MpPreference` / `Get-MpPreference` return `0x800106ba` (the Defender service is not running). As a result, no Defender exclusion could be applied. Endpoint protection is still active through Norton 360. Screenshots 05 and 10 document this.

## 4. Which section proves which learning objective

Course objectives are quoted from the IA 462 syllabus.

- **"Apply enterprise patch and policy management for Docker Containers, including container hardening."** → Section 3 (multi-stage, digest-pinned, non-root, read-only, cap-drop ALL, custom seccomp, daemon.json) and Section 5 (CIS Docker Benchmark: 55 PASS, 25 of 27 runtime checks passing).
- **"Implement Windows and Linux best practices to protect against Supply Chain Attacks."** → Section 1 (umask 027, SUID/world-writable audit, disabled services, sshd and pam_faillock hardening, Lynis) and Section 2 (Defender/Norton, firewall, SMBv1 removed, audit policy, Sysmon with a commit-pinned and hash-verified config).
- **"Utilize Supply Chain Security Techniques across Windows, Linux, and Docker container environments."** → Sections 2, 3 and 6: hash-verified Sysmon config, digest-pinned base image, hash-locked Python dependencies, SHA-pinned actions.
- **"Understand and integrate Software Bill of Materials (SBOM) into Docker Container workflows."** → Section 4 (Syft SPDX SBOM `sbom.spdx.json`, scanned by Grype) and Section 6 (SBOM generated in CI on every push).
- **"Perform Vulnerability Management: scan, patch, and retest continuously using CI/CD techniques in GitHub."** → Section 4 (Trivy + Grype, CVE-2026-85091 enrichment with a concrete patch and retest plan) and Section 6 (Trivy gate + weekly scheduled scan).
- **"Apply Dependency Pinning, Version Control, and Hashing to reduce surprise supply chain attacks."** → Section 6 (`requirements.txt` exact pins, `requirements.lock` with `--generate-hashes`, Dependabot for pip/docker/github-actions, branch protection).
- **"Configure and manage third-party security scanners within a GitHub CI/CD pipeline."** → Section 6 (`security-pipeline.yml` with Trivy, Syft and pip-audit; `dependency-review.yml` with `fail-on-severity: high`; PR #1 blocked) and Section 5 (Sigma rule for detection-as-code).
