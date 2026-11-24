# ia462-midterm-&lt;your-username&gt;

IA 462 Advanced OS Security & Administration midterm. Write-up: **[midterm/MIDTERM.md](midterm/MIDTERM.md)**.

```
.github/            dependabot.yml, workflows/security-pipeline.yml, workflows/dependency-review.yml
midterm/
  app/              Flask service (app.py)
  Dockerfile        hardened multi-stage build (CI builds this one)
  requirements.*    .in (direct pins) -> .txt (exact pins) + .lock (hashes)
  scripts/          the scripts that produce each section's evidence
  section1..6/      deliverables + screenshots/
  MIDTERM.md        Section 7
```

## 0. One-time GitHub setup (do this first)

1. Create the **public** repo `ia462-midterm-<username>`. Push this tree to `main`.
2. **Settings → Code security**: enable Dependency graph, Dependabot alerts, Dependabot security updates, Secret scanning, Push protection.
3. Wait for the first `security-pipeline` run to go green on `main` (screenshot 21).
4. **Settings → Branches → Add rule** (or Rulesets) for `main`:
   - Require a pull request before merging.
   - Require status checks to pass. Add `pip-audit`, `build-and-scan`, `dependency-review`. A check only appears in the list after it has run once.
   - Block force pushes.
   - Don't add `copies-in-sync` as required. Dependabot PRs update only the originals, so that check fails on them until you run `scripts/sync-copies.sh`.

## Run order

| # | Where | Command | Produces |
|---|---|---|---|
| 1 | WSL Ubuntu / Ubuntu VM | `cd midterm/section1 && script -q -c "sudo bash ../scripts/section1-linux-hardening.sh" linux-hardening-transcript.txt` | everything in `section1/` |
| 2 | Elevated PowerShell | `cd midterm\scripts; Set-ExecutionPolicy -Scope Process Bypass -Force; .\section2-windows-baseline.ps1` | everything in `section2/` (redacted) |
| 3 | Linux + Docker | `cd midterm && docker build -t ia462-midterm:hardened . && ./section3/run-command.sh` | screenshots 10–12 |
| 4 | Linux + Docker | `cd midterm && ./scripts/section4-scan.sh`, then fill in `section4/cve-writeup.md` | `section4/` |
| 5 | Linux host running dockerd | `cd midterm && sudo ./scripts/section5-docker-bench.sh` | `section5/docker-bench-report.txt` |
| 6 | GitHub | vulnerable-PR demo (below) | screenshots 22–23 |
| 7 | — | edit the *[slide: …]* markers in `MIDTERM.md` | Section 7 |

Section 1 changes PAM. **Keep a second terminal open with `sudo -i`** until you've confirmed `sudo` still works. On WSL, `wsl -u root` also gets you in.

## Section 6 — vulnerable-PR demo

```bash
git switch -c demo/vulnerable-flask
sed -i 's/^flask==.*/flask==2.0.0/' midterm/requirements.txt
git commit -am "demo: downgrade flask to 2.0.0 (known vulnerable)" && git push -u origin demo/vulnerable-flask
```
Open the PR. `dependency-review` fails (GHSA-m2qf-hxjv-5gpq / CVE-2023-30861, high), `pip-audit` fails, and the merge button is blocked (screenshot 22). Close the PR **without merging** and delete the branch (screenshot 23).

## After changing an original file

```bash
bash midterm/scripts/sync-copies.sh   # refreshes section3/Dockerfile and the section6/ copies
```

## Video (.wmv)

Record with OBS or Xbox Game Bar (they produce .mp4), then convert:
```bash
ffmpeg -i walkthrough.mp4 -c:v wmv2 -b:v 4M -c:a wmav2 -b:a 192k walkthrough.wmv
```
The `.wmv` goes to Canvas, not the repo (it's in `.gitignore`).

## Pre-submit checklist

- [ ] Every file listed in the exam exists under `midterm/sectionN/`, including **all screenshots** with the exact names
- [ ] `security-pipeline` is green on `main`; branch protection is on
- [ ] `cve-writeup.md` and `MIDTERM.md` placeholders are replaced
- [ ] `git grep -nI -iE 'password|secret|token|api[_-]?key'` turns up nothing sensitive
- [ ] Repo is public; the URL and the .wmv are submitted to Canvas
