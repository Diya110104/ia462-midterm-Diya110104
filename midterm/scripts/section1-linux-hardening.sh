#!/usr/bin/env bash
# IA 462 midterm - Section 1: Linux host hardening + Lynis.
# Target: WSL Ubuntu (with systemd enabled) or an Ubuntu VM. Run under `script`
# so the whole session becomes the transcript:
#
#   cd midterm/section1
#   script -q -c "sudo bash ../scripts/section1-linux-hardening.sh" linux-hardening-transcript.txt
#
# BEFORE YOU START: open a SECOND terminal and run `sudo -i` and leave it open.
# If the PAM change ever breaks authentication, that root shell is how you undo it:
#   cp /etc/pam.d/common-auth.bak.ia462 /etc/pam.d/common-auth
# (On WSL you can also get root with:  wsl -u root  from PowerShell.)
#
# The script backs up every file it changes (*.bak.ia462) and is safe to re-run.
set -uo pipefail
export LC_ALL=C

OUT="$(cd "$(dirname "$0")/../section1" && pwd)"
LAB_USER="${LAB_USER:-labuser}"
LAB_GROUP="${LAB_GROUP:-labgrp}"
STAMP() { date '+%Y-%m-%d %H:%M:%S %Z'; }
step()  { printf '\n==================================================================\n'
          printf '[%s] %s\n' "$(STAMP)" "$*"
          printf '==================================================================\n'; }
run()   { printf '\n$ %s\n' "$*"; bash -c "$*"; }
backup(){ [ -f "$1.bak.ia462" ] || cp -a "$1" "$1.bak.ia462"; }

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo."; exit 1; }

step "0. Host context"
run "cat /etc/os-release | head -4"
run "uname -r"
run "ps -p 1 -o comm="
if [ "$(ps -p 1 -o comm=)" != "systemd" ]; then
  echo "!! PID 1 is not systemd. On WSL add the following to /etc/wsl.conf, then run 'wsl --shutdown' from PowerShell and reopen:"
  printf '   [boot]\n   systemd=true\n'
  exit 1
fi

# ---------------------------------------------------------------------------
step "1. Non-root lab user + group (no sudo membership)"
getent group "$LAB_GROUP" >/dev/null || run "groupadd $LAB_GROUP"
id "$LAB_USER" >/dev/null 2>&1 || run "useradd -m -g $LAB_GROUP -s /bin/bash $LAB_USER"
echo "Set a password for $LAB_USER (needed later for the faillock test):"
passwd "$LAB_USER"
run "id $LAB_USER"
run "groups $LAB_USER"
if id -nG "$LAB_USER" | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
  echo "FAIL: $LAB_USER is in an admin group"; else echo "PASS: $LAB_USER has no sudo/admin group membership"; fi
run "sudo -l -U $LAB_USER"

# ---------------------------------------------------------------------------
step "2. Restrictive umask 027 in /etc/profile"
backup /etc/profile
if ! grep -qE '^\s*umask\s+027' /etc/profile; then
  printf '\n# IA462 midterm: restrictive default permissions (owner rw, group r, other none)\numask 027\n' >> /etc/profile
fi
run "grep -n 'umask' /etc/profile"
run "su - $LAB_USER -c 'umask; rm -f ~/umask-test; touch ~/umask-test; mkdir -p ~/umask-dir; ls -ld ~/umask-test ~/umask-dir'"
echo "Expected: umask 0027, file -rw-r-----, directory drwxr-x---"

# ---------------------------------------------------------------------------
step "3. SUID binaries and world-writable files under /"
PRUNE='\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /snap \) -prune -o'
{
  echo "# SUID binaries on $(hostname) - $(STAMP)"
  echo "# find / -xdev $PRUNE -type f -perm -4000 -print"
  eval "find / -xdev $PRUNE -type f -perm -4000 -print" 2>/dev/null | sort | xargs -r ls -l
  echo
  echo "# SGID binaries (bonus)"
  eval "find / -xdev $PRUNE -type f -perm -2000 -print" 2>/dev/null | sort | xargs -r ls -l
} > "$OUT/suid-binaries.txt"
{
  echo "# World-writable files on $(hostname) - $(STAMP)"
  echo "# find / -xdev $PRUNE -type f -perm -0002 -print"
  eval "find / -xdev $PRUNE -type f -perm -0002 -print" 2>/dev/null | sort | xargs -r ls -l
  echo
  echo "# World-writable directories WITHOUT the sticky bit (higher risk)"
  eval "find / -xdev $PRUNE -type d -perm -0002 ! -perm -1000 -print" 2>/dev/null | sort | xargs -r ls -ld
} > "$OUT/world-writable.txt"
run "cat '$OUT/suid-binaries.txt'"
run "cat '$OUT/world-writable.txt'"

# ---------------------------------------------------------------------------
step "4. Disable two non-essential services"
# Override with: SERVICES="cups avahi-daemon" sudo -E bash ...
CANDIDATES="cups cups-browsed avahi-daemon ModemManager bluetooth apport whoopsie motd-news.timer multipathd open-iscsi iscsid"
if [ -z "${SERVICES:-}" ]; then
  SERVICES=""
  for s in $CANDIDATES; do
    unit="$s"; [[ "$unit" == *.* ]] || unit="$unit.service"
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "$unit"; then
      SERVICES="$SERVICES $unit"
      [ "$(wc -w <<<"$SERVICES")" -ge 2 ] && break
    fi
  done
fi
echo "Selected services:$SERVICES"
[ "$(wc -w <<<"$SERVICES")" -ge 2 ] || echo "!! Fewer than two candidates found. Install one (e.g. 'apt install -y cups avahi-daemon') and re-run, or set SERVICES=..."
echo "--- PRE state ---"
for s in $SERVICES; do run "systemctl is-enabled $s; systemctl is-active $s; systemctl status $s --no-pager | head -5"; done
for s in $SERVICES; do run "systemctl disable --now $s"; done
echo "--- POST state ---"
for s in $SERVICES; do run "systemctl is-enabled $s; systemctl is-active $s; systemctl status $s --no-pager | head -5"; done
echo ">> Screenshot now: screenshots/01-service-disabled.png"

# ---------------------------------------------------------------------------
step "5. Harden /etc/ssh/sshd_config"
command -v sshd >/dev/null || run "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server"
CFG=/etc/ssh/sshd_config
backup "$CFG"
set_opt() {  # set_opt Key Value : replace first (commented or not) occurrence, else insert before first Match block
  local k="$1" v="$2"
  if grep -qiE "^\s*#?\s*$k\s" "$CFG"; then
    sed -i -E "0,/^\s*#?\s*$k\s.*/I s//$k $v/" "$CFG"
  elif grep -qiE '^\s*Match\s' "$CFG"; then
    sed -i -E "0,/^\s*Match\s/I s//$k $v\n&/" "$CFG"
  else
    echo "$k $v" >> "$CFG"
  fi
}
set_opt PermitRootLogin no
set_opt MaxAuthTries 3
set_opt PermitEmptyPasswords no
run "diff -u $CFG.bak.ia462 $CFG"
echo "--- drop-ins in /etc/ssh/sshd_config.d that could override (first value wins) ---"
run "grep -RHiE 'PermitRootLogin|MaxAuthTries|PermitEmptyPasswords' /etc/ssh/sshd_config.d/ 2>/dev/null || echo none"
run "sshd -t && echo 'sshd -t: config OK'"
run "systemctl restart ssh"
run "systemctl status ssh --no-pager | head -8"
echo "--- effective settings ---"
run "sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|maxauthtries|permitemptypasswords) '"
cp "$CFG" "$OUT/sshd_config.hardened"
echo ">> Screenshot now: screenshots/02-sshd-status.png"

# ---------------------------------------------------------------------------
step "6. pam_faillock: lock after 5 failed attempts"
AUTH=/etc/pam.d/common-auth
ACCT=/etc/pam.d/common-account
backup "$AUTH"; backup "$ACCT"
run "cat $AUTH | grep -v '^#' | grep -v '^$'"
if grep -q 'pam_faillock.so' "$AUTH"; then
  echo "pam_faillock already present - leaving common-auth unchanged."
elif [ "$(grep -cE '^\s*auth\s+\[success=1 default=ignore\]\s+pam_unix\.so' "$AUTH")" -eq 1 ] \
     && [ "$(grep -cE '^\s*auth\s+\[success=[0-9]+' "$AUTH")" -eq 1 ]; then
  # Standard Ubuntu layout (pam_unix is the only primary module). Ordering:
  #   preauth  -> refuse early if the account is already locked
  #   pam_unix -> success=1 jumps over 'authfail' straight to 'authsucc'
  #   authfail -> on failure: record the failure, deny (default=die)
  #   authsucc -> on success: clear the failure counter
  awk '
    /^[ \t]*auth[ \t]+\[success=1 default=ignore\][ \t]+pam_unix\.so/ {
      print "auth\trequisite\t\t\tpam_faillock.so preauth deny=5 unlock_time=900"
      print
      print "auth\t[default=die]\t\t\tpam_faillock.so authfail deny=5 unlock_time=900"
      print "auth\tsufficient\t\t\tpam_faillock.so authsucc deny=5 unlock_time=900"
      next }
    { print }' "$AUTH.bak.ia462" > "$AUTH.new" && mv "$AUTH.new" "$AUTH"
  grep -q 'pam_faillock.so' "$ACCT" || sed -i '0,/^account/s//account\trequired\t\t\tpam_faillock.so\n&/' "$ACCT"
else
  echo "!! common-auth is not the stock Ubuntu layout (extra primary modules such as sssd/krb5)."
  echo "!! Not editing automatically - add pam_faillock by hand; see the comments in this script."
fi
run "diff -u $AUTH.bak.ia462 $AUTH"
run "grep -n faillock $ACCT"
echo "--- sanity check: authentication still works (enter YOUR password if prompted) ---"
run "su - ${SUDO_USER:-root} -c 'sudo -k; sudo -v && echo PAM-OK' || echo '!! sudo failed - restore from the root shell: cp $AUTH.bak.ia462 $AUTH'"
cp "$AUTH" "$OUT/pam-common-auth.hardened"
cat <<EOF

Lockout test (do this in another terminal as YOUR normal user, not root - root's su skips auth):
  for i in 1 2 3 4 5; do su - $LAB_USER -c true; done     # type a WRONG password 5 times
  su - $LAB_USER -c true                                   # correct password is now refused
  sudo faillock --user $LAB_USER                           # shows the 5 failures
  sudo faillock --user $LAB_USER --reset                   # unlock
Then come back here. The counter is shown below for the transcript:
EOF
read -r -p "Press Enter after running the lockout test... " _
run "faillock --user $LAB_USER"
run "faillock --user $LAB_USER --reset && faillock --user $LAB_USER"

# ---------------------------------------------------------------------------
step "7. Lynis audit"
command -v lynis >/dev/null || run "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq lynis"
run "lynis --version"
lynis audit system --no-colors --quick 2>&1 | tee "$OUT/lynis-report.txt"
cp /var/log/lynis-report.dat "$OUT/lynis-report.dat" 2>/dev/null || true
run "grep -E 'Hardening index|Tests performed|Warnings|Suggestions' '$OUT/lynis-report.txt' | head"
chown -R "${SUDO_USER:-root}": "$OUT"
echo ">> Screenshot now: screenshots/03-lynis-summary.png (the 'Lynis security scan details' block)"
step "Section 1 complete. Evidence is in $OUT"
