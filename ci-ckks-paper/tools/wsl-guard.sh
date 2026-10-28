#!/usr/bin/env bash
# Guarded job runner for the WSL VM (replaces ICELAKE guard.sh).
# usage: wsl-guard.sh NAME MEM_GB 'command'
#   Runs 'command' (bash, cwd = repo root) as a transient systemd --user service in cickks.slice.
#   - cickks.slice caps ALL guarded jobs together: MemoryMax=$CICKKS_SLICE_MAX (default 20G, raised from 16G by the user 2026-10-28), no swap,
#     CPUQuota 1400% (14 of 20 threads), so the VM, VS Code and the user keep the rest.
#   - each job gets its own MemoryMax=MEM_GB, no swap, nice 10, OOMScoreAdjust=1000 (if the VM itself runs
#     short of RAM, the kernel OOM killer picks the guarded job first, never VS Code or the shell). Over the limit -> the job is OOM-killed
#     inside its cgroup; nothing else is touched.
#   - refuses to start (rc file "refused:mem") if MemAvailable < MEM_GB + 2 GB.
#   - log: ~/ci-ckks-wsl/logs/NAME.log ; exit status: ~/ci-ckks-wsl/logs/NAME.rc
#     (a number for a normal exit, "killed:<result>" if systemd stopped/killed it, e.g. killed:oom-kill).
#   - survives SSH/VS Code disconnects (systemd user manager owns the job), not a VM restart.
# Wait with: wsl-wait.sh NAME   Status: systemctl --user list-units 'cickks-*'   Stop: systemctl --user stop cickks-NAME
set -u
[ $# -ge 3 ] || { echo "usage: $0 NAME MEM_GB 'command'" >&2; exit 2; }
NAME=$1; MEM=$2; shift 2; CMD="$*"
ROOT=/home/caesar/development/projects/za-real-ckks-boot-fft/openfhe-development
LOGD=$HOME/ci-ckks-wsl/logs; mkdir -p "$LOGD"
LOG=$LOGD/$NAME.log; RC=$LOGD/$NAME.rc
SLICE_MAX=${CICKKS_SLICE_MAX:-20G}

# global slice (idempotent)
SD=$HOME/.config/systemd/user; mkdir -p "$SD"
WANT="[Slice]
MemoryMax=$SLICE_MAX
MemorySwapMax=0
CPUQuota=1400%"
if [ "$(cat "$SD/cickks.slice" 2>/dev/null)" != "$WANT" ]; then
  printf '%s\n' "$WANT" > "$SD/cickks.slice"; systemctl --user daemon-reload
fi

if systemctl --user is-active --quiet "cickks-$NAME.service"; then
  echo "job $NAME already running" >&2; exit 3
fi
rm -f "$RC" "$LOG"

availGB=$(awk '/MemAvailable/{printf "%d", $2/1048576}' /proc/meminfo)
if [ "$availGB" -lt $((MEM + 2)) ]; then
  echo "refused:mem (available ${availGB} GB < ${MEM}+2 GB)" | tee "$RC" >&2; exit 4
fi

systemctl --user reset-failed "cickks-$NAME.service" 2>/dev/null
systemd-run --user --quiet --collect --unit="cickks-$NAME" --slice=cickks.slice \
  -p MemoryMax="${MEM}G" -p MemorySwapMax=0 -p Nice=10 -p OOMScoreAdjust=1000 \
  -p WorkingDirectory="$ROOT" \
  -p ExecStopPost="/bin/sh -c '[ -f $RC ] || echo killed:\${SERVICE_RESULT} > $RC'" \
  /bin/bash -c "{ echo \"[guard] start \$(date '+%F %T') host=WSL mem=${MEM}G\"; uptime; $CMD ; } > '$LOG' 2>&1; echo \$? > '$RC'" \
  && echo "started cickks-$NAME (log $LOG)"
