#!/usr/bin/env bash
# usage: wsl-wait.sh NAME [timeout_s=3000]   Waits for ~/ci-ckks-wsl/logs/NAME.rc; prints it and the log tail.
NAME=$1; T=${2:-3000}; RC=$HOME/ci-ckks-wsl/logs/$NAME.rc; LOG=$HOME/ci-ckks-wsl/logs/$NAME.log
for ((i=0; i<T; i+=10)); do [ -f "$RC" ] && break; sleep 10; done
if [ -f "$RC" ]; then echo "rc=$(cat "$RC")"; else echo "still running after ${T}s"; fi
tail -5 "$LOG" 2>/dev/null
