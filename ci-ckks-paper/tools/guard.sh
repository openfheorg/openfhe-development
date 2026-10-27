#!/bin/bash
# Usage (on ICELAKE): guard.sh NAME 'command...'
# Runs the command detached in tmux; survives SSH drops. Log: ~/ci-ckks-fft/logs/NAME.log, exit code: NAME.rc
NAME=$1; shift
L=$HOME/ci-ckks-fft/logs
mkdir -p $L
rm -f $L/$NAME.rc
tmux kill-session -t "$NAME" 2>/dev/null || true
tmux new-session -d -s "$NAME" "bash -c 'cd ~/ci-ckks-fft && { $* ; } > $L/$NAME.log 2>&1; echo \$? > $L/$NAME.rc'"
echo "started $NAME"
