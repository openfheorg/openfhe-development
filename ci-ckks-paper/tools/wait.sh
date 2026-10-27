#!/bin/bash
# wait.sh NAME [maxsec]: poll ICELAKE until job NAME writes its .rc, then print rc + filtered log tail.
NAME=$1; MAX=${2:-3000}; t=0
while [ $t -lt $MAX ]; do
  rc=$(timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=10 ICE-Lake "cat ci-ckks-fft/logs/$NAME.rc 2>/dev/null" 2>/dev/null)
  if [ -n "$rc" ]; then
    echo "JOB $NAME rc=$rc"
    timeout 20 ssh -o BatchMode=yes ICE-Lake "grep -E 'RESULT|error|Error|rror:|terminate|what\(\)|Killed|Segmentation|Abort|\[100%\]' ci-ckks-fft/logs/$NAME.log | tail -40"
    exit 0
  fi
  sleep 15; t=$((t+15))
done
echo "JOB $NAME still running after ${MAX}s"
