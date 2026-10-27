#!/bin/bash
# Push the local CI-CKKS source tree to ICELAKE (code lives in WSL, execution on ICELAKE).
set -e
SRC=/home/caesar/development/projects/za-real-ckks-boot-fft/openfhe-development/
timeout 300 rsync -az --delete --exclude 'build*/' --exclude .git/ --exclude '*.pdf' --exclude '*Zone.Identifier' \
  -e "ssh -o BatchMode=yes -o ConnectTimeout=15" "$SRC" ICE-Lake:ci-ckks-fft/openfhe-development/
( cd "$SRC" && git rev-parse --short HEAD && git status --short | wc -l ) | tr '\n' ' ' | \
  timeout 30 ssh -o BatchMode=yes ICE-Lake 'cat > ci-ckks-fft/openfhe-development/SYNCED_FROM'
echo synced
