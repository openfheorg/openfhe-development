#!/usr/bin/env bash
# Item 6.3: context + bootstrap-key serialization round trip, save and load in separate processes.
# usage (cwd = repo root, through wsl-guard.sh): serial-matrix.sh BUILD_DIR "case" ["case" ...]
#   case = "scheme logN lbEnc lbDec secret stcfirst iters", e.g. "ci 12 3 3 encap 0 1"
# Files go to ~/ci-ckks-wsl/serial/<case>/ (deleted after a passing case). Prints one CASE line per case and a
# SUMMARY line; exit status 1 if any case failed.
set -u
BIN=$1/bin/benchmark/ci-boot-serial; shift
BASE=$HOME/ci-ckks-wsl/serial
pass=0; fail=0
for c in "$@"; do
  set -- $c
  d=$BASE/$(echo "$c" | tr ' ' '_'); rm -rf "$d"; mkdir -p "$d"
  t0=$(date +%s)
  if "$BIN" save "$d" "$@" && "$BIN" load "$d" "$@"; then
    echo "CASE PASS [$c] $(( $(date +%s) - t0 )) s"; pass=$((pass+1)); rm -rf "$d"
  else
    echo "CASE FAIL [$c]"; fail=$((fail+1))
  fi
done
echo "SUMMARY pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
