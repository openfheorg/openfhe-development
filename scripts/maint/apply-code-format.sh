#!/bin/bash
#
# Applies clang-format to the whole tree using the version pinned in
# .pre-commit-config.yaml, so the result matches what the commit hook enforces.
# Any arguments are passed through to pre-commit, for example:
#
#   scripts/maint/apply-code-format.sh --files src/pke/lib/cryptocontext.cpp
#
# Requires pre-commit (pip3 install pre-commit). With no arguments it formats
# every tracked C and C++ file.

set -eu

if ! command -v pre-commit > /dev/null 2>&1; then
    echo "error: pre-commit is not installed; run 'pip3 install pre-commit'" >&2
    exit 1
fi

cd "$(dirname "$0")/../.."

if [ "$#" -eq 0 ]; then
    exec pre-commit run clang-format --all-files
fi

exec pre-commit run clang-format "$@"
