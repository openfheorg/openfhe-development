#!/bin/bash
#
# Helps bring the application guide in agents/ up to date after a code change.
#
# The guide is prose, so it cannot be regenerated. This script does the mechanical
# part and hands the rest to a person or to a coding agent:
#
#   1. runs check-agents-guide.sh and shows what it found;
#   2. lists the guide files that the changes on this branch may affect;
#   3. prints a prompt that tells a coding agent how to update them.
#
# It works with any agent. To let one do the update, pass its non-interactive
# command with --run; the prompt is appended as the last argument:
#
#     agents/maint/update-agents-guide.sh --run "claude -p"
#     agents/maint/update-agents-guide.sh --run "codex exec"
#     agents/maint/update-agents-guide.sh --run "gemini -p"
#
# Review what the agent changed before committing.
#
# Usage: update-agents-guide.sh [--base REF] [--prompt] [--run COMMAND]
#   --base REF      git ref to compare with (default: where this branch left dev)
#   --prompt        print only the prompt for a coding agent
#   --run COMMAND   agent command to run with the prompt as its last argument

set -eu

here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."
checker="$here/check-agents-guide.sh"
self="agents/maint/update-agents-guide.sh"

base=""
prompt_only=0
run=""
while [ $# -gt 0 ]; do
    case "$1" in
        --base)
            base="${2:?--base needs a git ref}"
            shift 2
            ;;
        --base=*)
            base="${1#--base=}"
            shift
            ;;
        --prompt)
            prompt_only=1
            shift
            ;;
        --run)
            run="${2:?--run needs a command}"
            shift 2
            ;;
        --run=*)
            run="${1#--run=}"
            shift
            ;;
        -h | --help)
            sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown argument '$1' (see --help)" >&2
            exit 2
            ;;
    esac
done

if [ -z "$base" ]; then
    base=HEAD
    for ref in origin/dev dev origin/main main; do
        if merge_base=$(git merge-base HEAD "$ref" 2> /dev/null); then
            base=$merge_base
            break
        fi
    done
fi
if ! git rev-parse --verify --quiet "$base^{commit}" > /dev/null; then
    echo "error: '$base' is not a git commit to compare with" >&2
    exit 2
fi
short_base=$(printf '%s' "$base" | cut -c1-12)

# Which guide files describe which part of the tree. Prints the guide files for one changed path,
# one per line; nothing if the guide does not describe that path.
guide_files_for() {
    path=$1
    case "$path" in
        */unittest/* | */extras/*) return ;;
    esac
    lower=$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')
    case "$path" in
        src/*)
            case "$lower" in
                *-ser* | *serial*) echo "reference/serialization.md" ;;
            esac
            case "$lower" in
                *multiparty* | *threshold* | */pre*) echo "reference/multiparty.md" ;;
            esac
            ;;
    esac
    # the first matching prefix wins
    case "$path" in
        src/pke/include/scheme/ckksrns* | src/pke/lib/scheme/ckksrns*)
            echo "reference/ckks.md"
            ;;
        src/pke/include/scheme/bfvrns* | src/pke/lib/scheme/bfvrns* | \
            src/pke/include/scheme/bgvrns* | src/pke/lib/scheme/bgvrns*)
            echo "reference/bfv-bgv.md"
            ;;
        src/pke/lib/encoding*)
            printf '%s\n' "reference/ckks.md" "reference/bfv-bgv.md" "reference/troubleshooting.md"
            ;;
        src/pke/include/encoding*)
            printf '%s\n' "reference/ckks.md" "reference/bfv-bgv.md"
            ;;
        src/pke/include/scheme/gen-cryptocontext-params* | src/pke/include/constants*)
            printf '%s\n' "README.md" "reference/ckks.md" "reference/bfv-bgv.md"
            ;;
        src/pke/include/cryptocontext*)
            printf '%s\n' "README.md" "reference/ (every file that uses the changed functions)"
            ;;
        src/pke/include/schemebase* | src/pke/lib/schemebase*)
            printf '%s\n' "README.md" "reference/troubleshooting.md"
            ;;
        src/pke/lib/cryptocontext*)
            echo "reference/troubleshooting.md"
            ;;
        src/pke/examples*)
            printf '%s\n' "reference/examples-index.md" "the \"Further topics\" tables in reference/"
            ;;
        src/binfhe/examples*)
            printf '%s\n' "reference/examples-index.md" "reference/binfhe.md"
            ;;
        src/binfhe*)
            echo "reference/binfhe.md"
            ;;
        src/core/include/lattice/stdlatticeparms*)
            printf '%s\n' "README.md" "reference/ckks.md" "reference/bfv-bgv.md"
            ;;
        src/core/lib/lattice/stdlatticeparms*)
            printf '%s\n' "reference/ckks.md" "reference/bfv-bgv.md"
            ;;
        CMakeLists.User.txt* | OpenFHEConfig.cmake.in*)
            echo "template/CMakeLists.txt"
            ;;
        CMakeLists.txt*)
            printf '%s\n' "README.md (the OpenFHE version it names)" "template/CMakeLists.txt"
            ;;
        src/pke/include*)
            echo "reference/ (the file for the scheme or feature the header belongs to)"
            ;;
        src/pke/lib*)
            echo "reference/troubleshooting.md (if an exception message changed)"
            ;;
    esac
}

if checker_output=$("$checker" 2>&1); then
    checker_ok=1
    checker_report="agents/maint/check-agents-guide.sh passes at the moment."
else
    checker_ok=0
    checker_report="agents/maint/check-agents-guide.sh reports:

$checker_output"
fi

changed=$({
    git diff --name-only "$base"
    git ls-files --others --exclude-standard
} | LC_ALL=C sort -u)

listing=""
guide_touched=0
while IFS= read -r path; do
    [ -n "$path" ] || continue
    case "$path" in
        agents/*)
            guide_touched=1
            continue
            ;;
    esac
    targets=$(guide_files_for "$path" | sed 's|^|agents/|' | tr '\n' ',' | sed 's/,$//; s/,/, /g')
    if [ -n "$targets" ]; then
        listing="$listing  $path
      -> $targets
"
    fi
done << EOF
$changed
EOF
affected=1
if [ -z "$listing" ]; then
    affected=0
    listing="  (none)
"
fi
listing=${listing%
}

prompt="The application guide in agents/ teaches coding agents how to write programs with OpenFHE. Bring it up to date
with the code changes on this branch. Follow the section \"Keeping agents/ current\" in AGENTS.md.

$checker_report

Changed files that the guide may describe, and the guide files to review for each:
$listing

For each one, read the change (git diff $short_base -- <file>) and decide whether the guide says anything that is no
longer true or leaves out something a user of the library now needs: a renamed or removed function, a new parameter
or default, a different exception message, a new or removed example, a changed failure mode. Edit only what the
change makes necessary. Keep the guide short, keep lines within 120 columns, and do not describe internals.

Verify every statement you add or change against the library itself, by building and running a small program, as the
existing guide was. If a statement is checked by src/pke/unittest/UnitTestAgentGuide.cpp or
src/binfhe/unittest/UnitTestAgentGuide.cpp, update that test too. Finish by running
agents/maint/check-agents-guide.sh; it must pass. Do not commit. Report what you changed and what you verified."

if [ "$prompt_only" -eq 1 ]; then
    printf '%s\n' "$prompt"
    exit 0
fi

printf '%s\n\n' "$checker_report"
echo "Changes since $short_base that the guide may describe:"
printf '%s\n\n' "$listing"
if [ "$guide_touched" -eq 1 ]; then
    printf '%s\n\n' "agents/ is already modified on this branch."
fi
if [ "$affected" -eq 0 ] && [ "$checker_ok" -eq 1 ]; then
    echo "Nothing to update."
    exit 0
fi

if [ -n "$run" ]; then
    # the command is split on spaces, so "claude -p" becomes a program and its argument
    set -f
    # shellcheck disable=SC2086
    exec $run "$prompt"
fi

echo "Review the guide files listed above, or let a coding agent do it:"
echo
echo "    $self --run \"claude -p\"     (or \"codex exec\", \"gemini -p\")"
echo
echo "--prompt prints the instructions the agent receives."
[ "$checker_ok" -eq 1 ]
