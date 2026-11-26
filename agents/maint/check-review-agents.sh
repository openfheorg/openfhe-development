#!/bin/bash
#
# Checks that the code review agent is still wired to its checklist.
#
# The review instructions live in one place, agents/maint/review-checklist.md. AGENTS.md points at it, and Claude
# Code, Codex and Gemini CLI each have a small openfhe-reviewer agent that only tells the tool to follow it. This
# script fails when:
#
#   * the checklist or one of the three agent definitions is missing;
#   * an agent definition is not named openfhe-reviewer, does not name the checklist, or no longer tells the
#     agent not to edit files;
#   * AGENTS.md no longer names the checklist or the agent;
#   * the checklist refers to a section of AGENTS.md that is not there.
#
# The files and links the checklist names are checked by check-agents-guide.sh.
#
# Usage: check-review-agents.sh        (run from anywhere)
# Exit status: 0 everything is in place, 1 something is not.

set -eu

cd "$(dirname "$0")/../.."

AGENT=openfhe-reviewer
CHECKLIST=agents/maint/review-checklist.md
DEFINITIONS=".claude/agents/$AGENT.md .codex/agents/$AGENT.toml .gemini/agents/$AGENT.md"

problems=$(mktemp)
trap 'rm -f "$problems"' EXIT

if [ ! -f "$CHECKLIST" ]; then
    echo "$CHECKLIST: file is missing" >> "$problems"
fi

for definition in $DEFINITIONS; do
    if [ ! -f "$definition" ]; then
        echo "$definition: file is missing" >> "$problems"
        continue
    fi
    # "name: openfhe-reviewer" in Markdown front matter, 'name = "openfhe-reviewer"' in TOML
    if ! grep -Eq "^name(: *| *= *\")$AGENT\"?[[:space:]]*\$" "$definition"; then
        echo "$definition: the agent is not named $AGENT" >> "$problems"
    fi
    if ! grep -qF "$CHECKLIST" "$definition"; then
        echo "$definition: does not name $CHECKLIST" >> "$problems"
    fi
    if ! grep -qiF "do not edit" "$definition"; then
        echo "$definition: does not say \"Do not edit files\"; a review reports and does not edit" >> "$problems"
    fi
done

if [ ! -f AGENTS.md ]; then
    echo "AGENTS.md: file is missing" >> "$problems"
else
    for name in "$CHECKLIST" "$AGENT"; do
        if ! grep -qF "$name" AGENTS.md; then
            echo "AGENTS.md: does not name $name" >> "$problems"
        fi
    done
    # the checklist refers to sections of AGENTS.md by title: "Keeping agents/ current" in `AGENTS.md`
    if [ -f "$CHECKLIST" ]; then
        grep -n -oE '"[^"]+" in `AGENTS\.md`' "$CHECKLIST" | while IFS=: read -r line reference; do
            title=$(printf '%s' "$reference" | sed -E 's/^"([^"]+)".*/\1/')
            if ! grep -qxF "## $title" AGENTS.md; then
                echo "$CHECKLIST:$line: AGENTS.md has no section \"$title\"" >> "$problems"
            fi
        done
    fi
fi

if [ -s "$problems" ]; then
    echo "The code review agent no longer matches its checklist:"
    echo
    sed 's/^/  /' "$problems"
    exit 1
fi
