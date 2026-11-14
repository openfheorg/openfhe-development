#!/bin/bash
#
# Checks that the application guide in agents/ still matches the code.
#
# The guide teaches coding agents (and people) how to write applications with
# OpenFHE. It goes stale when the library changes underneath it, so this script
# fails when:
#
#   * a file the guide names (an example, a header, a note) no longer exists;
#   * a Markdown link in the guide points at a file or directory that is not there;
#   * an API name the guide uses in code no longer appears in the public headers;
#   * an exception message the guide quotes no longer appears in the sources;
#   * the OpenFHE version the guide says it describes, or the version of the plugin in
#     agents/.claude-plugin/plugin.json or agents/.codex-plugin/plugin.json, differs from CMakeLists.txt;
#   * the skill that Codex loads from the plugin has a different name or description from agents/SKILL.md.
#
# It cannot tell that a default changed; the unit tests in UnitTestAgentGuide.cpp
# cover the behaviour the guide states. Nor can it tell that a new feature
# deserves a place in the guide. For that, --pr-base makes it also print a
# warning when the changes since a git ref touch the public headers or the
# examples but leave agents/ alone. The warning does not fail the check; the pull
# request workflow uses it as a reminder.
#
# See "Keeping agents/ current" in AGENTS.md.
#
# Usage: check-agents-guide.sh [--pr-base REF]        (run from anywhere)

set -eu

cd "$(dirname "$0")/../.."

pr_base=""
while [ $# -gt 0 ]; do
    case "$1" in
        --pr-base)
            pr_base="${2:?--pr-base needs a git ref}"
            shift 2
            ;;
        --pr-base=*)
            pr_base="${1#--pr-base=}"
            shift
            ;;
        -h | --help)
            sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) shift ;; # pre-commit may pass file names; they are not needed
    esac
done

# File names the guide uses for files an application creates, not files of this repository.
APPLICATION_FILES="cc.bin ct.bin result.bin public.key secret.key mult.key rot.key"

# Capitalised identifiers in the guide's code that are not OpenFHE API: CMake and the environment,
# instruction files of coding agents, and notation inside code spans.
NOT_OPENFHE="CMAKE_PREFIX_PATH CMAKE_BUILD_TYPE LD_LIBRARY_PATH OMP_NUM_THREADS
OpenFHE_CXX_FLAGS OpenFHE CMakeLists Release Debug
AGENTS GEMINI CLAUDE SKILL README
N Q B A P"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
problems="$tmp/problems"
: > "$problems"

guide_md=$(find agents -name '*.md' | LC_ALL=C sort)
template_cpp=$(find agents/template -name '*.cpp' | LC_ALL=C sort)

# Everything a name in the guide may refer to: files and directories of the tree, relative to the root.
{
    find src docs agents scripts benchmark \( -type f -o -type d \)
    ls -A # the entries of the repository root
} > "$tmp/known"

# Split the guide into fragments, one per line: file, line number, kind and text, separated by tabs.
#   I  an inline code span          B  a line of a C++ code block
#   T  a line outside code blocks, with its inline code spans removed
# shellcheck disable=SC2086
awk '
    FNR == 1 { in_block = 0; language = "" }
    /^```/ {
        if (in_block) {
            in_block = 0
        } else {
            in_block = 1
            language = substr($0, 4)
            gsub(/[ \t\r]/, "", language)
        }
        next
    }
    in_block {
        if (language == "cpp" || language == "c++")
            print FILENAME "\t" FNR "\tB\t" $0
        next
    }
    {
        rest = $0
        while (match(rest, /`[^`]+`/)) {
            print FILENAME "\t" FNR "\tI\t" substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
        }
        plain = $0
        gsub(/`[^`]+`/, "", plain)
        print FILENAME "\t" FNR "\tT\t" plain
    }
' $guide_md > "$tmp/fragments"

# The application template is C++ as well.
# shellcheck disable=SC2086
awk '{ print FILENAME "\t" FNR "\tB\t" $0 }' $template_cpp > "$tmp/template"

# --- files the guide names -----------------------------------------------------------------------
awk -F '\t' -v known="$tmp/known" -v application="$APPLICATION_FILES" '
    BEGIN {
        n = split(application, names, " ")
        for (i = 1; i <= n; i++)
            app[names[i]] = 1
        while ((getline line < known) > 0) {
            count++
            paths[count] = line
            exists[line] = 1
            base = line
            sub(/.*\//, "", base)
            basename[base] = 1
        }
        file_name = "[A-Za-z0-9_./-]*[A-Za-z0-9_-]+[.](cpp|h|md|txt|json|py|sh)"
    }
    $3 == "I" {
        directory = $1
        sub(/\/[^\/]*$/, "", directory)
        text = $4
        before = ""
        while (match(text, file_name)) {
            name = substr(text, RSTART, RLENGTH)
            prefix = before substr(text, 1, RSTART - 1)
            after = substr(text, RSTART + RLENGTH, 1)
            before = before substr(text, 1, RSTART + RLENGTH - 1)
            text = substr(text, RSTART + RLENGTH)
            if (after ~ /[A-Za-z0-9_]/)
                continue  # the extension is only the start of a longer word
            if (name in app || substr(name, 1, 1) == "-" || index(prefix, "<"))
                continue
            relative = directory "/" name
            while (sub(/[^\/]+\/[.][.]\//, "", relative)) {
                # "reference/../README.md" -> "README.md"
            }
            if (name in exists || ("agents/" name) in exists || relative in exists)
                continue
            if (index(name, "/") == 0) {
                if (name in basename)
                    continue
            } else {
                # a path given relative to some directory of the tree, e.g. "utils/exception.h"
                found = 0
                suffix = "/" name
                for (i = 1; i <= count && !found; i++) {
                    start = length(paths[i]) - length(suffix) + 1
                    if (start > 0 && substr(paths[i], start) == suffix)
                        found = 1
                }
                if (found)
                    continue
            }
            print $1 ":" $2 ": file `" name "` does not exist"
        }
    }
' "$tmp/fragments" >> "$problems"

# --- Markdown links, such as the ones SKILL.md uses to reach the guide ---------------------------
awk -F '\t' '
    $3 == "T" {
        text = $4
        while (match(text, /\[[^]]*\]\([^) \t]+\)/)) {
            link = substr(text, RSTART, RLENGTH)
            text = substr(text, RSTART + RLENGTH)
            sub(/^\[[^]]*\]\(/, "", link)
            sub(/\)$/, "", link)
            sub(/#.*/, "", link)
            if (link == "" || link ~ /^[a-z][a-z0-9+.-]*:/)
                continue  # an anchor in the same file, or a URL
            print $1 "\t" $2 "\t" link
        }
    }
' "$tmp/fragments" | while IFS=$'\t' read -r file line target; do
    if [ ! -e "$(dirname "$file")/$target" ]; then
        echo "$file:$line: link target \`$target\` does not exist" >> "$problems"
    fi
done

# --- API names used in code -----------------------------------------------------------------------
find src/core/include src/pke/include src/binfhe/include -name '*.h' | LC_ALL=C sort | xargs cat |
    grep -oE '[A-Za-z_][A-Za-z0-9_]*' | LC_ALL=C sort -u > "$tmp/declared"

# agents/maint is for maintainers of the library, not part of the application guide: its files and links are
# checked above, but it may use build options and other names that are not API.
grep -v '^agents/maint/' "$tmp/fragments" | cat - "$tmp/template" |
    awk -F '\t' -v declared="$tmp/declared" -v ignored="$NOT_OPENFHE" '
    function strip_cpp_noise(code) {
        # comments and string literals hold prose, not API
        sub(/\/\/.*/, "", code)
        gsub(string_literal, "\"\"", code)
        return code
    }
    BEGIN {
        while ((getline line < declared) > 0)
            known[line] = 1
        known["std"] = 1
        n = split(ignored, names, /[ \n]+/)
        for (i = 1; i <= n; i++)
            known[names[i]] = 1
        string_literal = "\"([^\"\\\\]|\\\\.)*\""
        file_name = "^[A-Za-z0-9_./-]*[A-Za-z0-9_-]+[.](cpp|h|md|txt|json|py|sh)$"
    }
    $3 == "T" { next }
    {
        text = $4
        if ($3 == "I") {
            trimmed = text
            gsub(/^[ \t]+|[ \t]+$/, "", trimmed)
            if (text !~ /[A-Z]/)
                next
            # an inline span that is a phrase rather than code: quoted messages are checked elsewhere
            if (index(trimmed, " ") && text !~ /[(:;=]|->/)
                next
            if (trimmed ~ file_name)
                next
        }
        text = strip_cpp_noise(text)

        # OpenFHE names start with a capital letter (types, methods) or are upper-case constants
        previous = ""
        while (match(text, /[A-Za-z0-9_]+/)) {
            name = substr(text, RSTART, RLENGTH)
            if (RSTART > 1)
                previous = substr(text, RSTART - 1, 1)
            next_two = substr(text, RSTART + RLENGTH, 2)
            text = substr(text, RSTART + RLENGTH)
            before = previous
            previous = substr(name, length(name), 1)
            if (name !~ /^[A-Z]/ || before ~ /[$#{\/-]/)
                continue
            # in a code span a dot starts a file extension; in C++ code it is a member access, as in cc.Encrypt
            if (before == "." && $3 != "B")
                continue
            if (next_two ~ /^[\/.-][A-Za-z0-9_]$/)
                continue  # part of a path or a file name
            if (name in known || ($1 SUBSEP name) in reported)
                continue
            reported[$1, name] = 1
            print $1 ":" $2 ": `" name "` is not in the public headers (renamed or removed?)"
        }
    }
' >> "$problems"

# --- exception messages, quoted as definition terms in troubleshooting.md -------------------------
troubleshooting=agents/reference/troubleshooting.md
# adjacent string literals form one message: "... is " "too high" -> "... is too high"
{
    find src \( -name '*.h' -o -name '*.cpp' -o -name '*.c' \) | LC_ALL=C sort | xargs cat | tr '\n' ' '
    echo
} | sed -E 's/"[[:space:]]+"//g' > "$tmp/sources"

awk '
    { lines[NR] = $0 }
    END {
        for (i = 1; i < NR; i++) {
            if (substr(lines[i], 1, 1) != "`" || substr(lines[i + 1], 1, 2) != ": ")
                continue
            rest = lines[i]
            while (match(rest, /`[^`]+`/)) {
                span = substr(rest, RSTART + 1, RLENGTH - 2)
                rest = substr(rest, RSTART + RLENGTH)
                n = split(span, parts, /[.][.][.]/)
                for (j = 1; j <= n; j++) {
                    part = parts[j]
                    gsub(/^[ \t]+|[ \t]+$/, "", part)
                    if (length(part) >= 12)
                        print i "\t" part
                }
            }
        }
    }
' "$troubleshooting" | while IFS=$'\t' read -r line part; do
    if ! grep -qF -- "$part" "$tmp/sources"; then
        echo "$troubleshooting:$line: message \"$part\" is not in the sources" >> "$problems"
    fi
done

# --- the OpenFHE version the guide names ----------------------------------------------------------
major=$(sed -n 's/^set(OPENFHE_VERSION_MAJOR \([0-9][0-9]*\)).*/\1/p' CMakeLists.txt)
minor=$(sed -n 's/^set(OPENFHE_VERSION_MINOR \([0-9][0-9]*\)).*/\1/p' CMakeLists.txt)
# shellcheck disable=SC2086
awk -v current="$major.$minor" '
    {
        text = $0
        while (match(text, /OpenFHE [0-9]+[.][0-9]+/)) {
            found = substr(text, RSTART + 8, RLENGTH - 8)
            previous = RSTART > 1 ? substr(text, RSTART - 1, 1) : ""
            text = substr(text, RSTART + RLENGTH)
            if (previous !~ /[A-Za-z0-9_]/ && text !~ /^[0-9]/ && found != current)
                print FILENAME ":" FNR ": says OpenFHE " found ", CMakeLists.txt says " current
        }
    }
' $guide_md >> "$problems"

# the plugin is released with the library and carries its full version
patch=$(sed -n 's/^set(OPENFHE_VERSION_PATCH \([0-9][0-9]*\)).*/\1/p' CMakeLists.txt)
for manifest in agents/.claude-plugin/plugin.json agents/.codex-plugin/plugin.json; do
    plugin_version=$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$manifest")
    if [ "$plugin_version" != "$major.$minor.$patch" ]; then
        echo "$manifest: version is \"$plugin_version\", CMakeLists.txt says $major.$minor.$patch" >> "$problems"
    fi
done

# Codex finds the skills of a plugin only in a subdirectory, so the plugin carries a second SKILL.md that points at
# the real one. Its front matter, the name and the description, must be the same.
codex_skill=agents/.codex-plugin/skills/openfhe/SKILL.md
if [ "$(sed -n '1,/^---$/{1!p;}' "$codex_skill")" != "$(sed -n '1,/^---$/{1!p;}' agents/SKILL.md)" ]; then
    echo "$codex_skill: name or description differs from agents/SKILL.md" >> "$problems"
fi

# --- reminder: the public API changed and the guide did not ---------------------------------------
if [ -n "$pr_base" ]; then
    if ! changed=$(git diff --name-only "$pr_base...HEAD" 2> "$tmp/git-error"); then
        echo "cannot compare with $pr_base: $(tr '\n' ' ' < "$tmp/git-error")" >> "$problems"
    elif ! printf '%s\n' "$changed" | grep -q '^agents/'; then
        # a change under these paths may add something the guide should describe
        touched=$(printf '%s\n' "$changed" | grep -E '^src/[^/]+/(include|examples)/' | LC_ALL=C sort || true)
        if [ -n "$touched" ]; then
            total=$(printf '%s\n' "$touched" | wc -l | tr -d ' ')
            shown=$(printf '%s\n' "$touched" | head -n 5 | tr '\n' ',' | sed 's/,$//; s/,/, /g')
            if [ "$total" -gt 5 ]; then
                shown="$shown and $((total - 5)) more"
            fi
            message="Public headers or examples changed ($shown) but agents/ did not. Check whether the application"
            message="$message guide needs an update: agents/maint/update-agents-guide.sh lists what to review."
            if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
                # a workflow command: GitHub shows it as a warning on the pull request, next to the first file
                echo "::warning file=$(printf '%s\n' "$touched" | head -n 1),title=Agents guide::$message"
            else
                echo "warning: $message"
            fi
        fi
    fi
fi

if [ -s "$problems" ]; then
    echo "The application guide in agents/ no longer matches the code:"
    echo
    sed 's/^/  /' "$problems"
    echo
    echo "Update the guide (agents/maint/update-agents-guide.sh lists what to review), or, for a name that"
    echo "is not OpenFHE API, add it to NOT_OPENFHE in agents/maint/check-agents-guide.sh."
    exit 1
fi
