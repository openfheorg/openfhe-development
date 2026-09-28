#!/usr/bin/env python3
"""Reject direct stdout/stderr writes in OpenFHE library code.

Library diagnostics must go through the pluggable channel in
utils/diagnostic_output.h (OPENFHE_DIAGNOSTIC_ERR / OPENFHE_DIAGNOSTIC_OUT), so
that an embedder can redirect them and so that building with
-DWITH_DEFAULT_DIAGNOSTIC_SINK=OFF leaves the library with no reference to
std::cerr / std::cout at all. That matters for embedders which may not ship
compiled code writing to stdout/stderr -- an R package on CRAN, for instance,
has to route output through Rprintf / REprintf.

Only library sources and installed headers are checked. Examples, unit tests,
benchmarks and extras are programs in their own right: printing results is their
job, and they are not part of the shipped library.

Usage: check-diagnostic-output.py [file ...]   (defaults to the whole tree)
"""

import re
import sys
from pathlib import Path

# Paths whose contents end up in the library or its installed headers.
LIBRARY_DIR = re.compile(r"^src/[^/]+/(lib|include)/")

# Paths exempt from the rule, each with the reason it is exempt.
EXEMPT = {
    "src/core/lib/utils/diagnostic_output.cpp":
        "is the built-in sink itself, compiled only when WITH_DEFAULT_DIAGNOSTIC_SINK is set",
    "src/core/lib/utils/prng/blake2b-ref.c":
        "vendored BLAKE2 reference code; the writes are in a BLAKE2B_SELFTEST main()",
    "src/core/lib/utils/prng/blake2xb-ref.c":
        "vendored BLAKE2 reference code; the writes are in a BLAKE2XB_SELFTEST main()",
}

# Deliberately excludes sprintf/snprintf/asprintf, which format into a buffer
# rather than writing to a stream.
FORBIDDEN = re.compile(
    r"(?<![\w:])"
    r"(std::c(?:out|err|log)"
    r"|v?f?printf"
    r"|perror|putchar|puts|fputs|fputc|putc)"
    r"(?!\w)"
)

SUGGESTION = {
    "std::cout": "OPENFHE_DIAGNOSTIC_OUT",
    "std::cerr": "OPENFHE_DIAGNOSTIC_ERR",
    "std::clog": "OPENFHE_DIAGNOSTIC_ERR",
}


def strip_comments_and_strings(text):
    """Blank out comments and string/char literals, preserving line structure.

    Keeps offsets and newlines intact so reported line numbers stay correct.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check(path, root):
    rel = path.relative_to(root).as_posix()
    if not LIBRARY_DIR.match(rel) or rel in EXEMPT:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"{rel}: cannot read: {exc}", file=sys.stderr)
        return []
    findings = []
    code = strip_comments_and_strings(text)
    raw = text.split("\n")
    for lineno, line in enumerate(code.split("\n"), start=1):
        for m in FORBIDDEN.finditer(line):
            findings.append((rel, lineno, m.group(0), raw[lineno - 1].strip()))
    return findings


def main(argv):
    root = Path(__file__).resolve().parents[2]
    if argv:
        paths = [Path(a).resolve() for a in argv]
    else:
        paths = [p for d in root.glob("src/*/") for sub in ("lib", "include")
                 for p in (d / sub).rglob("*") if p.suffix in {".cpp", ".c", ".h", ".hpp"}]

    findings = []
    for p in paths:
        try:
            p.relative_to(root)
        except ValueError:
            continue
        if p.is_file() and p.suffix in {".cpp", ".c", ".h", ".hpp"}:
            findings += check(p, root)

    if not findings:
        return 0

    print("Direct stdout/stderr writes are not allowed in OpenFHE library code.\n")
    for rel, lineno, token, src in findings:
        hint = SUGGESTION.get(token)
        print(f"  {rel}:{lineno}: {token}")
        print(f"      {src}")
        if hint:
            print(f"      use {hint} from utils/diagnostic_output.h instead")
    print("\nLibrary diagnostics must go through utils/diagnostic_output.h so they can be")
    print("redirected, and so -DWITH_DEFAULT_DIAGNOSTIC_SINK=OFF leaves the library free")
    print("of std::cerr/std::cout. If a file is genuinely exempt (it is the sink, or is")
    print("vendored third-party code), add it with a reason to EXEMPT in")
    print("scripts/maint/check-diagnostic-output.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
