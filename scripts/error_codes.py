#!/usr/bin/env python3
"""The error codes modelpipe writes itself, as data a client can build against.

Every response modelpipe synthesizes rather than relays is built by one
function in modelpipe/src/refusal.rs, as a status line, a code and a message.
This reads them out of that file, works out which side writes each from where
it is called, and compares the result with docs/error-codes-v0.json.

Usage:
    scripts/error_codes.py            print the codes as data
    scripts/error_codes.py --check    fail when the published file disagrees
                                      with the source, or the README's table
                                      names a code that is not in it

Regenerate with: scripts/error_codes.py > docs/error-codes-v0.json
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "modelpipe" / "src"
REFUSALS = SRC / "refusal.rs"
PUBLISHED = ROOT / "docs" / "error-codes-v0.json"
README = ROOT / "README.md"

# The connect side's files. A refusal called from one of these is written by
# the connecting side; one called from anywhere else, by the serving side.
CONNECTING = {"dialer.rs"}

REFUSAL = re.compile(
    r'pub\(crate\) fn (?P<fn>[a-z_]+)\(\) -> Vec<u8> \{\s*refusal\(\s*'
    r'"HTTP/1\.1 (?P<status>\d{3}) [^"]*",\s*&\[[^\]]*\],\s*'
    r'"(?P<code>[a-z_]+)",\s*"(?P<message>(?:[^"\\]|\\.)*)",?\s*\)\s*\}'
)
# Every function that hands back a refusal, whether or not REFUSAL can read it.
REFUSAL_FN = re.compile(r"pub\(crate\) fn (?P<fn>[a-z_]+)\(\) -> Vec<u8> \{")
ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}


def unescape(literal: str) -> str:
    """A Rust string literal's text, for the escapes a message can carry."""
    return re.sub(r"\\(.)", lambda m: ESCAPES.get(m.group(1), m.group(0)), literal)


def side(fn: str) -> str:
    callers = set()
    for path in sorted(SRC.glob("*.rs")):
        if path.name == REFUSALS.name or path.name.endswith("_tests.rs"):
            continue
        if re.search(rf"\brefusal::{fn}\(\)", path.read_text()):
            callers.add(path.name)
    if not callers:
        raise SystemExit(f"refusal::{fn} is never called, so no side writes it")
    sides = {"connecting" if name in CONNECTING else "serving" for name in callers}
    if len(sides) != 1:
        raise SystemExit(f"refusal::{fn} is called from both sides: {sorted(callers)}")
    return sides.pop()


def codes() -> dict:
    source = REFUSALS.read_text()
    matches = list(REFUSAL.finditer(source))
    unread = sorted({m["fn"] for m in REFUSAL_FN.finditer(source)} - {m["fn"] for m in matches})
    if unread:
        raise SystemExit(
            f"{REFUSALS.relative_to(ROOT)}: could not read {', '.join(unread)}; each refusal is "
            "read as refusal(status line, headers, code, message) with literal arguments"
        )
    found = [
        {
            "code": m["code"],
            "status": int(m["status"]),
            "written_by": side(m["fn"]),
            "message": unescape(m["message"]),
        }
        for m in matches
    ]
    if not found:
        raise SystemExit(f"no refusal found in {REFUSALS.relative_to(ROOT)}")
    names = [c["code"] for c in found]
    if len(set(names)) != len(names):
        raise SystemExit(f"a code is written by two functions: {names}")
    return {
        "version": 0,
        "about": (
            "The error responses modelpipe writes itself rather than relaying "
            "from the backend. Each has the JSON body "
            '{"error":{"message":...,"code":...}}; match on code. written_by '
            "is the side that wrote it: serving is the machine with the "
            "backend, connecting the machine with the local port."
        ),
        "codes": found,
    }


def render() -> str:
    return json.dumps(codes(), indent=2) + "\n"


def readme_codes() -> list:
    """The codes in the README's table, the rows under its `code` header."""
    found, in_table = [], False
    for line in README.read_text().splitlines():
        if line.startswith("| `code` |"):
            in_table = True
        elif in_table and line.startswith("|---"):
            continue
        elif in_table and line.startswith("| `"):
            found.append(line.split("`")[1])
        else:
            in_table = False
    if not found:
        raise SystemExit("README.md has no table of codes under a `code` header")
    return found


def check() -> int:
    expected = render()
    problems = []
    if not PUBLISHED.exists():
        problems.append(f"{PUBLISHED.relative_to(ROOT)} is missing")
    elif PUBLISHED.read_text() != expected:
        problems.append(
            f"{PUBLISHED.relative_to(ROOT)} disagrees with refusal.rs; "
            "regenerate it with scripts/error_codes.py > docs/error-codes-v0.json"
        )
    published = {c["code"] for c in codes()["codes"]}
    for code in readme_codes():
        if code not in published:
            problems.append(f"README.md's table names {code}, which modelpipe does not write")
    for problem in problems:
        print(f"error codes: {problem}", file=sys.stderr)
    if not problems:
        print(f"error codes: {len(published)} codes match refusal.rs")
    return 1 if problems else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--check"]:
        sys.exit(check())
    if not args:
        sys.stdout.write(render())
        sys.exit(0)
    print(__doc__, file=sys.stderr)
    sys.exit(2)
