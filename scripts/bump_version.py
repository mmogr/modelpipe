#!/usr/bin/env python3
"""Set the workspace version everywhere it is written down.

Adapted from gglib's bump-version.yml, which does this inline with
`sed -i 's/^version = ".*"/.../' Cargo.toml`. That would silently half-work
here: this workspace writes its version in *two* places, and only one of them
is a line starting with `version = `.

  [workspace.package]                        -> version = "X.Y.Z"
  [workspace.dependencies]                   -> modelpipe = { path = ..., version = "X.Y.Z" }

The second is the requirement the published modelpipe-cli reaches its library
through. Miss it and `cargo check` fails outright with "failed to select a
version for the requirement" — loudly, at least, but only after the commit.

Line-based rather than a TOML round-trip on purpose: every rewriting TOML
library reflows the file and drops or relocates comments, and the comments in
this manifest carry the reasoning. Editing the two lines in place is the only
way to leave the rest byte-identical.

Usage: scripts/bump_version.py X.Y.Z
       scripts/bump_version.py --check

--check prints the current version and exits without writing — and fails if
the two version sites disagree. That check is load-bearing: ^0.1.0 admits
0.1.1, so from the first minor release onward a requirement left behind by
a hand edit satisfies every cargo command while publishing modelpipe-cli
with a permanently loose dependency. String equality here (wired into
ci.yml and release.yml) is what catches it.
"""

import re
import sys
from pathlib import Path

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "Cargo.toml"


def read_current(lines):
    """Both version sites: ([workspace.package], the modelpipe requirement)."""
    section, pkg, dep = None, None, None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
        elif section == "[workspace.package]" and pkg is None:
            m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                pkg = m.group(1)
        elif section == "[workspace.dependencies]" and re.match(r"modelpipe\s*=", stripped):
            m = re.search(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                dep = m.group(1)
    if pkg is None:
        raise SystemExit("error: no version found under [workspace.package]")
    if dep is None:
        raise SystemExit(
            "error: no modelpipe version requirement found under [workspace.dependencies]"
        )
    return pkg, dep


def bump(lines, new):
    """Rewrite both version sites. Returns the edited lines."""
    out, section, hits = [], None, {"package": 0, "dependency": 0}
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
        elif section == "[workspace.package]" and re.match(r'version\s*=\s*"', stripped):
            line = re.sub(r'"[^"]+"', f'"{new}"', line, count=1)
            hits["package"] += 1
        elif section == "[workspace.dependencies]" and stripped.startswith("modelpipe"):
            # Only the `version = "..."` field; `path` must survive untouched.
            line, n = re.subn(r'(version\s*=\s*)"[^"]+"', rf'\1"{new}"', line, count=1)
            hits["dependency"] += n
        out.append(line)

    for name, count in hits.items():
        if count != 1:
            raise SystemExit(
                f"error: expected exactly one {name} version to rewrite, found {count} — "
                "the manifest layout changed and this script needs updating"
            )
    return out


def main():
    args = sys.argv[1:]
    lines = MANIFEST.read_text().splitlines(keepends=True)
    current, dep = read_current(lines)

    if "--check" in args:
        if args != ["--check"]:
            raise SystemExit("usage: scripts/bump_version.py --check  (no other arguments)")
        if dep != current:
            raise SystemExit(
                f"error: [workspace.package] says {current} but the modelpipe requirement "
                f"says {dep} — the two sites have drifted; run make bump, never edit one by hand"
            )
        print(current)
        return

    if len(args) != 1:
        raise SystemExit("usage: scripts/bump_version.py X.Y.Z  (or --check)")

    new = args[0].lstrip("v")
    if not SEMVER.match(new):
        raise SystemExit(f"error: {new!r} is not semver (expected X.Y.Z or X.Y.Z-rc.1)")
    if new == current:
        raise SystemExit(f"error: {new} is already the current version")

    MANIFEST.write_text("".join(bump(lines, new)))
    print(f"{current} -> {new}")
    print("both [workspace.package] and the modelpipe requirement updated")
    print("now run: cargo update --workspace && cargo metadata --locked >/dev/null")


if __name__ == "__main__":
    main()
