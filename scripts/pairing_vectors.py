#!/usr/bin/env python3
"""Reference implementation of the modelpipe pairing string (v0) — the
executable companion to docs/pairing-v0.md.

A pairing string is a ticket, and the first time a one-time code after it:
`<ticket>` or `<ticket>-<code>`. The ticket half is docs/ticket-format-v0.md's
and is decoded by scripts/ticket_vectors.py, imported here rather than copied,
so the two references cannot disagree about what a ticket is.

Usage:
    scripts/pairing_vectors.py            print the vectors, spec-formatted
    scripts/pairing_vectors.py --check    assert the spec's vectors, its
                                          refusal table and the JSON match
    scripts/pairing_vectors.py --json     print the vectors as data

There is deliberately no --update, for the reason the ticket's reference gives:
a v0 vector that changes is a broken client in another language.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ticket_vectors as tv  # noqa: E402

SEPARATOR = "-"
CODE_DIGITS = 6
ASCII_DIGITS = "0123456789"
# Trimmed from both ends and nowhere else: space, tab, line feed, form feed and
# carriage return, the ASCII whitespace Rust's `char::is_ascii_whitespace`
# names. Deliberately not Unicode whitespace, for the ticket's ASCII rule.
TRIMMED = " \t\n\x0c\r"

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "pairing-v0.md"
VECTORS_JSON = ROOT / "docs" / "pairing-vectors-v0.json"

VERDICTS = ["accepted", "empty", "code", "ticket-malformed", "ticket-unsupported-version"]


class Refused(ValueError):
    def __init__(self, verdict: str):
        super().__init__(verdict)
        self.verdict = verdict


def parse(s: str):
    """(canonical ticket string, code or None), or raises Refused(verdict).

    The order is normative: trim, then the separator and the code, then the
    ticket. A string whose code and ticket are both wrong is refused for its
    code."""
    s = s.strip(TRIMMED)
    if not s:
        raise Refused("empty")
    if SEPARATOR in s:
        ticket, code = s.rsplit(SEPARATOR, 1)
        if len(code) != CODE_DIGITS or any(c not in ASCII_DIGITS for c in code):
            raise Refused("code")
    else:
        ticket, code = s, None
    try:
        raw = tv.decode_string(ticket)
        tv.decode_ticket(raw)
    except tv.UnsupportedVersion:
        raise Refused("ticket-unsupported-version")
    except tv.TicketError:
        raise Refused("ticket-malformed")
    return tv.encode_string(raw), code


def verdict(s: str) -> str:
    try:
        parse(s)
    except Refused as r:
        return r.verdict
    return "accepted"


V1 = tv.encode_string(tv.encode_ticket(tv.RFC8032_TEST1_PK, []))
V2 = tv.encode_string(
    tv.encode_ticket(
        tv.RFC8032_TEST1_PK,
        [("relay", "https://relay.example.com/"), ("ip", ("192.168.1.7", 4433))],
    )
)
V3 = tv.encode_string(tv.encode_ticket(tv.RFC8032_TEST1_PK, [("ip", ("2001:db8::1", 8080))]))

ACCEPTED = [
    ("a ticket alone", V1),
    ("a ticket and a code", f"{V1}-483920"),
    ("a ticket that carries addresses, and a code with leading zeros", f"{V3}-000417"),
    ("the whole string upper-cased, as a QR code carries it", f"{V2}-017284".upper()),
    ("ASCII whitespace at either end", f" \t{V1}-483920\r\n"),
]


def refusals():
    newer = tv.encode_string(bytes([0x01]) + tv.encode_ticket(tv.RFC8032_TEST1_PK, [])[1:])
    return [
        ("nothing but whitespace", " \t\r\n", "empty"),
        ("a separator with nothing after it", f"{V1}-", "code"),
        ("a code one digit short", f"{V1}-48392", "code"),
        ("a code one digit long", f"{V1}-4839201", "code"),
        ("a code with a letter in it", f"{V1}-48392a", "code"),
        ("a code in digits outside ASCII", f"{V1}-４８３９２０", "code"),
        ("a non-ASCII space after the code", f"{V1}-483920 ", "code"),
        ("a code and a ticket that are both wrong", "not-a-ticket-4839", "code"),
        ("two codes", f"{V1}-483920-483920", "ticket-malformed"),
        ("whitespace inside the string", f"{V1} -483920", "ticket-malformed"),
        ("a code with no ticket before it", "-483920", "ticket-malformed"),
        ("a ticket that is not one", "not-a-ticket-483920", "ticket-malformed"),
        ("a ticket from a format this build does not speak", f"{newer}-483920", "ticket-unsupported-version"),
    ]


def _render():
    out = []
    for name, value in ACCEPTED:
        ticket, code = parse(value)
        assert verdict(value) == "accepted", name
        assert ticket == ticket.lower() and tv.encode_string(tv.decode_string(ticket)) == ticket
        out.append((name, f"input: {json.dumps(value)}", f"ticket: {ticket}", f"code: {code or 'none'}"))
    return out


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _vectors_json() -> str:
    vectors = []
    for name, value in ACCEPTED:
        ticket, code = parse(value)
        vectors.append({"id": f"accept/{_slug(name)}", "name": name, "input": value,
                        "verdict": "accepted", "ticket": ticket, "code": code})
    for name, value, want in refusals():
        vectors.append({"id": f"refuse/{_slug(name)}", "name": name, "input": value, "verdict": want})
    doc = {
        "format": "modelpipe-pairing-string",
        "version": 0,
        "provenance": {
            "repository": "https://github.com/mmogr/modelpipe",
            "spec": "docs/pairing-v0.md",
            "generator": "scripts/pairing_vectors.py",
            "regenerate": "scripts/pairing_vectors.py --json > docs/pairing-vectors-v0.json",
            "note": "Normative. There is deliberately no --update: a v0 vector that changes is a broken client in another language, not a stale fixture.",
        },
        "verdicts": VERDICTS,
        "string_form": {
            "separator": SEPARATOR,
            "code_digits": CODE_DIGITS,
            "code_alphabet": ASCII_DIGITS,
            "trimmed": list(TRIMMED),
            "ticket": "docs/ticket-format-v0.md",
            "order": ["trim", "empty", "code", "ticket"],
        },
        "vectors": vectors,
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def _check() -> int:
    failed = False
    if not SPEC.exists():
        print(f"✗ spec not found: {SPEC}", file=sys.stderr)
        return 1
    text = SPEC.read_text()
    rendered = _render()
    got = list(zip(
        re.findall(r"^input: (.+)$", text, re.M),
        re.findall(r"^ticket: (pipe[a-z2-7]+)$", text, re.M),
        re.findall(r"^code: ([0-9]+|none)$", text, re.M),
    ))
    want = [(r[1][len("input: "):], r[2][len("ticket: "):], r[3][len("code: "):]) for r in rendered]
    if got != want:
        print("✗ the spec's accepted vectors disagree with this script", file=sys.stderr)
        for i, (g, w) in enumerate(zip(got + [None] * len(want), want)):
            if g != w:
                print(f"    vector {i + 1}: spec {g}\n              here {w}", file=sys.stderr)
        failed = True
    for name, value, want_v in refusals():
        if verdict(value) != want_v:
            print(f"✗ refusal '{name}': expected {want_v}, got {verdict(value)}", file=sys.stderr)
            failed = True
    want_rows = {(name, v) for name, _, v in refusals()}
    got_rows = set(re.findall(r"^\| (.+?) \| `(" + "|".join(VERDICTS[1:]) + r")` \|$", text, re.M))
    for row in sorted(want_rows - got_rows):
        print(f"✗ refusal table is missing: | {row[0]} | `{row[1]}` |", file=sys.stderr)
        failed = True
    for row in sorted(got_rows - want_rows):
        print(f"✗ refusal table names a case this script does not run: {row[0]}", file=sys.stderr)
        failed = True
    if not VECTORS_JSON.exists() or VECTORS_JSON.read_text() != _vectors_json():
        print(f"✗ {VECTORS_JSON.name} is missing or stale; regenerate it with "
              "scripts/pairing_vectors.py --json > docs/pairing-vectors-v0.json", file=sys.stderr)
        failed = True
    if failed:
        print("\nThe spec and this script disagree. Fix whichever is wrong; there is\n"
              "deliberately no --update.", file=sys.stderr)
        return 1
    print(f"✓ {len(rendered)} vectors and {len(refusals())} refusals agree with the spec "
          f"and with {VECTORS_JSON.name}")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args == ["--check"]:
        raise SystemExit(_check())
    if args == ["--json"]:
        sys.stdout.write(_vectors_json())
        raise SystemExit(0)
    if args == ["--update"]:
        print("There is no --update, deliberately: a v0 vector that changes is a broken\n"
              "client in another language, not a stale fixture.", file=sys.stderr)
        raise SystemExit(2)
    if args:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    for i, (name, *lines) in enumerate(_render(), 1):
        print(f"**{i}. {name[0].upper() + name[1:]}**\n\n```")
        print("\n".join(lines))
        print("```\n")
    print("| input | verdict |\n|---|---|")
    for name, _, v in refusals():
        print(f"| {name} | `{v}` |")
