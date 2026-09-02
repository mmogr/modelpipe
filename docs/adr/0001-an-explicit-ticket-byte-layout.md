# ADR 0001 — An explicit ticket byte layout, not postcard over iroh's types

- **Status:** Accepted
- **Date:** 2026-09-02
- **Binding on:** ticket wire format
- **Depends on:** nothing
- **Supersedes:** nothing
- **Superseded by:** nothing

`Binding on` says what overturning this costs. `ticket wire format` means
a reversal is a new format version and a re-pair for every device holding
a ticket — not a semver-major, which would be cheaper, and not free.

## Context

A modelpipe ticket has to travel through a terminal, a QR code, a chat
message and occasionally a person reading it aloud, and it has to be
implementable by a client that is not written in Rust. Mobile is the
obvious case: iroh ships official Swift and Kotlin bindings, so a phone
app is a plausible second implementation and the ticket is the only thing
standing between it and a working pipe.

The README long leaned toward "iroh-tickets conventions: base32-nopad
over postcard", which is what the surrounding ecosystem does. That is a
decision about two separable things — how the bytes are spelled as a
string, and what the bytes are — and only the first of them survived.

This ADR exists because the argument for the second lived in a commit
message, which is the one place nobody looks. Rustdoc says what the code
does; this says why the bytes are the shape they are, and what would have
to change for them to be different.

## Decision

**The string form follows iroh-tickets exactly**: a lowercase `pipe` kind
prefix followed by RFC 4648 base32 without padding. One deliberate
divergence — parsers accept the whole string case-insensitively, prefix
included — because QR alphanumeric mode encodes uppercase only, and a
display layer that upcases a ticket for a smaller QR code must produce
something that scans back. iroh-tickets matches its prefix
case-sensitively, which would break precisely that.

**The bytes are an explicit, hand-specified big-endian layout**, written
out field by field in `docs/ticket-format-v0.md`, rather than a postcard
serialization of iroh's own address types.

## Why not postcard over iroh's types

It would have been less code here and more code everywhere else.

Postcard-serializing `iroh-base`'s types makes the wire format an
undocumented echo of that crate's serde internals: a `#[non_exhaustive]`
enum with a `Custom` variant, a hand-written `PublicKey` impl, `BTreeSet`
ordering. None of that is specified anywhere except Rust source, and all
of it is free to change in any iroh release — a patch bump could alter
modelpipe's wire format without modelpipe changing a line.

A Swift or Kotlin implementer would then be reading `iroh-base`'s source
and reimplementing serde's postcard conventions to derive a format nobody
wrote down. The explicit layout is perhaps sixty lines of table; that is
the entire cost, and it buys a document one page long that a second
implementation can be built from without reading any Rust at all.

The same reasoning drives the two other choices the spec makes that a
serializer would have made differently:

**CRC-32C over the payload, framed honestly.** It guards transcription
and scan corruption — a mistyped character, a misread QR — and not
tampering: anyone who can alter a ticket in transit can replace it
wholesale. The security is the endpoint key and the out-of-band bearer
token; the checksum is ergonomics, and it gives
`TicketParseError::Malformed`'s "checksum failure" wording a contract to
stand on.

**Every address body is length-prefixed, including the fixed-width ones.**
Two redundant bytes on each IP address buy the ability to skip a tag a
parser does not recognise, which makes adding a transport later a
graceful degrade instead of a flag day. This is the one framing decision
a version byte does not rescue, because the rescue is exactly what would
have been deferred: an old parser that cannot find where an unknown
address ends cannot read the rest of the ticket either. The first draft
of the spec length-prefixed only the relay body and recorded skippable
tags as "a live option for v1"; taking the option cost two bytes per
address while no ticket existed, and would have cost a re-pair of every
paired device afterwards.

## What this costs a dependent

**Good:** a non-Rust client implements from one page. The format is
stable against iroh's internals, so an iroh upgrade cannot silently
change what modelpipe puts on the wire.

**Costs, accepted:** the layout is maintained by hand, so a new address
kind means editing a table, a reference implementation and a Rust codec
rather than deriving all three. `scripts/ticket_vectors.py --check` runs
in CI to keep those from drifting, which is a gate that would not exist
if a serializer owned the format.

**Stated plainly, because it surprises people:** iroh's own address types
are richer than the three tags v0 defines. A ticket minted by a modelpipe
that learns a new transport will carry an address older parsers skip, and
those parsers will dial the peer with fewer paths than the ticket
described. That is the intended behaviour and not a degradation to fix —
the fallback is the relay, which is what the address set exists to let a
client avoid, not to let it connect at all.

## Change criteria

This decision is reversed by adopting a serializer for the ticket bytes.
The readings that would justify it:

- **No second implementation exists.** If, at 1.0, no non-Rust client has
  been written or attempted, the argument above is speculative and the
  hand-maintained layout is pure cost. The reading is the issue tracker:
  a search for issues referencing `docs/ticket-format-v0.md`, and whether
  any of them came from someone building a client.
- **The hand-maintained format is where the bugs are.** If
  `ticket_vectors.py --check` has caught spec-versus-implementation drift
  more than twice, or a released version has shipped a codec that
  disagreed with the published vectors, the maintenance cost is real
  rather than theoretical. The reading is `git log` on
  `docs/ticket-format-v0.md` and `scripts/ticket_vectors.py`, and the CI
  history of that check.

Neither reading can be taken yet — the format has existed for one commit
and nothing has been published — and both are recorded now so the
question is settled by a reading later rather than by memory.

A reversal is a **new version byte**, never an edit to v0. The refusal of
`--update` in `scripts/ticket_vectors.py` is the mechanical form of that
rule: a v0 vector that changes is a broken client somewhere, not a stale
fixture.
