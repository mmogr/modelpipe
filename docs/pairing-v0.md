# modelpipe pairing string, version 0

Status: **new in 0.6.0**. This is the string one machine shows and another
takes in, pasted or scanned, to pair with it. The test vectors and the
refusal table below are normative. `scripts/pairing_vectors.py` is the
executable reference that prints them, and `scripts/pairing_vectors.py
--check` asserts on every CI run that it, this page and
[`pairing-vectors-v0.json`](pairing-vectors-v0.json) agree. The Rust parser
hard-codes the same vectors rather than generating them, so three
implementations have to agree before anything is released.

This page defers to [the ticket format](ticket-format-v0.md) for everything
about a ticket, and the reference imports `scripts/ticket_vectors.py` for
the ticket half rather than copying it. What this page adds is the code, the
separator, and the order a parser checks them in.

As with the ticket, a v0 pairing string will always parse as one, which is
why the reference refuses to have an `--update` flag.

## String form

A pairing string is one of two ASCII strings:

```
ticket
ticket "-" code
```

- `ticket` is a ticket, in the string form the ticket format specifies.
- `code` is **exactly six ASCII digits**, `0` to `9`. Leading zeros are part
  of the code: `000417` is a code and `417` is refused.
- The first form says where a machine is. The second is for a first pairing:
  the code is spent once, with the machine the ticket names, for a
  credential of the pairing device's own. How it is spent is the redeem
  exchange below.
- Producers emit the ticket in lower case, as the ticket format requires,
  then `-` and the code.
- A producer may upper-case the **whole** string for a QR code, for the
  reason the ticket format gives: QR alphanumeric mode encodes upper case
  only. The separator and the digits are unchanged by it, and the ticket
  half parses case-insensitively, so a scan parses to the same value.
- **The separator is the last `-`.** A ticket's string form is `pipe` and
  RFC 4648 base32, and neither contains `-`, so a string a producer emits
  has at most one. A parser splits on the last, so the characters it checks
  as the code are always the end of the string.
- A producer draws the code **uniformly** from the million strings `000000`
  to `999999`, with a cryptographically secure generator. A 32-bit draw
  reduced modulo 1,000,000 is not uniform: the reference redraws any value
  at or above the largest multiple of 1,000,000 a `u32` holds. Six digits do
  not survive guessing on their own, and how many guesses one survives is
  bounded by the exchange that spends it.

## Parsing (normative)

A parser takes these steps in this order, and refuses with the first
verdict that applies.

1. **Trim** ASCII whitespace from both ends: space, tab (U+0009), line feed
   (U+000A), form feed (U+000C) and carriage return (U+000D). Nothing else is
   trimmed, and nothing inside the string is. A string copied from a
   terminal or a message ends in a newline often enough that refusing one
   would be refusing people. Unicode whitespace is not trimmed, for the
   reason the ticket format refuses non-ASCII input. Rust's
   `char::is_ascii_whitespace` is exactly this set; Python's `str.strip()`
   with no argument is not, so the reference names the set itself.
2. **`empty`** if nothing is left.
3. If the string contains `-`, everything after the last one is the code:
   **`code`** unless it is exactly six ASCII digits. The code is checked
   before the ticket, so a string wrong in both is refused for its code.
4. The rest, or the whole string when it has no `-`, is parsed as a ticket:
   **`ticket-malformed`** for the ticket format's `Malformed`, and
   **`ticket-unsupported-version`** for its `UnsupportedVersion`.

Each verdict is something a person can do: paste something, check the end of
what they pasted, copy the ticket again, or upgrade.

A client that cannot decode a ticket may prefilter a pairing string by taking
steps 1 to 3 and applying the ticket format's prefilter to the ticket half.
That section's rule binds it too: a prefilter must never refuse a string a
conforming parser accepts.

## Test vectors (normative)

Each `input` is JSON-quoted, so whitespace in it can be seen. `ticket` is
the ticket half re-encoded, which is lower case, and `code` is the code or
`none`. They reuse the ticket format's vectors 1, 2 and 3.

**1. A ticket alone**

```
input: "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na"
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na
code: none
```

**2. A ticket and a code**

```
input: "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na-483920"
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na
code: 483920
```

**3. A ticket that carries addresses, and a code with leading zeros**

```
input: "pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw-000417"
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaicaajcaainxaaaaaaaaaaaaaaaaaaach4qaabstehw
code: 000417
```

**4. The whole string upper-cased, as a QR code carries it**

```
input: "PIPEADLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRUAQAAANGQ5DUOBZTULZPOJSWYYLZFZSXQYLNOBWGKLTDN5WS6AIAA3AKQAIHCFIQBRP5XR4Q-017284"
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaqaaangq5duobztulzpojswyylzfzsxqylnobwgkltdn5ws6aiaa3akqaihcfiqbrp5xr4q
code: 017284
```

**5. ASCII whitespace at either end**

```
input: " \tpipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na-483920\r\n"
ticket: pipeadlvvgabqkyqvn6vjp7nhslea45a5yls6pnkmizfv4bbu2hxa5iruaaauhlp2na
code: 483920
```

A conforming parser yields the ticket and code shown for each input, and
prints the pairing string back as `ticket` or `ticket-code`, with no
whitespace.

## Refusals (normative)

Each input below must be refused with the verdict given.
`scripts/pairing_vectors.py --check` constructs each case, asserts its
verdict, and asserts that this table lists the same set. The inputs are in
[`pairing-vectors-v0.json`](pairing-vectors-v0.json).

| input | verdict |
|---|---|
| nothing but whitespace | `empty` |
| a separator with nothing after it | `code` |
| a code one digit short | `code` |
| a code one digit long | `code` |
| a code with a letter in it | `code` |
| a code in digits outside ASCII | `code` |
| a non-ASCII space after the code | `code` |
| a code and a ticket that are both wrong | `code` |
| two codes | `ticket-malformed` |
| whitespace inside the string | `ticket-malformed` |
| a code with no ticket before it | `ticket-malformed` |
| a ticket that is not one | `ticket-malformed` |
| a ticket from a format this build does not speak | `ticket-unsupported-version` |

This table pins the classification, not message text. A parser may attach
the ticket's own error to a ticket refusal, as the reference implementation
does.

## The redeem exchange (normative)

A code is spent with the machine the ticket names, through the pipe, in one
request the serve side's edge answers itself. The backend never sees it.

**Request.** `POST /modelpipe/pair`, with the code as the bearer:
`Authorization: Bearer 483920`. The body is optional. It is the device's own
label as UTF-8 text, at most 4096 bytes, framed by `Content-Length`. The
target is matched exactly, in origin form, so `/modelpipe/pair?x=1` is not
this route and goes through ordinary admission.

**Order.** The edge takes these steps in this order, and refuses at the first
that fails.

1. The method is `POST`.
2. The body is empty, or framed by a `Content-Length` of at most 4096.
3. The bearer is not a credential the listener already holds, and the
   connection's endpoint is not one a pinned token names. A device that has
   paired has no business here, and its key never counts against a code.
4. A client that asked with `Expect: 100-continue` is told to continue, and the
   whole body is read. The head and the body share one deadline of thirty
   seconds, and the body is UTF-8.
5. The bearer is a live, armed code, and this endpoint is not locked out of
   it.

**Refusal.** Every refusal, at every step, is the same response: status
`401 Unauthorized`, `WWW-Authenticate: Bearer`,
`Content-Type: application/json`, `Connection: close`, and the body
`{"error":{"message":"that pairing code was not accepted","code":"invalid_pairing_code"}}`.
What a client can tell apart is when a refusal comes. Steps 1 to 3 refuse
before any `100 Continue` and before the body is read, which says only whether
the client's own bearer is a key the listener holds, or its own endpoint is
pinned. Among the refusals at step 5, a wrong, unarmed, expired or spent code,
an endpoint locked out, and no invite live, nothing differs.

**Success.** Status `200 OK`, `Content-Type: application/json`,
`Cache-Control: no-store`, `Connection: close`, and the body
`{"api_key":"…","device_id":"…","peer":"…"}`. `api_key` is the device's
credential from then on, presented as its bearer. `device_id` is the name the
serve side holds it under, and `peer` is the serve side's endpoint id as
sixty-four hex characters. Every value is from an alphabet that needs no
escaping. The key is the device's secret, so nothing on either side logs it.

**The label** has control characters and invisible formatting characters
dropped: the bidirectional overrides and isolates, the zero-width characters,
the line and paragraph separators and the byte-order mark. It is then cut to
64 characters and trimmed, and an empty result is no label.

**Strikes.** A wrong code counts one strike against the endpoint that
presented it. An endpoint with as many strikes as an invite allows (three by
default, at most ten) is locked out of that invite, and its presentations of
that invite's code are refused without counting. A code whose invite is not
armed yet is a wrong code. A request with no bearer, and a bearer on any other
path, count nothing. The edge tracks 64 endpoints, and a wrong code from a
sixty-fifth ends every live invite. Strikes are forgotten whenever no invite
is live. An invite lives at most fifteen minutes.

**The odds.** With `k` invites live and `w` wrong codes allowed, a guesser who
mints a fresh endpoint whenever one is locked out finds a code before the
invites burn with a chance of about k(64w + 1)/10^6 per round: 0.019% for one
invite at the defaults, and 1 − (1 − p)^n over n rounds. Denying pairing costs
about 65 handshakes. An invite that burns is the sign that someone holding the
ticket is guessing, and retiring the serve side's identity, and with it the
ticket, is the remedy.
