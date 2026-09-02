# modelpipe

**Your model server, from anywhere. No VPN, no account, no cloud in the path.**

modelpipe makes local AI inference reachable from your other devices over an
end-to-end encrypted peer-to-peer connection, paired by a ticket. Neither
machine needs a public IP, an open port, a VPN profile, or an account with
anyone. It works with any OpenAI-compatible server.

```bash
# On the machine with the models
modelpipe serve http://127.0.0.1:11434
# → prints a pairing ticket (and a QR code), plus a bearer token

# On any other machine
modelpipe connect <ticket> --bind 127.0.0.1:8080
# → http://127.0.0.1:8080/v1 on this machine now *is* your model server
#   (omit --bind and it picks a free loopback port, printing the URL)
```

Point any OpenAI-compatible client at the printed URL, with the token from
the serve side as the API key. That's the whole product.

## Install

```bash
cargo install modelpipe-cli   # installs a binary named `modelpipe`
```

Embedding it instead? The library is `cargo add modelpipe`.

## How it works

modelpipe embeds [iroh](https://github.com/n0-computer/iroh), the Rust p2p
library ([1.0](https://www.iroh.computer/blog/the-road-to-iroh-1-0), and
production-proven well before that). Both machines dial *outward* to a
public relay, which introduces them; they then hole-punch a direct
encrypted QUIC connection — roughly 90% of connections go direct in
[iroh's published numbers](https://www.iroh.computer/docs/protocols/net/holepunching),
carrying ~95% of data volume. When hole-punching fails — strict corporate
or carrier-grade NAT — traffic falls back to the relay, which only ever
carries ciphertext. The encryption keys are the machines' identities; no
TLS certificates, no certificate authorities, no third party that can read
a byte.

## Auth is not optional

`modelpipe serve` generates a bearer token and validates
`Authorization: Bearer …` — in constant time — on every request **before**
a byte reaches your backend. Ollama has no built-in auth;
[researchers found ~175,000 Ollama hosts exposed raw to the internet](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html).
modelpipe in front of a naked backend gives it the API key it never
shipped. Running open requires an explicit flag whose name
(`--insecure-no-auth`) makes you feel bad typing it.

Two independent locks, and they travel separately: the **ticket** gates
who can connect at all, the **token** gates who can make requests. The
token is deliberately *not* inside the ticket — a leaked ticket alone
cannot make a request, and a leaked token alone cannot reach the listener.
Rotation is asymmetric on purpose: restarting the listener rotates the
ticket (and re-pairs everyone), while the token rotates in place with no
re-pairing (`ServeHandle::rotate_token`). Embedding modelpipe behind an
auth layer you already have? `serve` accepts a supplied token
(`TokenPolicy::Supplied`) so your existing API key is enforced at the
tunnel edge too — one credential, checked before a byte reaches the
backend, rotated on your schedule (`ServeHandle::set_token`). One honest caveat for v0: a
ticket has no expiry and no revocation list, so a leaked ticket can reach
the listener until the serve process restarts. Treat tickets like keys,
not like invitations.

The backend itself must be local: loopback always, private (RFC 1918 /
ULA) ranges only behind an explicit `--allow-private-backend`, link-local
ranges — where cloud instance metadata lives — never, whatever that flag
says. The check runs against resolved addresses, not URL text, so a DNS
name can't smuggle an address past it. modelpipe extends trust outward
from your machine; it does not re-export someone else's server.

## Ticket format (v0 — draft)

A ticket is a base32 string carrying a version, the serve side's endpoint
id, a set of transport addresses, and a backend hint. The bearer token is
**not** in it — it travels separately, which is what makes it a second
lock.

The field-by-field layout deliberately does not appear here. It lives in
one place, [docs/ticket-format-v0.md](docs/ticket-format-v0.md), with
normative test vectors, a refusal taxonomy, and an executable reference
implementation that CI checks the page against — a copy in this README
would be a third description of the same bytes with nothing keeping it
honest. Why the bytes are hand-specified rather than serialized from
iroh's own types is
[ADR 0001](docs/adr/0001-an-explicit-ticket-byte-layout.md).

The short version: the string form follows
[iroh-tickets](https://crates.io/crates/iroh-tickets)' conventions — a
lowercase `pipe` prefix, then base32-nopad — with one addition for QR
codes: parsers accept the whole string case-insensitively, so a display
layer can upcase a ticket into QR alphanumeric mode without breaking the
round-trip. The bytes are an explicit, language-neutral layout with a
CRC-32C transcription check, and every address body is length-prefixed so
a client that meets a transport it does not know skips it rather than
failing. A non-Rust client — mobile apps via iroh's
official Swift/Kotlin bindings are the obvious case — implements from
that one page alone; if you're building one and the page leaves you a
question, that's a spec bug: open an issue.

## Non-goals (v0)

- Multiple backends per ticket, named endpoints, routing — one pipe, one
  backend.
- A daemon, config files, a UI, accounts, hosted relays (iroh's public
  relays are the default; `--relay` if you run your own).
- Browser support (browsers can't hole-punch; a relay-only WASM client is
  possible but out of scope here).
- Model management of any kind. modelpipe moves requests; it has no opinion
  about what serves them.

## Relationship to gglib

modelpipe was extracted from (and is consumed by)
[gglib](https://github.com/mmogr/gglib)'s `gglib remote` feature. gglib is
the reliability layer for llama.cpp — tool-call repair, loop defense,
sampling authority; modelpipe is the transport that makes any such endpoint
reachable. gglib is AGPL-3.0; both projects have the same author and
copyright holder, and this extraction is relicensed MIT by that copyright
holder specifically so clients and other servers can embed it. gglib's
licensing does not apply here.

## Status

Pre-implementation. The API sketch in `modelpipe/src/lib.rs` and this README
are the contract under review; implementation follows a two-week dogfooding
gate of the manual dumbpipe equivalent. Issues and opinions welcome.
