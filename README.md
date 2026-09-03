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
re-pairing (`ServeHandle::rotate_token`). If re-pairing every device on
every reboot is the wrong trade for you, `--identity <file>` stores the
endpoint key so the ticket survives a restart — and revocation becomes
deleting that file. The trade is real in both directions and is spelled out
in [ADR 0002](docs/adr/0002-a-stored-endpoint-key-opt-in.md).

**A durable ticket is not automatically a reachable one**, and it is worth
knowing before you rely on "pair once". The stored key fixes the *name* in
the ticket; the addresses beside it are a snapshot, and a restarted process
holds a different UDP port. Resolving that name to the new address is
discovery's job — n0's by default, which is the same service the disclosure
below is about — so `--identity` and that disclosure are one subject seen
from two directions, and switching off the part modelpipe does not control
takes the part it does with it. Measured on a host with n0's DNS blocked: a
listener restarted with the same identity minted the identical ticket, a
*fresh* ticket from it paired and served, and the old one could not reach
it at all. Already have an API key you want
enforced instead of a generated one? Give `serve` yours — `--token-file
<path>`, or the `MODELPIPE_TOKEN` environment variable, or `--token` if you
do not mind it in your shell history and in `ps`. An exported-but-empty
`MODELPIPE_TOKEN` is refused rather than enforced, because a listener
quietly demanding `Bearer ` and 401ing everything is worse than one that
will not start. Embedders reach the same thing as
`TokenPolicy::Supplied`, rotated on your schedule with
`ServeHandle::set_token`. One honest caveat for v0: a
ticket has no expiry and no revocation list, so a leaked ticket can reach
the listener until the serve process restarts. Treat tickets like keys,
not like invitations.

The backend itself must be local: loopback always, private (RFC 1918 /
ULA) ranges only behind an explicit `--allow-private-backend`, link-local
ranges — where cloud instance metadata lives — never, whatever that flag
says. The check runs against resolved addresses, not URL text, so a DNS
name can't smuggle an address past it. modelpipe extends trust outward
from your machine; it does not re-export someone else's server.

## Every flag

`modelpipe serve <BACKEND_URL>` — host and port only; the request path comes
from the client.

| Flag | What it does |
|---|---|
| `--token <T>` | Enforce this token instead of generating one. Also read from `MODELPIPE_TOKEN`; `--help` never prints the value. Visible in `ps` and shell history, so prefer the other two. |
| `--token-file <PATH>` | Read the token from a file, trimming the trailing newline every editor adds. |
| `--insecure-no-auth` | Serve with no token at all. The name is the warning. |
| `--identity <FILE>` | Keep the endpoint key here so the ticket survives a restart. Created `0600`; refuses to start if others can read it. |
| `--allow-private-backend` | Accept a backend on a private (RFC 1918 / ULA) address, not only loopback. Link-local is never accepted. |
| `--relay <URL>` | Use your own relay instead of the public ones. Does **not** disable discovery — see below. |
| `--no-qr` | Do not print the QR code beside the ticket. |

`modelpipe connect <TICKET>`

| Flag | What it does |
|---|---|
| `--bind <ADDR>` | Local address to listen on. Defaults to a free loopback port. Binding off loopback exposes the one hop with no encryption in front of it, and warns you. |

Both commands

| Flag | What it does |
|---|---|
| `-v`, `-vv`, `-vvv` | Print more about what the pipe is doing. See below. Accepted before or after the subcommand. |
| `--version` | Print the version. |
| `--help` | Print help. |

## Ticket format (v0)

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

## Seeing what it is doing

`-v` prints a line per request on the serve side: the method, the path, the
status your backend gave, and how long it took. Once more (`-vv`) adds the
transport, which is where the answer lives when two machines will not pair.

```
$ modelpipe serve http://127.0.0.1:11434 -v
ticket: pipeaabjlod6a2h5g6lxw53tnnw7727qadq7iultzkz2xgd76bffp7r7uaibaadmaaacalemwagwxdija
token:  L3TY477IP3LQNAJDNJDC2KHVQTWIE66ZNT3WJFL3ONUEBQUMIRFA
status: direct
2026-09-03T05:32:54.574788Z  INFO peer{peer=3ca82708b995 path="direct"}: peer connected
2026-09-03T05:32:59.580759Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="GET" path="/v1/models" status=200}: exchange outcome="forwarded" elapsed_ms=1
2026-09-03T05:32:59.588755Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="POST" path="/v1/chat/completions" status=200}: exchange outcome="forwarded" elapsed_ms=0
```

The first two lines are stdout; everything after them is stderr, which is
what lets `modelpipe serve … | head -1` still give you just the ticket. Pass
`-vv` and each line also names the crate it came from, because from there
on iroh's lines are mixed in with modelpipe's.

Without any `-v` you still hear about warnings, which is mostly an exchange
that failed partway through — a backend that stopped mid-response, or a
client that vanished.

No line ever carries your token, your ticket, a header value, or a query
string — the path is logged without its query precisely because a query
string is somewhere clients put credentials. `RUST_LOG` replaces the flag
entirely if you want to choose targets and levels yourself, and turns the
crate-name column on while it is set.

Embedding the library instead? It emits [`tracing`](https://docs.rs/tracing)
events and installs no subscriber, so the events go wherever your binary
already sends them, and nowhere if it sends them nowhere.

## What it contacts, and what it doesn't

"No cloud in the path" is a claim about your **data**, and it is true: the
relay carries ciphertext it cannot read, and most connections do not touch a
relay at all. It is not a claim that nothing is contacted. With default
settings iroh publishes address records to n0's discovery service and may
ask your router for a UPnP/NAT-PMP mapping, both before any client connects.

`--relay` does **not** turn either of those off, and v0 has no switch that
does. It replaces the relay and nothing else: discovery still publishes to
and resolves from n0's DNS, and the port-mapping attempt still happens. It
is also a `serve`-side flag only — the connect side always uses the public
relays and the public discovery service. If contacting n0 at all is the
thing you need to avoid, v0 is not yet the tool for it; that is an honest
gap rather than a setting you have missed.

A relay operator, when one is used, sees endpoint identities, both IP
addresses, timing and volume. Observability is not readability — and it is
not nothing. [`SECURITY.md`](SECURITY.md) says what else modelpipe does and
does not defend against, including the one most people miss: the token is
equivalent to full access to your backend, `/api/pull` included.

## Status

**0.1.0: the commands above work.** A request crosses the pipe, the bearer
check runs before a byte reaches your backend, streaming arrives as it is
produced, and a client that hangs up takes the backend's work with it.

Early, and honestly so. It has not been dogfooded across real networks for
long, it has not been audited, and the ticket format — though specified,
vectored and CI-checked — has no second implementation yet. The API is `0.x`
and will move if using it teaches us something. Issues and opinions welcome;
if you are building a non-Rust client and
[the spec](docs/ticket-format-v0.md) leaves you a question, that is a spec
bug.
