# modelpipe

**Your model server, from anywhere. No VPN, no account, no cloud in the path.**

modelpipe makes a local AI inference server reachable from your other
devices over an end-to-end encrypted peer-to-peer connection, paired by a
ticket. Neither machine needs a public IP, an open port, a VPN profile, or
an account with anyone. It works with any OpenAI-compatible server.

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

Embedding it instead? `cargo add modelpipe`.

## How it works

It's [iroh](https://github.com/n0-computer/iroh). Both machines dial *out*
to a public relay, which introduces them; then they hole-punch a direct,
encrypted QUIC connection to each other. When the punch fails — some
corporate and carrier-grade NATs — traffic goes through the relay instead,
which only ever sees ciphertext. The machines' keys are their identities,
so there are no certificates, no certificate authorities, and nobody in the
middle who can read a byte.

## Auth is not optional

`serve` generates a bearer token and checks `Authorization: Bearer …`, in
constant time, before a byte of any request reaches your backend. Ollama has
no auth of its own
([and it shows](https://thehackernews.com/2026/01/researchers-find-175000-publicly.html));
modelpipe in front of it is the API key it never had. Running open takes a
flag called `--insecure-no-auth`, and the name is the warning.

There are two locks, and they travel separately. The **ticket** gets you to
the listener; the **token** gets a request through it. The token is not
inside the ticket, so a leaked ticket alone cannot make a request and a
leaked token alone cannot find the listener. Restarting the listener rotates
the ticket and re-pairs every device; the token rotates in place
(`ServeHandle::rotate_token`).

If re-pairing on every reboot is the wrong trade for you, `--identity
<file>` keeps the endpoint key so the ticket survives a restart, and
revoking it becomes deleting the file. One catch, worth knowing before you
rely on "pair once": the stored key keeps the *name* in the ticket, but the
addresses beside it still go stale, and finding the new ones is n0's
discovery service's job — the same service the section on what modelpipe
contacts is about. Measured with n0's DNS blocked: a restarted listener
minted the identical ticket, a fresh ticket from it paired and served, and
the old one could not reach it at all. The trade in both directions is
[ADR 0002](docs/adr/0002-a-stored-endpoint-key-opt-in.md).

Already have a key? `--token-file` and friends are in the table below;
embedders use `TokenPolicy::Supplied` and `ServeHandle::set_token`. One v0
caveat: tickets have no expiry and no revocation list, so treat them like
keys, not like invitations.

The backend has to be local: loopback always, private (RFC 1918 / ULA)
ranges only behind `--allow-private-backend`, and link-local — where cloud
instance metadata lives — never. The check runs on resolved addresses, not
URL text, so a DNS name can't smuggle one past it. modelpipe extends trust
outward from your machine; it does not re-export someone else's server.

## Every flag

`modelpipe serve <BACKEND_URL>` — host and port only; the request path
comes from the client.

| Flag | What it does |
|---|---|
| `--token <T>` | Enforce this token instead of generating one. Also read from `MODELPIPE_TOKEN` (exported but empty is refused, not enforced); `--help` never prints the value. Visible in `ps` and shell history, so prefer the next one. |
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

A ticket is `pipe` followed by base32: a version, the serve side's endpoint
id, its addresses, and a backend hint. The token is not in it. Parsers
accept the whole string case-insensitively, so a QR code can upcase it
into alphanumeric mode and it still round-trips. The byte layout lives in
one place, [docs/ticket-format-v0.md](docs/ticket-format-v0.md), with test
vectors and a reference implementation that CI checks the page against, so
a client in another language — iroh has Swift and Kotlin bindings — can be
written from that page alone. If the page leaves you a question, that's a
spec bug: open an issue. Why the bytes are spelled out by hand rather than
serialized from iroh's types is
[ADR 0001](docs/adr/0001-an-explicit-ticket-byte-layout.md).

## Non-goals (v0)

- Multiple backends per ticket, named endpoints, routing. One pipe, one
  backend.
- A daemon, config files, a UI, accounts, hosted relays.
- Browser support. Browsers can't hole-punch.
- Model management of any kind. modelpipe moves requests; it has no opinion
  about what serves them.

## Relationship to gglib

modelpipe was extracted from [gglib](https://github.com/mmogr/gglib) to
become the transport behind its `gglib remote` feature. gglib is AGPL-3.0;
both projects have the same author and copyright holder, and this
extraction is relicensed MIT by that holder so that clients and other
servers can embed it. gglib's licensing does not apply here.

## Seeing what it is doing

`-v` prints a line per request on the serve side: the method, the path, the
status your backend gave, and how long it took. `-vv` adds the transport,
which is where the answer usually is when two machines will not pair.

```
$ modelpipe serve http://127.0.0.1:11434 -v
ticket: pipeaabjlod6a2h5g6lxw53tnnw7727qadq7iultzkz2xgd76bffp7r7uaibaadmaaacalemwagwxdija
token:  L3TY477IP3LQNAJDNJDC2KHVQTWIE66ZNT3WJFL3ONUEBQUMIRFA
status: direct
2026-09-03T05:32:54.574788Z  INFO peer{peer=3ca82708b995 path="direct"}: peer connected
2026-09-03T05:32:59.580759Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="GET" path="/v1/models" status=200}: exchange outcome="forwarded" elapsed_ms=1
2026-09-03T05:32:59.588755Z  INFO peer{peer=3ca82708b995 path="direct"}:exchange{method="POST" path="/v1/chat/completions" status=200}: exchange outcome="forwarded" elapsed_ms=0
```

The first two lines are stdout and everything after them is stderr, so
`modelpipe serve … | head -1` still gives you just the ticket. Without any
`-v` you still hear about warnings, which is mostly an exchange that failed
partway: a backend that stopped mid-response, or a client that vanished.

No line ever carries your token, your ticket, a header value, or a query
string — the path is logged without its query precisely because a query
string is somewhere clients put credentials. `RUST_LOG` replaces the flag
entirely if you want to pick targets and levels yourself.

Embedding the library instead? It emits [`tracing`](https://docs.rs/tracing)
events and installs no subscriber, so they go wherever your binary already
sends them, and nowhere if it sends them nowhere.

## What it contacts, and what it doesn't

"No cloud in the path" is a claim about your **data**, and it holds: the
relay carries ciphertext it cannot read, and most connections do not touch
a relay at all. It is not a claim that nothing is contacted. With default
settings iroh publishes address records to n0's discovery service and may
ask your router for a UPnP/NAT-PMP mapping, both before any client connects.

`--relay` turns off neither. It replaces the relay and nothing else:
discovery still publishes to and resolves from n0's DNS, the port-mapping
attempt still happens, and it is a `serve`-side flag — the connect side
always uses the public relays and the public discovery service. If
contacting n0 at all is what you need to avoid, v0 is not yet the tool for
it. That is a gap, not a setting you have missed.

A relay operator, when one is used, sees endpoint identities, both IP
addresses, timing and volume. Observability is not readability, and it is
not nothing. [`SECURITY.md`](SECURITY.md) says what else modelpipe does and
does not defend against, including the one most people miss: the token is
full access to your backend, `/api/pull` included.

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
