# Security

## Reporting

Report a vulnerability privately through GitHub's [security advisory
form](https://github.com/mmogr/modelpipe/security/advisories/new). Please do
not open a public issue for anything exploitable.

This is a one-person project. You will get an acknowledgement within a few
days; a fix depends on what it is.

## What modelpipe defends

**The backend gets an API key it never shipped.** Every request is checked
against a bearer token, in constant time, before a byte reaches your server.
Ollama and llama-server have no built-in authentication; modelpipe in front
of one is the credential it was missing.

**Two independent locks, travelling separately.** The ticket gates who can
connect at all; the token gates who can make requests. The token is
deliberately not inside the ticket, so a leaked ticket alone cannot make a
request and a leaked token alone cannot reach the listener.

**The backend must be local.** Loopback always, private ranges only behind
an explicit flag, link-local — where cloud instance metadata lives — never,
whatever that flag says. The check runs against the *resolved* address of
every outbound connection, and resolution and connection are one operation,
so a DNS name cannot smuggle an address past it.

**The transport is end-to-end encrypted** and authenticated by the machines'
own keys. A relay carries ciphertext it cannot read.

**Requests that are ambiguous are refused, not resolved.** A message
carrying both `Content-Length` and `Transfer-Encoding` is rejected rather
than interpreted, because interpreting it correctly is what makes a proxy
exploitable — the next hop resolves the same ambiguity the other way.

## What modelpipe does not defend against

Stated plainly, because each of these surprises somebody.

**The token is equivalent to full access to your backend.** modelpipe is a
tunnel, not a policy layer: it forwards every path. On Ollama that includes
`/api/pull` and `/api/delete`. Anyone holding the token can do anything your
backend allows, not merely run inference. This inverts the usual framing of
"put a key in front of it" — the key is total.

**A leaked ticket has no expiry and no revocation list.** It works until the
serve process restarts, and restarting is the only revocation. Treat tickets
like keys, not like invitations. (The token, separately, rotates in place
without re-pairing.)

**A malicious connect side.** Anyone you give a ticket and token to has the
access above. There is no per-client scoping, quota or audit.

**A compromised backend.** modelpipe forwards what your server says. If it
is compromised, modelpipe faithfully delivers whatever it returns.

**Relay metadata.** Hole-punching fails under some NATs and traffic then
falls back to a relay. The relay cannot read your data, but a relay operator
sees endpoint identities, both IP addresses, timing and volume.
*Observability is not readability, and it is not nothing.*

**What the default configuration contacts before any client connects.** With
default settings, iroh publishes address records to n0's discovery service
and may solicit a UPnP/NAT-PMP port mapping on your LAN. "No cloud in the
path" is a claim about your data — which is true — not a claim that nothing
is contacted. Use `--relay` to run your own relay.

**Anything reachable from the local port on the connect side.** That port is
the one hop with no encryption in front of it. It binds to loopback by
default; binding it elsewhere exposes the pipe to anyone who can reach it,
and the CLI warns when you do.

**Denial of service.** There are bounds on what an unauthenticated
ticket-holder can cost — a maximum head size, a per-peer concurrent stream
cap, and a timeout on sending a request head — but no rate limiting, no
per-client quota, and deliberately no request body limit, because a
legitimate vision payload is megabytes.

## Cryptography

None of it is ours. The transport is iroh's QUIC with TLS 1.3; the bearer
comparison is `subtle`; tokens are 256 bits from the operating system's
CSPRNG. The ticket carries a CRC-32C, which guards transcription and QR
scans and is **not** a signature — anyone who can modify a ticket in transit
can replace it wholesale. The security is the endpoint key and the
out-of-band token.

## Status

modelpipe has not been audited. It is early software whose security claims
are tested but not externally reviewed, and the honest summary is that it
raises the floor for a backend that had no authentication at all rather than
being a hardened perimeter.
