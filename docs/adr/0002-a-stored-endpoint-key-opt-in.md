# ADR 0002 — A stored endpoint key, opt-in rather than on by default

- **Status:** Accepted
- **Date:** 2026-09-03
- **Binding on:** the serve side's identity and revocation story
- **Depends on:** nothing
- **Supersedes:** nothing
- **Superseded by:** nothing

`Binding on` says what overturning this costs. Flipping the default later is
a minor version and a paragraph in `SECURITY.md`; it is cheap in code and
expensive in trust, because it changes what "restarting revokes a leaked
ticket" means for people who read that sentence and stopped reading. The
file format is the part that is genuinely awkward to reverse — an identity
already on disk has to keep working — and that is why it is written down
below rather than left to whatever `store` happened to emit.

## Context

An endpoint's secret key is its name on the network. The public half is what
a ticket carries and what a connecting peer dials, and until now the key was
generated fresh per process.

That has one good consequence and one bad one, and they are the same
consequence. A restart mints a new key, so every ticket ever handed out
names a peer nobody is — which `SECURITY.md` describes as the revocation
mechanism ("restarting is the only revocation") and which a user with a
desktop and a laptop experiences as re-pairing after every reboot.

Measured on the shipped behaviour: a serve side killed and restarted leaves
its paired connect side dialling an endpoint that no longer exists, for
ever. [ADR 0001](0001-an-explicit-ticket-byte-layout.md) is about what a
ticket *says*; this is about how long what it says stays true.

The reconnection work that landed alongside this makes a connect side
survive a network drop, a sleep and a change of address, because iroh
resolves the endpoint id through discovery. It cannot make it survive a
restart, and no amount of retrying will: the peer being dialled is not a
peer that is temporarily away, it is a peer that never existed.

## Decision

**The key may be stored, and by default it is not.** `ServeOptions::identity`
and `--identity <file>` name a file; absent, the behaviour is exactly what
it was.

**The stored form is base32 of the thirty-two key bytes, lower-case, one
line, trailing newline.** Read case-insensitively and whitespace-trimmed.
Text rather than raw bytes so it survives an editor, a copy-paste and a
config-management tool that assumes UTF-8; base32 rather than hex or base64
for the reason the bearer token uses it — no character a person can confuse
reading it off a screen, and nothing a shell wants to quote.

**The file is created readable only by its owner, and a key others can read
is refused.** Created with mode `0600` at open time rather than tightened
afterwards, because a key that was briefly world-readable is a key that
leaked. On start-up a file with any group or other bits set stops the
listener with a message naming `chmod`. This is the check `ssh` makes, for
the reason `ssh` makes it.

**Absent, the file is minted rather than demanded.** A first run creates it;
every run after reads it back. Requiring a separate generate step would be a
second command whose only purpose is to make the first one work.

**It is loaded before the backend and before the socket**, joining the
ordering `serve` already states: everything the operator typed is checked
before anything is opened, so a bad path is reported as a bad path rather
than as a listener that came up with a ticket nobody expected.

## Why not on by default

It is the better default and it is the wrong one to *ship first*.

Persisting does not weaken revocation, and it is worth being exact because
the intuition says otherwise. Today a leaked ticket is killed by restarting,
which re-pairs every device. With a stored key it is killed by deleting the
file and restarting, which re-pairs every device. The same action, the same
cost, one extra `rm`. What persistence removes is revocation *by accident* —
a reboot silently invalidating a ticket — which is a property nobody chose
and most people experience as the bug.

What it genuinely adds is a secret on disk. There was nothing to steal
before and now there is: backups, sync clients, a shared home directory, a
container image built from a working tree. The `0600` creation and the
start-up refusal are the mitigations, and neither exists on Windows, where
there is no mode to set or inspect and the file lands with whatever the
directory grants.

That is a real change in the shape of the attack surface, in the release
that first publishes this crate to anybody. Shipping it opt-in means the
capability is available on day one to whoever wants it, the security
documents stay true as written for everyone who does not, and the default
flips — if it flips — on evidence rather than on the author's guess.

The alternative rejected alongside it was a `--rotate-identity` flag. It
would do exactly what `rm` does, and a flag whose entire behaviour is a file
deletion is surface without capability; the documentation says `rm` instead.

## What this costs an operator

**Good:** pair once. A desktop that reboots, a laptop that sleeps, a network
that changes — the ticket on the laptop keeps working, with no QR to
re-scan and no client config to edit.

**Costs, accepted:** a file to keep, back up carefully or not at all, and
delete when a ticket leaks. On Windows, a file this crate cannot make
private for you.

**Stated plainly, because it surprises people:** the ticket surviving a
restart is exactly the same thing as a *leaked* ticket surviving a restart.
The convenience and the exposure are one property, not two, and the flag
buys both.

**And a durable ticket is not automatically a reachable one.** The key fixes
the name in the ticket; the addresses beside it are a snapshot, and a
restarted process holds a different UDP port. Resolving the name to the new
address is discovery's job — n0's by default, as `README.md` discloses — so
this flag and that disclosure are the same subject seen twice. Measured on a
host with n0's DNS blocked: the restarted listener minted the identical
ticket, a fresh ticket from it served fine, and the old one could not reach
it. Nothing was wrong with the key, and nothing here can substitute for
discovery.

## Change criteria

- **The default is wrong.** If the ephemeral default turns out to be
  something people work around rather than rely on — issues asking why
  pairing does not stick, README examples in other projects that all pass
  `--identity`, questions that assume it is the default — then it should be.
  The reading is the issue tracker and any downstream that wraps `serve`.
- **The refusal is a nuisance rather than a guard.** If the permission check
  turns out to reject more working setups than leaking ones — shared
  deployment directories, images built with a broad umask — it should warn
  rather than refuse. The reading is issues about a listener that will not
  start, weighed against the fact that a warning nobody sees is not a guard.
- **The format needs to change.** It will not: thirty-two bytes have no
  version, no options and nothing to extend. If it somehow does, the file is
  on the operator's disk and cannot simply be re-emitted — a new form has to
  read the old one, which is the one genuinely awkward reversal here.

Neither of the first two readings can be taken yet — the flag has existed
for one commit — and both are recorded now so the question is settled by a
reading later rather than by memory.
