# ADR 0005 — A state folder, and the endpoint key kept in it by default

- **Status:** Accepted
- **Date:** 2026-09-23
- **Binding on:** the CLI's identity and revocation story, and where `serve`
  keeps what survives a restart
- **Depends on:** [ADR 0002](0002-a-stored-endpoint-key-opt-in.md), whose
  file format and refusals this keeps
- **Supersedes:** the default ADR 0002 chose, and nothing else in it
- **Superseded by:** nothing

## Context

ADR 0002 made a stored endpoint key opt-in and wrote down what would flip
it: "if the ephemeral default turns out to be something people work around
rather than rely on — issues asking why pairing does not stick, README
examples in other projects that all pass `--identity`, questions that
assume it is the default — then it should be. The reading is the issue
tracker and any downstream that wraps `serve`."

The reading has been taken. The one downstream that embeds the library and
wraps its serve side — gglib's `remote enable` — keeps the endpoint key
always, keeps every paired device's key always, and re-arms both on a
restart with nothing typed; it went through an opt-in flag of its own and
removed it, because a pairing that did not stick was the thing its users
reported. The CLI's own pairing had the same shape and the worse version of
it: a device paired with `serve --named --invite` and no `--devices` was
forgotten when serve stopped, and a `--devices` file without `--identity`
kept the keys and lost the ticket they were paired against, so a restart
admitted the devices and none of them could find it. Five flags made it
work. Nobody who read only the quick start would have known which five.

The property ADR 0002 was protecting — that a restart revokes a leaked
ticket — was, in its own words, "a property nobody chose and most people
experience as the bug". What it wanted to avoid was a secret appearing on
disk in the release that first published the crate. That release has
shipped; the folder and its refusals below are the mitigation it asked for.

## Decision

1. **One folder per backend, under the platform's data directory.**
   `$XDG_DATA_HOME/modelpipe` when that is set and absolute, otherwise
   `~/.local/share/modelpipe`; on macOS `~/Library/Application
   Support/modelpipe`. Under it, a folder named by the backend's host and
   port, so two serves on one machine fronting two servers share nothing.
   In it: `identity`, in ADR 0002's format; `devices.json`, the record of
   every device invited; and `lock`. `--state-dir <DIR>` (or
   `MODELPIPE_STATE_DIR`) puts the root elsewhere; `--identity` and
   `--devices` each still name their own file, and win over the folder.

2. **The folder is private and singly held.** The two folders that are
   this program's are created `0700`, and a folder other users can read
   into is refused, as a readable identity file already was. A lock file,
   held for the life of the process, refuses a second `serve` on the same
   backend by name and pid: two listeners loading one key would serve one
   ticket from two places, which is the failure ADR 0002's create-once
   write exists to prevent, one layer up. The lock is `0600` beside them.

3. **On by default, on Unix, when there is something to keep.** A `serve`
   with neither flag keeps its state. Three cases keep nothing unless asked
   with `--state-dir` or `--identity`, and say so on stderr:
   - `--no-state`, which is the old behaviour by name;
   - `--insecure-no-auth`, because a ticket that is the only lock there is
     is a credential with no expiry and nothing behind it, and it has no
     business outliving a restart unasked;
   - a platform with no mode to set, which today means Windows, where the
     folder could not be made private and the refusal could not be checked.
   A `HOME` that is unset or empty is an error naming both flags, not a
   folder relative to the working directory: an identity inside a
   repository or a synced folder is the one place it must not land.

4. **An unredeemed invite stays on the record and is not held again.** The
   devices record keeps a row for every invite ever offered, marked with
   whether it was redeemed. What this machine offered is always visible;
   clearing the row is the person's act. Only a row that did pair is held
   when serve restarts, so a key nobody ever received admits nobody, and
   the key of an invite that expires, is withdrawn or is burned is taken
   back out of the running listener the moment it ends.

## Consequences

**Revocation is now two different acts, and the documents say which.**
Revoking one device is taking its row out of the devices record, and the
listener stops admitting it at the next start (a running serve will drop it
the moment the CLI can be told to; that is a later change). Revoking the
ticket itself is deleting the folder's `identity` file and restarting,
after which every device pairs again — exactly what restarting cost before,
plus one `rm`. `README.md`'s sentence "restarting is revocation" was true
and is now true only under `--no-state`, and it has been rewritten rather
than left for someone to read and stop reading.

**A secret is on disk by default.** Everything ADR 0002 said about backups,
sync clients and container images applies to everyone now, not only to
those who opted in. The mitigations are the folder's mode, the refusals,
and the fact that the data directory is where every other program on the
machine keeps the same kind of thing.

**Two serves on one backend on one machine no longer both start.** Before
this, they shared nothing and both came up; now the second is refused with
the first's pid. Two serves on *different* backends are unaffected, which
is why the folder is per backend rather than per user. `--state-dir` or
`--no-state` on one of them is the escape.

**A supervisor that starts `serve` with no `HOME` now gets an error where
it used to get a listener.** The error names the flags; the alternative,
a key file relative to whatever the working directory was, is worse than
a refusal.

**The integration tests never touch the real data directory.** Every run
either passes `--no-state` or is given a `HOME` under the temp directory,
and the harness clears `XDG_DATA_HOME` and `MODELPIPE_STATE_DIR` so a
developer's shell cannot move the folder out from under it.

## Change criteria

- **The lock refuses more than it protects.** If the second-serve refusal
  turns out to hit working setups — a supervisor restarting into a process
  that has not yet released the lock, say — the reading is issues about a
  serve that will not start while nothing else is running, and the answer
  is a wait with a deadline rather than a refusal.
- **Per-backend is the wrong grain.** If people run one backend behind two
  serves on purpose, with different tokens or relays, the folder needs a
  second key beside the backend's. Nothing suggests it yet.
- **The `--insecure-no-auth` exception is wrong.** If people serving open
  ask why pairing does not stick, the exception has cost more than the
  property it protects, and it goes. The reading is the issue tracker.
