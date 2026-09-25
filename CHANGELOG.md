# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1](https://github.com/mmogr/modelpipe/compare/v0.8.0...v0.8.1) - 2026-09-25

### Fixed

- *(cli)* modelpipe ollama takes --allow-private-backend, and a backend refused as not local names it ([#138](https://github.com/mmogr/modelpipe/pull/138))
- *(cli)* serve and connect keep running when whatever reads their stdout has gone ([#137](https://github.com/mmogr/modelpipe/pull/137))
- *(body)* a chunk-size line carrying a bare CR or LF is refused, and shutdown's docs say what can hold the drain ([#136](https://github.com/mmogr/modelpipe/pull/136))
- *(identity)* a key or devices path that is not a regular file is refused before it is read ([#135](https://github.com/mmogr/modelpipe/pull/135))
- *(cli)* an invite whose devices record cannot be written leaves no key held ([#127](https://github.com/mmogr/modelpipe/pull/127))

## [0.8.0](https://github.com/mmogr/modelpipe/compare/v0.7.0...v0.8.0) - 2026-09-24

### Added

- *(cli)* add modelpipe ollama ([#126](https://github.com/mmogr/modelpipe/pull/126))
- *(cli)* invite, list and forget devices from the serve window ([#125](https://github.com/mmogr/modelpipe/pull/125))
- *(cli)* [**breaking**] keep serve's identity and devices across restarts by default ([#124](https://github.com/mmogr/modelpipe/pull/124))
- *(cli)* record paired devices in devices.json ([#123](https://github.com/mmogr/modelpipe/pull/123))
- *(cli)* keep serve's state in one private folder with --state-dir ([#122](https://github.com/mmogr/modelpipe/pull/122))

### Fixed

- *(cli)* take an unredeemed invite's key back out of the listener ([#114](https://github.com/mmogr/modelpipe/pull/114))

### Other

- *(cli)* move the serve flow out of main ([#121](https://github.com/mmogr/modelpipe/pull/121))

## [0.7.0](https://github.com/mmogr/modelpipe/compare/v0.6.0...v0.7.0) - 2026-09-22

### Added

- *(connect)* how long a pipe has been idle, and a nudge while it is ([#110](https://github.com/mmogr/modelpipe/pull/110))
- *(serve)* [**breaking**] the backend carries its own permission to be dialled ([#107](https://github.com/mmogr/modelpipe/pull/107))
- *(pair)* [**breaking**] a pairing answer's unexpected status is a number, not a sentence ([#106](https://github.com/mmogr/modelpipe/pull/106))

### Fixed

- *(identity)* the endpoint key is written atomically, and an empty one says so ([#105](https://github.com/mmogr/modelpipe/pull/105))

### Other

- *(release)* the version is 0.7.0-rc.1 ([#111](https://github.com/mmogr/modelpipe/pull/111))

## [0.6.0](https://github.com/mmogr/modelpipe/compare/v0.5.0...v0.6.0) - 2026-09-14

### Added

- *(serve)* a peer's view names its whole endpoint id
- *(cli)* a device pairs from the command line
- *(connect)* a device pairs in one call
- *(serve)* an invite is answered at the edge
- *(serve)* a named token can be pinned to one endpoint
- *(serve)* a serve handle says why its listener closed
- *(connect)* a connect handle can wait until it has reached the serve side
- *(connect)* a connect side can keep its key, and says who it connects as
- *(serve)* the listener's peer and connection caps are options
- *(listener)* the listener bounds how many connections and how many peers it carries
- *(pairing)* a pairing string has a spec, vectors and a type

### Fixed

- *(serve)* a client that hangs up is not a warning
- *(body)* a trailer whose name this edge cannot read is dropped, as the comment always said
- *(body)* the chunk size is trimmed of spaces and tabs only, as a content length is
- *(http-head)* a folded header line is refused, and the parser is told so explicitly
- *(http-head)* a request carrying two authorization headers is refused instead of half-read

### Other

- *(pipe)* the integration tests leave discovery and port mapping off
- *(errors)* the codes the edge writes are published as data
- *(serve)* [**breaking**] one-time grants are gone

## [0.5.0](https://github.com/mmogr/modelpipe/compare/v0.4.0...v0.5.0) - 2026-09-10

### Added

- *(serve)* the edge presents the backend's own bearer in the device's place ([#64](https://github.com/mmogr/modelpipe/pull/64))
- *(credential)* a token per paired device, added and removed by name
- *(credential)* a grant burns where the guesses arrive ([#62](https://github.com/mmogr/modelpipe/pull/62))
- *(ticket)* the vectors a client builds against are machine-readable ([#60](https://github.com/mmogr/modelpipe/pull/60))

## [0.4.0](https://github.com/mmogr/modelpipe/compare/v0.3.0...v0.4.0) - 2026-09-07

### Added

- *(serve)* a rotated key honours the one it replaced, briefly ([#56](https://github.com/mmogr/modelpipe/pull/56))
- *(cli)* the CLI says when the relay is rate limiting this endpoint ([#55](https://github.com/mmogr/modelpipe/pull/55))
- *(api)* the accessors an embedder needs ([#51](https://github.com/mmogr/modelpipe/pull/51))
- *(peer)* the path a live connection takes is followed, not sampled once ([#50](https://github.com/mmogr/modelpipe/pull/50))

### Fixed

- *(cli)* a ticket that names nowhere is refused rather than printed ([#53](https://github.com/mmogr/modelpipe/pull/53))

## [0.3.0](https://github.com/mmogr/modelpipe/compare/v0.2.0...v0.3.0) - 2026-09-06

Cut at `4cf01ee`. #50 and #51 merged after that commit and are **not** in the
published crate — they ship in 0.4.0.

### Added

- *(status)* say why a pipe closed, not only that it did ([#47](https://github.com/mmogr/modelpipe/pull/47))
- *(connect)* return with the listener up and dial behind the handle ([#46](https://github.com/mmogr/modelpipe/pull/46))

### Fixed

- *(connect)* close the endpoint, so the far side is told rather than left to time out ([#49](https://github.com/mmogr/modelpipe/pull/49))

## [0.2.0](https://github.com/mmogr/modelpipe/compare/v0.1.0...v0.2.0) - 2026-09-06

### Added

- *(ticket)* a serde feature for the ticket and the two status types ([#42](https://github.com/mmogr/modelpipe/pull/42))
- *(status)* name each connected peer and its path ([#40](https://github.com/mmogr/modelpipe/pull/40))
- *(net)* a switch for each thing the endpoint contacts ([#39](https://github.com/mmogr/modelpipe/pull/39))
- *(edge)* tell the backend a request came through the tunnel, and from whom ([#38](https://github.com/mmogr/modelpipe/pull/38))
- *(serve)* admit one request with a short-lived grant ([#37](https://github.com/mmogr/modelpipe/pull/37))
- *(serve)* CLI quick fixes, signal handling, and ticket timing ([#36](https://github.com/mmogr/modelpipe/pull/36))

### Fixed

- *(listener)* the stream cap is per peer, as the docs said ([#43](https://github.com/mmogr/modelpipe/pull/43))

### Other

- *(readme)* Link the published crates from the top of the page ([#34](https://github.com/mmogr/modelpipe/pull/34))

## [0.1.0](https://github.com/mmogr/modelpipe/releases/tag/v0.1.0) - 2026-09-03

### Other

- *(readme)* Explain how to use it before explaining how it works ([#32](https://github.com/mmogr/modelpipe/pull/32))
- *(readme)* Say the same things in fewer words ([#29](https://github.com/mmogr/modelpipe/pull/29))
- *(edge)* Pin which 502 the connect side writes, and put two comments back on their code ([#28](https://github.com/mmogr/modelpipe/pull/28))
- Make every claim in the tree true, and add the examples that had none ([#26](https://github.com/mmogr/modelpipe/pull/26))
- Answer six requests the way HTTP says they should be answered ([#25](https://github.com/mmogr/modelpipe/pull/25))
- Say what the pipe is doing, without saying what it carries ([#24](https://github.com/mmogr/modelpipe/pull/24))
- Let a listener keep its identity, so a ticket can outlive the process ([#19](https://github.com/mmogr/modelpipe/pull/19))
- Look for the peer again when it goes, and say so while it is gone ([#18](https://github.com/mmogr/modelpipe/pull/18))
- Report a rotation this listener refused, rather than swallowing it ([#17](https://github.com/mmogr/modelpipe/pull/17))
- Answer a request body that stops short, rather than waiting on it ([#16](https://github.com/mmogr/modelpipe/pull/16))
- Bound what a leaked ticket costs, and finish the CLI ([#13](https://github.com/mmogr/modelpipe/pull/13))
- Fix the defects an adversarial review of the stack turned up ([#14](https://github.com/mmogr/modelpipe/pull/14))
- Move the first byte end to end
- Bind the iroh endpoint and share the handles' lifecycle
- Implement the authentication edge
- Implement the backend locality rule and the header edge
- Implement the ticket codec against the normative vectors
- Pin the ticket wire format, with every address body length-prefixed
- Split lib.rs into a composition root and private modules
- Correct the API contract before it is split across modules
- Fold the gglib compile-spike findings into the API sketch ([#4](https://github.com/mmogr/modelpipe/pull/4))
- Let serve enforce a caller-supplied bearer token ([#3](https://github.com/mmogr/modelpipe/pull/3))
- first commit
