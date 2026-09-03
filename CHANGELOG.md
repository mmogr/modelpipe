# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
