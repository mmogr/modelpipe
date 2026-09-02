# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1](https://github.com/mmogr/modelpipe/releases/tag/v0.0.1) - 2026-09-02

### Other

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
