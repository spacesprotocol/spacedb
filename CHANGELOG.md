# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4](https://github.com/spacesprotocol/spacedb/compare/v0.1.3...v0.1.4) - 2026-08-04

### Bug Fixes

- *(subtree)* Honest error semantics for delete and merge
- *(path)* Out-of-bounds read in unaligned split_point comparison
- *(subtree)* Trim non-subtree keys from both ends in SubTree::prove

## [0.1.3](https://github.com/spacesprotocol/spacedb/compare/v0.1.2...v0.1.3) - 2026-08-03

### Bug Fixes

- *(prove)* Trim non-subtree keys from both ends of the sorted key slice

### Chore

- *(lint)* Fix clippy errors under -D warnings

## [0.1.2](https://github.com/spacesprotocol/spacedb/compare/v0.1.1...v0.1.2) - 2026-04-16

### Bug Fixes

- *(encode)* Reject subtrees whose nested prefixes exceed the key length
- *(path)* Cap split_point comparison at self's remaining bits

## [0.1.1](https://github.com/spacesprotocol/spacedb/compare/example-v0.1.0...example-v0.1.1) - 2026-04-16

### Refactor

- Resolve clippy warnings across the crate

## [0.1.0] - 2026-04-16

Initial release on crates.io.

### Features

- Merkle-ized binary trie with MVCC concurrency (multi-reader, single-writer).
- Subtree accumulators with inclusion and exclusion proofs.
- `no_std` support (RISC0 zkVM compatible) via `default-features = false`.
- Optional wasm bindings behind the `wasm` feature.
- Optional sqlite-backed hash index sidecar behind the `hash-idx` feature for fast `prove` and `compute_root` on large trees.
- Snapshot iteration and rollback.