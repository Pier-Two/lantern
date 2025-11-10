# ![Lantern Logo](docs/assets/lantern_logo.svg)

Lantern is a C implementation for Lean consensus. It
implements gossip, fork-choice, state transition, and storage against the
Devnet containers defined in [`tools/leanSpec`](../tools/leanSpec).

## Prerequisites

The build now links against the hash-based signature bindings in
`external/c-hash-sig`, which are produced with Rust. Make sure the following
tools are available on your `PATH`:

- CMake 3.20+
- A C compiler toolchain supported by your platform
- [Rust](https://www.rust-lang.org/tools/install) (which provides `cargo`)

## Quick Start

```sh
cd lantern
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Logging

Lantern emits structured log lines with color-coded levels (TRACE/DEBUG/INFO/WARN/ERROR) when the output stream is a TTY. Set `LANTERN_LOG_COLOR=always|never|auto` to override the detection.

Libp2p internals are now routed through the Lantern logger and are suppressed unless they are fatal. To inspect verbose libp2p traces, run Lantern with `--log-level trace` (or `LANTERN_LOG_LEVEL=trace`) and the libp2p entries will appear under the `component=libp2p` namespace.

## Regenerating Fixtures

The consensus JSON and SSZ fixtures live in `tests/fixtures`. To refresh them from LeanSpec, run:

```sh
./scripts/fixtures/fill_consensus_fixtures.sh
```

## License

Lantern is released under the terms of the Apache 2.0 license. See
[LICENSE](LICENSE) for details.
