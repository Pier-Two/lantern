# ![Lantern Logo](docs/assets/lantern_logo.svg)

Lantern is a C implementation for [`Lean consensus`](../tools/leanSpec).

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

## Regenerating Fixtures

The consensus JSON and SSZ fixtures live in `tests/fixtures`. To refresh them from LeanSpec, run:

```sh
./scripts/fixtures/fill_consensus_fixtures.sh
```

Networking fixtures (Status, BlocksByRoot, gossip payloads) come from LeanSpec as well. Build the helper encoder once and regenerate the SSZ + Snappy blobs with:

```sh
cmake --build build --target lantern_generate_gossip_snappy
PYTHONPATH=tools/leanSpec/src python3 scripts/fixtures/generate_networking_ssz.py
```

The helper ensures the Snappy frames exactly match Lantern’s `lantern_gossip_encode_*` outputs.

## License

Lantern is released under the terms of the MIT license. See
[LICENSE](LICENSE) for details.
