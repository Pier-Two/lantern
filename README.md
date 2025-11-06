# Lantern

Lantern is a C implementation for Lean consensus. It
implements gossip, fork-choice, state transition, and storage against the
Devnet containers defined in [`tools/leanSpec`](../tools/leanSpec).

## Quick Start

```sh
cd lantern
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Regenerating Fixtures

The consensus JSON and SSZ fixtures live in `tests/fixtures`. To refresh them
from LeanSpec, run:

```sh
./scripts/fixtures/fill_consensus_fixtures.sh
```

## License

Lantern is released under the terms of the Apache 2.0 license. See
[LICENSE](LICENSE) for details.
