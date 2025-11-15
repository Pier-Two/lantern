#!/usr/bin/env python3
"""
Generate a LeanSpec-compatible genesis state and write it to an SSZ file.

Usage:
    python tools/debug/generate_lean_genesis.py <config_yaml> <output_ssz>

Reads GENESIS_TIME and VALIDATOR_COUNT from the YAML config and builds
that many zeroed validators (the same placeholder values the unit tests expect).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Bytes52, Uint64


def build_state(genesis_time: int, validator_count: int) -> bytes:
    validators = Validators(
        data=[Validator(pubkey=Bytes52.zero()) for _ in range(validator_count)]
    )
    state = State.generate_genesis(
        genesis_time=Uint64(genesis_time), validators=validators
    )
    return state.encode_bytes()


def main() -> None:
    if len(sys.argv) != 3:
        print(
            "usage: python tools/debug/generate_lean_genesis.py <config_yaml> <output_ssz>",
            file=sys.stderr,
        )
        sys.exit(1)

    config_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    with config_path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh)

    genesis_time = int(config.get("GENESIS_TIME", 0))
    validator_count = int(config.get("VALIDATOR_COUNT", 0))
    if validator_count <= 0:
        print("validator count must be positive", file=sys.stderr)
        sys.exit(1)

    ssz_bytes = build_state(genesis_time, validator_count)
    output_path.write_bytes(ssz_bytes)
    print(
        f"Wrote genesis SSZ ({len(ssz_bytes)} bytes) to {output_path}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
