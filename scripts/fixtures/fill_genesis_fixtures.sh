#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LANTERN_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LEAN_SPEC_DIR="${LANTERN_ROOT}/tools/leanSpec"
OUTPUT_DIR="${LANTERN_ROOT}/tests/fixtures/consensus/genesis"

if [[ ! -d "${LEAN_SPEC_DIR}" ]]; then
  echo "leanSpec tools directory not found: ${LEAN_SPEC_DIR}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

(
  cd "${LEAN_SPEC_DIR}"
  uv run fill tests/consensus/devnet/state_transition/test_genesis.py --fork=Devnet --layer=consensus --clean --output "${OUTPUT_DIR}"
)
