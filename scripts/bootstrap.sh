#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

if [[ -d "${ROOT_DIR}/.git" ]]; then
    git submodule update --init --recursive external/c-libp2p external/c-ssz
else
    echo "bootstrap: skipping submodule sync (git metadata unavailable)" >&2
fi
