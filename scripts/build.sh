#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

BUILD_TYPE=${BUILD_TYPE:-RelWithDebInfo}
BUILD_DIR=${BUILD_DIR:-build}
CMAKE_TIMEOUT_SECONDS=${CMAKE_TIMEOUT_SECONDS:-120}
CMAKE_KILL_AFTER_SECONDS=${CMAKE_KILL_AFTER_SECONDS:-15}

run_with_timeout() {
  local label=$1
  shift
  "${SCRIPT_DIR}/run_with_timeout.py" \
    --label "${label}" \
    --timeout "${CMAKE_TIMEOUT_SECONDS}" \
    --kill-after "${CMAKE_KILL_AFTER_SECONDS}" \
    -- "$@"
}

run_with_timeout "cmake (configure)" \
  cmake -S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

run_with_timeout "cmake (build)" \
  cmake --build "${BUILD_DIR}" --parallel "$@"
