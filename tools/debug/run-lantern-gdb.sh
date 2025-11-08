#!/usr/bin/env bash
# Runs lantern_cli under gdb inside the lean-quickstart podman image with the
# local devnet config/data mounted in.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
DEFAULT_CONFIG_DIR="$REPO_ROOT/tools/lean-quickstart/local-devnet/genesis"
DEFAULT_DATA_DIR="$REPO_ROOT/tools/lean-quickstart/local-devnet/data/lantern_0"
DEFAULT_NODE_ID="lantern_0"
DEFAULT_IMAGE="${LANTERN_GDB_IMAGE:-lantern:lean-quickstart}"
DEFAULT_LISTEN_PORT="9003"
DEFAULT_HTTP_PORT="5053"
DEFAULT_METRICS_PORT="8083"
DEFAULT_DEVNET="local-devnet"

usage() {
cat <<'EOF'
Usage: run-lantern-gdb.sh [options] [-- gdb-args]

Options:
  --config-dir PATH      Path to genesis/config directory (default: local-devnet/genesis)
  --data-dir PATH        Path to lantern data dir (default: local-devnet/data/lantern_0)
  --node-id NAME         Node ID to pass to lantern (default: lantern_0)
  --listen-port PORT     QUIC listen UDP port (default: 9003)
  --http-port PORT       HTTP diagnostics port (default: 5053)
  --metrics-port PORT    Prometheus metrics port (default: 8083)
  --devnet NAME          Devnet/topic identifier (default: local-devnet)
  --image IMAGE          Podman image to run (default: lantern:lean-quickstart)
  --lantern-args 'ARGS'  Extra arguments appended to lantern_cli invocation
  -h, --help             Show this message

All arguments after a literal "--" are forwarded directly to gdb (e.g. custom
commands or an alternate script).
EOF
}

CONFIG_DIR="$DEFAULT_CONFIG_DIR"
DATA_DIR="$DEFAULT_DATA_DIR"
NODE_ID="$DEFAULT_NODE_ID"
LISTEN_PORT="$DEFAULT_LISTEN_PORT"
HTTP_PORT="$DEFAULT_HTTP_PORT"
METRICS_PORT="$DEFAULT_METRICS_PORT"
DEVNET="$DEFAULT_DEVNET"
IMAGE="$DEFAULT_IMAGE"
LANTERN_EXTRA_ARGS=""
GDB_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config-dir)
      CONFIG_DIR="$2"; shift 2;;
    --data-dir)
      DATA_DIR="$2"; shift 2;;
    --node-id)
      NODE_ID="$2"; shift 2;;
    --listen-port)
      LISTEN_PORT="$2"; shift 2;;
    --http-port)
      HTTP_PORT="$2"; shift 2;;
    --metrics-port)
      METRICS_PORT="$2"; shift 2;;
    --devnet)
      DEVNET="$2"; shift 2;;
    --image)
      IMAGE="$2"; shift 2;;
    --lantern-args)
      LANTERN_EXTRA_ARGS="$2"; shift 2;;
    --)
      shift
      GDB_ARGS=("$@")
      break;;
    -h|--help)
      usage
      exit 0;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1;;
  esac
done

for dir in "$CONFIG_DIR" "$DATA_DIR"; do
  if [[ ! -d "$dir" ]]; then
    echo "Required directory not found: $dir" >&2
    exit 1
  fi
done

LANERN_CMD=(/opt/lantern/bin/lantern
  --data-dir /data
  --genesis-config /config/config.yaml
  --validator-registry-path /config/validators.yaml
  --nodes-path /config/nodes.yaml
  --genesis-state /config/genesis.ssz
  --validator-config /config/validator-config.yaml
  --node-id "$NODE_ID"
  --node-key-path "/config/${NODE_ID}.key"
  --listen-address "/ip4/0.0.0.0/udp/${LISTEN_PORT}/quic-v1"
  --http-port "$HTTP_PORT"
  --metrics-port "$METRICS_PORT"
  --devnet "$DEVNET"
  --bootnodes /config/nodes.yaml
)

if [[ -n "$LANTERN_EXTRA_ARGS" ]]; then
  # shellcheck disable=SC2206
  EXTRA_PARTS=($LANTERN_EXTRA_ARGS)
  LANERN_CMD+=("${EXTRA_PARTS[@]}")
fi

GDB_CMD=(gdb -q -ex "run" -ex "bt 40" -ex "quit" --args "${LANERN_CMD[@]}")
if [[ ${#GDB_ARGS[@]} -gt 0 ]]; then
  GDB_CMD=(gdb "${GDB_ARGS[@]}")
fi

exec podman run --rm -it \
  --network host \
  -e LANTERN_DEBUG_STATE_HASH="${LANTERN_DEBUG_STATE_HASH:-1}" \
  -v "$CONFIG_DIR":/config \
  -v "$DATA_DIR":/data \
  "$IMAGE" \
  "${GDB_CMD[@]}"
