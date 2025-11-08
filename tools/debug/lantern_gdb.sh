#!/bin/bash
set -euo pipefail
exec gdb -q -ex "run" -ex "bt 40" -ex "quit" --args /opt/lantern/bin/lantern \
  --data-dir /data \
  --genesis-config /config/config.yaml \
  --validator-registry-path /config/validators.yaml \
  --nodes-path /config/nodes.yaml \
  --genesis-state /config/genesis.ssz \
  --validator-config /config/validator-config.yaml \
  --node-id lantern_0 \
  --node-key-path /config/lantern_0.key \
  --listen-address /ip4/0.0.0.0/udp/9003/quic-v1 \
  --http-port 5053 \
  --metrics-port 8083 \
  --devnet local-devnet \
  --bootnodes /config/nodes.yaml
