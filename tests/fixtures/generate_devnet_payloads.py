#!/usr/bin/env python3
"""
Generate SSZ + Snappy payload fixtures from local-pq-devnet JSON captures.

The local-pq-devnet Docker stack exposes HTTP JSON views of blocks that were
gossiped on the network. These are not directly SSZ encoded, so this script
reconstructs the canonical SSZ ``SignedBlock`` containers using the Lean spec
reference implementation, then emits both the raw SSZ bytes and their Snappy
compressed form so Lantern's tests can replay real payloads.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import snappy  # type: ignore[import]

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = REPO_ROOT.parent
LEAN_SPEC_SRC = PROJECT_ROOT / "leanSpec" / "src"

sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(LEAN_SPEC_SRC))

from lean_spec.subspecs.containers.block import Block, BlockBody, SignedBlock
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.vote import SignedVote, Vote
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64


def bytes32_from_hex(hex_str: str) -> Bytes32:
    """
    Convert a 0x-prefixed hex string into a Bytes32 instance.

    Many JSON captures include longer zeroed signatures (for example BLS-sized),
    but Devnet 0 uses placeholder zero signatures. Truncate anything longer than
    32 bytes so it matches the Devnet 0 container definitions.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    raw = bytes.fromhex(hex_str)
    if len(raw) < Bytes32.LENGTH:
        raw = raw.ljust(Bytes32.LENGTH, b"\x00")
    elif len(raw) > Bytes32.LENGTH:
        raw = raw[: Bytes32.LENGTH]
    return Bytes32(raw)


def load_signed_block(json_path: Path) -> SignedBlock:
    """Reconstruct a SignedBlock from the captured JSON structure."""
    block_data = json.loads(json_path.read_text())

    attestations = []
    for att_json in block_data.get("body", {}).get("attestations", []):
        message = att_json["message"]
        vote_data = message["data"]
        vote_slot = vote_data["slot"]
        target_slot = max(vote_data["target"]["slot"], vote_slot)
        target_root_hex = vote_data["target"]["root"]
        if target_slot != vote_data["target"]["slot"]:
            target_root_hex = vote_data["head"]["root"]
        vote = Vote(
            validator_id=Uint64(message["validator_id"]),
            slot=Slot(vote_data["slot"]),
            head=Checkpoint(
                root=bytes32_from_hex(vote_data["head"]["root"]),
                slot=Slot(vote_data["head"]["slot"]),
            ),
            target=Checkpoint(
                root=bytes32_from_hex(target_root_hex),
                slot=Slot(target_slot),
            ),
            source=Checkpoint(
                root=bytes32_from_hex(vote_data["source"]["root"]),
                slot=Slot(vote_data["source"]["slot"]),
            ),
        )
        signed_vote = SignedVote(
            data=vote,
            signature=bytes32_from_hex(att_json.get("signature", "0x00")),
        )
        attestations.append(signed_vote)

    block = Block(
        slot=Slot(block_data["slot"]),
        proposer_index=Uint64(block_data["proposer_index"]),
        parent_root=bytes32_from_hex(block_data["parent_root"]),
        state_root=bytes32_from_hex(block_data["state_root"]),
        body=BlockBody(attestations=Attestations(data=attestations)),
    )

    signed_block = SignedBlock(
        message=block,
        signature=bytes32_from_hex(block_data.get("signature", "0x00")),
    )
    return signed_block


def write_payloads(json_path: Path) -> None:
    """Emit SSZ and Snappy payload files plus a metadata summary."""
    signed_block = load_signed_block(json_path)
    ssz_bytes = signed_block.encode_bytes()
    block_root = hash_tree_root(signed_block.message)

    ssz_path = json_path.with_suffix(".ssz")
    snappy_path = json_path.with_suffix(".ssz_snappy")
    meta_path = json_path.with_suffix(".meta.json")

    ssz_path.write_bytes(ssz_bytes)
    snappy_path.write_bytes(snappy.compress(ssz_bytes))

    metadata = {
        "slot": int(signed_block.message.slot),
        "proposer_index": int(signed_block.message.proposer_index),
        "block_root": f"0x{bytes(block_root).hex()}",
        "attestation_count": len(signed_block.message.body.attestations),
    }
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n")


def main() -> None:
    fixtures_dir = Path(__file__).resolve().parent / "devnet0"
    json_files = sorted(
        path
        for path in fixtures_dir.glob("block_slot*.json")
        if not path.name.endswith(".meta.json")
    )
    if not json_files:
        raise SystemExit("No block_slot*.json captures found")

    for json_path in json_files:
        write_payloads(json_path)
        print(f"Generated payloads for {json_path.name}")


if __name__ == "__main__":
    main()
