#!/usr/bin/env python3
"""Generate LeanSpec networking SSZ fixtures for Lantern tests."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from lean_spec.subspecs.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockWithAttestation,
    Checkpoint,
    SignedBlockWithAttestation,
    Signature,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.collections import SSZList
from lean_spec.types.container import Container


class StatusContainer(Container):
    finalized: Checkpoint
    head: Checkpoint


class BlocksByRootRequestList(SSZList):
    ELEMENT_TYPE = Bytes32
    LIMIT = MAX_REQUEST_BLOCKS


class BlocksByRootResponseList(SSZList):
    ELEMENT_TYPE = SignedBlockWithAttestation
    LIMIT = MAX_REQUEST_BLOCKS


def _crc32c(data: bytes) -> int:
    poly = 0x82F63B78
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return (~crc) & 0xFFFFFFFF


def _mask_crc32c(crc: int) -> int:
    rotated = ((crc >> 15) | ((crc & 0xFFFFFFFF) << 17)) & 0xFFFFFFFF
    return (rotated + 0xA282EAD8) & 0xFFFFFFFF


def _le24(value: int) -> bytes:
    return bytes((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF))


def encode_snappy_uncompressed(payload: bytes) -> bytes:
    """Wrap raw bytes into a Snappy framed stream using an uncompressed chunk."""

    frame = bytearray()
    # Stream identifier chunk
    frame.append(0xFF)
    frame.extend(_le24(6))
    frame.extend(b"sNaPpY")

    # Uncompressed chunk with masked CRC32C
    frame.append(0x01)
    frame.extend(_le24(len(payload) + 4))
    crc = _mask_crc32c(_crc32c(payload))
    frame.extend(crc.to_bytes(4, byteorder="little"))
    frame.extend(payload)
    return bytes(frame)


def repeating_bytes(seed: int, length: int) -> bytes:
    return bytes(((seed + i) & 0xFF) for i in range(length))


def make_checkpoint(seed: int, slot: int) -> Checkpoint:
    return Checkpoint(root=Bytes32(repeating_bytes(seed, 32)), slot=Slot(slot))


def make_attestation(seed: int, validator_id: int, slot: int) -> Attestation:
    return Attestation(
        validator_id=Uint64(validator_id),
        data=AttestationData(
            slot=Slot(slot),
            head=make_checkpoint(seed, slot + 1),
            target=make_checkpoint(seed + 0x20, slot + 2),
            source=make_checkpoint(seed + 0x40, slot),
        ),
    )


def make_signatures(seed: int, count: int) -> BlockSignatures:
    sig_len = len(Signature.zero())
    signatures = [Signature(repeating_bytes(seed + (i * 3), sig_len)) for i in range(count)]
    return BlockSignatures(data=signatures)


def make_signed_block(seed: int, base_slot: int, proposer_index: int, attestation_count: int) -> SignedBlockWithAttestation:
    attestations: list[Attestation] = [
        make_attestation(seed + (i * 5), (proposer_index + i + seed) % 16, base_slot + i + 1)
        for i in range(attestation_count)
    ]
    block = Block(
        slot=Slot(base_slot),
        proposer_index=Uint64(proposer_index),
        parent_root=Bytes32(repeating_bytes(seed, 32)),
        state_root=Bytes32(repeating_bytes(seed + 0x50, 32)),
        body=BlockBody(attestations=Attestations(data=attestations)),
    )
    proposer_att = make_attestation(seed + 0x80, (proposer_index + 3) % 16, base_slot + attestation_count + 4)
    signatures = make_signatures(seed + 0xA0, attestation_count + 1)
    return SignedBlockWithAttestation(
        message=BlockWithAttestation(block=block, proposer_attestation=proposer_att),
        signature=signatures,
    )


def write_fixture(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def describe_fixture(name: str, values: Sequence[str]) -> None:
    summary = ", ".join(values)
    print(f"wrote {name}: {summary}")


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    fixture_dir = repo_root / "tests/fixtures/networking"

    status_fixture = StatusContainer(
        finalized=make_checkpoint(0x11, 42),
        head=make_checkpoint(0x41, 96),
    )
    status_bytes = status_fixture.encode_bytes()
    status_path = fixture_dir / "status_leanspec.ssz"
    write_fixture(status_path, status_bytes)
    describe_fixture("Status", [f"bytes={len(status_bytes)}"])
    status_snappy_path = fixture_dir / "status_leanspec.snappy"
    status_snappy = encode_snappy_uncompressed(status_bytes)
    write_fixture(status_snappy_path, status_snappy)
    describe_fixture(
        "Status Snappy",
        [f"raw={len(status_bytes)}", f"framed={len(status_snappy)}", "chunk=uncompressed"],
    )

    request_fixture = BlocksByRootRequestList(
        data=[
            Bytes32(repeating_bytes(0x21, 32)),
            Bytes32(repeating_bytes(0x52, 32)),
            Bytes32(repeating_bytes(0x83, 32)),
        ]
    )
    request_bytes = request_fixture.encode_bytes()
    request_path = fixture_dir / "blocks_by_root_request_leanspec.ssz"
    write_fixture(request_path, request_bytes)
    describe_fixture("BlocksByRoot request", [f"roots={len(request_fixture)}", f"bytes={len(request_bytes)}"])

    response_fixture = BlocksByRootResponseList(
        data=[
            make_signed_block(seed=0x10, base_slot=12, proposer_index=1, attestation_count=1),
            make_signed_block(seed=0x30, base_slot=18, proposer_index=3, attestation_count=2),
        ]
    )
    response_bytes = response_fixture.encode_bytes()
    response_path = fixture_dir / "blocks_by_root_response_leanspec.ssz"
    write_fixture(response_path, response_bytes)
    describe_fixture(
        "BlocksByRoot response",
        [f"blocks={len(response_fixture)}", f"bytes={len(response_bytes)}"],
    )


if __name__ == "__main__":
    main()
