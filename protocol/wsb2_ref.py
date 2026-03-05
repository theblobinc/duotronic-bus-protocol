from __future__ import annotations

import binascii
import math
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

WSB2_MAGIC = b"WSB2"
WSB2_VERSION = 1
WSB2_COLS = 8
WSB2_HEADER_BYTES = 16
WSB2_FLAG_BODY_CRC32 = 0x0001


@dataclass
class SparseWitnessStore:
    rows: int
    cols: int
    present: int
    bitmap: bytes
    row_to_dense: List[int]
    data: List[float]


def _assert_u16(name: str, value: int) -> None:
    if not isinstance(value, int) or value < 0 or value > 0xFFFF:
        raise ValueError(f"{name} must be uint16")


def _popcount_bitmap(bitmap: bytes, rows: int) -> int:
    count = 0
    for row in range(rows):
        count += (bitmap[row >> 3] >> (row & 7)) & 1
    return count


def _build_row_to_dense(bitmap: bytes, rows: int) -> List[int]:
    out = [-1] * rows
    dense = 0
    for row in range(rows):
        bit = (bitmap[row >> 3] >> (row & 7)) & 1
        if bit:
            out[row] = dense
            dense += 1
    return out


def validate_sparse_store(store: SparseWitnessStore) -> None:
    _assert_u16("rows", store.rows)
    _assert_u16("present", store.present)

    if store.cols != WSB2_COLS:
        raise ValueError(f"cols must be {WSB2_COLS}")

    expected_bitmap_bytes = (store.rows + 7) // 8
    if len(store.bitmap) != expected_bitmap_bytes:
        raise ValueError(f"bitmap must be {expected_bitmap_bytes} bytes")

    if len(store.row_to_dense) != store.rows:
        raise ValueError("row_to_dense length mismatch")

    if len(store.data) != store.present * WSB2_COLS:
        raise ValueError("data length mismatch")

    if _popcount_bitmap(store.bitmap, store.rows) != store.present:
        raise ValueError("present count must equal bitmap popcount")


def build_sparse_witness_store_from_dense(dense: Iterable[Iterable[float]], rows: int) -> SparseWitnessStore:
    _assert_u16("rows", rows)

    dense_rows = list(dense)
    if len(dense_rows) != rows:
        raise ValueError(f"dense row count must be {rows}")

    bitmap = bytearray((rows + 7) // 8)
    row_to_dense = [-1] * rows
    packed: List[float] = []
    present = 0

    for row in range(rows):
        values = list(dense_rows[row])
        if len(values) != WSB2_COLS:
            raise ValueError(f"row {row} must have {WSB2_COLS} columns")
        if not any(v != 0.0 for v in values):
            continue

        bitmap[row >> 3] |= (1 << (row & 7))
        row_to_dense[row] = present
        packed.extend(float(v) for v in values)
        present += 1

    return SparseWitnessStore(
        rows=rows,
        cols=WSB2_COLS,
        present=present,
        bitmap=bytes(bitmap),
        row_to_dense=row_to_dense,
        data=packed,
    )


def sparse_store_to_dense(store: SparseWitnessStore) -> List[List[float]]:
    validate_sparse_store(store)

    dense = [[0.0] * WSB2_COLS for _ in range(store.rows)]
    for row in range(store.rows):
        dense_idx = store.row_to_dense[row]
        if dense_idx < 0:
            continue
        src = dense_idx * WSB2_COLS
        dense[row] = [float(v) for v in store.data[src : src + WSB2_COLS]]
    return dense


def get_sparse_row(store: SparseWitnessStore, row: int) -> Optional[List[float]]:
    validate_sparse_store(store)
    if row < 0 or row >= store.rows:
        raise ValueError("row out of range")
    dense_idx = store.row_to_dense[row]
    if dense_idx < 0:
        return None
    start = dense_idx * WSB2_COLS
    return [float(v) for v in store.data[start : start + WSB2_COLS]]


def encode_wsb2(
    store: SparseWitnessStore,
    overlay_id: int = 0,
    version: int = WSB2_VERSION,
    flags: int = 0,
    include_body_crc32: bool = False,
) -> bytes:
    validate_sparse_store(store)
    _assert_u16("overlay_id", overlay_id)
    _assert_u16("version", version)
    _assert_u16("flags", flags)

    effective_flags = (flags | WSB2_FLAG_BODY_CRC32) if include_body_crc32 else (flags & ~WSB2_FLAG_BODY_CRC32)

    header = bytearray(WSB2_HEADER_BYTES)
    header[0:4] = WSB2_MAGIC
    struct.pack_into("<H", header, 4, version)
    struct.pack_into("<H", header, 6, overlay_id)
    struct.pack_into("<H", header, 8, store.rows)
    struct.pack_into("<H", header, 10, WSB2_COLS)
    struct.pack_into("<H", header, 12, store.present)
    struct.pack_into("<H", header, 14, effective_flags)

    data_bytes = struct.pack("<" + "f" * len(store.data), *store.data) if store.data else b""
    body = store.bitmap + data_bytes

    out = bytes(header) + body
    if include_body_crc32:
        crc = binascii.crc32(body) & 0xFFFFFFFF
        out += struct.pack("<I", crc)

    return out


def decode_wsb2(blob: bytes, expect_body_crc32: Optional[bool] = None) -> Dict[str, object]:
    if len(blob) < WSB2_HEADER_BYTES:
        raise ValueError("WSB2 buffer too short")

    magic = blob[0:4]
    if magic != WSB2_MAGIC:
        raise ValueError("invalid WSB2 magic")

    version, overlay_id, rows, cols, present, flags = struct.unpack_from("<HHHHHH", blob, 4)
    if cols != WSB2_COLS:
        raise ValueError(f"unsupported WSB2 cols={cols}")

    has_body_crc32 = (flags & WSB2_FLAG_BODY_CRC32) != 0
    if expect_body_crc32 is not None and bool(expect_body_crc32) != has_body_crc32:
        raise ValueError("WSB2 CRC expectation mismatch")

    bitmap_len = (rows + 7) // 8
    body_start = WSB2_HEADER_BYTES
    body_data_start = body_start + bitmap_len
    if len(blob) < body_data_start:
        raise ValueError("WSB2 truncated bitmap")

    payload_end = len(blob) - (4 if has_body_crc32 else 0)
    if payload_end < body_data_start:
        raise ValueError("WSB2 truncated payload")

    data_len = payload_end - body_data_start
    expected_data_len = present * WSB2_COLS * 4
    if data_len != expected_data_len:
        raise ValueError("WSB2 packed data length mismatch")

    body = blob[body_start:payload_end]
    if has_body_crc32:
        crc_expected = struct.unpack_from("<I", blob, payload_end)[0]
        crc_actual = binascii.crc32(body) & 0xFFFFFFFF
        if crc_expected != crc_actual:
            raise ValueError("WSB2 body CRC32 mismatch")

    bitmap = blob[body_start:body_data_start]
    if _popcount_bitmap(bitmap, rows) != present:
        raise ValueError("WSB2 present count does not match bitmap popcount")

    data_bytes = blob[body_data_start:payload_end]
    data = list(struct.unpack("<" + "f" * (len(data_bytes) // 4), data_bytes)) if data_bytes else []
    row_to_dense = _build_row_to_dense(bitmap, rows)

    store = SparseWitnessStore(
        rows=rows,
        cols=cols,
        present=present,
        bitmap=bitmap,
        row_to_dense=row_to_dense,
        data=data,
    )
    validate_sparse_store(store)

    return {
        "magic": WSB2_MAGIC.decode("ascii"),
        "version": version,
        "overlay_id": overlay_id,
        "flags": flags,
        "has_body_crc32": has_body_crc32,
        "store": store,
    }


def _donor_capacity_cells(
    donor_band: int,
    band4_available: bool,
    band5_available: bool,
    band6_available: bool,
    hardened_mux: bool,
) -> Optional[Dict[str, int]]:
    if donor_band == 4:
        if not band4_available:
            return None
        return {"donor_band": 4, "start_cell": 148, "max_cells": 128}
    if donor_band == 5:
        if not band5_available:
            return None
        return {"donor_band": 5, "start_cell": 276, "max_cells": 384}
    if donor_band == 6:
        if not band6_available:
            return None
        if hardened_mux:
            return {"donor_band": 6, "start_cell": 684, "max_cells": 316}
        return {"donor_band": 6, "start_cell": 660, "max_cells": 340}
    return None


def plan_wsb2_opaque_abb_slices(
    total_payload_bytes: int,
    donor_order: Optional[List[int]] = None,
    band4_available: bool = True,
    band5_available: bool = True,
    band6_available: bool = True,
    hardened_mux: bool = False,
) -> Dict[str, object]:
    if not isinstance(total_payload_bytes, int) or total_payload_bytes < 0:
        raise ValueError("total_payload_bytes must be a non-negative integer")

    order = donor_order if donor_order is not None else [5, 4, 6]
    bytes_per_cell = 4
    slices: List[Dict[str, int]] = []
    remaining = total_payload_bytes
    offset = 0

    for donor_band in order:
        if remaining <= 0:
            break

        donor = _donor_capacity_cells(
            donor_band,
            band4_available=band4_available,
            band5_available=band5_available,
            band6_available=band6_available,
            hardened_mux=hardened_mux,
        )
        if donor is None:
            continue

        max_bytes = donor["max_cells"] * bytes_per_cell
        payload_this_slice = min(remaining, max_bytes)
        cells_needed = math.ceil(payload_this_slice / bytes_per_cell)
        slice_capacity = cells_needed * bytes_per_cell

        slices.append(
            {
                "donor_band": donor_band,
                "lane_type": 4,  # opaque_bytes
                "start_cell": donor["start_cell"],
                "cell_count": cells_needed,
                "byte_offset": offset,
                "byte_length": payload_this_slice,
                "byte_capacity": slice_capacity,
            }
        )

        offset += payload_this_slice
        remaining -= payload_this_slice

    return {
        "total_payload_bytes": total_payload_bytes,
        "bytes_planned": total_payload_bytes - remaining,
        "remaining_bytes": remaining,
        "can_fit": remaining == 0,
        "slices": slices,
    }


def _run_self_test() -> None:
    dense = [[0.0] * WSB2_COLS for _ in range(8)]
    dense[1] = [0.25, 0.3, 1.0, 0.25, 2.0, 0.0, 0.0, 1.0]
    dense[6] = [0.75, 0.4, 1.0, 0.75, 1.0, 0.5, 0.0, 1.0]

    store = build_sparse_witness_store_from_dense(dense, rows=8)
    if store.present != 2:
        raise RuntimeError("self-test: expected 2 present rows")

    blob = encode_wsb2(store, overlay_id=7, include_body_crc32=True)
    decoded = decode_wsb2(blob)
    decoded_store: SparseWitnessStore = decoded["store"]  # type: ignore[assignment]

    if decoded["overlay_id"] != 7:
        raise RuntimeError("self-test: overlay_id mismatch")
    if decoded_store.present != 2:
        raise RuntimeError("self-test: present mismatch")

    roundtrip_dense = sparse_store_to_dense(decoded_store)
    for r in range(8):
        for c in range(WSB2_COLS):
            if abs(roundtrip_dense[r][c] - dense[r][c]) > 1e-7:
                raise RuntimeError(f"self-test: dense roundtrip mismatch row={r} col={c}")

    plan = plan_wsb2_opaque_abb_slices(
        total_payload_bytes=len(blob),
        band4_available=True,
        band5_available=True,
        band6_available=True,
        hardened_mux=True,
    )
    if not plan["can_fit"]:
        raise RuntimeError("self-test: ABB plan should fit")

    print(
        "wsb2_ref.py self-test ok",
        {
            "rows": store.rows,
            "present": store.present,
            "blob_bytes": len(blob),
            "slices": len(plan["slices"]),
        },
    )


if __name__ == "__main__":
    _run_self_test()
