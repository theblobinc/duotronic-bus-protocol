import { crc32IsoHdlc } from "./dbp_ref.mjs";
import { fileURLToPath } from "url";

export const WSB2_MAGIC_TEXT = "WSB2";
export const WSB2_VERSION = 1;
export const WSB2_COLS = 8;
export const WSB2_HEADER_BYTES = 16;
export const WSB2_FLAG_BODY_CRC32 = 0x0001;

const WSB2_MAGIC_U32_LE = 0x32425357; // "WSB2" as little-endian u32

function assertUInt16(name, value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xFFFF) {
    throw new Error(`${name} must be uint16`);
  }
}

function popcountBitmap(bitmap, rows) {
  let count = 0;
  for (let row = 0; row < rows; row++) {
    const bit = (bitmap[row >>> 3] >>> (row & 7)) & 1;
    count += bit;
  }
  return count;
}

function buildRowToDense(bitmap, rows) {
  const rowToDense = new Int32Array(rows);
  let dense = 0;
  for (let row = 0; row < rows; row++) {
    const bit = (bitmap[row >>> 3] >>> (row & 7)) & 1;
    if (bit) {
      rowToDense[row] = dense;
      dense += 1;
    } else {
      rowToDense[row] = -1;
    }
  }
  return rowToDense;
}

function float32ToBytesLE(dataF32) {
  const out = new Uint8Array(dataF32.length * 4);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < dataF32.length; i++) {
    dv.setFloat32(i * 4, dataF32[i], true);
  }
  return out;
}

function bytesToFloat32LE(bytes) {
  if ((bytes.length % 4) !== 0) {
    throw new Error("float32 byte length must be multiple of 4");
  }
  const out = new Float32Array(bytes.length / 4);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < out.length; i++) {
    out[i] = dv.getFloat32(i * 4, true);
  }
  return out;
}

function normalizeDenseInput(dense, rows) {
  if (dense instanceof Float32Array) {
    const expected = rows * WSB2_COLS;
    if (dense.length !== expected) {
      throw new Error(`dense Float32Array length must be ${expected}`);
    }
    return dense;
  }

  if (Array.isArray(dense)) {
    if (dense.length !== rows) {
      throw new Error(`dense row array length must be ${rows}`);
    }
    const out = new Float32Array(rows * WSB2_COLS);
    for (let row = 0; row < rows; row++) {
      const r = dense[row];
      if (!Array.isArray(r) || r.length !== WSB2_COLS) {
        throw new Error(`row ${row} must have ${WSB2_COLS} columns`);
      }
      for (let col = 0; col < WSB2_COLS; col++) {
        out[row * WSB2_COLS + col] = r[col];
      }
    }
    return out;
  }

  throw new Error("dense input must be Float32Array or row-array");
}

export function buildSparseWitnessStoreFromDense(dense, rows) {
  assertUInt16("rows", rows);
  const denseF32 = normalizeDenseInput(dense, rows);

  const bitmap = new Uint8Array(Math.ceil(rows / 8));
  const rowToDense = new Int32Array(rows);
  rowToDense.fill(-1);

  const packed = [];
  let present = 0;

  for (let row = 0; row < rows; row++) {
    let any = false;
    const base = row * WSB2_COLS;
    for (let col = 0; col < WSB2_COLS; col++) {
      if (denseF32[base + col] !== 0) {
        any = true;
        break;
      }
    }
    if (!any) continue;

    bitmap[row >>> 3] |= (1 << (row & 7));
    rowToDense[row] = present;
    for (let col = 0; col < WSB2_COLS; col++) packed.push(denseF32[base + col]);
    present += 1;
  }

  const data = new Float32Array(packed);

  return {
    rows,
    cols: WSB2_COLS,
    present,
    bitmap,
    rowToDense,
    data
  };
}

export function sparseStoreToDense(store) {
  validateSparseStore(store);
  const out = new Float32Array(store.rows * WSB2_COLS);
  for (let row = 0; row < store.rows; row++) {
    const denseIdx = store.rowToDense[row];
    if (denseIdx < 0) continue;
    const srcBase = denseIdx * WSB2_COLS;
    const dstBase = row * WSB2_COLS;
    for (let col = 0; col < WSB2_COLS; col++) {
      out[dstBase + col] = store.data[srcBase + col];
    }
  }
  return out;
}

export function getSparseRow(store, row) {
  validateSparseStore(store);
  if (!Number.isInteger(row) || row < 0 || row >= store.rows) {
    throw new Error("row out of range");
  }
  const denseIdx = store.rowToDense[row];
  if (denseIdx < 0) return null;
  const start = denseIdx * WSB2_COLS;
  return store.data.subarray(start, start + WSB2_COLS);
}

export function validateSparseStore(store) {
  if (!store || typeof store !== "object") {
    throw new Error("store must be an object");
  }
  assertUInt16("rows", store.rows);
  assertUInt16("present", store.present);
  if (store.cols !== WSB2_COLS) {
    throw new Error(`cols must be ${WSB2_COLS}`);
  }
  if (!(store.bitmap instanceof Uint8Array)) {
    throw new Error("bitmap must be Uint8Array");
  }
  if (!(store.rowToDense instanceof Int32Array)) {
    throw new Error("rowToDense must be Int32Array");
  }
  if (!(store.data instanceof Float32Array)) {
    throw new Error("data must be Float32Array");
  }

  const expectedBitmapBytes = Math.ceil(store.rows / 8);
  if (store.bitmap.length !== expectedBitmapBytes) {
    throw new Error(`bitmap must be ${expectedBitmapBytes} bytes`);
  }
  if (store.rowToDense.length !== store.rows) {
    throw new Error("rowToDense length mismatch");
  }
  if (store.data.length !== store.present * WSB2_COLS) {
    throw new Error("data length mismatch");
  }

  const counted = popcountBitmap(store.bitmap, store.rows);
  if (counted !== store.present) {
    throw new Error("present count must equal bitmap popcount");
  }
}

export function encodeWsb2(store, {
  overlayId = 0,
  version = WSB2_VERSION,
  flags = 0,
  includeBodyCrc32 = false
} = {}) {
  validateSparseStore(store);
  assertUInt16("overlayId", overlayId);
  assertUInt16("version", version);
  assertUInt16("flags", flags);

  const effectiveFlags = includeBodyCrc32 ? (flags | WSB2_FLAG_BODY_CRC32) : (flags & ~WSB2_FLAG_BODY_CRC32);
  const bitmapBytes = store.bitmap;
  const dataBytes = float32ToBytesLE(store.data);
  const bodyBytesLen = bitmapBytes.length + dataBytes.length;
  const trailerBytes = includeBodyCrc32 ? 4 : 0;
  const out = new Uint8Array(WSB2_HEADER_BYTES + bodyBytesLen + trailerBytes);
  const dv = new DataView(out.buffer);

  dv.setUint32(0, WSB2_MAGIC_U32_LE, true);
  dv.setUint16(4, version, true);
  dv.setUint16(6, overlayId, true);
  dv.setUint16(8, store.rows, true);
  dv.setUint16(10, WSB2_COLS, true);
  dv.setUint16(12, store.present, true);
  dv.setUint16(14, effectiveFlags, true);

  out.set(bitmapBytes, WSB2_HEADER_BYTES);
  out.set(dataBytes, WSB2_HEADER_BYTES + bitmapBytes.length);

  if (includeBodyCrc32) {
    const bodyStart = WSB2_HEADER_BYTES;
    const bodyEnd = WSB2_HEADER_BYTES + bodyBytesLen;
    const crc = crc32IsoHdlc(out.subarray(bodyStart, bodyEnd));
    dv.setUint32(bodyEnd, crc >>> 0, true);
  }

  return out;
}

export function decodeWsb2(bytesLike, {
  expectBodyCrc32 = null
} = {}) {
  if (!(bytesLike instanceof Uint8Array)) {
    throw new Error("bytes must be Uint8Array");
  }
  if (bytesLike.length < WSB2_HEADER_BYTES) {
    throw new Error("WSB2 buffer too short");
  }

  const dv = new DataView(bytesLike.buffer, bytesLike.byteOffset, bytesLike.byteLength);
  const magic = dv.getUint32(0, true);
  if (magic !== WSB2_MAGIC_U32_LE) {
    throw new Error("invalid WSB2 magic");
  }

  const version = dv.getUint16(4, true);
  const overlayId = dv.getUint16(6, true);
  const rows = dv.getUint16(8, true);
  const cols = dv.getUint16(10, true);
  const present = dv.getUint16(12, true);
  const flags = dv.getUint16(14, true);

  if (cols !== WSB2_COLS) {
    throw new Error(`unsupported WSB2 cols=${cols}`);
  }

  const hasBodyCrc32 = (flags & WSB2_FLAG_BODY_CRC32) !== 0;
  if (expectBodyCrc32 !== null && Boolean(expectBodyCrc32) !== hasBodyCrc32) {
    throw new Error("WSB2 CRC expectation mismatch");
  }

  const bitmapLen = Math.ceil(rows / 8);
  const baseBodyEnd = WSB2_HEADER_BYTES + bitmapLen;
  if (bytesLike.length < baseBodyEnd) {
    throw new Error("WSB2 truncated bitmap");
  }

  let payloadEnd = bytesLike.length;
  if (hasBodyCrc32) {
    if (bytesLike.length < (WSB2_HEADER_BYTES + bitmapLen + 4)) {
      throw new Error("WSB2 missing CRC32 trailer");
    }
    payloadEnd -= 4;
  }

  const dataLen = payloadEnd - (WSB2_HEADER_BYTES + bitmapLen);
  if (dataLen !== present * WSB2_COLS * 4) {
    throw new Error("WSB2 packed data length mismatch");
  }

  if (hasBodyCrc32) {
    const crcExpected = dv.getUint32(payloadEnd, true) >>> 0;
    const crcActual = crc32IsoHdlc(bytesLike.subarray(WSB2_HEADER_BYTES, payloadEnd));
    if (crcExpected !== crcActual) {
      throw new Error("WSB2 body CRC32 mismatch");
    }
  }

  const bitmap = bytesLike.slice(WSB2_HEADER_BYTES, WSB2_HEADER_BYTES + bitmapLen);
  const bitmapPop = popcountBitmap(bitmap, rows);
  if (bitmapPop !== present) {
    throw new Error("WSB2 present count does not match bitmap popcount");
  }

  const dataBytes = bytesLike.slice(WSB2_HEADER_BYTES + bitmapLen, payloadEnd);
  const data = bytesToFloat32LE(dataBytes);
  const rowToDense = buildRowToDense(bitmap, rows);

  const store = {
    rows,
    cols,
    present,
    bitmap,
    rowToDense,
    data
  };
  validateSparseStore(store);

  return {
    magic: WSB2_MAGIC_TEXT,
    version,
    overlayId,
    flags,
    hasBodyCrc32,
    store
  };
}

function donorCapacityCells(options, donorBand) {
  const hardenedMux = Boolean(options.hardenedMux);
  if (donorBand === 4) {
    if (!options.band4Available) return null;
    return { donorBand: 4, startCell: 148, maxCells: 128 };
  }
  if (donorBand === 5) {
    if (!options.band5Available) return null;
    return { donorBand: 5, startCell: 276, maxCells: 384 };
  }
  if (donorBand === 6) {
    if (!options.band6Available) return null;
    if (hardenedMux) {
      return { donorBand: 6, startCell: 684, maxCells: 316 };
    }
    return { donorBand: 6, startCell: 660, maxCells: 340 };
  }
  return null;
}

export function planWsb2OpaqueAbbSlices(totalPayloadBytes, {
  donorOrder = [5, 4, 6],
  band4Available = true,
  band5Available = true,
  band6Available = true,
  hardenedMux = false
} = {}) {
  if (!Number.isInteger(totalPayloadBytes) || totalPayloadBytes < 0) {
    throw new Error("totalPayloadBytes must be a non-negative integer");
  }

  const options = { band4Available, band5Available, band6Available, hardenedMux };
  const bytesPerCell = 4;
  const slices = [];
  let remaining = totalPayloadBytes;
  let offset = 0;

  for (const donorBand of donorOrder) {
    if (remaining <= 0) break;

    const donor = donorCapacityCells(options, donorBand);
    if (!donor) continue;

    const maxBytes = donor.maxCells * bytesPerCell;
    const payloadThisSlice = Math.min(remaining, maxBytes);
    const cellsNeeded = Math.ceil(payloadThisSlice / bytesPerCell);
    const sliceCapacity = cellsNeeded * bytesPerCell;

    slices.push({
      donorBand,
      laneType: 4, // opaque_bytes
      startCell: donor.startCell,
      cellCount: cellsNeeded,
      byteOffset: offset,
      byteLength: payloadThisSlice,
      byteCapacity: sliceCapacity
    });

    offset += payloadThisSlice;
    remaining -= payloadThisSlice;
  }

  return {
    totalPayloadBytes,
    bytesPlanned: totalPayloadBytes - remaining,
    remainingBytes: remaining,
    canFit: remaining === 0,
    slices
  };
}

function runSelfTest() {
  const rows = 8;
  const dense = new Float32Array(rows * WSB2_COLS);
  // Two present rows, six absent rows.
  dense.set([0.25, 0.3, 1, 0.25, 2, 0, 0, 1], 1 * WSB2_COLS);
  dense.set([0.75, 0.4, 1, 0.75, 1, 0.5, 0, 1], 6 * WSB2_COLS);

  const store = buildSparseWitnessStoreFromDense(dense, rows);
  if (store.present !== 2) throw new Error("self-test: expected 2 present rows");

  const blob = encodeWsb2(store, { overlayId: 7, includeBodyCrc32: true });
  const decoded = decodeWsb2(blob);

  if (decoded.overlayId !== 7) throw new Error("self-test: overlayId mismatch");
  if (decoded.store.present !== 2) throw new Error("self-test: present mismatch");

  const roundtripDense = sparseStoreToDense(decoded.store);
  for (let i = 0; i < dense.length; i++) {
    if (Math.fround(roundtripDense[i]) !== Math.fround(dense[i])) {
      throw new Error(`self-test: dense roundtrip mismatch at index ${i}`);
    }
  }

  const plan = planWsb2OpaqueAbbSlices(blob.length, {
    band4Available: true,
    band5Available: true,
    band6Available: true,
    hardenedMux: true
  });
  if (!plan.canFit) throw new Error("self-test: ABB plan should fit");

  console.log("wsb2_ref.mjs self-test ok", {
    rows: store.rows,
    present: store.present,
    blobBytes: blob.length,
    slices: plan.slices.length
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runSelfTest();
}
