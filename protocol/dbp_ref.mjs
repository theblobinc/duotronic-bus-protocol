import crypto from "crypto";

export const DBP_CELLS = 1024;
export const DBP_BYTES = 4096;
export const CRC_INPUT_BYTES = 4080; // bytes[0..4079]
export const S1_MAC_INPUT_BYTES = 4016; // bytes[0..4015]
export const SEC_TRAILER_PRESENT_MASK = 0x0020;
export const MIN_NORMAL_F32 = 1.17549435e-38; // 2^-126
export const DEFAULT_MAC_DOMAIN_TAG = Uint8Array.from(Buffer.from("DBP-S1\0", "ascii"));

export const DBP_LANE_HEADER_V1_MAGIC = 0x4C48; // "HL" LE on wire
export const DBP_LANE_HEADER_V1_VERSION = 1;
export const DBP_LANE_HEADER_V1_BYTES = 32;
export const DBP_LANE_FLAG_START = 0x01;
export const DBP_LANE_FLAG_END = 0x02;

export const REJECT_REGISTRY = Object.freeze({
  E_SHAPE: { event: "DBP_REJECT_SHAPE", counter: "reject_shape" },
  E_NONFINITE: { event: "DBP_REJECT_NONFINITE", counter: "reject_nonfinite" },
  E_SUBNORMAL: { event: "DBP_REJECT_SUBNORMAL", counter: "reject_subnormal" },
  E_INT_FIELD: { event: "DBP_REJECT_INT_FIELD", counter: "reject_int_field" },
  E_MAGIC: { event: "DBP_REJECT_MAGIC", counter: "reject_magic" },
  E_FOOTER: { event: "DBP_REJECT_FOOTER", counter: "reject_footer" },
  E_CRC: { event: "DBP_REJECT_CRC", counter: "reject_crc" },
  E_SEC_PROFILE: { event: "DBP_REJECT_SEC_PROFILE", counter: "reject_sec_profile" },
  E_REPLAY: { event: "DBP_SEC_REPLAY_REJECT", counter: "sec_replay_reject" },
  E_S1_TAG: { event: "DBP_SEC_S1_TAG_MISMATCH", counter: "sec_s1_tag_mismatch" },
  E_S2_TAG: { event: "DBP_SEC_S2_TAG_MISMATCH", counter: "sec_s2_tag_mismatch" },
  E_S2_NONCE_REUSE: { event: "DBP_SEC_NONCE_REUSE", counter: "sec_s2_nonce_reuse" },
  E_S2_SUITE: { event: "DBP_SEC_S2_SUITE_REJECT", counter: "sec_s2_suite_reject" },
  E_KEY_EPOCH: { event: "DBP_SEC_KEY_EPOCH_ROLLBACK", counter: "sec_key_epoch_rollback" },
  E_POLICY_DOWNGRADE: { event: "DBP_SEC_DOWNGRADE_ATTEMPT", counter: "sec_policy_downgrade" },
  E_RESERVED_POLICY: { event: "DBP_POLICY_RESERVED_FIELD", counter: "policy_reserved_field" },
  E_ABB_MANIFEST: { event: "DBP_ABB_MANIFEST_INVALID", counter: "abb_manifest_invalid" },
  E_ABB_DONOR_STATE: { event: "DBP_ABB_DONOR_STATE_INVALID", counter: "abb_donor_state_invalid" },
  E_MCB_INVALID: { event: "DBP_MCB_INVALID", counter: "mcb_invalid" },
  E_PROFILE_UNSUPPORTED: { event: "DBP_PROFILE_UNSUPPORTED", counter: "profile_unsupported" },
  E_WITNESS_INSECURE_MODE: { event: "DBP_WITNESS_INSECURE_MODE", counter: "witness_insecure_mode" }
});

export function rejectMetaFor(code) {
  return REJECT_REGISTRY[code] ?? { event: "DBP_REJECT_UNKNOWN", counter: "reject_unknown" };
}

export class DBPRejectError extends Error {
  constructor(code, message, context = {}) {
    super(message ?? code);
    this.name = "DBPRejectError";
    this.code = code;
    this.context = context;
    const meta = rejectMetaFor(code);
    this.event = meta.event;
    this.counter = meta.counter;
  }
}

function reject(code, message, context = {}) {
  throw new DBPRejectError(code, message, context);
}

function asBytes(value, name) {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (Buffer.isBuffer(value)) return new Uint8Array(value);
  reject("E_SHAPE", `${name} must be Uint8Array/Buffer`);
}

function requireUInt(name, value, max) {
  if (!Number.isInteger(value) || value < 0 || value > max) {
    reject("E_INT_FIELD", `${name} must be integer in 0..${max}`, { name, value, max });
  }
}

function assertFiniteNonSubnormal(x, { field = "value", cell = null } = {}) {
  if (!Number.isFinite(x)) {
    reject("E_NONFINITE", `${field} is non-finite`, { field, cell, value: x });
  }
  if (x !== 0 && Math.abs(x) < MIN_NORMAL_F32) {
    reject("E_SUBNORMAL", `${field} is subnormal`, { field, cell, value: x });
  }
}

function isNegativeZero(x) {
  return Object.is(x, -0);
}

export function decodeU16AsFloat(x, { strictNegZero = false, field = "u16", cell = null } = {}) {
  assertFiniteNonSubnormal(x, { field, cell });
  if (strictNegZero && isNegativeZero(x)) {
    reject("E_INT_FIELD", `${field} is -0.0 in strict mode`, { field, cell });
  }
  if (x !== Math.trunc(x)) {
    reject("E_INT_FIELD", `${field} is fractional`, { field, cell, value: x });
  }
  if (x < 0 || x > 0xFFFF) {
    reject("E_INT_FIELD", `${field} out of range`, { field, cell, value: x });
  }
  const n = Math.trunc(x);
  if (Math.fround(n) !== x) {
    reject("E_INT_FIELD", `${field} is non-exact`, { field, cell, value: x });
  }
  return n >>> 0;
}

export function decodeU24AsFloat(x, { strictNegZero = false, field = "u24", cell = null } = {}) {
  assertFiniteNonSubnormal(x, { field, cell });
  if (strictNegZero && isNegativeZero(x)) {
    reject("E_INT_FIELD", `${field} is -0.0 in strict mode`, { field, cell });
  }
  if (x !== Math.trunc(x)) {
    reject("E_INT_FIELD", `${field} is fractional`, { field, cell, value: x });
  }
  if (x < 0 || x > 0xFFFFFF) {
    reject("E_INT_FIELD", `${field} out of range`, { field, cell, value: x });
  }
  const n = Math.trunc(x);
  if (Math.fround(n) !== x) {
    reject("E_INT_FIELD", `${field} is non-exact`, { field, cell, value: x });
  }
  return n >>> 0;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32IsoHdlc(bytesLike) {
  const bytes = asBytes(bytesLike, "bytes");
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

export function packBytesToU16WordsLE(bytesLike) {
  const bytes = asBytes(bytesLike, "bytes");
  const out = [];
  for (let i = 0; i < bytes.length; i += 2) {
    const lo = bytes[i];
    const hi = i + 1 < bytes.length ? bytes[i + 1] : 0;
    out.push((lo | (hi << 8)) >>> 0);
  }
  return out;
}

export function unpackU16WordsToBytesLE(words, expectedLength = null) {
  if (!Array.isArray(words)) reject("E_INT_FIELD", "words must be an array");
  const outLen = expectedLength ?? (words.length * 2);
  const out = new Uint8Array(outLen);
  let off = 0;
  for (let i = 0; i < words.length && off < outLen; i++) {
    const w = words[i] >>> 0;
    out[off++] = w & 0xFF;
    if (off < outLen) out[off++] = (w >>> 8) & 0xFF;
  }
  return out;
}

export function floatArrayFromWireBytes(bytesLike) {
  const bytes = asBytes(bytesLike, "wireBytes");
  if (bytes.length !== DBP_BYTES) {
    reject("E_SHAPE", `wireBytes must be exactly ${DBP_BYTES} bytes`, { length: bytes.length });
  }
  const out = new Float32Array(DBP_CELLS);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < DBP_CELLS; i++) {
    out[i] = dv.getFloat32(i * 4, true);
  }
  return out;
}

export function wireBytesFromFloatArray(frame) {
  if (!(frame instanceof Float32Array) || frame.length !== DBP_CELLS) {
    reject("E_SHAPE", `frame must be Float32Array(${DBP_CELLS})`);
  }
  const out = new Uint8Array(DBP_BYTES);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < DBP_CELLS; i++) {
    dv.setFloat32(i * 4, frame[i], true);
  }
  return out;
}

export function canonicalizeWriterCells(frame, { start = 0, end = frame.length } = {}) {
  if (!(frame instanceof Float32Array)) {
    reject("E_SHAPE", "frame must be Float32Array");
  }
  const from = Math.max(0, start | 0);
  const to = Math.min(frame.length, end | 0);
  for (let i = from; i < to; i++) {
    const v = frame[i];
    if (!Number.isFinite(v)) {
      reject("E_NONFINITE", "cannot encode non-finite cell", { cell: i, value: v });
    }
    if (v === 0 || isNegativeZero(v)) {
      frame[i] = 0;
      continue;
    }
    if (Math.abs(v) < MIN_NORMAL_F32) {
      frame[i] = 0;
    }
  }
  return frame;
}

export function hmacSha256Tag(keyLike, payloadLike, domainTagLike = DEFAULT_MAC_DOMAIN_TAG) {
  const key = asBytes(keyLike, "hmac_key");
  const payload = asBytes(payloadLike, "payload");
  const domainTag = asBytes(domainTagLike, "domain_tag");
  const out = crypto
    .createHmac("sha256", Buffer.from(key))
    .update(Buffer.from(domainTag))
    .update(Buffer.from(payload))
    .digest();
  return new Uint8Array(out);
}

function timingSafeEqualBytes(aLike, bLike) {
  const a = asBytes(aLike, "a");
  const b = asBytes(bLike, "b");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function nonceWordsFromBytes(nonceLike) {
  const nonce = asBytes(nonceLike, "nonce96");
  if (nonce.length !== 12) {
    reject("E_INT_FIELD", "nonce96 must be 12 bytes", { length: nonce.length });
  }
  const words = packBytesToU16WordsLE(nonce);
  if (words.length !== 6) {
    reject("E_INT_FIELD", "nonce96 pack failure");
  }
  return words;
}

export function nonceBytesFromWords(words) {
  if (!Array.isArray(words) || words.length !== 6) {
    reject("E_INT_FIELD", "nonce words must be length 6");
  }
  return unpackU16WordsToBytesLE(words, 12);
}

export function tagWordsFromBytes(tagLike) {
  const tag = asBytes(tagLike, "aead_tag128");
  if (tag.length !== 16) {
    reject("E_INT_FIELD", "AEAD tag must be 16 bytes", { length: tag.length });
  }
  const words = packBytesToU16WordsLE(tag);
  if (words.length !== 8) {
    reject("E_INT_FIELD", "tag pack failure");
  }
  return words;
}

export function tagBytesFromWords(words) {
  if (!Array.isArray(words) || words.length !== 8) {
    reject("E_INT_FIELD", "tag words must be length 8");
  }
  return unpackU16WordsToBytesLE(words, 16);
}

export function ctr64FromNonce96(nonceLike) {
  const nonce = asBytes(nonceLike, "nonce96");
  if (nonce.length !== 12) {
    reject("E_INT_FIELD", "nonce96 must be 12 bytes", { length: nonce.length });
  }
  let out = 0n;
  for (let i = 0; i < 8; i++) {
    out |= BigInt(nonce[4 + i]) << (8n * BigInt(i));
  }
  return out;
}

function nonce96FromSalt32AndCtr64(salt32Like, ctr64) {
  const salt32 = asBytes(salt32Like, "session_salt32");
  if (salt32.length !== 4) reject("E_INT_FIELD", "session_salt32 must be 4 bytes");
  if (typeof ctr64 !== "bigint" || ctr64 < 0n || ctr64 > 0xFFFFFFFFFFFFFFFFn) {
    reject("E_INT_FIELD", "ctr64 must be uint64");
  }
  const out = new Uint8Array(12);
  out.set(salt32, 0);
  for (let i = 0; i < 8; i++) {
    out[4 + i] = Number((ctr64 >> (8n * BigInt(i))) & 0xFFn);
  }
  return out;
}

export function getS2AadBytes(wireBytesLike) {
  const wireBytes = asBytes(wireBytesLike, "wireBytes");
  if (wireBytes.length !== DBP_BYTES) {
    reject("E_SHAPE", `wireBytes must be exactly ${DBP_BYTES} bytes`, { length: wireBytes.length });
  }
  const out = new Uint8Array(60);
  out.set(wireBytes.subarray(0, 36), 0); // cells 0..8
  out.set(wireBytes.subarray(4000, 4016), 36); // cells 1000..1003
  out.set(wireBytes.subarray(4072, 4080), 52); // cells 1018..1019
  return out;
}

function normalizeAeadAlgorithm(name) {
  const n = String(name ?? "aes-256-gcm").toLowerCase();
  if (n === "aes-256-gcm") return "aes-256-gcm";
  if (n === "chacha20-poly1305" || n === "chacha20poly1305") return "chacha20-poly1305";
  reject("E_S2_SUITE", `unsupported AEAD algorithm: ${name}`);
}

function aeadEncrypt(algorithm, keyLike, nonceLike, aadLike, plaintextLike) {
  const key = asBytes(keyLike, "aead_key");
  const nonce = asBytes(nonceLike, "nonce96");
  const aad = asBytes(aadLike, "aad");
  const plaintext = asBytes(plaintextLike, "plaintext");

  if (key.length !== 32) {
    reject("E_INT_FIELD", "AEAD key must be 32 bytes", { length: key.length });
  }
  if (nonce.length !== 12) {
    reject("E_INT_FIELD", "AEAD nonce must be 12 bytes", { length: nonce.length });
  }

  const algo = normalizeAeadAlgorithm(algorithm);
  const cipher = crypto.createCipheriv(algo, Buffer.from(key), Buffer.from(nonce), { authTagLength: 16 });
  cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const c0 = cipher.update(Buffer.from(plaintext));
  const c1 = cipher.final();
  const tag = cipher.getAuthTag();
  const ciphertext = new Uint8Array(c0.length + c1.length);
  ciphertext.set(c0, 0);
  ciphertext.set(c1, c0.length);
  return { ciphertext, tag: new Uint8Array(tag) };
}

function aeadDecrypt(algorithm, keyLike, nonceLike, aadLike, ciphertextLike, tagLike) {
  const key = asBytes(keyLike, "aead_key");
  const nonce = asBytes(nonceLike, "nonce96");
  const aad = asBytes(aadLike, "aad");
  const ciphertext = asBytes(ciphertextLike, "ciphertext");
  const tag = asBytes(tagLike, "tag");

  if (key.length !== 32) {
    reject("E_INT_FIELD", "AEAD key must be 32 bytes", { length: key.length });
  }
  if (nonce.length !== 12) {
    reject("E_INT_FIELD", "AEAD nonce must be 12 bytes", { length: nonce.length });
  }
  if (tag.length !== 16) {
    reject("E_INT_FIELD", "AEAD tag must be 16 bytes", { length: tag.length });
  }

  const algo = normalizeAeadAlgorithm(algorithm);
  try {
    const decipher = crypto.createDecipheriv(algo, Buffer.from(key), Buffer.from(nonce), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.length });
    decipher.setAuthTag(Buffer.from(tag));
    const p0 = decipher.update(Buffer.from(ciphertext));
    const p1 = decipher.final();
    const plaintext = new Uint8Array(p0.length + p1.length);
    plaintext.set(p0, 0);
    plaintext.set(p1, p0.length);
    return plaintext;
  } catch (err) {
    reject("E_S2_TAG", "S2 AEAD verification failed", { detail: String(err?.message ?? err) });
  }
}

function decodeHeader(frame, strictNegZero) {
  const magic = decodeU16AsFloat(frame[0], { strictNegZero, field: "magic", cell: 0 });
  if (magic !== 56081 && magic !== 56065) {
    reject("E_MAGIC", "unsupported magic", { magic });
  }
  const version = decodeU16AsFloat(frame[1], { strictNegZero, field: "version", cell: 1 });
  const seqLo = decodeU24AsFloat(frame[2], { strictNegZero, field: "seq_lo", cell: 2 });
  const seqHi = decodeU24AsFloat(frame[3], { strictNegZero, field: "seq_hi", cell: 3 });
  const unixDay = decodeU24AsFloat(frame[4], { strictNegZero, field: "unix_day", cell: 4 });
  const secOfDay = decodeU24AsFloat(frame[5], { strictNegZero, field: "sec_of_day", cell: 5 });
  const ms = decodeU24AsFloat(frame[6], { strictNegZero, field: "ms", cell: 6 });
  const flagsProfile = decodeU24AsFloat(frame[7], { strictNegZero, field: "flags_profile", cell: 7 });
  const tickRate = decodeU16AsFloat(frame[8], { strictNegZero, field: "tick_rate", cell: 8 });
  return {
    magic,
    version,
    seqLo,
    seqHi,
    unixDay,
    secOfDay,
    ms,
    flagsProfile,
    flags16: flagsProfile & 0xFFFF,
    profileId: (flagsProfile >>> 16) & 0xFF,
    tickRate
  };
}

function decodeFooter(frame, strictNegZero) {
  const crcLo = decodeU16AsFloat(frame[1020], { strictNegZero, field: "crc_lo", cell: 1020 });
  const crcHi = decodeU16AsFloat(frame[1021], { strictNegZero, field: "crc_hi", cell: 1021 });
  const byteSize = decodeU16AsFloat(frame[1022], { strictNegZero, field: "byte_size", cell: 1022 });
  const magicEcho = decodeU16AsFloat(frame[1023], { strictNegZero, field: "magic_echo", cell: 1023 });
  return { crcLo, crcHi, byteSize, magicEcho, crc32: ((crcHi << 16) | crcLo) >>> 0 };
}

function validateAllFiniteNonSubnormal(frame, { fromCell, toCell }) {
  for (let i = fromCell; i <= toCell; i++) {
    assertFiniteNonSubnormal(frame[i], { field: `cell_${i}`, cell: i });
  }
}

function validateTrailerU16(frame, strictNegZero) {
  const out = [];
  for (let i = 1000; i <= 1019; i++) {
    out.push(decodeU16AsFloat(frame[i], { strictNegZero, field: `cell_${i}`, cell: i }));
  }
  return out;
}

function parseSecurityHeader(frame, strictNegZero) {
  const secProfile = decodeU16AsFloat(frame[1000], { strictNegZero, field: "sec_profile", cell: 1000 });
  const keyId = decodeU16AsFloat(frame[1001], { strictNegZero, field: "key_id", cell: 1001 });
  const secCounterLo = decodeU16AsFloat(frame[1002], { strictNegZero, field: "sec_counter_lo", cell: 1002 });
  const secCounterHi = decodeU16AsFloat(frame[1003], { strictNegZero, field: "sec_counter_hi", cell: 1003 });
  return {
    secProfile,
    keyId,
    secCounterLo,
    secCounterHi,
    secCounter32: ((secCounterHi << 16) | secCounterLo) >>> 0
  };
}

function replayTupleKey(identity, keyEpoch, keyId, direction, channel) {
  return `${identity}|${keyEpoch}|${keyId}|${direction}|${channel}`;
}

export function createReplayWindow(width = 64) {
  requireUInt("replay_window_width", width, 4096);
  if (width < 1) reject("E_INT_FIELD", "replay window width must be >= 1");
  return {
    width,
    maxSeen: null,
    seen: new Set()
  };
}

export function acceptReplayCounter(state, counterLike) {
  if (!state || typeof state !== "object" || !(state.seen instanceof Set)) {
    reject("E_INT_FIELD", "invalid replay window state");
  }
  const counter = typeof counterLike === "bigint" ? counterLike : BigInt(counterLike);
  if (counter < 0n) {
    return { accepted: false, reason: "negative" };
  }

  const width = BigInt(state.width);
  const key = counter.toString();

  if (state.maxSeen === null) {
    state.maxSeen = counter;
    state.seen.add(key);
    return { accepted: true, reason: "first" };
  }

  if (counter > state.maxSeen) {
    state.maxSeen = counter;
    const floor = state.maxSeen - width + 1n;
    for (const k of state.seen) {
      if (BigInt(k) < floor) state.seen.delete(k);
    }
    state.seen.add(key);
    return { accepted: true, reason: "new_high" };
  }

  const floor = state.maxSeen - width + 1n;
  if (counter < floor) {
    return { accepted: false, reason: "too_old" };
  }
  if (state.seen.has(key)) {
    return { accepted: false, reason: "replay" };
  }
  state.seen.add(key);
  return { accepted: true, reason: "in_window_new" };
}

function ensureReplayMap(replayState, profile) {
  if (!replayState || typeof replayState !== "object") {
    return new Map();
  }
  if (!replayState[profile]) replayState[profile] = new Map();
  return replayState[profile];
}

function enforceReplay({
  replayState,
  profile,
  tupleKey,
  counter,
  windowWidth
}) {
  const map = ensureReplayMap(replayState, profile);
  let state = map.get(tupleKey);
  if (!state) {
    state = createReplayWindow(windowWidth);
    map.set(tupleKey, state);
  }
  const decision = acceptReplayCounter(state, counter);
  if (!decision.accepted) {
    reject("E_REPLAY", "replay window reject", { tupleKey, counter: counter.toString(), reason: decision.reason });
  }
  return decision;
}

function writeU16CellAsFloat(dv, cellIndex, value) {
  requireUInt(`cell_${cellIndex}`, value, 0xFFFF);
  dv.setFloat32(cellIndex * 4, value, true);
}

function writeU24CellAsFloat(dv, cellIndex, value) {
  requireUInt(`cell_${cellIndex}`, value, 0xFFFFFF);
  dv.setFloat32(cellIndex * 4, value, true);
}

function buildBaseFrameBytes(options = {}) {
  const header = options.header ?? {};
  const security = options.security ?? {};

  const secProfile = security.secProfile ?? 0;
  if (![0, 1, 2].includes(secProfile)) {
    reject("E_SEC_PROFILE", "secProfile must be 0, 1, or 2", { secProfile });
  }

  const magic = header.magic ?? 56081;
  const version = header.version ?? 11;
  const seqLo = header.seqLo ?? 0;
  const seqHi = header.seqHi ?? 0;
  const unixDay = header.unixDay ?? 0;
  const secOfDay = header.secOfDay ?? 0;
  const ms = header.ms ?? 0;
  const profileId = header.profileId ?? 0;
  let flags16 = header.flags16 ?? 0;
  const tickRate = header.tickRate ?? 0;

  if (secProfile !== 0) flags16 |= SEC_TRAILER_PRESENT_MASK;
  else flags16 &= ~SEC_TRAILER_PRESENT_MASK;
  const flagsProfile = (((profileId & 0xFF) << 16) | (flags16 & 0xFFFF)) >>> 0;

  const wireBytes = new Uint8Array(DBP_BYTES);
  const dv = new DataView(wireBytes.buffer);

  writeU16CellAsFloat(dv, 0, magic);
  writeU16CellAsFloat(dv, 1, version);
  writeU24CellAsFloat(dv, 2, seqLo);
  writeU24CellAsFloat(dv, 3, seqHi);
  writeU24CellAsFloat(dv, 4, unixDay);
  writeU24CellAsFloat(dv, 5, secOfDay);
  writeU24CellAsFloat(dv, 6, ms);
  writeU24CellAsFloat(dv, 7, flagsProfile);
  writeU16CellAsFloat(dv, 8, tickRate);

  if (options.cells && typeof options.cells === "object") {
    for (const [k, v] of Object.entries(options.cells)) {
      const cell = Number(k);
      if (!Number.isInteger(cell) || cell < 0 || cell >= DBP_CELLS) continue;
      dv.setFloat32(cell * 4, Number(v), true);
    }
  }

  const secProfileVal = secProfile;
  const keyId = security.keyId ?? 0;
  const secCounter32 = (security.secCounter32 ?? 0) >>> 0;
  const secCounterLo = secCounter32 & 0xFFFF;
  const secCounterHi = (secCounter32 >>> 16) & 0xFFFF;

  writeU16CellAsFloat(dv, 1000, secProfileVal);
  writeU16CellAsFloat(dv, 1001, keyId);
  writeU16CellAsFloat(dv, 1002, secCounterLo);
  writeU16CellAsFloat(dv, 1003, secCounterHi);
  for (let i = 1004; i <= 1019; i++) writeU16CellAsFloat(dv, i, 0);

  const frame = floatArrayFromWireBytes(wireBytes);
  canonicalizeWriterCells(frame, { start: 0, end: DBP_CELLS });
  const canonicalBytes = wireBytesFromFloatArray(frame);
  return { wireBytes: canonicalBytes, secProfile: secProfileVal, flags16, flagsProfile, keyId, secCounter32 };
}

export function encodeFrame(options = {}) {
  const security = options.security ?? {};
  const s1 = options.s1 ?? {};
  const s2 = options.s2 ?? {};

  const built = buildBaseFrameBytes(options);
  const wireBytes = new Uint8Array(built.wireBytes);
  const dv = new DataView(wireBytes.buffer);

  if (built.secProfile === 1) {
    const key = asBytes(s1.key, "s1.key");
    if (key.length !== 32) reject("E_INT_FIELD", "s1.key must be 32 bytes");
    const macDomainTag = s1.macDomainTag ? asBytes(s1.macDomainTag, "s1.macDomainTag") : DEFAULT_MAC_DOMAIN_TAG;
    const tag = hmacSha256Tag(key, wireBytes.subarray(0, S1_MAC_INPUT_BYTES), macDomainTag);
    const words = packBytesToU16WordsLE(tag);
    for (let i = 0; i < 16; i++) {
      writeU16CellAsFloat(dv, 1004 + i, words[i] ?? 0);
    }
  } else if (built.secProfile === 2) {
    const key = asBytes(s2.key, "s2.key");
    if (key.length !== 32) reject("E_INT_FIELD", "s2.key must be 32 bytes");

    let nonce96;
    if (s2.nonce96) {
      nonce96 = asBytes(s2.nonce96, "s2.nonce96");
      if (nonce96.length !== 12) reject("E_INT_FIELD", "s2.nonce96 must be 12 bytes");
    } else {
      const salt32 = s2.sessionSalt32 ? asBytes(s2.sessionSalt32, "s2.sessionSalt32") : new Uint8Array(4);
      let ctr64;
      if (typeof s2.counter64 === "bigint") ctr64 = s2.counter64;
      else if (Number.isInteger(s2.counter64)) ctr64 = BigInt(s2.counter64 >>> 0);
      else ctr64 = BigInt(built.secCounter32 >>> 0);
      nonce96 = nonce96FromSalt32AndCtr64(salt32, ctr64);
    }

    const nonceWords = nonceWordsFromBytes(nonce96);
    for (let i = 0; i < 6; i++) writeU16CellAsFloat(dv, 1004 + i, nonceWords[i]);

    const profileClass = security.profileClass ?? s2.profileClass ?? "dbp-core";
    if (profileClass === "dbp-hardened-s2-mux") {
      const suiteId = (s2.suiteId ?? security.suiteId ?? 1) >>> 0;
      const keyEpoch = (s2.keyEpoch ?? security.keyEpoch ?? 0) >>> 0;
      writeU16CellAsFloat(dv, 1018, suiteId);
      writeU16CellAsFloat(dv, 1019, keyEpoch);
    } else {
      writeU16CellAsFloat(dv, 1018, 0);
      writeU16CellAsFloat(dv, 1019, 0);
    }

    const aad = getS2AadBytes(wireBytes);
    const plaintext = new Uint8Array(wireBytes.subarray(36, 4000));
    const algorithm = normalizeAeadAlgorithm(s2.algorithm ?? "aes-256-gcm");
    const { ciphertext, tag } = aeadEncrypt(algorithm, key, nonce96, aad, plaintext);
    wireBytes.set(ciphertext, 36);

    const tagWords = tagWordsFromBytes(tag);
    for (let i = 0; i < 8; i++) {
      writeU16CellAsFloat(dv, 1010 + i, tagWords[i]);
    }
  }

  const crc32 = crc32IsoHdlc(wireBytes.subarray(0, CRC_INPUT_BYTES));
  writeU16CellAsFloat(dv, 1020, crc32 & 0xFFFF);
  writeU16CellAsFloat(dv, 1021, (crc32 >>> 16) & 0xFFFF);
  writeU16CellAsFloat(dv, 1022, DBP_BYTES);
  const magic = decodeU16AsFloat(dv.getFloat32(0, true), { field: "magic", cell: 0 });
  writeU16CellAsFloat(dv, 1023, magic);

  return { wireBytes, crc32 };
}

function maybeParseMcbForOpaqueRanges(decryptedFrame, strictNegZero) {
  let mcbMagic = 0;
  try {
    mcbMagic = decodeU16AsFloat(decryptedFrame[660], { strictNegZero, field: "mcb_magic", cell: 660 });
  } catch {
    return [];
  }
  if (mcbMagic !== 0x4D43) return [];
  const parsed = parseMcb(decryptedFrame, { strictNegZero });
  return opaqueRangesFromMcb(parsed);
}

function cellInAnyRange(cell, ranges) {
  for (const r of ranges) {
    if (cell >= r.startCell && cell <= r.endCellInclusive) return true;
  }
  return false;
}

export function decodeFrame(wireBytesLike, options = {}) {
  const wireBytes = asBytes(wireBytesLike, "wireBytes");
  if (wireBytes.length !== DBP_BYTES) {
    reject("E_SHAPE", `frame must be exactly ${DBP_BYTES} bytes`, { length: wireBytes.length });
  }

  const strictNegZero = options.strictStructuralNegZero === true;
  const frame = floatArrayFromWireBytes(wireBytes);
  const header = decodeHeader(frame, strictNegZero);
  const footer = decodeFooter(frame, strictNegZero);

  if (footer.byteSize !== DBP_BYTES || footer.magicEcho !== header.magic) {
    reject("E_FOOTER", "footer sanity precheck failed", {
      byteSize: footer.byteSize,
      magicEcho: footer.magicEcho,
      magic: header.magic
    });
  }

  const secTrailerPresent = (header.flags16 & SEC_TRAILER_PRESENT_MASK) !== 0;
  const sec = parseSecurityHeader(frame, strictNegZero);

  if (secTrailerPresent) {
    if (sec.secProfile !== 1 && sec.secProfile !== 2) {
      reject("E_SEC_PROFILE", "invalid sec_profile for trailer-present frame", { secProfile: sec.secProfile });
    }
    validateTrailerU16(frame, strictNegZero);
  } else if (sec.secProfile !== 0) {
    reject("E_SEC_PROFILE", "sec_profile non-zero while SEC_TRAILER_PRESENT=0", { secProfile: sec.secProfile });
  }

  if (sec.secProfile === 2) {
    validateAllFiniteNonSubnormal(frame, { fromCell: 0, toCell: 8 });
    validateAllFiniteNonSubnormal(frame, { fromCell: 1000, toCell: 1023 });
  } else {
    validateAllFiniteNonSubnormal(frame, { fromCell: 0, toCell: 1023 });
  }

  const crc32Actual = crc32IsoHdlc(wireBytes.subarray(0, CRC_INPUT_BYTES));
  if (crc32Actual !== footer.crc32) {
    reject("E_CRC", "CRC mismatch", { expected: footer.crc32, actual: crc32Actual });
  }

  if (!secTrailerPresent || sec.secProfile === 0) {
    return {
      header,
      security: { secProfile: 0, keyId: 0, secCounter32: 0 },
      footer,
      wireBytes: new Uint8Array(wireBytes),
      frame
    };
  }

  const replayState = options.replayState ?? {};
  const replayWindow = Number.isInteger(options.replayWindow) ? options.replayWindow : 64;
  const direction = options.direction ?? 0;
  const channel = options.channel ?? 0;

  if (sec.secProfile === 1) {
    const s1 = options.s1 ?? {};
    const key = asBytes(s1.key, "s1.key");
    if (key.length !== 32) reject("E_INT_FIELD", "s1.key must be 32 bytes");
    const macDomainTag = s1.macDomainTag ? asBytes(s1.macDomainTag, "s1.macDomainTag") : DEFAULT_MAC_DOMAIN_TAG;

    const expectedTag = hmacSha256Tag(key, wireBytes.subarray(0, S1_MAC_INPUT_BYTES), macDomainTag);
    const gotWords = [];
    for (let i = 0; i < 16; i++) {
      gotWords.push(decodeU16AsFloat(frame[1004 + i], { strictNegZero, field: `s1_tag_word_${i}`, cell: 1004 + i }));
    }
    const gotTag = unpackU16WordsToBytesLE(gotWords, 32);
    if (!timingSafeEqualBytes(expectedTag, gotTag)) {
      reject("E_S1_TAG", "S1 tag mismatch");
    }

    const identity = s1.writerIdentity ?? options.writerIdentity ?? `key:${sec.keyId}`;
    const keyEpoch = s1.keyEpoch ?? options.keyEpoch ?? 0;
    const tupleKey = replayTupleKey(identity, keyEpoch, sec.keyId, direction, channel);
    enforceReplay({
      replayState,
      profile: "s1",
      tupleKey,
      counter: BigInt(sec.secCounter32),
      windowWidth: replayWindow
    });

    return {
      header,
      security: {
        secProfile: 1,
        keyId: sec.keyId,
        secCounter32: sec.secCounter32,
        replayCounter: BigInt(sec.secCounter32)
      },
      footer,
      wireBytes: new Uint8Array(wireBytes),
      frame
    };
  }

  const s2 = options.s2 ?? {};
  const key = asBytes(s2.key, "s2.key");
  if (key.length !== 32) reject("E_INT_FIELD", "s2.key must be 32 bytes");
  const algorithm = normalizeAeadAlgorithm(s2.algorithm ?? "aes-256-gcm");

  const nonceWords = [];
  for (let i = 0; i < 6; i++) {
    nonceWords.push(decodeU16AsFloat(frame[1004 + i], { strictNegZero, field: `nonce_word_${i}`, cell: 1004 + i }));
  }
  const tagWords = [];
  for (let i = 0; i < 8; i++) {
    tagWords.push(decodeU16AsFloat(frame[1010 + i], { strictNegZero, field: `tag_word_${i}`, cell: 1010 + i }));
  }
  const suiteId = decodeU16AsFloat(frame[1018], { strictNegZero, field: "suite_id", cell: 1018 });
  const keyEpoch = decodeU16AsFloat(frame[1019], { strictNegZero, field: "key_epoch", cell: 1019 });

  const profileClass = s2.profileClass ?? options.profileClass ?? "dbp-core";
  if (profileClass !== "dbp-hardened-s2-mux" && (suiteId !== 0 || keyEpoch !== 0)) {
    reject("E_RESERVED_POLICY", "sec_words[14..15] must be zero outside hardened-s2-mux", {
      suiteId,
      keyEpoch,
      profileClass
    });
  }

  const nonce96 = nonceBytesFromWords(nonceWords);
  const tag128 = tagBytesFromWords(tagWords);
  const ctr64 = ctr64FromNonce96(nonce96);

  if (s2.requireCounterMirror === true) {
    if (((Number(ctr64 & 0xFFFFFFFFn)) >>> 0) !== sec.secCounter32) {
      reject("E_RESERVED_POLICY", "sec_counter mirror mismatch", {
        secCounter32: sec.secCounter32,
        ctr64: ctr64.toString()
      });
    }
  }

  const aad = getS2AadBytes(wireBytes);
  const ciphertext = wireBytes.subarray(36, 4000);
  const plaintext = aeadDecrypt(algorithm, key, nonce96, aad, ciphertext, tag128);

  const decryptedWireBytes = new Uint8Array(wireBytes);
  decryptedWireBytes.set(plaintext, 36);
  const decryptedFrame = floatArrayFromWireBytes(decryptedWireBytes);

  const opaqueRanges = maybeParseMcbForOpaqueRanges(decryptedFrame, strictNegZero);
  for (let cell = 9; cell <= 999; cell++) {
    if (cellInAnyRange(cell, opaqueRanges)) continue;
    assertFiniteNonSubnormal(decryptedFrame[cell], { field: `cell_${cell}`, cell });
  }

  const identity = s2.writerIdentity ?? options.writerIdentity ?? `key:${sec.keyId}`;
  const replayKeyEpoch = profileClass === "dbp-hardened-s2-mux" ? keyEpoch : (s2.keyEpoch ?? options.keyEpoch ?? 0);
  const tupleKey = replayTupleKey(identity, replayKeyEpoch, sec.keyId, direction, channel);
  enforceReplay({
    replayState,
    profile: "s2",
    tupleKey,
    counter: ctr64,
    windowWidth: replayWindow
  });

  return {
    header,
    security: {
      secProfile: 2,
      keyId: sec.keyId,
      secCounter32: sec.secCounter32,
      nonce96,
      replayCounter: ctr64,
      suiteId,
      keyEpoch
    },
    footer,
    wireBytes: new Uint8Array(wireBytes),
    frame,
    decryptedWireBytes,
    decryptedFrame,
    opaqueRanges
  };
}

function mcbCoverageBytesExcludingCrc(frame) {
  const wire = wireBytesFromFloatArray(frame);
  const start = 660 * 4;
  const end = (683 + 1) * 4;
  const crcStart = 666 * 4;
  const crcEnd = (667 + 1) * 4;
  const out = new Uint8Array((end - start) - (crcEnd - crcStart));
  out.set(wire.subarray(start, crcStart), 0);
  out.set(wire.subarray(crcEnd, end), crcStart - start);
  return out;
}

function rangeForDonorBand(donorBand) {
  if (donorBand === 4) return [148, 275];
  if (donorBand === 5) return [276, 659];
  if (donorBand === 6) return [660, 999];
  return null;
}

export function parseMcb(frame, { strictNegZero = false } = {}) {
  if (!(frame instanceof Float32Array) || frame.length !== DBP_CELLS) {
    reject("E_SHAPE", `frame must be Float32Array(${DBP_CELLS})`);
  }

  const mcbMagic = decodeU16AsFloat(frame[660], { strictNegZero, field: "mcb_magic", cell: 660 });
  const mcbVersion = decodeU16AsFloat(frame[661], { strictNegZero, field: "mcb_version", cell: 661 });
  const leaseSeqLo = decodeU24AsFloat(frame[662], { strictNegZero, field: "lease_seq_lo", cell: 662 });
  const leaseSeqHi = decodeU24AsFloat(frame[663], { strictNegZero, field: "lease_seq_hi", cell: 663 });
  const dir = decodeU16AsFloat(frame[664], { strictNegZero, field: "dir", cell: 664 });
  const sliceCount = decodeU16AsFloat(frame[665], { strictNegZero, field: "slice_count", cell: 665 });
  const mcbCrcLo = decodeU16AsFloat(frame[666], { strictNegZero, field: "mcb_crc_lo", cell: 666 });
  const mcbCrcHi = decodeU16AsFloat(frame[667], { strictNegZero, field: "mcb_crc_hi", cell: 667 });
  const mcbCrc32 = ((mcbCrcHi << 16) | mcbCrcLo) >>> 0;

  if (mcbMagic !== 0x4D43) reject("E_MCB_INVALID", "invalid MCB magic", { mcbMagic });
  if (mcbVersion !== 1) reject("E_MCB_INVALID", "unsupported MCB version", { mcbVersion });
  if (dir !== 0 && dir !== 1) reject("E_MCB_INVALID", "invalid MCB direction", { dir });
  if (sliceCount > 8) reject("E_MCB_INVALID", "slice_count > 8", { sliceCount });

  if (mcbCrc32 !== 0) {
    const cover = mcbCoverageBytesExcludingCrc(frame);
    const actual = crc32IsoHdlc(cover);
    if (actual !== mcbCrc32) {
      reject("E_MCB_INVALID", "MCB CRC mismatch", { expected: mcbCrc32, actual });
    }
  }

  const slices = [];
  for (let i = 0; i < sliceCount; i++) {
    const desc0 = decodeU24AsFloat(frame[668 + i * 2], { strictNegZero, field: `desc0_${i}`, cell: 668 + i * 2 });
    const desc1 = decodeU24AsFloat(frame[669 + i * 2], { strictNegZero, field: `desc1_${i}`, cell: 669 + i * 2 });

    const donorBand = (desc0 >>> 16) & 0xFF;
    const laneType = (desc0 >>> 8) & 0xFF;
    const flags8 = desc0 & 0xFF;
    const startCell = (desc1 >>> 12) & 0xFFF;
    const cellCount = desc1 & 0xFFF;
    const endCellInclusive = startCell + cellCount - 1;

    if (flags8 & 0xF8) reject("E_MCB_INVALID", "reserved flags8 bits must be zero", { i, flags8 });
    if (cellCount === 0) reject("E_MCB_INVALID", "cell_count must be non-zero", { i });
    if (startCell > 1023) reject("E_MCB_INVALID", "start_cell out of range", { i, startCell });
    if (startCell + cellCount > 1024) {
      reject("E_MCB_INVALID", "slice exceeds frame bounds", { i, startCell, cellCount });
    }

    const donorRange = rangeForDonorBand(donorBand);
    if (!donorRange) reject("E_MCB_INVALID", "invalid donor_band", { i, donorBand });
    if (startCell < donorRange[0] || endCellInclusive > donorRange[1]) {
      reject("E_MCB_INVALID", "slice not contained in donor band", {
        i,
        donorBand,
        startCell,
        endCellInclusive,
        donorRange
      });
    }

    if (donorBand === 4 && ((flags8 & 0x01) === 0)) {
      reject("E_MCB_INVALID", "donor_band=4 requires quantum_inactive=1", { i, flags8 });
    }

    for (const prev of slices) {
      const overlap = !(endCellInclusive < prev.startCell || startCell > prev.endCellInclusive);
      if (overlap) {
        reject("E_MCB_INVALID", "slice overlap", { i, startCell, endCellInclusive, prev });
      }
    }

    slices.push({
      index: i,
      donorBand,
      laneType,
      flags8,
      startCell,
      cellCount,
      endCellInclusive
    });
  }

  return {
    mcbMagic,
    mcbVersion,
    leaseSeqLo,
    leaseSeqHi,
    leaseSeq: (BigInt(leaseSeqHi) << 24n) | BigInt(leaseSeqLo),
    dir,
    sliceCount,
    mcbCrc32,
    slices
  };
}

export function opaqueRangesFromMcb(mcb) {
  if (!mcb || !Array.isArray(mcb.slices)) return [];
  return mcb.slices
    .filter((s) => s.laneType === 4)
    .map((s) => ({ startCell: s.startCell, endCellInclusive: s.endCellInclusive, cellCount: s.cellCount }));
}

export function encodeLaneHeaderV1(input = {}) {
  const laneId = input.laneId ?? 0;
  const laneType = input.laneType ?? 0;
  const msgId = input.msgId ?? 0;
  const fragIndex = input.fragIndex ?? 0;
  const fragTotal = input.fragTotal ?? 1;
  const fragLen = input.fragLen ?? 0;
  const flags = input.flags ?? 0;
  const totalLen = input.totalLen ?? fragLen;
  const totalCrc32 = input.totalCrc32 ?? 0;
  const msgNonce32 = input.msgNonce32 ?? input.nonceCommit32 ?? 0;

  requireUInt("laneId", laneId, 0xFFFF);
  requireUInt("laneType", laneType, 0xFFFF);
  requireUInt("msgId", msgId, 0xFFFFFFFF);
  requireUInt("fragIndex", fragIndex, 0xFFFF);
  requireUInt("fragTotal", fragTotal, 0xFFFF);
  requireUInt("fragLen", fragLen, 0xFFFF);
  requireUInt("flags", flags, 0xFF);
  requireUInt("totalLen", totalLen, 0xFFFFFFFF);
  requireUInt("totalCrc32", totalCrc32 >>> 0, 0xFFFFFFFF);
  requireUInt("msgNonce32", msgNonce32 >>> 0, 0xFFFFFFFF);

  if (fragTotal < 1) reject("E_ABB_MANIFEST", "fragTotal must be >= 1");
  if (fragIndex >= fragTotal) reject("E_ABB_MANIFEST", "fragIndex must be < fragTotal");

  const out = new Uint8Array(DBP_LANE_HEADER_V1_BYTES);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, DBP_LANE_HEADER_V1_MAGIC, true);
  dv.setUint8(2, DBP_LANE_HEADER_V1_VERSION);
  dv.setUint8(3, flags & 0xFF);
  dv.setUint16(4, laneId, true);
  dv.setUint16(6, laneType, true);
  dv.setUint32(8, msgId >>> 0, true);
  dv.setUint16(12, fragIndex, true);
  dv.setUint16(14, fragTotal, true);
  dv.setUint16(16, fragLen, true);
  dv.setUint16(18, 0, true); // reserved
  dv.setUint32(20, totalLen >>> 0, true);
  dv.setUint32(24, totalCrc32 >>> 0, true);
  dv.setUint32(28, msgNonce32 >>> 0, true);
  return out;
}

export function decodeLaneHeaderV1(bytesLike, offset = 0) {
  const bytes = asBytes(bytesLike, "lane_header_bytes");
  const off = offset | 0;
  if (off < 0 || off + DBP_LANE_HEADER_V1_BYTES > bytes.length) {
    reject("E_ABB_MANIFEST", "insufficient bytes for lane header", { offset: off, length: bytes.length });
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset + off, DBP_LANE_HEADER_V1_BYTES);
  const magic = dv.getUint16(0, true);
  const version = dv.getUint8(2);
  const flags = dv.getUint8(3);
  const laneId = dv.getUint16(4, true);
  const laneType = dv.getUint16(6, true);
  const msgId = dv.getUint32(8, true);
  const fragIndex = dv.getUint16(12, true);
  const fragTotal = dv.getUint16(14, true);
  const fragLen = dv.getUint16(16, true);
  const reserved = dv.getUint16(18, true);
  const totalLen = dv.getUint32(20, true);
  const totalCrc32 = dv.getUint32(24, true);
  const msgNonce32 = dv.getUint32(28, true);

  if (magic !== DBP_LANE_HEADER_V1_MAGIC) {
    reject("E_ABB_MANIFEST", "invalid lane header magic", { magic });
  }
  if (version !== DBP_LANE_HEADER_V1_VERSION) {
    reject("E_ABB_MANIFEST", "unsupported lane header version", { version });
  }
  if (reserved !== 0) {
    reject("E_ABB_MANIFEST", "reserved lane header bytes must be zero", { reserved });
  }
  if (fragTotal < 1 || fragIndex >= fragTotal) {
    reject("E_ABB_MANIFEST", "invalid fragment indexing", { fragIndex, fragTotal });
  }

  return {
    magic,
    version,
    flags,
    laneId,
    laneType,
    msgId,
    fragIndex,
    fragTotal,
    fragLen,
    totalLen,
    totalCrc32: totalCrc32 >>> 0,
    msgNonce32: msgNonce32 >>> 0,
    // Backward-compat alias for pre-v1.1 naming in local tools.
    nonceCommit32: msgNonce32 >>> 0
  };
}

export function laneReassemblyTimeoutMsFromTickRate(tickRate, frames = 3) {
  requireUInt("tickRate", tickRate, 0xFFFF);
  requireUInt("frames", frames, 0xFFFF);
  if (tickRate === 0) return 1000;
  return Math.max(1, Math.ceil((1000 * frames) / tickRate));
}

export function reassembleLaneFragmentsV1(fragments, { nowMs = Date.now(), timeoutMs = 0 } = {}) {
  if (!Array.isArray(fragments) || fragments.length === 0) {
    return { complete: false, reason: "no_fragments" };
  }

  const parsed = fragments.map((frag, index) => {
    const header = frag.header ?? decodeLaneHeaderV1(frag.headerBytes ?? frag.bytes ?? frag);
    const payload = asBytes(frag.payload ?? frag.payloadBytes ?? new Uint8Array(), `frag_${index}_payload`);
    if (payload.length !== header.fragLen) {
      reject("E_ABB_MANIFEST", "fragment payload length mismatch", {
        index,
        fragLen: header.fragLen,
        payloadLen: payload.length
      });
    }
    const ts = Number.isFinite(frag.recvTsMs) ? Number(frag.recvTsMs) : nowMs;
    return { header, payload, recvTsMs: ts };
  });

  const first = parsed[0].header;
  const key = `${first.laneId}|${first.msgId}|${first.msgNonce32}`;
  const byIndex = new Map();
  let latestTs = parsed[0].recvTsMs;

  for (const item of parsed) {
    const h = item.header;
    const same =
      h.laneId === first.laneId &&
      h.laneType === first.laneType &&
      h.msgId === first.msgId &&
      h.fragTotal === first.fragTotal &&
      h.totalLen === first.totalLen &&
      h.totalCrc32 === first.totalCrc32 &&
      h.msgNonce32 === first.msgNonce32;
    if (!same) {
      return { complete: false, reason: "incompatible_fragments", key };
    }
    if (byIndex.has(h.fragIndex)) {
      return { complete: false, reason: "duplicate_fragment", key, fragIndex: h.fragIndex };
    }
    byIndex.set(h.fragIndex, item.payload);
    if (item.recvTsMs > latestTs) latestTs = item.recvTsMs;
  }

  if (timeoutMs > 0 && (nowMs - latestTs) > timeoutMs) {
    return { complete: false, reason: "timeout", key };
  }

  if (byIndex.size !== first.fragTotal) {
    return { complete: false, reason: "incomplete", key, have: byIndex.size, need: first.fragTotal };
  }

  let total = 0;
  for (let i = 0; i < first.fragTotal; i++) {
    const p = byIndex.get(i);
    if (!p) return { complete: false, reason: "missing_index", key, missing: i };
    total += p.length;
  }
  if (total !== first.totalLen) {
    return { complete: false, reason: "total_length_mismatch", key, total, expected: first.totalLen };
  }

  const message = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < first.fragTotal; i++) {
    const p = byIndex.get(i);
    message.set(p, off);
    off += p.length;
  }
  const crc = crc32IsoHdlc(message);
  if ((crc >>> 0) !== (first.totalCrc32 >>> 0)) {
    return { complete: false, reason: "message_crc_mismatch", key, crc, expected: first.totalCrc32 >>> 0 };
  }

  return {
    complete: true,
    key,
    header: first,
    messageBytes: message,
    totalCrc32: crc >>> 0
  };
}
