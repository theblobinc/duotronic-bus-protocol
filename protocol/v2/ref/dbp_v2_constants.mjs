// DBP v2 draft reference constants.
// This file intentionally avoids crypto and parsing side effects; it is a small registry for implementers.

export const DBP2 = Object.freeze({
  WIRE_CLASS: 'DBP2-F4096',
  BYTES: 4096,
  CELLS: 1024,
  MAGIC_HEX: '0xDB20',
  MAGIC_DEC: 56096,
  VERSION: 20,
  MCB2_MAGIC_HEX: '0xD2B2',
  MCB2_MAGIC_DEC: 53938,
  MCB2_VERSION: 2,
});

export const DBP2_DIRECTIONS = Object.freeze({
  DOWNLINK: 0,
  UPLINK: 1,
  PEER: 2,
  LOCAL: 3,
});

export const DBP2_BANDS = Object.freeze({
  HEADER: [0, 8],
  BAND1_CONTROL: [9, 19],
  BAND2_DIGITAL_OR_LANE: [20, 83],
  BAND3_DIGITAL_OR_LANE: [84, 147],
  BAND4_WITNESS: [148, 275],
  BAND5_WITNESS: [276, 659],
  BAND6_MUX: [660, 999],
  MCB2: [660, 683],
  SECURITY_TRAILER: [1000, 1019],
  FOOTER: [1020, 1023],
});

export const DBP2_LANE_TYPES = Object.freeze({
  DIGITAL_U24: 1,
  ANALOG_F32: 2,
  QUANTUM_PAIR: 3,
  OPAQUE_BYTES: 4,
  WITNESS8_DENSE: 5,
  WSB2_SPARSE: 6,
  DPFC_OBJECT_REF: 7,
  GCD_JUMP_GATE: 8,
  DW_SSM_EVENT: 9,
  SEMANTIC_DESCRIPTOR: 10,
});

export const DBP2_PRESENCE_STATUS = Object.freeze({
  STRUCTURALLY_ABSENT: 'structurally_absent',
  PRESENT_UNKNOWN: 'present_unknown',
  TOKEN_FREE_ABSENT: 'token_free_absent',
  PRESENT_ZERO_VALUE: 'present_zero_value',
  PRESENT_NONZERO_VALUE: 'present_nonzero_value',
  PRESENT_INVALID: 'present_invalid',
  REJECTED_UNTRUSTED: 'rejected_untrusted',
});

export const DBP2_TRUST_STATUS = Object.freeze({
  RAW: 'raw',
  TRANSPORT_VALIDATED: 'transport_validated',
  SEMANTIC_VALIDATED: 'semantic_validated',
  CANONICALIZED: 'canonicalized',
  TRUSTED_FOR_LOOKUP: 'trusted_for_lookup',
  TRUSTED_FOR_RECURRENCE: 'trusted_for_recurrence',
  TRUSTED_FOR_PROMOTION: 'trusted_for_promotion',
  REJECTED: 'rejected',
});

export const DBP2_VALIDATION_ORDER = Object.freeze([
  'shape_validation',
  'structural_field_validation',
  'crc_or_integrity_validation',
  'replay_validation',
  'decrypt_if_s2',
  'lane_manifest_validation',
  'payload_decode',
  'witness_or_wsb2_validation',
  'family_registry_lookup',
  'normalizer_execution',
  'canonicalization',
  'policy_gate',
]);

export function isAuthorityAllowed({ transportValid, canonicalizationResult, policyMode, confidence, requestedAuthority, policyLimit }) {
  if (!transportValid) return 0;
  if (!['canonical_success', 'canonical_success_low_confidence'].includes(canonicalizationResult)) return 0;
  if (['transport_bypass', 'full_bypass'].includes(policyMode)) return 0;
  return Math.max(0, Math.min(Number(confidence ?? 0), Number(requestedAuthority ?? 0), Number(policyLimit ?? 1)));
}
