/** AFiR v1 body and signed lengths from arkhe-verify-core::afir. */

export const VERSION = 0x01;
export const PROFILE_MLDSA65 = 0x01;
export const PAYLOAD_LEN = 174;
export const SIGNATURE_LEN = 3309;
export const SIGNED_LEN = PAYLOAD_LEN + SIGNATURE_LEN;
export const PUBLIC_KEY_LEN = 1952;
export const CID_PREFIX = Object.freeze([0x01, 0x55, 0x1e, 0x20]);
export const CID_LEN = 36;
export const CONTEXT = "ARKHE_AFIR_RECEIPT_V1";

const FIELD = Object.freeze({
  policy_id: 16,
  model_fp: 32,
  chunk_cid: 36,
  input_hash: 32,
  output_hash: 32,
  session_nonce: 16,
});

export class AfirShapeError extends Error {
  constructor(code) {
    super(code);
    this.name = "AfirShapeError";
    this.code = code;
  }
}

function copyField(name, value) {
  const size = FIELD[name];
  if (!(value instanceof Uint8Array) || value.length !== size) {
    throw new AfirShapeError(name.toUpperCase());
  }
  return value;
}

function prefixMatches(cid) {
  return CID_PREFIX.every((byte, index) => cid[index] === byte);
}

/**
 * Structural body only. A decoded body is not a verified receipt.
 * @param {Uint8Array} bytes
 */
export function decodePayload(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== PAYLOAD_LEN) {
    throw new AfirShapeError("LENGTH");
  }
  if (bytes[0] !== VERSION) throw new AfirShapeError("VERSION");
  if (bytes[1] !== PROFILE_MLDSA65) throw new AfirShapeError("PROFILE");
  let at = 2;
  const take = (size) => {
    const part = bytes.subarray(at, at + size);
    at += size;
    return new Uint8Array(part);
  };
  const receipt = {
    version: VERSION,
    profile: PROFILE_MLDSA65,
    policy_id: take(FIELD.policy_id),
    model_fp: take(FIELD.model_fp),
    chunk_cid: take(FIELD.chunk_cid),
    input_hash: take(FIELD.input_hash),
    output_hash: take(FIELD.output_hash),
    session_nonce: take(FIELD.session_nonce),
    timestamp: new DataView(bytes.buffer, bytes.byteOffset + at, 8).getBigUint64(0),
  };
  if (!prefixMatches(receipt.chunk_cid)) throw new AfirShapeError("CHUNK_CID");
  if (receipt.session_nonce.every((byte) => byte === 0)) throw new AfirShapeError("NONCE");
  return receipt;
}

/**
 * Writes the 174-byte body. Does not sign it.
 * @param {{
 *   policy_id: Uint8Array,
 *   model_fp: Uint8Array,
 *   chunk_cid: Uint8Array,
 *   input_hash: Uint8Array,
 *   output_hash: Uint8Array,
 *   session_nonce: Uint8Array,
 *   timestamp: bigint,
 * }} fields
 */
export function encodePayload(fields) {
  const policy_id = copyField("policy_id", fields.policy_id);
  const model_fp = copyField("model_fp", fields.model_fp);
  const chunk_cid = copyField("chunk_cid", fields.chunk_cid);
  const input_hash = copyField("input_hash", fields.input_hash);
  const output_hash = copyField("output_hash", fields.output_hash);
  const session_nonce = copyField("session_nonce", fields.session_nonce);
  if (typeof fields.timestamp !== "bigint" || fields.timestamp < 0n || fields.timestamp > 0xffffffffffffffffn) {
    throw new AfirShapeError("TIMESTAMP");
  }
  if (!prefixMatches(chunk_cid)) throw new AfirShapeError("CHUNK_CID");
  if (session_nonce.every((byte) => byte === 0)) throw new AfirShapeError("NONCE");
  const out = new Uint8Array(PAYLOAD_LEN);
  out[0] = VERSION;
  out[1] = PROFILE_MLDSA65;
  let at = 2;
  for (const part of [policy_id, model_fp, chunk_cid, input_hash, output_hash, session_nonce]) {
    out.set(part, at);
    at += part.length;
  }
  new DataView(out.buffer).setBigUint64(at, fields.timestamp);
  return out;
}

/**
 * Forwards a 3483-byte signed receipt and the host public key to the
 * `verify_afir_receipt` export of arkhe-verify-wasm. This module does not
 * verify ML-DSA-65 itself and does not emit a receipt.
 *
 * @param {(signed: Uint8Array, publicKey: Uint8Array, expectationJson: string) => unknown} verify
 * @param {Uint8Array} signed
 * @param {Uint8Array} hostPublicKey
 * @param {string} expectationJson
 */
export function verifyAfirReceipt(verify, signed, hostPublicKey, expectationJson) {
  if (typeof verify !== "function") throw new TypeError("verify_afir_receipt binding required");
  if (!(signed instanceof Uint8Array) || signed.length !== SIGNED_LEN) {
    throw new AfirShapeError("LENGTH");
  }
  if (!(hostPublicKey instanceof Uint8Array) || hostPublicKey.length !== PUBLIC_KEY_LEN) {
    throw new AfirShapeError("PUBLIC_KEY");
  }
  if (typeof expectationJson !== "string") throw new AfirShapeError("EXPECTATION_JSON");
  return verify(signed, hostPublicKey, expectationJson);
}
