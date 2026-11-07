export const VERSION: 0x01;
export const PROFILE_MLDSA65: 0x01;
export const PAYLOAD_LEN: 174;
export const SIGNATURE_LEN: 3309;
export const SIGNED_LEN: 3483;
export const PUBLIC_KEY_LEN: 1952;
export const CID_PREFIX: readonly [0x01, 0x55, 0x1e, 0x20];
export const CID_LEN: 36;
export const CONTEXT: "ARKHE_AFIR_RECEIPT_V1";

export class AfirShapeError extends Error {
  readonly code: string;
}

export interface AfirBody {
  version: 0x01;
  profile: 0x01;
  policy_id: Uint8Array;
  model_fp: Uint8Array;
  chunk_cid: Uint8Array;
  input_hash: Uint8Array;
  output_hash: Uint8Array;
  session_nonce: Uint8Array;
  timestamp: bigint;
}

export interface AfirFields {
  policy_id: Uint8Array;
  model_fp: Uint8Array;
  chunk_cid: Uint8Array;
  input_hash: Uint8Array;
  output_hash: Uint8Array;
  session_nonce: Uint8Array;
  timestamp: bigint;
}

export type VerifyAfirReceipt = (
  signed: Uint8Array,
  publicKey: Uint8Array,
  expectationJson: string,
) => unknown;

export function decodePayload(bytes: Uint8Array): AfirBody;
export function encodePayload(fields: AfirFields): Uint8Array;
export function verifyAfirReceipt(
  verify: VerifyAfirReceipt,
  signed: Uint8Array,
  hostPublicKey: Uint8Array,
  expectationJson: string,
): unknown;
