import assert from "node:assert/strict";
import test from "node:test";
import {
  CID_PREFIX,
  PAYLOAD_LEN,
  PUBLIC_KEY_LEN,
  SIGNATURE_LEN,
  SIGNED_LEN,
  decodePayload,
  encodePayload,
  verifyAfirReceipt,
} from "../src/afir.js";

function fields() {
  const chunk_cid = new Uint8Array(36);
  chunk_cid.set(CID_PREFIX);
  return {
    policy_id: new Uint8Array(16).fill(1),
    model_fp: new Uint8Array(32).fill(2),
    chunk_cid,
    input_hash: new Uint8Array(32).fill(3),
    output_hash: new Uint8Array(32).fill(4),
    session_nonce: new Uint8Array(16).fill(5),
    timestamp: 1_700_000_000n,
  };
}

test("the signed block is 174 plus 3309 bytes", () => {
  assert.equal(PAYLOAD_LEN, 174);
  assert.equal(SIGNATURE_LEN, 3309);
  assert.equal(SIGNED_LEN, 3483);
  assert.equal(encodePayload(fields()).length, 174);
});

test("decode reads version, profile, and the seven fields", () => {
  const body = decodePayload(encodePayload(fields()));
  assert.equal(body.version, 0x01);
  assert.equal(body.profile, 0x01);
  assert.equal(body.timestamp, 1_700_000_000n);
  assert.deepEqual(body.policy_id, fields().policy_id);
});

test("a chunk cid without 01 55 1e 20 is refused", () => {
  const bad = fields();
  bad.chunk_cid = new Uint8Array(36);
  assert.throws(() => encodePayload(bad), /CHUNK_CID/);
});

test("an all-zero session nonce is refused", () => {
  const bad = fields();
  bad.session_nonce = new Uint8Array(16);
  assert.throws(() => encodePayload(bad), /NONCE/);
});

test("verify forwards the host public key and does not sign", () => {
  const signed = new Uint8Array(SIGNED_LEN);
  signed.set(encodePayload(fields()));
  const hostPublicKey = new Uint8Array(PUBLIC_KEY_LEN).fill(9);
  const expectationJson = "{}";
  let seen;
  const result = verifyAfirReceipt(
    (bytes, key, expectation) => {
      seen = { bytes, key, expectation };
      return "{\"version\":1}";
    },
    signed,
    hostPublicKey,
    expectationJson,
  );
  assert.equal(result, "{\"version\":1}");
  assert.equal(seen.bytes, signed);
  assert.equal(seen.key, hostPublicKey);
  assert.equal(seen.expectation, expectationJson);
});

test("verify refuses a short signed buffer", () => {
  assert.throws(
    () => verifyAfirReceipt(() => "", new Uint8Array(10), new Uint8Array(PUBLIC_KEY_LEN), "{}"),
    /LENGTH/,
  );
});
