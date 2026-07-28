import { expect, test } from "bun:test";

import { verifySignature } from "../src/signature";

function toPem(bytes: ArrayBuffer): string {
  const base64 = Buffer.from(bytes).toString("base64");
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

test("RealtimeKit verification binds the signature to the exact raw bytes", async () => {
  const keys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const rawBody = new TextEncoder().encode(
    '{"event":"meeting.started","meeting_id":"room-1"}',
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    keys.privateKey,
    rawBody,
  );
  const publicKey = await crypto.subtle.exportKey("spki", keys.publicKey);
  const encodedSignature = Buffer.from(signature).toString("base64");

  expect(
    await verifySignature(toPem(publicKey), encodedSignature, rawBody.buffer),
  ).toBe(true);

  const normalizedBody = new TextEncoder().encode(
    '{"meeting_id":"room-1","event":"meeting.started"}',
  );
  expect(
    await verifySignature(
      toPem(publicKey),
      encodedSignature,
      normalizedBody.buffer,
    ),
  ).toBe(false);
});
