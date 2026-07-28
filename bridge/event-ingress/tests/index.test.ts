import { afterEach, expect, test } from "bun:test";

import worker from "../src/index";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function toPem(bytes: ArrayBuffer): string {
  const base64 = Buffer.from(bytes).toString("base64");
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

async function signedRequest(contentLength: boolean): Promise<{
  publicKey: string;
  request: Request;
}> {
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
  const body = '{"event":"meeting.started","meeting_id":"room-1"}';
  const bytes = new TextEncoder().encode(body);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    keys.privateKey,
    bytes,
  );
  const headers = new Headers({
    "content-type": "application/json",
    "rtk-signature": Buffer.from(signature).toString("base64"),
    "rtk-uuid": "delivery-a",
    "rtk-webhook-id": "webhook-a",
  });
  if (contentLength) {
    headers.set("content-length", String(bytes.byteLength));
  }
  return {
    publicKey: toPem(await crypto.subtle.exportKey("spki", keys.publicKey)),
    request: new Request("https://bridge.test/webhook/realtimekit", {
      method: "POST",
      headers,
      body,
    }),
  };
}

test("accepts a valid signed webhook without Content-Length", async () => {
  const { publicKey, request } = await signedRequest(false);
  globalThis.fetch = Object.assign(
    async () => Response.json({ success: true, data: { publicKey } }),
    { preconnect: originalFetch.preconnect },
  );
  const receipts: unknown[] = [];
  const response = await worker.fetch(
    request,
    {
      REALTIMEKIT_WEBHOOK_PUBLIC_KEY_URL:
        "https://api.realtime.cloudflare.com/.well-known/webhooks.json",
      EVENT_QUEUE: {
        send: async (receipt: unknown) => {
          receipts.push(receipt);
        },
      },
    } as never,
  );

  expect(response.status).toBe(202);
  expect(receipts).toHaveLength(1);
  expect(receipts[0]).toMatchObject({
    signature_status: "verified",
    dedupe_key: "realtimekit:delivery-a",
  });
});

test("returns a controlled 401 for a malformed signature", async () => {
  globalThis.fetch = Object.assign(
    async () =>
      Response.json({
        success: true,
        data: { publicKey: "not-a-public-key" },
      }),
    { preconnect: originalFetch.preconnect },
  );
  const response = await worker.fetch(
    new Request("https://bridge.test/webhook/realtimekit", {
      method: "POST",
      headers: {
        "rtk-signature": "not-base64",
        "rtk-uuid": "delivery-a",
        "rtk-webhook-id": "webhook-a",
      },
      body: "{}",
    }),
    {
      REALTIMEKIT_WEBHOOK_PUBLIC_KEY_URL:
        "https://api.realtime.cloudflare.com/.well-known/webhooks.json",
      EVENT_QUEUE: { send: async () => undefined },
    } as never,
  );

  expect(response.status).toBe(401);
});
