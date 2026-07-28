interface RealtimeKitKeyResponse {
  success: boolean;
  data: { publicKey: string };
}

interface RealtimeKitPayload {
  event?: string;
  [key: string]: unknown;
}

interface VerifiedEventInputV1 {
  schema_version: number;
  upstream: {
    provider: string;
    source: string;
    event_type: string;
    event_id: string;
    subscription_id: string;
  };
  upstream_schema_version: number;
  occurred_at: string;
  received_at: string;
  dedupe_key: string;
  signature_status: "verified";
  resource_refs: unknown[];
  payload: RealtimeKitPayload;
}

type EventIngressEnv = Omit<Env, "EVENT_QUEUE"> & {
  EVENT_QUEUE: Queue<VerifiedEventInputV1>;
};

const verifiedDeliveryBrand = Symbol("verified-delivery");

interface VerifiedDelivery {
  readonly deliveryId: string;
  readonly webhookId: string;
  readonly [verifiedDeliveryBrand]: true;
}

const MAX_WEBHOOK_BYTES = 1_048_576;
import { verifySignature } from "./signature";

export default {
  async fetch(request: Request, env: EventIngressEnv): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/webhook/realtimekit") {
      return new Response("Not found", { status: 404 });
    }

    const signature = request.headers.get("rtk-signature");
    const deliveryId = request.headers.get("rtk-uuid");
    const webhookId = request.headers.get("rtk-webhook-id");
    if (!signature || !deliveryId || !webhookId) {
      return new Response("Missing RealtimeKit delivery headers", { status: 400 });
    }

    const contentLengthHeader = request.headers.get("content-length");
    let contentLength: number | undefined;
    if (contentLengthHeader !== null) {
      contentLength = Number(contentLengthHeader);
      if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
        return new Response("Invalid Content-Length", { status: 400 });
      }
      if (contentLength > MAX_WEBHOOK_BYTES) {
        return new Response("Webhook body too large", { status: 413 });
      }
    }

    // Signature verification must use the exact bytes received. Parse only
    // after verification so JSON normalization cannot change signed content.
    const rawBody = await request.arrayBuffer();
    if (rawBody.byteLength > MAX_WEBHOOK_BYTES) {
      return new Response("Webhook body too large", { status: 413 });
    }
    if (contentLength !== undefined && rawBody.byteLength !== contentLength) {
      return new Response("Content-Length mismatch", { status: 400 });
    }
    let keyResponse: Response;
    try {
      keyResponse = await fetch(env.REALTIMEKIT_WEBHOOK_PUBLIC_KEY_URL);
    } catch {
      return new Response("Public key unavailable", { status: 503 });
    }
    if (!keyResponse.ok) {
      return new Response("Public key unavailable", { status: 503 });
    }
    const key = await keyResponse.json<RealtimeKitKeyResponse>();
    if (!key.success || !key.data?.publicKey) {
      return new Response("Public key response invalid", { status: 503 });
    }
    const delivery = await verifiedDelivery(
      key.data.publicKey,
      signature,
      rawBody,
      deliveryId,
      webhookId,
    );
    if (delivery === null) {
      return new Response("Invalid signature", { status: 401 });
    }

    let payload: RealtimeKitPayload;
    try {
      payload = JSON.parse(new TextDecoder().decode(rawBody));
    } catch {
      return new Response("Invalid JSON", { status: 400 });
    }
    const receivedAt = new Date().toISOString();
    const receipt = verifiedEventReceipt(delivery, payload, receivedAt);

    // A successful response is emitted only after Queue accepted the receipt.
    // The local ledger performs durable delivery-ID deduplication before a
    // pull consumer is allowed to acknowledge the Queue message.
    try {
      await env.EVENT_QUEUE.send(receipt, { contentType: "json" });
    } catch {
      return new Response("Event Queue unavailable", { status: 503 });
    }
    return new Response(null, { status: 202 });
  },
} satisfies ExportedHandler<EventIngressEnv>;

async function verifiedDelivery(
  publicKey: string,
  signature: string,
  rawBody: ArrayBuffer,
  deliveryId: string,
  webhookId: string,
): Promise<VerifiedDelivery | null> {
  try {
    if (!(await verifySignature(publicKey, signature, rawBody))) {
      return null;
    }
  } catch {
    return null;
  }
  return {
    deliveryId,
    webhookId,
    [verifiedDeliveryBrand]: true,
  };
}

function verifiedEventReceipt(
  delivery: VerifiedDelivery,
  payload: RealtimeKitPayload,
  receivedAt: string,
): VerifiedEventInputV1 {
  return {
      schema_version: 1,
      upstream: {
        provider: "cloudflare",
        source: "realtimekit",
        event_type: payload.event ?? "unknown",
        event_id: delivery.deliveryId,
        subscription_id: delivery.webhookId,
      },
      upstream_schema_version: 1,
      occurred_at: receivedAt,
      received_at: receivedAt,
      dedupe_key: `realtimekit:${delivery.deliveryId}`,
      signature_status: "verified",
      resource_refs: [],
      payload,
  };
}
