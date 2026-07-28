function cleanPublicKey(pem: string): string {
  return pem
    .replace(/\n/g, "")
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
}

export async function verifySignature(
  publicKeyPem: string,
  signature: string,
  rawBody: ArrayBuffer,
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    Uint8Array.from(atob(cleanPublicKey(publicKeyPem)), (character) =>
      character.charCodeAt(0),
    ),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    Uint8Array.from(atob(signature), (character) => character.charCodeAt(0)),
    rawBody,
  );
}
