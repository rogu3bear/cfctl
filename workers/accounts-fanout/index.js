// Accounts fanout email-routing Worker (template).
//
// Replace EXPECTED_RECIPIENT and FORWARD_TO with the values for your deployment,
// then upload via `cfctl wrangler deploy` or one of the provision scripts under
// `scripts/`. Set the matching catch-all rule on the source zone to route to
// this Worker.
//
// Required Cloudflare features:
//   - Email Routing enabled on the source zone
//   - Each FORWARD_TO address verified as an Email Routing destination
const EXPECTED_RECIPIENT = "accounts@example.com";
const FORWARD_TO = ["primary@example.com", "backup@example.com"];

export default {
  async email(message) {
    if (message.to.toLowerCase() !== EXPECTED_RECIPIENT) {
      message.setReject(`unexpected recipient: ${message.to}`);
      return;
    }

    for (const recipient of FORWARD_TO) {
      await message.forward(
        recipient,
        new Headers({
          "X-Original-Envelope-To": message.to,
          "X-Forwarded-By-Worker": "accounts-fanout",
        }),
      );
    }
  },
};
