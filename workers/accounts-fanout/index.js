// Accounts fanout email-routing Worker (template).
//
// This source template is not a cfctl deployment surface. Copy it into the app
// repository that owns the Worker and deploy through that repository's checked-
// in Wrangler configuration and release gate. Use `cfctl resolve "configure
// email routing"` for account-level discovery and governed planning; cfctl has
// no public `wrangler deploy` subcommand or backend-script fallback.
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
