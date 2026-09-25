use leptos::prelude::*;
use leptos_meta::Title;

use crate::components::{EvidenceReceipt, SiteShell};

#[component]
pub fn SecurityPage() -> impl IntoView {
    view! {
        <SiteShell>
            <Title text="Security · cfctl"/>
            <main id="main-content" class="route-page">
                <p class="eyebrow">"Security"</p>
                <h1>"Review the plan. Control the change."</h1>
                <p class="lede">"cfctl keeps credentials, approval, execution, and verification separate. A token gives access to Cloudflare; it does not approve every action that access makes possible."</p>
                <div class="security-ledger">
                    <EvidenceReceipt label="Credentials" title="Keep access scoped" body="Use an account-pinned token with the permissions needed for the job. Choose platform storage or explicit private local storage. Private files are accessible to software running as your OS user."/>
                    <EvidenceReceipt label="Plans" title="Inspect before execution" body="A write produces a plan binding the account, target, input, permissions, cost, verification, and recovery information. Changed inputs invalidate that binding."/>
                    <EvidenceReceipt label="Approval" title="Authorize the exact operation" body="Protected work requires approval of its operation ID. A narrow safe class may be admitted by deterministic policy; bounded token automation requires a separately approved standing policy."/>
                    <EvidenceReceipt label="Recovery" title="Check before retrying" body="Inspect operation status after a failure. If execution may have reached Cloudflare, reconcile the saved records with plans rectify instead of running the mutation again."/>
                </div>
                <section class="policy-links" aria-labelledby="policy-heading">
                    <h2 id="policy-heading">"Inspect the security model."</h2>
                    <p><a href="https://github.com/rogu3bear/cfctl/blob/main/SECURITY.md">"Security policy and release identities"</a></p>
                    <p><a href="https://github.com/rogu3bear/cfctl/blob/main/docs/runtime-policy.md">"Runtime policy and approval rules"</a></p>
                    <p><a href="https://github.com/rogu3bear/cfctl/blob/main/docs/v2-security.md">"Credential handling and threat model"</a></p>
                    <p>"Public cfctl OAuth is disabled. Routine setup uses a scoped API token; an explicitly configured OAuth client is a separate option."</p>
                </section>
                <aside class="bounded-note">
                    <strong>"Report a vulnerability privately."</strong>
                    <p>"Follow the "<a href="https://github.com/rogu3bear/cfctl/security/advisories/new">"private security advisory process"</a>". Include reproduction steps and redacted evidence. Keep credentials and sensitive account data out of public issues."</p>
                </aside>
            </main>
        </SiteShell>
    }
}
