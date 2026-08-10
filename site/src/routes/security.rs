use leptos::prelude::*;

use crate::components::{EvidenceReceipt, SiteShell};

#[component]
pub fn SecurityPage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content" class="route-page">
                <p class="eyebrow">"Security · explicit boundaries"</p>
                <h1>"Your credential is not your consent."</h1>
                <p class="lede">"cfctl separates credential custody, plan construction, exact approval, provider execution, and post-change verification."</p>
                <div class="security-ledger">
                    <EvidenceReceipt label="local" title="Credential backend" body="Ordinary use stays on the governed local backend. Keychain repair is explicit and warned."/>
                    <EvidenceReceipt label="preview" title="Hash-bound plans" body="Account, target, permissions, cost, warnings, verification, and compensation travel together."/>
                    <EvidenceReceipt label="authority" title="Exact approval" body="Consent binds to one reviewed operation ID. Model output never grants it."/>
                    <EvidenceReceipt label="readback" title="Verification" body="A provider response is not convergence. Close only with the declared live read."/>
                </div>
                <section class="policy-links" aria-labelledby="policy-heading">
                    <h2 id="policy-heading">"Review the actual contracts."</h2>
                    <p><a href="https://github.com/rogu3bear/cfctl/blob/main/SECURITY.md">"Repository security policy"</a></p>
                    <p><a href="https://github.com/rogu3bear/cfctl/blob/main/docs/runtime-policy.md">"Runtime policy"</a></p>
                    <p>"Report vulnerabilities privately through the repository's GitHub security advisory."</p>
                </section>
            </main>
        </SiteShell>
    }
}
