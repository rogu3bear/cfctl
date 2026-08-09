use leptos::prelude::*;

use crate::components::SiteShell;

#[component]
pub fn PrivacyPage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content" class="route-page legal-copy">
                <p class="eyebrow">"Privacy"</p>
                <h1>"The website does not build a profile of you."</h1>
                <p>"The cfctl website requires no account, form submission, database, object storage, analytics, or third-party script."</p>
                <p>"The CLI stores profiles, plans, catalogs, and redacted evidence locally. Credential values remain in the governed local credential backend or an explicit mode-0600 sink."</p>
                <p>"The OAuth callback processes one bounded authorization response in your browser. It does not server-render, persist, analyze, or intentionally log callback values; the displayed value is cleared after copy, expiry, or page restoration."</p>
                <p>"Cloudflare may process ordinary request metadata under its platform policies. The callback route is configured no-store and no-referrer, and site-controlled observability is disabled."</p>
                <p>"Last updated: August 5, 2026."</p>
            </main>
        </SiteShell>
    }
}

#[component]
pub fn TermsPage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content" class="route-page legal-copy">
                <p class="eyebrow">"Terms"</p>
                <h1>"Review before authority. Verify after execution."</h1>
                <p>"cfctl is open-source software provided under the licenses in its repository. Cloudflare products, accounts, pricing, availability, and upstream APIs remain governed by Cloudflare's terms."</p>
                <p>"The website explains the project's current contracts; it does not guarantee that every cataloged capability is executable or that a provider operation will succeed."</p>
                <p>"You remain responsible for reviewing the exact account, target, permissions, cost, warning, verification, and recovery context before approving an operation."</p>
                <p>"Last updated: August 5, 2026."</p>
            </main>
        </SiteShell>
    }
}
