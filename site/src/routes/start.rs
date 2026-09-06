use leptos::prelude::*;

use crate::components::{CommandBlock, SiteShell};

#[component]
pub fn StartPage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content" class="route-page">
                <p class="eyebrow">"Start · bounded activation"</p>
                <h1>"Reach one verified read."</h1>
                <p class="lede">"No broad token, no surprise mutation, no green-by-command-output."</p>
                <ol class="procedure-ledger">
                    <li><div><h2>"Install the intended build"</h2><p>"Use an authenticated prebuilt release when available, or a clean source build. A source-only release contains no prebuilt installer. Then check the binary on PATH."</p><CommandBlock label="build identity".to_owned() command="cfctl version --json".to_owned()/></div></li>
                    <li><div><h2>"Choose private local storage"</h2><p>"Keep routine use free of password dialogs. Review the local storage choice, then run the activation command it returns. Other software running as your OS user can access these files."</p><CommandBlock label="storage setup".to_owned() command="cfctl auth evidence-key private-preview --json".to_owned()/></div></li>
                    <li><div><h2>"Diagnose locally"</h2><p>"Confirm catalog freshness, managed instructions, and the active credential backend."</p><CommandBlock label="local proof".to_owned() command="cfctl doctor --json".to_owned()/></div></li>
                    <li><div><h2>"Import one scoped credential"</h2><p>"Pass the value through stdin and pin the account. Never put a secret in argv."</p><CommandBlock label="secret-safe input".to_owned() command="printf '%s' \"$CLOUDFLARE_API_TOKEN\" | cfctl auth import-api-token --profile production --account <account-id> --stdin".to_owned()/></div></li>
                    <li><div><h2>"Resolve, inspect, read"</h2><p>"Let the catalog choose the governed capability, inspect its guide, then run the exact emitted read."</p><CommandBlock label="deterministic discovery".to_owned() command="cfctl resolve \"list my Workers\" --json".to_owned()/></div></li>
                </ol>
                <aside class="bounded-note"><strong>"A 403 is evidence, not an invitation to broaden scope."</strong><p>"Read the declared permission lane or select a purpose-built profile. Do not route around the control plane."</p></aside>
            </main>
        </SiteShell>
    }
}
