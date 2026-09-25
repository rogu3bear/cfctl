use leptos::prelude::*;
use leptos_meta::Title;

use crate::components::{CommandBlock, SiteShell};

#[component]
pub fn StartPage() -> impl IntoView {
    view! {
        <SiteShell>
            <Title text="Get started · cfctl"/>
            <main id="main-content" class="route-page">
                <p class="eyebrow">"Get started"</p>
                <h1>"Install. Connect. Read."</h1>
                <p class="lede">"Start by listing Workers in one Cloudflare account. This walkthrough reads your account without changing it."</p>
                <aside class="bounded-note">
                    <strong>"Before you begin"</strong>
                    <p>"You need macOS or Linux, Git, the repository's pinned Rust toolchain, and its build tools. Follow the "<a href="https://github.com/rogu3bear/cfctl/blob/main/CONTRIBUTING.md#development-setup">"development setup"</a>" first. To connect, have your Cloudflare account ID and an API token scoped to Workers Scripts Read for that account."</p>
                </aside>
                <ol class="procedure-ledger">
                    <li><div>
                        <h2>"Build and install from source"</h2>
                        <p>"Clone the repository, review the source, and run bootstrap from the clean checkout. It verifies the project, installs cfctl, and checks that the installed binary matches the source. This is a local source build; source-only releases do not contain prebuilt installers."</p>
                        <CommandBlock label="Terminal · source installation".to_owned() command="git clone https://github.com/rogu3bear/cfctl.git\ncd cfctl\n./bootstrap.sh\nexport PATH=\"${CARGO_INSTALL_ROOT:-$HOME/.local}/bin:$PATH\"\ncfctl version --json".to_owned()/>
                        <p>"Keep the install directory on PATH in your shell configuration for future terminals. Bootstrap refreshes already-managed agent integrations. Use its --skip-agent-sync option if you want a binary-only installation. See the "<a href="https://github.com/rogu3bear/cfctl/blob/main/QUICKSTART.md#build-and-install">"installation guide"</a>" for requirements and release verification."</p>
                    </div></li>
                    <li><div>
                        <h2>"Choose credential storage"</h2>
                        <p>"Preview private local storage, then review and run the activation command it returns. This avoids platform password dialogs. Other software running as your OS user can access these private files. An existing installation should review which profiles and approvals the transition affects."</p>
                        <CommandBlock label="Preview the storage choice".to_owned() command="cfctl auth evidence-key private-preview --json".to_owned()/>
                        <p>"After activation, check the storage status and local setup."</p>
                        <CommandBlock label="Check your installation".to_owned() command="cfctl auth evidence-key status --json\ncfctl doctor --json\ncfctl agents doctor --json".to_owned()/>
                    </div></li>
                    <li><div>
                        <h2>"Connect one account"</h2>
                        <p>"Replace your-account-id below. Load your existing scoped token into CLOUDFLARE_API_TOKEN through your secure local workflow; never paste it into chat, source code, or command arguments. The pipe sends the value to cfctl through standard input."</p>
                        <CommandBlock label="Import an existing read token".to_owned() command="ACCOUNT_ID='your-account-id'\nprintf '%s' \"$CLOUDFLARE_API_TOKEN\" | cfctl auth import-api-token --profile first-read --account \"$ACCOUNT_ID\" --stdin --json\nunset CLOUDFLARE_API_TOKEN".to_owned()/>
                        <p>"Need a token? The "<a href="https://github.com/rogu3bear/cfctl/blob/main/QUICKSTART.md#authenticate">"authentication guide"</a>" explains creating a scoped token from a qualified parent and reviewing its separate approval."</p>
                    </div></li>
                    <li><div>
                        <h2>"Inspect the operation, then read"</h2>
                        <p>"The guide explains required permissions and inputs. The second command reads Workers using the same profile and account you just configured."</p>
                        <CommandBlock label="List Workers · read only".to_owned() command="cfctl guide listWorkers --json\ncfctl call listWorkers --profile first-read --account \"$ACCOUNT_ID\" --selector account_id=\"$ACCOUNT_ID\" --json".to_owned()/>
                        <p>"A successful response has ok: true and performed: true, with result data and evidence references. An empty list can mean the account has no Workers. This is a live read; it does not verify a deployment or change your account."</p>
                    </div></li>
                </ol>
                <section class="policy-links" aria-labelledby="next-heading">
                    <h2 id="next-heading">"Where to go next"</h2>
                    <p>"Use cfctl resolve to map an intent to an operation, or cfctl catalog search to explore. If a request is ambiguous, inspect the returned candidates and choose the exact capability before calling it."</p>
                    <p>"For writes, inspect the returned plan and its operation ID. Required approval and execution are separate steps. Follow the "<a href="https://github.com/rogu3bear/cfctl/blob/main/QUICKSTART.md#first-governed-write">"first-write walkthrough"</a>" when you are ready."</p>
                </section>
                <aside class="bounded-note">
                    <strong>"Something did not work?"</strong>
                    <p>"For a 403, check that the token belongs to the intended account and has the permission shown in the guide. A blocked operation explains its missing requirements. Use the "<a href="https://github.com/rogu3bear/cfctl/blob/main/docs/runbooks/cfctl.md">"operator guide"</a>" or "<a href="https://github.com/rogu3bear/cfctl/issues">"report a redacted error"</a>". Do not include your token or callback values."</p>
                </aside>
            </main>
        </SiteShell>
    }
}
