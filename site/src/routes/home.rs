use leptos::prelude::*;

use crate::components::{ActionLink, CommandBlock, EvidenceReceipt, LifecycleLedger, SiteShell};

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content">
                <section class="hero-ledger">
                    <div class="hero-ledger__promise">
                        <p class="eyebrow">"Cloudflare, from your terminal"</p>
                        <h1>"Know what changes. Before it changes."</h1>
                        <p class="lede">"cfctl is an open-source CLI for people and agents working with Cloudflare. Inspect your account, preview a change, then apply it with a record of what happened."</p>
                        <div class="hero-actions">
                            <ActionLink href="/start" label="Get started"/>
                            <ActionLink href="https://github.com/rogu3bear/cfctl/tree/main/docs" label="Read the docs" secondary=true/>
                        </div>
                        <p class="hero-caption">"Runs locally on macOS and Linux. Built in Rust."</p>
                    </div>
                    <aside class="hero-ledger__proof" aria-label="Explore before connecting an account">
                        <CommandBlock label="Explore a read operation".to_owned() command="cfctl guide listWorkers --json".to_owned()/>
                        <p>"See the required permissions and exact command to list Workers. Reading a guide needs no Cloudflare credential."</p>
                    </aside>
                </section>

                <section class="ledger-section" aria-labelledby="use-heading">
                    <div class="section-heading">
                        <span class="margin-label">"What it does"</span>
                        <div><h2 id="use-heading">"A clearer way to work with your account."</h2></div>
                    </div>
                    <div class="trust-ledger">
                        <EvidenceReceipt label="Explore" title="Find the right operation" body="Browse Workers, DNS, storage, and more. The catalog shows what is supported, what is read-only, and what is blocked."/>
                        <EvidenceReceipt label="Review" title="See the change first" body="Writes produce a plan with the account, target, permissions, cost, and recovery information before execution."/>
                        <EvidenceReceipt label="Automate" title="Give agents a clear contract" body="Use stable JSON, explicit approval, and redacted evidence to connect the same CLI to your local agent or scripts."/>
                    </div>
                </section>

                <section class="ledger-section" aria-labelledby="lifecycle-heading">
                    <div class="section-heading">
                        <span class="margin-label">"How it works"</span>
                        <div>
                            <h2 id="lifecycle-heading">"From intent to a checked result."</h2>
                            <p>"A write command prepares a plan. Execution happens separately, after the required approval. Each stage keeps a record you can inspect."</p>
                        </div>
                    </div>
                    <LifecycleLedger/>
                    <p class="section-note"><a href="/security">"Understand credentials, approval, and recovery"</a></p>
                </section>

                <section class="ledger-section" aria-labelledby="resources-heading">
                    <div class="section-heading">
                        <span class="margin-label">"Go deeper"</span>
                        <div><h2 id="resources-heading">"The details are in the open."</h2></div>
                    </div>
                    <div class="resource-links">
                        <a href="https://github.com/rogu3bear/cfctl/blob/main/QUICKSTART.md"><strong>"Quickstart"</strong><span>"Install, authenticate, and prepare your first change."</span></a>
                        <a href="https://github.com/rogu3bear/cfctl/blob/main/docs/runbooks/cfctl.md"><strong>"Operator guide"</strong><span>"Check health, understand failures, and recover safely."</span></a>
                        <a href="https://github.com/rogu3bear/cfctl"><strong>"Source code"</strong><span>"Inspect the implementation, report a bug, or contribute."</span></a>
                    </div>
                </section>

                <section class="closing-action" aria-labelledby="closing-heading">
                    <p class="eyebrow">"Start with a read"</p>
                    <h2 id="closing-heading">"Get cfctl running on your machine."</h2>
                    <ActionLink href="/start" label="Install and connect"/>
                </section>
            </main>
        </SiteShell>
    }
}
