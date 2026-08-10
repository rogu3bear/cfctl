use leptos::prelude::*;

use crate::components::{ActionLink, CommandBlock, EvidenceReceipt, LifecycleLedger, SiteShell};

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <SiteShell>
            <main id="main-content">
                <section class="hero-ledger">
                    <div class="hero-ledger__promise">
                        <p class="eyebrow">"A local-first Cloudflare control plane"</p>
                        <h1>"See the boundary before you cross it."</h1>
                        <p class="lede">"cfctl turns Cloudflare intent into exact reads, reviewable plans, explicit approval, one governed execution, and live verification."</p>
                        <div class="hero-actions">
                            <ActionLink href="/start" label="Reach one verified read"/>
                            <ActionLink href="https://github.com/rogu3bear/cfctl" label="Inspect the source" secondary=true/>
                        </div>
                    </div>
                    <aside class="hero-ledger__proof" aria-label="Read-only proof">
                        <CommandBlock label="first proof · read only".to_owned() command="cfctl doctor --json".to_owned()/>
                        <p>"Build identity, credential backend, catalog freshness—without opening a mutation boundary."</p>
                    </aside>
                </section>

                <section class="ledger-section" aria-labelledby="lifecycle-heading">
                    <div class="section-heading">
                        <span class="margin-label">"Authority ledger"</span>
                        <div>
                            <h2 id="lifecycle-heading">"One ordered path. No implied green."</h2>
                            <p>"Each stage says what is known, what is authorized, and what remains unproven."</p>
                        </div>
                    </div>
                    <LifecycleLedger/>
                </section>

                <section class="ledger-section" aria-labelledby="first-read-heading">
                    <div class="section-heading">
                        <span class="margin-label">"First verified read"</span>
                        <div><h2 id="first-read-heading">"Start with evidence, not authority."</h2></div>
                    </div>
                    <ol class="first-read">
                        <li><div><strong>"Install and identify"</strong><code>"cfctl version --json"</code></div></li>
                        <li><div><strong>"Diagnose locally"</strong><code>"cfctl doctor --json"</code></div></li>
                        <li><div><strong>"Resolve intent"</strong><code>"cfctl resolve \"list my Workers\" --json"</code></div></li>
                        <li><div><strong>"Run the emitted bounded read"</strong><p>"The result separates command success, provider performance, and verification state."</p></div></li>
                    </ol>
                </section>

                <section class="ledger-section" aria-labelledby="trust-heading">
                    <div class="section-heading">
                        <span class="margin-label">"Trust boundaries"</span>
                        <div><h2 id="trust-heading">"Custody, authority, and evidence stay separate."</h2></div>
                    </div>
                    <div class="trust-ledger">
                        <EvidenceReceipt label="01 · custody" title="Credential custody" body="Scoped, account-pinned credentials remain in the governed local backend."/>
                        <EvidenceReceipt label="02 · authority" title="Mutation authority" body="A plan previews. Exact approval admits. Run executes."/>
                        <EvidenceReceipt label="03 · proof" title="Evidence class" body="Source, plan, apply receipt, and live readback are not interchangeable."/>
                    </div>
                </section>

                <section class="closing-action" aria-labelledby="closing-heading">
                    <p class="eyebrow">"Your next safe action"</p>
                    <h2 id="closing-heading">"Reach one verified read before you plan a write."</h2>
                    <ActionLink href="/start" label="Start the bounded path"/>
                </section>
            </main>
        </SiteShell>
    }
}
