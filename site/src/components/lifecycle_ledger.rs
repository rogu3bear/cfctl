use leptos::prelude::*;

const STAGES: [(&str, &str, &str, bool); 8] = [
    (
        "01",
        "Orient",
        "Check the installed build, account, and workspace.",
        false,
    ),
    (
        "02",
        "Discover",
        "Find an operation and inspect its requirements.",
        false,
    ),
    (
        "03",
        "Read",
        "Read the current Cloudflare state and save redacted evidence.",
        false,
    ),
    (
        "04",
        "Plan",
        "Preview the exact change, permissions, cost, and recovery path.",
        false,
    ),
    (
        "05",
        "Approve",
        "Approve the exact operation when the policy requires it.",
        true,
    ),
    ("06", "Execute", "Run the approved plan once.", true),
    (
        "07",
        "Verify",
        "Check the outcome against live state using the declared verifier.",
        false,
    ),
    (
        "08",
        "Finish or recover",
        "Keep the evidence. Reconcile an uncertain result before retrying.",
        false,
    ),
];

#[component]
pub fn LifecycleLedger() -> impl IntoView {
    view! {
        <ol class="lifecycle-ledger">
            {STAGES.into_iter().map(|(number, title, body, crossing)| {
                let title_class = crossing.then_some("boundary-crossing");
                view! {
                    <li>
                        <span class="lifecycle-ledger__number">{number}</span>
                        <strong class=title_class>{title}</strong>
                        <span>{body}</span>
                    </li>
                }
            }).collect_view()}
        </ol>
    }
}
