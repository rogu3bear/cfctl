use leptos::prelude::*;

const STAGES: [(&str, &str, &str, bool); 8] = [
    (
        "01",
        "Orient",
        "Bind build, account, target, and workspace.",
        false,
    ),
    (
        "02",
        "Discover",
        "Resolve the governed capability and its contract.",
        false,
    ),
    (
        "03",
        "Read",
        "Inspect bounded live state with a redacted receipt.",
        false,
    ),
    (
        "04",
        "Plan",
        "A write becomes a pinned preview—not an apply.",
        false,
    ),
    (
        "05",
        "Admit",
        "Approval binds to one exact operation ID.",
        true,
    ),
    ("06", "Execute", "Cross the provider boundary once.", true),
    (
        "07",
        "Verify",
        "Read live state with the declared verifier.",
        false,
    ),
    (
        "08",
        "Close or rectify",
        "Close with evidence; never replay uncertainty.",
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
