use leptos::prelude::*;

#[component]
pub fn EvidenceReceipt(
    label: &'static str,
    title: &'static str,
    body: &'static str,
) -> impl IntoView {
    view! {
        <article class="evidence-receipt">
            <span class="margin-label">{label}</span>
            <h3>{title}</h3>
            <p>{body}</p>
        </article>
    }
}
