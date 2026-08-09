use leptos::prelude::*;

#[component]
pub fn ActionLink(
    href: &'static str,
    label: &'static str,
    #[prop(optional)] secondary: bool,
) -> impl IntoView {
    let class = if secondary {
        "action-link action-link--secondary"
    } else {
        "action-link"
    };

    view! { <a class=class href=href>{label}<span aria-hidden="true">" ↗"</span></a> }
}
