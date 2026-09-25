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

    let arrow = if href.starts_with("https://") {
        " ↗"
    } else {
        " →"
    };
    view! { <a class=class href=href>{label}<span aria-hidden="true">{arrow}</span></a> }
}
