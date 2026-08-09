use leptos::prelude::*;

use crate::components::SiteShell;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    #[cfg(feature = "ssr")]
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.set_status(axum::http::StatusCode::NOT_FOUND);
    }

    view! {
        <SiteShell>
            <main id="main-content" class="route-page route-miss">
                <p class="eyebrow">"404 · route not found"</p>
                <h1>"This path has no governed contract."</h1>
                <p>"Return to the product overview, start with a verified read, or inspect the source."</p>
                <p><a href="/">"Return home"</a></p>
            </main>
        </SiteShell>
    }
}
