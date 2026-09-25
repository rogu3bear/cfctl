use leptos::prelude::*;
use leptos_meta::Title;

use crate::components::SiteShell;

#[component]
pub fn NotFoundPage() -> impl IntoView {
    #[cfg(feature = "ssr")]
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.set_status(axum::http::StatusCode::NOT_FOUND);
    }

    view! {
        <SiteShell>
            <Title text="Page not found · cfctl"/>
            <main id="main-content" class="route-page route-miss">
                <p class="eyebrow">"404 · route not found"</p>
                <h1>"Page not found."</h1>
                <p>"The link may be out of date. Return home or open the getting-started guide."</p>
                <p><a href="/">"Return home"</a>" · "<a href="/start">"Get started"</a></p>
            </main>
        </SiteShell>
    }
}
