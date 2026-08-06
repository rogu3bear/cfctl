use leptos::prelude::*;
use leptos_meta::{Meta, MetaTags, Title, provide_meta_context};
use leptos_router::{
    SsrMode, StaticSegment, WildcardSegment,
    components::{Route, Router, Routes},
};

use crate::routes::{
    HomePage, NotFoundPage, OAuthCallbackPage, PrivacyPage, SecurityPage, StartPage, TermsPage,
};

#[allow(dead_code)]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <link rel="icon" href="/favicon.svg" type="image/svg+xml"/>
                <link rel="manifest" href="/site.webmanifest"/>
                <meta name="theme-color" content="#f3efe6"/>
                <AutoReload options=options.clone()/>
                <HashedStylesheet options=options.clone()/>
                <EdgeHydrationScripts options=options/>
                <MetaTags/>
            </head>
            <body><App/></body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="cfctl — governed Cloudflare control"/>
        <Meta name="description" content="A local-first Cloudflare control plane that makes changes reviewable before execution and provable after."/>
        <Router>
            <Routes fallback=|| view! { <NotFoundPage/> }.into_view()>
                <Route path=StaticSegment("") view=HomePage ssr=SsrMode::OutOfOrder/>
                <Route path=StaticSegment("start") view=StartPage ssr=SsrMode::OutOfOrder/>
                <Route path=StaticSegment("security") view=SecurityPage ssr=SsrMode::OutOfOrder/>
                <Route path=StaticSegment("privacy") view=PrivacyPage ssr=SsrMode::OutOfOrder/>
                <Route path=StaticSegment("terms") view=TermsPage ssr=SsrMode::OutOfOrder/>
                <Route path=(StaticSegment("oauth"), StaticSegment("callback")) view=OAuthCallbackPage ssr=SsrMode::OutOfOrder/>
                <Route path=WildcardSegment("any") view=NotFoundPage ssr=SsrMode::OutOfOrder/>
            </Routes>
        </Router>
    }
}

#[component]
fn HashedStylesheet(options: LeptosOptions) -> impl IntoView {
    let href = asset_href(&options, "css", crate::asset_hashes::CSS_HASH);
    view! { <link id="leptos" rel="stylesheet" href=href/> }
}

#[component]
fn EdgeHydrationScripts(options: LeptosOptions) -> impl IntoView {
    let js_href = asset_href(&options, "js", crate::asset_hashes::JS_HASH);
    let wasm_href = asset_href(&options, "wasm", crate::asset_hashes::WASM_HASH);
    let hydration_script = edge_hydration_script(&options);

    view! {
        <link rel="modulepreload" href=js_href.clone()/>
        <link rel="preload" href=wasm_href.clone() r#as="fetch" r#type="application/wasm"/>
        <script type="module">{hydration_script}</script>
    }
}

pub(crate) fn edge_hydration_script(options: &LeptosOptions) -> String {
    let js_href = asset_href(options, "js", crate::asset_hashes::JS_HASH);
    let wasm_href = asset_href(options, "wasm", crate::asset_hashes::WASM_HASH);
    format!(
        "import({js_href:?}).then(async mod=>{{await mod.default({{module_or_path:{wasm_href:?}}});mod.hydrate();const hydrate=async el=>{{const name=el.dataset.component;const island=mod[name];if(!island)throw new Error(`Missing island ${{name}}`);await island(el);}};const run=()=>Promise.all([...document.querySelectorAll('leptos-island')].map(hydrate));if('requestIdleCallback'in window)window.requestIdleCallback(run);else queueMicrotask(run);}});"
    )
}

fn asset_href(options: &LeptosOptions, extension: &str, hash: &str) -> String {
    let output_name = options.output_name.as_ref();
    let output_name = if output_name.is_empty() {
        env!("CARGO_PKG_NAME")
    } else {
        output_name
    };
    let pkg_dir = options.site_pkg_dir.as_ref();
    if hash.is_empty() {
        format!("/{pkg_dir}/{output_name}.{extension}")
    } else {
        format!("/{pkg_dir}/{output_name}.{hash}.{extension}")
    }
}
