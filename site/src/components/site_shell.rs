use leptos::prelude::*;

#[component]
pub fn SiteShell(children: Children) -> impl IntoView {
    view! {
        <a class="skip-link" href="#main-content">"Skip to content"</a>
        <header class="site-header">
            <a class="wordmark" href="/" aria-label="cfctl home">"cfctl"<span aria-hidden="true">"/"</span></a>
            <nav aria-label="Primary navigation">
                <a href="/start">"Get started"</a>
                <a href="https://github.com/rogu3bear/cfctl/tree/main/docs">"Docs"</a>
                <a href="/security">"Security"</a>
                <a href="https://github.com/rogu3bear/cfctl" rel="noreferrer">"Source"</a>
            </nav>
        </header>
        {children()}
        <footer class="site-footer">
            <span>"cfctl · Open-source tools for Cloudflare. An independent project."</span>
            <nav aria-label="Legal navigation">
                <a href="https://github.com/rogu3bear/cfctl/issues">"Support"</a>
                <a href="/privacy">"Privacy"</a>
                <a href="/terms">"Terms"</a>
            </nav>
        </footer>
    }
}
