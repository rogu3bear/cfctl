use leptos::prelude::*;

#[component]
pub fn SiteShell(children: Children) -> impl IntoView {
    view! {
        <header class="site-header">
            <a class="wordmark" href="/" aria-label="cfctl home">"cfctl"<span aria-hidden="true">"/"</span></a>
            <nav aria-label="Primary navigation">
                <a href="/start">"Start"</a>
                <a href="/security">"Security"</a>
                <a href="https://github.com/rogu3bear/cfctl" rel="noreferrer">"Source"</a>
            </nav>
        </header>
        {children()}
        <footer class="site-footer">
            <span>"Local first. Exact authority. Live proof."</span>
            <nav aria-label="Legal navigation">
                <a href="/privacy">"Privacy"</a>
                <a href="/terms">"Terms"</a>
            </nav>
        </footer>
    }
}
