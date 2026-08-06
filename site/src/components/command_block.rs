use leptos::prelude::*;

#[island]
#[allow(unused_variables)]
pub fn CommandBlock(label: String, command: String) -> impl IntoView {
    let (status, set_status) = signal("Ready to copy.");
    let command_for_copy = command.clone();

    let copy = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let Some(window) = web_sys::window() else {
                set_status.set("Clipboard unavailable. Select the command manually.");
                return;
            };
            let clipboard = window.navigator().clipboard();
            let promise = clipboard.write_text(&command_for_copy);
            wasm_bindgen_futures::spawn_local(async move {
                if wasm_bindgen_futures::JsFuture::from(promise).await.is_ok() {
                    set_status.set("Copied.");
                } else {
                    set_status.set("Copy denied. Select the command manually.");
                }
            });
        }
    };

    view! {
        <div class="command-block">
            <div class="command-block__label">{label}</div>
            <code>{command}</code>
            <button type="button" on:click=copy>"Copy"</button>
            <span class="command-block__status" role="status">{status}</span>
        </div>
    }
}
