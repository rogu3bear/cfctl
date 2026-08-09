use leptos::prelude::*;

#[cfg(feature = "hydrate")]
use crate::oauth::CallbackResult;

#[component]
pub fn OAuthCallbackPage() -> impl IntoView {
    view! {
        <main id="main-content" class="callback-page">
            <a class="wordmark" href="/" aria-label="cfctl home">"cfctl"<span aria-hidden="true">"/"</span></a>
            <section class="callback-sheet" aria-labelledby="callback-heading">
                <p class="eyebrow">"OAuth callback · isolated route"</p>
                <h1 id="callback-heading">"Return authorization to your waiting CLI."</h1>
                <p>"This page never server-renders callback values and does not send them to analytics or third parties."</p>
                <OAuthCallbackBridge/>
                <noscript><p class="callback-status callback-status--error">"JavaScript is required to process this callback safely. Close this page and retry the login, or cancel in the CLI."</p></noscript>
            </section>
        </main>
    }
}

#[island]
#[allow(unused_variables)]
fn OAuthCallbackBridge() -> impl IntoView {
    let (payload, set_payload) = signal::<Option<String>>(None);
    let (message, set_message) = signal("Checking the authorization response…");
    let (failed, set_failed) = signal(false);

    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::{JsCast, closure::Closure};

        Effect::new(move |_| {
            let Some(window) = web_sys::window() else {
                set_failed.set(true);
                set_message.set("This browser cannot process the authorization response.");
                return;
            };

            let location = window.location();
            let search = location.search().unwrap_or_default();
            let path = location
                .pathname()
                .unwrap_or_else(|_| "/oauth/callback/".to_owned());
            let _ = window.history().and_then(|history| {
                history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path))
            });

            let params = match web_sys::UrlSearchParams::new_with_str(&search) {
                Ok(params) => params,
                Err(_) => {
                    set_failed.set(true);
                    set_message
                        .set("The authorization response is malformed. Start a fresh login.");
                    return;
                }
            };

            let collect = |name: &str| {
                params
                    .get_all(name)
                    .iter()
                    .filter_map(|value| value.as_string())
                    .collect::<Vec<_>>()
            };

            match crate::oauth::validate_callback(
                &collect("state"),
                &collect("code"),
                &collect("error"),
            ) {
                CallbackResult::Success(value) => {
                    set_payload.set(Some(value));
                    set_failed.set(false);
                    set_message.set(
                        "Authorization is ready. Copy it once, then return to the waiting CLI.",
                    );
                }
                CallbackResult::OAuthError => {
                    set_failed.set(true);
                    set_message.set("Cloudflare did not authorize this login. Close the page and start a fresh attempt.");
                }
                CallbackResult::Invalid => {
                    set_failed.set(true);
                    set_message.set("The authorization response is incomplete or malformed. Start a fresh login.");
                }
            }

            let clear_sensitive = move || {
                set_payload.set(None);
                set_failed.set(true);
                set_message.set("This authorization response has expired. Start a fresh login.");
            };

            let timeout_clear = clear_sensitive;
            let timeout = Closure::<dyn FnMut()>::new(timeout_clear);
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                timeout.as_ref().unchecked_ref(),
                120_000,
            );
            timeout.forget();

            let page_clear = clear_sensitive;
            let page_event = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| page_clear());
            let _ = window
                .add_event_listener_with_callback("pagehide", page_event.as_ref().unchecked_ref());
            let _ = window
                .add_event_listener_with_callback("pageshow", page_event.as_ref().unchecked_ref());
            page_event.forget();

            if let Some(document) = window.document() {
                let visibility_clear = clear_sensitive;
                let visibility_document = document.clone();
                let visibility_event = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                    if visibility_document.visibility_state() == web_sys::VisibilityState::Hidden {
                        visibility_clear();
                    }
                });
                let _ = document.add_event_listener_with_callback(
                    "visibilitychange",
                    visibility_event.as_ref().unchecked_ref(),
                );
                visibility_event.forget();
            }
        });
    }

    let copy = move |_| {
        let Some(value) = payload.get() else {
            return;
        };

        #[cfg(feature = "hydrate")]
        {
            let Some(window) = web_sys::window() else {
                set_failed.set(true);
                set_message.set("Clipboard unavailable. Select the value manually.");
                return;
            };
            let promise = window.navigator().clipboard().write_text(&value);
            wasm_bindgen_futures::spawn_local(async move {
                if wasm_bindgen_futures::JsFuture::from(promise).await.is_ok() {
                    set_payload.set(None);
                    set_failed.set(false);
                    set_message.set("Copied and cleared. Return to the waiting CLI.");
                } else {
                    set_failed.set(true);
                    set_message
                        .set("Copy denied. Select the value manually, then close this page.");
                }
            });
        }
    };

    view! {
        <div class="callback-result">
            <p class:callback-status--error=move || failed.get() class="callback-status" role="status">{message}</p>
            {move || payload.get().map(|value| view! {
                <div class="callback-payload">
                    <code>{value}</code>
                    <button type="button" on:click=copy>"Copy and clear"</button>
                </div>
            })}
        </div>
    }
}
