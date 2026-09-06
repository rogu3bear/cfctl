#![recursion_limit = "256"]

mod app;
mod asset_hashes;
mod components;
#[cfg(any(feature = "hydrate", test))]
mod oauth;
mod routes;

#[cfg(feature = "ssr")]
#[worker::event(fetch)]
async fn fetch(
    req: worker::HttpRequest,
    _env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<axum::http::Response<axum::body::Body>> {
    use axum::body::Body;
    use axum::http::{Method, Response, StatusCode};
    use leptos::prelude::*;
    use tower_service::Service;

    if !matches!(req.method(), &Method::GET | &Method::HEAD) {
        let mut response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method not allowed."))
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        apply_response_headers(&mut response, req.uri().path())?;
        return Ok(response);
    }

    let conf =
        get_configuration(None).map_err(|error| worker::Error::RustError(error.to_string()))?;
    let leptos_options = conf.leptos_options;
    let mut router = app_router(leptos_options);

    let request_path = req.uri().path().to_owned();
    let mut response = router.call(req).await?;
    apply_response_headers(&mut response, &request_path)?;
    Ok(response)
}

#[cfg(feature = "ssr")]
pub fn app_router(leptos_options: leptos::prelude::LeptosOptions) -> axum::Router {
    use axum::Router;
    use leptos_axum::{LeptosRoutes, generate_route_list};

    let routes = generate_route_list(app::App);
    Router::new()
        .leptos_routes_with_context(&leptos_options, routes, install_ssr_csp, {
            let leptos_options = leptos_options.clone();
            move || app::shell(leptos_options.clone())
        })
        .with_state(leptos_options)
}

#[cfg(feature = "ssr")]
fn apply_response_headers(
    response: &mut axum::http::Response<axum::body::Body>,
    request_path: &str,
) -> worker::Result<()> {
    use axum::http::header::{
        CACHE_CONTROL, HeaderName, HeaderValue, PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    };

    let callback = request_path == "/oauth/callback" || request_path == "/oauth/callback/";
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(if callback {
            "no-store, no-cache, max-age=0"
        } else {
            "no-cache, max-age=0, must-revalidate"
        }),
    );
    if callback {
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    }
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static(if callback {
            "no-referrer"
        } else {
            "strict-origin-when-cross-origin"
        }),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), geolocation=(), microphone=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000"),
    );
    // The SSR integration owns its per-response nonce. Non-SSR responses use
    // the strict hash-only fallback and never invent a nonce after rendering.
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            content_security_policy(None)?,
        );
    }
    Ok(())
}

#[cfg(feature = "ssr")]
fn content_security_policy(nonce: Option<&str>) -> worker::Result<axum::http::header::HeaderValue> {
    use base64::Engine;
    use leptos::prelude::*;
    use sha2::{Digest, Sha256};

    let conf =
        get_configuration(None).map_err(|error| worker::Error::RustError(error.to_string()))?;
    let script = hydration_script(&conf.leptos_options);
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
    let mut script_sources = if cfg!(debug_assertions) {
        "'self' 'unsafe-inline' 'wasm-unsafe-eval'".to_owned()
    } else {
        format!("'self' 'sha256-{hash}' 'wasm-unsafe-eval'")
    };
    if let Some(nonce) = nonce {
        script_sources.push_str(&format!(" 'nonce-{nonce}'"));
    }
    let connect_sources = if cfg!(debug_assertions) {
        "'self' ws: wss:"
    } else {
        "'self'"
    };
    let value = format!(
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; font-src 'self'; connect-src {connect_sources}; style-src 'self'; script-src {script_sources};"
    );
    axum::http::header::HeaderValue::from_str(&value)
        .map_err(|error| worker::Error::RustError(error.to_string()))
}

#[cfg(feature = "ssr")]
fn install_ssr_csp() {
    use leptos::prelude::*;
    let response = expect_context::<leptos_axum::ResponseOptions>();
    let nonce = leptos::nonce::use_nonce().expect("Leptos SSR provides its response nonce");
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        content_security_policy(Some(&nonce)).expect("configured CSP is a valid header"),
    );
}

#[cfg(feature = "ssr")]
fn hydration_script(options: &leptos::prelude::LeptosOptions) -> String {
    app::edge_hydration_script(options)
}

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_islands();
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Response, header};

    #[test]
    fn callback_response_is_ephemeral_and_unframeable() {
        let mut response = Response::new(Body::empty());
        apply_response_headers(&mut response, "/oauth/callback").expect("valid headers");
        let headers = response.headers();

        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store, no-cache, max-age=0")
        );
        assert_eq!(
            headers
                .get(header::REFERRER_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            headers
                .get("strict-transport-security")
                .and_then(|value| value.to_str().ok()),
            Some("max-age=31536000")
        );
        let csp = headers
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .expect("CSP");
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("form-action 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn ssr_policy_uses_the_framework_nonce_and_survives_response_headers() {
        use leptos::prelude::*;
        let owner = Owner::new();
        let policy = owner.with(|| {
            let response = leptos_axum::ResponseOptions::default();
            provide_context(response.clone());
            leptos::nonce::provide_nonce();
            let nonce = leptos::nonce::use_nonce().expect("framework nonce");
            install_ssr_csp();
            let headers = response.0.read().expect("response options");
            let policy = headers.headers[header::CONTENT_SECURITY_POLICY].clone();
            assert!(
                policy
                    .to_str()
                    .expect("policy")
                    .contains(&format!("'nonce-{nonce}'"))
            );
            policy
        });
        let mut response = Response::new(Body::empty());
        response
            .headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, policy.clone());
        apply_response_headers(&mut response, "/start").expect("headers");
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], policy);
        assert!(
            !content_security_policy(None)
                .expect("fallback")
                .to_str()
                .expect("policy")
                .contains("'nonce-")
        );
    }

    #[test]
    fn ordinary_response_does_not_claim_callback_cache_semantics() {
        let mut response = Response::new(Body::empty());
        apply_response_headers(&mut response, "/").expect("valid headers");

        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache, max-age=0, must-revalidate")
        );
    }
}
