#[cfg(all(
    feature = "ssr",
    feature = "local-preview",
    not(target_arch = "wasm32")
))]
#[tokio::main]
async fn main() {
    use leptos::prelude::*;
    use tower_http::services::ServeDir;

    any_spawner::Executor::init_tokio().expect("initialize Leptos Tokio executor");
    let conf = get_configuration(Some("Cargo.toml")).expect("valid cargo-leptos configuration");
    let address = conf.leptos_options.site_addr;
    let site_root = conf.leptos_options.site_root.clone();
    let app = cfctl_site::app_router(conf.leptos_options)
        .nest_service("/pkg", ServeDir::new(format!("{site_root}/pkg")))
        .route_service(
            "/favicon.svg",
            ServeDir::new(site_root.as_ref()).append_index_html_on_directories(false),
        )
        .route_service(
            "/site.webmanifest",
            ServeDir::new(site_root.as_ref()).append_index_html_on_directories(false),
        )
        .route_service(
            "/robots.txt",
            ServeDir::new(site_root.as_ref()).append_index_html_on_directories(false),
        );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind local preview address");
    println!("cfctl site preview: http://{address}");
    axum::serve(listener, app)
        .await
        .expect("serve local preview");
}

#[cfg(not(all(
    feature = "ssr",
    feature = "local-preview",
    not(target_arch = "wasm32")
)))]
pub fn main() {}
