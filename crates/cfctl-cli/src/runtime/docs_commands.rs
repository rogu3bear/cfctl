use super::credential_resolution::ensure_catalog;
use super::prelude::StreamExt;
use super::prelude::{
    DocsCommand, OfficialTextFeedsV1, Result, ResultEnvelopeV2, SearchArgs, StateStore, Value,
    json, stream,
};
use super::support::docs_file;
use super::support::http_client;
use cfctl_catalog::fetch_official_text_feeds;

pub(super) async fn docs_command(
    store: &StateStore,
    command: DocsCommand,
) -> Result<ResultEnvelopeV2> {
    let _catalog = ensure_catalog(store).await?;
    let mut feeds: OfficialTextFeedsV1 = store.read_json(&docs_file(store))?;
    if feeds.product_indexes.is_empty() {
        feeds = fetch_official_text_feeds(&http_client()?).await?;
        store.write_json(&docs_file(store), &feeds)?;
    }
    match command {
        DocsCommand::Search(SearchArgs { query, limit }) => {
            let matches = search_docs(&http_client()?, &feeds, &query, limit.min(100)).await;
            Ok(ResultEnvelopeV2::success(
                "docs search",
                json!({
                    "query": query,
                    "matches": matches,
                    "fetched_at": feeds.fetched_at,
                    "result_limit": limit.min(100),
                    "limit_capped": limit > 100,
                }),
            ))
        }
        DocsCommand::Changes => Ok(ResultEnvelopeV2::success(
            "docs changes",
            json!({"source": feeds.changelog_url, "fetched_at": feeds.fetched_at, "text": feeds.changelog}),
        )),
        DocsCommand::Coverage => {
            let linked_pages = feeds
                .product_indexes
                .values()
                .flat_map(|index| index.lines())
                .filter_map(cfctl_catalog::markdown_link)
                .filter(|url| url.ends_with("/index.md"))
                .count();
            Ok(ResultEnvelopeV2::success(
                "docs coverage",
                json!({
                    "official_index": feeds.docs_index_url,
                    "official_changelog": feeds.changelog_url,
                    "linked_pages": linked_pages,
                    "product_indexes": feeds.product_indexes.len(),
                    "unread_product_indexes": feeds.unread_product_indexes,
                    "fetched_at": feeds.fetched_at,
                    "note": "Coverage indexes official product feeds; matching page bodies are fetched from Cloudflare on demand and returned with per-page fetch status."
                }),
            ))
        }
    }
}

pub(super) async fn search_docs(
    client: &reqwest::Client,
    feeds: &OfficialTextFeedsV1,
    query: &str,
    limit: usize,
) -> Vec<Value> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let candidates: Vec<String> = feeds
        .docs_index
        .lines()
        .chain(
            feeds
                .product_indexes
                .values()
                .flat_map(|index| index.lines()),
        )
        .chain(feeds.changelog.lines())
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            terms.iter().all(|term| line.contains(term))
        })
        .take(limit)
        .map(str::to_owned)
        .collect();
    let mut matches = stream::iter(candidates.into_iter().enumerate())
        .map(|(position, index_entry)| {
            let client = client.clone();
            let terms = terms.clone();
            async move {
                let Some(url) = cfctl_catalog::markdown_link(&index_entry).map(str::to_owned) else {
                    return (
                        position,
                        json!({"index_entry": index_entry, "body_status": "not_a_page_link"}),
                    );
                };
                let response = client
                    .get(&url)
                    .header(reqwest::header::ACCEPT, "text/markdown")
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status);
                match response {
                    Ok(response) => match response.text().await {
                        Ok(body) => (
                            position,
                            json!({
                                "index_entry": index_entry,
                                "url": url,
                                "body_status": "fetched",
                                "excerpt": docs_excerpt(&body, &terms),
                            }),
                        ),
                        Err(error) => (
                            position,
                            json!({"index_entry": index_entry, "url": url, "body_status": "unread", "reason": error.to_string()}),
                        ),
                    },
                    Err(error) => (
                        position,
                        json!({"index_entry": index_entry, "url": url, "body_status": "unread", "reason": error.to_string()}),
                    ),
                }
            }
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    matches.sort_by_key(|(position, _)| *position);
    matches.into_iter().map(|(_, value)| value).collect()
}

pub(super) fn docs_excerpt(body: &str, terms: &[String]) -> String {
    let matching: Vec<&str> = body
        .lines()
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            terms.iter().all(|term| line.contains(term))
        })
        .filter(|line| !line.trim().is_empty())
        .take(6)
        .collect();
    let lines = if matching.is_empty() {
        body.lines()
            .filter(|line| !line.trim().is_empty())
            .take(6)
            .collect()
    } else {
        matching
    };
    lines.join("\n").chars().take(2_000).collect()
}
