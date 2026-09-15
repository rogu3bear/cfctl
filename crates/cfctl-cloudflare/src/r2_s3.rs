//! Native, account-pinned S3 requests. Callers never supply an endpoint or key.
use super::{CloudflareError, Result};
use cfctl_auth::AuthCredential;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{
    Client, Method, Request, Response,
    header::{HeaderName, HeaderValue},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;

pub(crate) fn rejected() -> CloudflareError {
    CloudflareError::InvalidRequestBody(
        "private R2 restore transport or source contract failed; no private value was disclosed"
            .into(),
    )
}

pub(crate) struct S3Transport {
    client: Client,
    #[cfg(test)]
    pub(crate) test_origin: Option<Url>,
}

pub(crate) struct S3Target<'a> {
    pub(crate) account: &'a str,
    pub(crate) bucket: &'a str,
    pub(crate) key: &'a str,
}

impl S3Transport {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            #[cfg(test)]
            test_origin: None,
        }
    }

    pub(crate) async fn send(
        &self,
        target: &S3Target<'_>,
        method: Method,
        mut headers: BTreeMap<String, String>,
        body: Option<Vec<u8>>,
        token_id: &str,
        credential: &AuthCredential,
    ) -> Result<Response> {
        let token = credential.bearer_token().ok_or_else(rejected)?;
        if token_id.len() != 32 || !token_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(rejected());
        }
        let url = target_url(target)?;
        #[cfg(test)]
        let url = self.test_origin.as_ref().map_or(url.clone(), |origin| {
            let mut test = origin.clone();
            test.set_path(url.path());
            test
        });
        let mut request = Request::new(method, url);
        let payload_hash = hex::encode(Sha256::digest(body.as_deref().unwrap_or_default()));
        if let Some(body) = body {
            headers.insert("content-length".into(), body.len().to_string());
            *request.body_mut() = Some(body.into());
        }
        for (name, value) in headers {
            request.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| rejected())?,
                HeaderValue::from_str(&value).map_err(|_| rejected())?,
            );
        }
        let derived_secret = hex::encode(Sha256::digest(token.as_bytes()));
        sign(
            &mut request,
            token_id,
            &derived_secret,
            "auto",
            Utc::now(),
            &payload_hash,
        )?;
        // No retry, redirect, alternative endpoint or response-bearing error.
        self.client.execute(request).await.map_err(|_| rejected())
    }
    /// Capture-only `ListObjectsV2`. No caller-controlled query or endpoint.
    pub(crate) async fn list(
        &self,
        account: &str,
        bucket: &str,
        cursor: Option<&str>,
        token_id: &str,
        credential: &AuthCredential,
    ) -> Result<Response> {
        let token = credential.bearer_token().ok_or_else(rejected)?;
        if token_id.len() != 32 || !token_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(rejected());
        }
        let mut url = target_url(&S3Target {
            account,
            bucket,
            key: "list-validation",
        })?;
        url.set_path(&format!("/{bucket}"));
        let query = list_query(cursor)?;
        url.set_query(Some(&query));
        #[cfg(test)]
        let url = self.test_origin.as_ref().map_or(url.clone(), |origin| {
            let mut test = origin.clone();
            test.set_path(url.path());
            test.set_query(url.query());
            test
        });
        let mut request = Request::new(Method::GET, url.clone());
        *request.timeout_mut() = Some(std::time::Duration::from_mins(1));
        request
            .headers_mut()
            .insert("accept-encoding", HeaderValue::from_static("identity"));
        sign(
            &mut request,
            token_id,
            &hex::encode(Sha256::digest(token.as_bytes())),
            "auto",
            Utc::now(),
            &hex::encode(Sha256::digest([])),
        )?;
        let response = self.client.execute(request).await.map_err(|_| rejected())?;
        if response.url() != &url {
            return Err(rejected());
        }
        Ok(response)
    }
}

fn target_url(target: &S3Target<'_>) -> Result<Url> {
    if target.account.len() != 32
        || !target
            .account
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !(3..=63).contains(&target.bucket.len())
        || !target
            .bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || target.bucket.starts_with('-')
        || target.bucket.ends_with('-')
        || !cfctl_core::r2_restore::key_supported(target.key)
    {
        return Err(rejected());
    }
    let path = format!("/{}/{}", target.bucket, encode_key(target.key));
    let url = Url::parse(&format!(
        "https://{}.r2.cloudflarestorage.com{path}",
        target.account
    ))
    .map_err(|_| rejected())?;
    if url.path() != path || url.query().is_some() || url.fragment().is_some() {
        return Err(rejected());
    }
    Ok(url)
}

fn encode_key(key: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

fn list_query(cursor: Option<&str>) -> Result<String> {
    let mut query = String::new();
    if let Some(cursor) = cursor {
        if cursor.is_empty() || cursor.len() > cfctl_core::r2_recovery::MAX_CURSOR_BYTES {
            return Err(rejected());
        }
        query.push_str("continuation-token=");
        query.push_str(&encode_key(cursor).replace('/', "%2F"));
        query.push('&');
    }
    query.push_str("encoding-type=url&list-type=2&max-keys=100");
    Ok(query)
}

/// A query can enter the signer only if it is exactly the closed list query.
fn canonical_query(url: &Url) -> Result<String> {
    let Some(query) = url.query() else {
        return Ok(String::new());
    };
    let pairs = url.query_pairs().collect::<Vec<_>>();
    let cursor = pairs.iter().find(|(name, _)| name == "continuation-token");
    let expected = list_query(cursor.map(|(_, value)| value.as_ref()))?;
    if query != expected || url.path().split('/').count() != 2 || url.fragment().is_some() {
        return Err(rejected());
    }
    Ok(expected)
}

fn hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<sha2_compat::Sha256>::new_from_slice(key).map_err(|_| rejected())?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sign(
    request: &mut Request,
    access_key: &str,
    secret: &str,
    region: &str,
    now: DateTime<Utc>,
    payload_hash: &str,
) -> Result<()> {
    let host = request.url().host_str().ok_or_else(rejected)?.to_owned();
    let host = request
        .url()
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}"));
    let date = now.format("%Y%m%d").to_string();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    for (name, value) in [
        ("host", host.as_str()),
        ("x-amz-date", &timestamp),
        ("x-amz-content-sha256", payload_hash),
    ] {
        request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).map_err(|_| rejected())?,
        );
    }
    let mut canonical = BTreeMap::new();
    for (name, value) in request.headers() {
        if name == reqwest::header::AUTHORIZATION {
            return Err(rejected());
        }
        let value = value.to_str().map_err(|_| rejected())?;
        canonical.insert(
            name.as_str(),
            value.split_ascii_whitespace().collect::<Vec<_>>().join(" "),
        );
    }
    let names = canonical.keys().copied().collect::<Vec<_>>().join(";");
    let mut headers = String::new();
    for (key, value) in &canonical {
        headers.push_str(key);
        headers.push(':');
        headers.push_str(value);
        headers.push('\n');
    }
    let query = canonical_query(request.url())?;
    let canonical_request = format!(
        "{}\n{}\n{query}\n{headers}\n{names}\n{payload_hash}",
        request.method(),
        request.url().path()
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let key = hmac(&key, region.as_bytes())?;
    let key = hmac(&key, b"s3")?;
    let key = hmac(&key, b"aws4_request")?;
    let signature = hex::encode(hmac(&key, to_sign.as_bytes())?);
    let mut header = HeaderValue::from_str(&format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={names},Signature={signature}"))
        .map_err(|_| rejected())?;
    header.set_sensitive(true);
    request
        .headers_mut()
        .insert(reqwest::header::AUTHORIZATION, header);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    #[test]
    fn bucket_query_is_closed_sorted_and_exactly_encoded() {
        let cursor = "opaque /+%=雪";
        let query = list_query(Some(cursor)).unwrap();
        assert_eq!(
            query,
            "continuation-token=opaque%20%2F%2B%25%3D%E9%9B%AA&encoding-type=url&list-type=2&max-keys=100"
        );
        let url = Url::parse(&format!("https://example.test/bucket?{query}")).unwrap();
        assert_eq!(canonical_query(&url).unwrap(), query);
        for suffix in ["&prefix=hidden", "&max-keys=100", "&delimiter=%2F"] {
            assert!(canonical_query(&Url::parse(&format!("{url}{suffix}")).unwrap()).is_err());
        }
        assert!(
            canonical_query(
                &Url::parse(
                    "https://example.test/bucket/object?encoding-type=url&list-type=2&max-keys=100"
                )
                .unwrap()
            )
            .is_err()
        );
        assert!(
            canonical_query(
                &Url::parse(
                    "https://example.test/bucket?max-keys=100&list-type=2&encoding-type=url"
                )
                .unwrap()
            )
            .is_err()
        );
        assert!(list_query(Some("")).is_err());
    }

    #[test]
    fn aws_published_get_object_signature_vector() {
        let mut request = Request::new(
            Method::GET,
            Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").expect("public example"),
        );
        request
            .headers_mut()
            .insert("range", HeaderValue::from_static("bytes=0-9"));
        let now = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .expect("date")
            .with_timezone(&Utc);
        sign(
            &mut request,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            now,
            &hex::encode(Sha256::digest([])),
        )
        .expect("sign");
        assert!(
            request.headers()["authorization"]
                .to_str()
                .expect("header")
                .ends_with(
                    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
                )
        );
        assert!(request.headers()["authorization"].is_sensitive());
    }
    #[test]
    fn target_is_account_bound_and_preserves_exact_key() {
        let account = "a".repeat(32);
        let url = target_url(&S3Target {
            account: &account,
            bucket: "private-pdfs",
            key: "docs//é +?#%\\file",
        })
        .expect("encoded target");
        assert_eq!(
            url.path(),
            "/private-pdfs/docs//%C3%A9%20%2B%3F%23%25%5Cfile"
        );
        assert_eq!(
            url.host_str(),
            Some(format!("{account}.r2.cloudflarestorage.com").as_str())
        );
        for key in ["docs/../other", "./other", "docs/."] {
            assert!(
                target_url(&S3Target {
                    account: &account,
                    bucket: "private-pdfs",
                    key
                })
                .is_err()
            );
        }
    }
}
