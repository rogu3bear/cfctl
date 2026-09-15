//! Capture-wide inventory and response budgets, shared by both observations.
use super::{CaptureProgress, CaptureReason, Result, contract, failure, s3_inventory};
use crate::r2_s3::S3Transport;
use cfctl_auth::AuthCredential;
use futures_util::StreamExt;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Budget {
    pub pages: u32,
    pub xml_bytes: u64,
    pub metadata_bytes: u64,
}
pub(super) struct InventoryContext<'a> {
    pub transport: &'a S3Transport,
    pub account: &'a str,
    pub bucket: &'a str,
    pub token_id: &'a str,
    pub credential: &'a AuthCredential,
    pub progress: &'a CaptureProgress,
}
impl InventoryContext<'_> {
    pub async fn read(
        &self,
        budget: &mut Budget,
    ) -> Result<BTreeMap<String, s3_inventory::Object>> {
        let mut objects = BTreeMap::new();
        let mut cursors = BTreeSet::new();
        let mut cursor = None;
        let mut bytes = 0_u64;
        loop {
            self.progress.expect(CaptureReason::PaginationBounds);
            if budget.pages >= contract::MAX_PAGES {
                return Err(failure("private capture page budget exhausted"));
            }
            self.progress.expect(CaptureReason::BodyLimit);
            if budget.xml_bytes >= contract::MAX_XML_BYTES {
                return Err(failure("private XML byte budget exhausted"));
            }
            budget.pages += 1;
            self.progress.begin_request()?;
            let response = self
                .transport
                .list(
                    self.account,
                    self.bucket,
                    cursor.as_deref(),
                    self.token_id,
                    self.credential,
                )
                .await?;
            self.progress.observed_status(response.status().as_u16());
            self.progress.expect(CaptureReason::HttpResponse);
            if response.status().as_u16() != 200 {
                return Err(failure("private S3 listing did not return HTTP 200"));
            }
            let body = bounded_response(
                response,
                &mut budget.xml_bytes,
                contract::MAX_XML_BYTES,
                self.progress,
            )
            .await?;
            let page = s3_inventory::parse(&body, self.bucket, cursor.as_deref(), self.progress)?;
            for row in page.rows {
                self.progress.expect(CaptureReason::PopulationBounds);
                bytes = bytes
                    .checked_add(row.size)
                    .filter(|n| *n <= contract::MAX_BYTES)
                    .ok_or_else(|| failure("private capture byte budget exhausted"))?;
                if objects.insert(row.key.clone(), row).is_some()
                    || objects.len() > contract::MAX_OBJECTS
                {
                    return Err(failure(
                        "private inventory repeated key or exceeded population limit",
                    ));
                }
            }
            let Some(next) = page.next else {
                return Ok(objects);
            };
            self.progress.expect(CaptureReason::PaginationCursor);
            if !cursors.insert(next.clone()) {
                return Err(failure("private S3 listing repeated cursor"));
            }
            cursor = Some(next);
        }
    }
}

pub(super) async fn bounded_response(
    response: reqwest::Response,
    total: &mut u64,
    limit: u64,
    progress: &CaptureProgress,
) -> Result<Vec<u8>> {
    progress.expect(CaptureReason::BodyLimit);
    if *total >= limit
        || response
            .content_length()
            .is_some_and(|n| n > contract::MAX_RESPONSE_BYTES || n > limit - *total)
    {
        return Err(failure("private response byte budget exhausted"));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    loop {
        progress.expect(CaptureReason::BodyRead);
        let Some(chunk) = stream.next().await else {
            break;
        };
        let chunk = chunk.map_err(|_| failure("private response stream failed"))?;
        progress.expect(CaptureReason::BodyLimit);
        *total = total
            .checked_add(chunk.len() as u64)
            .filter(|n| *n <= limit)
            .ok_or_else(|| failure("private response aggregate budget exhausted"))?;
        if body.len() as u64 + chunk.len() as u64 > contract::MAX_RESPONSE_BYTES {
            return Err(failure("private response per-request budget exhausted"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
