//! Capture-specific `ListObjectsV2` grammar. No absence inferred from row counts.
use super::{CaptureProgress, CaptureReason, contract, failure};
use crate::Result;
use chrono::{DateTime, Utc};
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use serde_json::Value;
use std::collections::BTreeMap;

const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
type Fields = BTreeMap<String, String>;
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Object {
    pub key: String,
    pub size: u64,
    etag: String,
    modified: DateTime<Utc>,
    storage_class: String,
}
impl Object {
    pub(super) fn matches(&self, metadata: &Value) -> bool {
        metadata["key"] == self.key
            && metadata["size"].as_u64() == Some(self.size)
            && metadata["etag"] == self.etag
            && metadata["storage_class"] == self.storage_class
            && metadata["last_modified"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|date| date == self.modified)
    }
}
pub(super) struct Page {
    pub rows: Vec<Object>,
    pub next: Option<String>,
}
fn rejected() -> crate::CloudflareError {
    failure("private S3 inventory contract rejected")
}

/// Decode Key once; unlike form decoding, '+' is a literal plus.
fn decode_key(encoded: &str) -> Result<String> {
    let mut bytes = Vec::new();
    let mut input = encoded.bytes();
    while let Some(byte) = input.next() {
        bytes.push(if byte == b'%' {
            let hi = char::from(input.next().ok_or_else(rejected)?)
                .to_digit(16)
                .ok_or_else(rejected)?;
            let lo = char::from(input.next().ok_or_else(rejected)?)
                .to_digit(16)
                .ok_or_else(rejected)?;
            u8::try_from(hi * 16 + lo).map_err(|_| rejected())?
        } else {
            byte
        });
        if bytes.len() > 1024 {
            return Err(rejected());
        }
    }
    let key = String::from_utf8(bytes).map_err(|_| rejected())?;
    if key.is_empty() {
        return Err(rejected());
    }
    Ok(key)
}
fn object(fields: &Fields) -> Result<Object> {
    let get = |name: &str| fields.get(name).map(String::as_str).ok_or_else(rejected);
    let etag = get("ETag")?
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(rejected)?;
    if etag.is_empty()
        || etag.len() > 256
        || !etag.bytes().all(|b| b.is_ascii_graphic() && b != b'"')
    {
        return Err(rejected());
    }
    let size = get("Size")?.parse::<u64>().map_err(|_| rejected())?;
    if size > contract::MAX_BYTES {
        return Err(rejected());
    }
    Ok(Object {
        key: decode_key(get("Key")?)?,
        size,
        etag: etag.into(),
        modified: DateTime::parse_from_rfc3339(get("LastModified")?)
            .map_err(|_| rejected())?
            .with_timezone(&Utc),
        storage_class: match get("StorageClass")? {
            "STANDARD" => "Standard",
            "STANDARD_IA" => "InfrequentAccess",
            _ => return Err(rejected()),
        }
        .into(),
    })
}

fn allowed_field(parent: &str, field: &str) -> bool {
    match parent {
        "ListBucketResult" => matches!(
            field,
            "Name"
                | "Prefix"
                | "Delimiter"
                | "StartAfter"
                | "MaxKeys"
                | "KeyCount"
                | "EncodingType"
                | "ContinuationToken"
                | "NextContinuationToken"
                | "IsTruncated"
        ),
        "Contents" => matches!(
            field,
            "Key" | "ETag" | "Size" | "LastModified" | "StorageClass"
        ),
        _ => false,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded XML event grammar keeps namespace, duplicate and terminal admission together"
)]
pub(super) fn parse(
    bytes: &[u8],
    bucket: &str,
    cursor: Option<&str>,
    progress: &CaptureProgress,
) -> Result<Page> {
    progress.expect(CaptureReason::Xml);
    if bytes.len() as u64 > contract::MAX_RESPONSE_BYTES {
        return Err(rejected());
    }
    let input = std::str::from_utf8(bytes).map_err(|_| rejected())?;
    // XML 1.0 characters; keys needing controls must use encoding-type=url.
    if input.chars().any(|c| !xml_char(c)) {
        return Err(rejected());
    }
    let mut reader = NsReader::from_str(input);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<(String, String)> = Vec::new();
    let mut root = Fields::new();
    let mut member = Fields::new();
    let mut rows = Vec::new();
    let mut seen_root = false;
    let mut declaration = false;
    loop {
        let (namespace, event) = reader.read_resolved_event().map_err(|_| rejected())?;
        let valid_ns = matches!(namespace, ResolveResult::Bound(ns) if ns.as_ref() == NS);
        match event {
            Event::Decl(decl) if !seen_root && !declaration && stack.is_empty() => {
                declaration = true;
                if decl.version().map_err(|_| rejected())?.as_ref() != "1.0"
                    || decl
                        .encoding()
                        .transpose()
                        .map_err(|_| rejected())?
                        .is_some_and(|s| !s.eq_ignore_ascii_case("utf-8"))
                {
                    return Err(rejected());
                }
            }
            Event::Start(start) => {
                if !valid_ns {
                    return Err(rejected());
                }
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(|_| rejected())?;
                    let name = attribute.key.as_ref();
                    if name != "xmlns" && !name.starts_with("xmlns:") {
                        return Err(rejected());
                    }
                }
                let name = start.local_name().as_ref().to_owned();
                if stack.is_empty() {
                    if seen_root || name != "ListBucketResult" {
                        return Err(rejected());
                    }
                    seen_root = true;
                } else if stack.len() == 1 && name == "Contents" {
                    if rows.len() >= contract::PAGE_SIZE as usize {
                        return Err(rejected());
                    }
                    member.clear();
                } else if !stack
                    .last()
                    .is_some_and(|(parent, _)| allowed_field(parent, &name))
                {
                    return Err(rejected());
                }
                if stack.len() >= 16 {
                    return Err(rejected());
                }
                stack.push((name, String::new()));
            }
            Event::End(_) => {
                if !valid_ns {
                    return Err(rejected());
                }
                let (name, value) = stack.pop().ok_or_else(rejected)?;
                if name == "Contents" {
                    if !value.trim().is_empty() {
                        return Err(rejected());
                    }
                    progress.expect(CaptureReason::ObjectMetadata);
                    rows.push(object(&member)?);
                    progress.expect(CaptureReason::Xml);
                } else if name == "ListBucketResult" {
                    if !value.trim().is_empty() {
                        return Err(rejected());
                    }
                } else {
                    let fields = if stack.len() == 2 {
                        &mut member
                    } else {
                        &mut root
                    };
                    if fields.insert(name, value).is_some() {
                        return Err(rejected());
                    }
                }
            }
            Event::Text(text) => append_text(
                &mut stack,
                &text.xml_content(quick_xml::XmlVersion::Implicit1_0),
            )?,
            Event::GeneralRef(reference) => {
                let raw = format!("&{};", reference.as_ref());
                let value = quick_xml::escape::unescape(&raw).map_err(|_| rejected())?;
                if value.chars().any(|c| !xml_char(c)) {
                    return Err(rejected());
                }
                append_text(&mut stack, &value)?;
            }
            Event::Eof if seen_root && stack.is_empty() => break,
            _ => return Err(rejected()),
        }
    }
    progress.expect(CaptureReason::PaginationMetadata);
    if root.get("Name").map(String::as_str) != Some(bucket)
        || root.get("EncodingType").map(String::as_str) != Some("url")
        || ["Prefix", "Delimiter", "StartAfter"]
            .iter()
            .any(|key| root.get(*key).is_some_and(|s| !s.is_empty()))
        || root
            .get("MaxKeys")
            .is_some_and(|n| n.parse::<u32>().ok() != Some(contract::PAGE_SIZE))
        || root
            .get("KeyCount")
            .is_some_and(|n| n.parse::<usize>().ok() != Some(rows.len()))
        || root
            .get("ContinuationToken")
            .is_some_and(|s| Some(s.as_str()) != cursor)
    {
        return Err(rejected());
    }
    progress.expect(CaptureReason::PaginationTerminal);
    let next = root
        .remove("NextContinuationToken")
        .filter(|s| !s.is_empty());
    match root.get("IsTruncated").map(String::as_str) {
        Some("false") if next.is_none() => Ok(Page { rows, next }),
        Some("true")
            if next.as_ref().is_some_and(|s| {
                s.len() <= contract::MAX_CURSOR_BYTES && Some(s.as_str()) != cursor
            }) =>
        {
            Ok(Page { rows, next })
        }
        _ => Err(rejected()),
    }
}
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn append_text(stack: &mut [(String, String)], text: &str) -> Result<()> {
    if let Some((_, value)) = stack.last_mut() {
        if value.len() + text.len() > contract::MAX_CURSOR_BYTES {
            return Err(rejected());
        }
        value.push_str(text);
    } else if !text.trim().is_empty() {
        return Err(rejected());
    }
    Ok(())
}
