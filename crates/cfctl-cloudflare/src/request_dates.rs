//! Date-only syntax shared by schemas and bounded analytics inputs.

use crate::{CallInput, CapabilityV1, Result, TimestampFormatV1, analytics_timestamp};
use chrono::NaiveDate;

pub(super) fn parse(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || !bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
    {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

pub(super) fn validate_analytics_dates(capability: &CapabilityV1, input: &CallInput) -> Result<()> {
    let Some(time) = capability
        .analytics_query
        .as_ref()
        .filter(|contract| contract.read_only && !capability.mutating)
        .and_then(|contract| contract.time_range.as_ref())
        .filter(|time| time.timestamp_format == TimestampFormatV1::Date)
    else {
        return Ok(());
    };
    let Some(body) = input.body.as_ref().filter(|body| body.is_object()) else {
        return Ok(());
    };
    let (Some(start), Some(end)) = (
        body.pointer(&time.start_pointer)
            .filter(|value| value.is_string()),
        body.pointer(&time.end_pointer)
            .filter(|value| value.is_string()),
    ) else {
        return Ok(());
    };
    // Preserve the analytics diagnostic for date strings before the generic schema
    // check, including mixed invalid-date/schema input. Missing/type errors and
    // the remaining analytics bounds stay with their existing validators.
    analytics_timestamp(start, TimestampFormatV1::Date)?;
    analytics_timestamp(end, TimestampFormatV1::Date)?;
    Ok(())
}
