use cfctl_core::d1_read_inventory::{
    D1ReadParameterEvidenceV1, D1ReadQueryResultV1, D1ReadQueryV1, D1ReadStatusV1,
    D1ReadValueKindV1,
};
use serde_json::Value;

pub(super) struct BoundParameters {
    pub values: Vec<Value>,
    pub provenance: Vec<D1ReadParameterEvidenceV1>,
}

/// Only the preceding qualified entries of this execution are eligible. The
/// caller provides no values, SQL fragments, result cache or alternate scope.
pub(super) fn bind(
    query: &D1ReadQueryV1,
    previous: &[D1ReadQueryResultV1],
) -> Option<BoundParameters> {
    let mut bound = BoundParameters {
        values: Vec::new(),
        provenance: Vec::new(),
    };
    for parameter in &query.parameters {
        let prior = previous.iter().find(|prior| {
            prior.query_id == parameter.from_query && prior.status == D1ReadStatusV1::Complete
        })?;
        let source = prior
            .receipt
            .as_ref()?
            .pointer("/result/0/results")?
            .as_array()?
            .get(usize::try_from(parameter.row_index).ok()?)?
            .get(&parameter.column)?;
        let value = match parameter.kind {
            D1ReadValueKindV1::Text => {
                let text = source.as_str()?;
                let text = if parameter.trim {
                    text.trim_matches(ecmascript_whitespace)
                } else {
                    text
                };
                if (parameter.nonempty && text.is_empty())
                    || text.contains('\0')
                    || text.len() as u64 > parameter.max_bytes?
                {
                    return None;
                }
                Value::String(text.into())
            }
            D1ReadValueKindV1::Integer if source.as_i64().is_some() => source.clone(),
            D1ReadValueKindV1::Real
                if source.is_f64() && source.as_f64().is_some_and(f64::is_finite) =>
            {
                source.clone()
            }
            D1ReadValueKindV1::Boolean if source.is_boolean() => source.clone(),
            _ => return None,
        };
        bound.provenance.push(D1ReadParameterEvidenceV1 {
            index: parameter.index,
            from_query: prior.query_id.clone(),
            from_query_sha256: prior.query_sha256.clone(),
            row_index: parameter.row_index,
            column: parameter.column.clone(),
            value_sha256: cfctl_core::hash_value(&value).ok()?,
        });
        bound.values.push(value);
    }
    Some(bound)
}

// Match JavaScript String.trim used by the existing read consumer, including
// BOM and excluding NEL. The behavior is explicit in the source contract.
fn ecmascript_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
        | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
