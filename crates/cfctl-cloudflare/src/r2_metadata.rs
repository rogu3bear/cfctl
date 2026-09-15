//! Exact positive REST membership, shared by capture and conditional restore.
use crate::{Result, r2_recovery::failure};
use serde_json::{Value, json};

pub(crate) fn member_url(base: &url::Url, key: &str) -> url::Url {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("prefix", key)
        .append_pair("per_page", "100");
    url
}

pub(crate) fn exact_member(value: &Value, key: &str) -> Result<Value> {
    let rejected = || failure("private exact-member metadata contract rejected");
    if value["success"] != true || value["errors"].as_array().is_none_or(|e| !e.is_empty()) {
        return Err(rejected());
    }
    let rows = value["result"]
        .as_array()
        .filter(|r| r.len() <= 100)
        .ok_or_else(rejected)?;
    let mut matching = rows.iter().filter(|r| r["key"] == key);
    let record = matching.next().ok_or_else(rejected)?;
    if matching.next().is_some() {
        return Err(rejected());
    }
    cfctl_core::r2_recovery::validate_object(record).map_err(|_| rejected())?;
    // Positive membership only: no claim about prefix pagination or absence.
    Ok(record.clone())
}

/// Reject duplicate object keys at every depth and trailing input before Value
/// construction can collapse keys. Strings (including application JSON TEXT)
/// are opaque; serde's normal recursion limit remains enabled.
pub(crate) fn strict_json(bytes: &[u8]) -> std::result::Result<Value, serde_json::Error> {
    use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct StrictVisitor;
            impl<'de> Visitor<'de> for StrictVisitor {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("duplicate-free JSON")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(v)))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(v)))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(v)))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(v)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                    Ok(Strict(json!(v)))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut v = Vec::new();
                    while let Some(Strict(item)) = a.next_element()? {
                        v.push(item);
                    }
                    Ok(Strict(Value::Array(v)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut v = serde_json::Map::new();
                    while let Some(key) = a.next_key::<String>()? {
                        if v.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate JSON key"));
                        }
                        let Strict(item) = a.next_value()?;
                        v.insert(key, item);
                    }
                    Ok(Strict(Value::Object(v)))
                }
            }
            d.deserialize_any(StrictVisitor)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}
