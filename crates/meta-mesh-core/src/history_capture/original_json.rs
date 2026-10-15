use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::fmt;

// Reject duplicate keys at every depth. A later-value-wins JSON parse must not
// give an archived signed payload two possible interpretations.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|value| UniqueJson(Value::Number(value)))
                    .ok_or_else(|| E::custom("Invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.into())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("Duplicate original JSON key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

#[derive(Clone, Copy)]
pub(super) enum Defaults {
    None,
    Authorization,
    Control,
}

impl Defaults {
    fn may_omit(self, key: &str, expected: &Value) -> bool {
        match self {
            Self::None => false,
            Self::Authorization => key == "grant" && expected.is_null(),
            Self::Control => {
                matches!(
                    key,
                    "ownershipTransfers"
                        | "successionClaims"
                        | "revocations"
                        | "deviceRevocations"
                        | "departures"
                ) && expected.as_array().is_some_and(Vec::is_empty)
            }
        }
    }
}

fn equivalent(actual: &Value, expected: &Value, defaults: Defaults) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            actual.keys().all(|key| expected.contains_key(key))
                && expected.iter().all(|(key, value)| {
                    actual
                        .get(key)
                        .map_or(defaults.may_omit(key, value), |actual| {
                            equivalent(actual, value, Defaults::None)
                        })
                })
        }
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(a, b)| equivalent(a, b, Defaults::None))
        }
        _ => actual == expected,
    }
}

pub(super) fn verify(bytes: &[u8], expected: &Value, defaults: Defaults) -> Result<(), String> {
    let actual: UniqueJson =
        serde_json::from_slice(bytes).map_err(|_| "Invalid or ambiguous original history JSON")?;
    // Normalize only these unsigned container defaults for comparison. Never
    // manufacture fields inside an original signed payload or certificate.
    if !equivalent(&actual.0, expected, defaults) {
        return Err("Original history evidence differs from Native preparation".into());
    }
    Ok(())
}
