//! Helpers for moving sensitive JSON strings into zeroizing ownership.
//!
//! `serde_json::Value` does not wipe string allocations when dropped. RPC
//! handlers must therefore remove password, session, content, query, and draft
//! fields through this module and scrub every response object after framing it.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

/// A safe classification for sensitive JSON extraction failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveJsonError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field had a non-string JSON type.
    StringRequired(&'static str),
    /// A base64url field was not canonical unpadded data.
    InvalidBase64Url(&'static str),
    /// An encoded or decoded field exceeded its public byte limit.
    LimitExceeded(&'static str),
}

impl fmt::Display for SensitiveJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingField(_) => "required request field is missing",
            Self::StringRequired(_) => "request field must be a string",
            Self::InvalidBase64Url(_) => "request field is not canonical base64url",
            Self::LimitExceeded(_) => "request field exceeds its byte limit",
        })
    }
}

impl std::error::Error for SensitiveJsonError {}

/// Remove one required string field and transfer its allocation to a
/// [`Zeroizing`] owner.
///
/// If the field has another JSON type, that removed value is recursively
/// scrubbed before the safe type error is returned.
///
/// # Errors
///
/// Returns [`SensitiveJsonError::MissingField`] when absent or
/// [`SensitiveJsonError::StringRequired`] for another JSON type.
pub fn take_string(
    object: &mut Map<String, Value>,
    field: &'static str,
) -> Result<Zeroizing<String>, SensitiveJsonError> {
    let Some(value) = object.remove(field) else {
        return Err(SensitiveJsonError::MissingField(field));
    };
    take_removed_string(value, field)
}

/// Remove an optional string field and transfer its allocation to a zeroizing
/// owner.
///
/// # Errors
///
/// Returns [`SensitiveJsonError::StringRequired`] when the present field has
/// another JSON type.
pub fn take_optional_string(
    object: &mut Map<String, Value>,
    field: &'static str,
) -> Result<Option<Zeroizing<String>>, SensitiveJsonError> {
    object
        .remove(field)
        .map(|value| take_removed_string(value, field))
        .transpose()
}

/// Decode canonical unpadded base64url into a zeroizing byte allocation.
///
/// The encoded input is wiped on return. `maximum_decoded_bytes` is checked
/// before allocation and again after decoding.
///
/// # Errors
///
/// Returns [`SensitiveJsonError::LimitExceeded`] for an oversized value or
/// [`SensitiveJsonError::InvalidBase64Url`] for invalid/non-canonical text.
pub fn decode_base64url(
    encoded: Zeroizing<String>,
    field: &'static str,
    maximum_decoded_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SensitiveJsonError> {
    let maximum_encoded = maximum_decoded_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .unwrap_or(usize::MAX);
    if encoded.len() > maximum_encoded {
        return Err(SensitiveJsonError::LimitExceeded(field));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| SensitiveJsonError::InvalidBase64Url(field))?;
    let decoded = Zeroizing::new(decoded);
    if decoded.len() > maximum_decoded_bytes {
        return Err(SensitiveJsonError::LimitExceeded(field));
    }
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if canonical.as_bytes() != encoded.as_bytes() {
        return Err(SensitiveJsonError::InvalidBase64Url(field));
    }
    drop(encoded);
    Ok(decoded)
}

/// Encode sensitive bytes as canonical unpadded base64url in a zeroizing
/// string allocation.
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))
}

/// Recursively zeroize all string keys and values, then empty a JSON object.
///
/// Call this after emitting a response and on any rejected request parameters
/// that were not transferred into dedicated zeroizing owners.
pub fn scrub_object(object: &mut Map<String, Value>) {
    for (mut key, mut value) in std::mem::take(object) {
        key.zeroize();
        scrub_value(&mut value);
    }
}

/// Recursively zeroize all JSON string storage and replace `value` with null.
pub fn scrub_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                scrub_value(value);
            }
        }
        Value::Object(object) => scrub_object(object),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    *value = Value::Null;
}

fn take_removed_string(
    value: Value,
    field: &'static str,
) -> Result<Zeroizing<String>, SensitiveJsonError> {
    match value {
        Value::String(text) => Ok(Zeroizing::new(text)),
        mut other => {
            scrub_value(&mut other);
            Err(SensitiveJsonError::StringRequired(field))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{
        SensitiveJsonError, decode_base64url, encode_base64url, scrub_object, take_optional_string,
        take_string,
    };

    #[test]
    fn required_and_optional_strings_move_out_of_json() {
        let mut object = Map::from_iter([
            ("password".to_owned(), Value::String("canary".to_owned())),
            ("optional".to_owned(), Value::String("value".to_owned())),
        ]);
        let password = take_string(&mut object, "password")
            .unwrap_or_else(|error| panic!("password extraction failed: {error}"));
        let optional = take_optional_string(&mut object, "optional")
            .unwrap_or_else(|error| panic!("optional extraction failed: {error}"));
        assert_eq!(password.as_str(), "canary");
        assert_eq!(optional.as_ref().map(|value| value.as_str()), Some("value"));
        assert!(object.is_empty());
    }

    #[test]
    fn wrong_types_are_scrubbed_and_errors_never_echo_values() {
        let mut object = Map::from_iter([(
            "password".to_owned(),
            json!({"canary-secret": ["nested-canary"]}),
        )]);
        let error =
            take_string(&mut object, "password").expect_err("object password must be rejected");
        assert_eq!(error, SensitiveJsonError::StringRequired("password"));
        assert!(!format!("{error:?}").contains("canary"));
        assert!(!error.to_string().contains("canary"));
        assert!(object.is_empty());
    }

    #[test]
    fn base64url_round_trip_is_canonical_and_bounded() {
        let encoded = encode_base64url("秘密".as_bytes());
        let decoded = decode_base64url(encoded, "contentBase64", 16)
            .unwrap_or_else(|error| panic!("base64 decode failed: {error}"));
        assert_eq!(decoded.as_slice(), "秘密".as_bytes());
        assert!(matches!(
            decode_base64url(
                zeroize::Zeroizing::new("YQ==".to_owned()),
                "contentBase64",
                16,
            ),
            Err(SensitiveJsonError::InvalidBase64Url("contentBase64"))
        ));
        assert!(matches!(
            decode_base64url(
                zeroize::Zeroizing::new("YWFhYQ".to_owned()),
                "contentBase64",
                3,
            ),
            Err(SensitiveJsonError::LimitExceeded("contentBase64"))
        ));
    }

    #[test]
    fn recursive_scrub_empties_objects_and_nulls_values() {
        let mut object = json!({
            "secret-key": "secret-value",
            "nested": ["one", {"two": "three"}],
        })
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("test object missing"));
        scrub_object(&mut object);
        assert!(object.is_empty());
    }
}
