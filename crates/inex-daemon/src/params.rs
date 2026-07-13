//! Strict, redacted extraction of method-specific JSON-RPC parameters.
//!
//! [`crate::protocol`] validates the request envelope and applies recursive
//! complexity limits. This module is the second stage: handlers remove each
//! field with an exact type and bound, then call [`ParamObject::finish`] to
//! prove that no unknown fields remain. Sensitive strings are transferred to
//! [`Zeroizing`] owners instead of being copied out of `serde_json::Value`.

use std::fmt;

use inex_core::path::{AssetPath, LogicalDir, LogicalPath};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{ErrorCode, Params};
use crate::sensitive::{self, SensitiveJsonError};

/// Safe class of a method-parameter validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamErrorKind {
    /// A required field was missing or a field had an invalid type or value.
    InvalidParams,
    /// A public byte or numeric resource bound was exceeded.
    LimitExceeded,
}

/// Redacted method-parameter validation failure.
///
/// Only the public schema field name is retained. Supplied values, capability
/// tokens, plaintext, passwords, and physical paths are never retained or
/// formatted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParamError {
    kind: ParamErrorKind,
    field: Option<&'static str>,
}

impl ParamError {
    const fn invalid(field: Option<&'static str>) -> Self {
        Self {
            kind: ParamErrorKind::InvalidParams,
            field,
        }
    }

    const fn limit(field: &'static str) -> Self {
        Self {
            kind: ParamErrorKind::LimitExceeded,
            field: Some(field),
        }
    }

    /// Return the safe failure class.
    #[must_use]
    pub const fn kind(self) -> ParamErrorKind {
        self.kind
    }

    /// Return the public schema field associated with the failure, if any.
    #[must_use]
    pub const fn field(self) -> Option<&'static str> {
        self.field
    }

    /// Map the failure to the frozen JSON-RPC error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self.kind {
            ParamErrorKind::InvalidParams => ErrorCode::InvalidParams,
            ParamErrorKind::LimitExceeded => ErrorCode::LimitExceeded,
        }
    }
}

impl fmt::Debug for ParamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParamError")
            .field("kind", &self.kind)
            .field("field", &self.field)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for ParamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().safe_message())
    }
}

impl std::error::Error for ParamError {}

impl From<SensitiveJsonError> for ParamError {
    fn from(error: SensitiveJsonError) -> Self {
        match error {
            SensitiveJsonError::MissingField(field)
            | SensitiveJsonError::StringRequired(field)
            | SensitiveJsonError::InvalidBase64Url(field) => Self::invalid(Some(field)),
            SensitiveJsonError::LimitExceeded(field) => Self::limit(field),
        }
    }
}

/// An exact, lowercase, hyphenated UUID string.
///
/// The wrapper keeps accidental diagnostics redacted. Convert it to the UUID
/// type required by a downstream API only at that API boundary.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CanonicalUuid(String);

impl CanonicalUuid {
    /// Borrow the canonical wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the canonical wire spelling.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for CanonicalUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalUuid(<redacted>)")
    }
}

impl fmt::Display for CanonicalUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted UUID>")
    }
}

/// A canonical `sha256:` ciphertext etag.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CanonicalEtag(String);

impl CanonicalEtag {
    /// Borrow the canonical etag for a core precondition check.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the canonical etag.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for CanonicalEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalEtag(<redacted>)")
    }
}

impl fmt::Display for CanonicalEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted etag>")
    }
}

/// Destructive, schema-driven view of one request's parameter object.
///
/// Removed sensitive fields receive zeroizing ownership. Remaining fields are
/// recursively scrubbed when this object is dropped, including on an early
/// parse error.
pub struct ParamObject {
    fields: Map<String, Value>,
}

impl ParamObject {
    /// Start method-specific extraction from complexity-checked parameters.
    #[must_use]
    pub fn new(params: Params) -> Self {
        Self {
            fields: params.into_object(),
        }
    }

    fn from_fields(fields: Map<String, Value>) -> Self {
        Self { fields }
    }

    /// Remove a required bounded string.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when absent, wrongly typed, or shorter than
    /// `minimum_bytes`, and `LimitExceeded` when longer than `maximum_bytes`.
    pub fn required_string(
        &mut self,
        field: &'static str,
        minimum_bytes: usize,
        maximum_bytes: usize,
    ) -> Result<String, ParamError> {
        let value = self.take_required(field)?;
        let Value::String(value) = value else {
            return Err(invalid_removed(value, field));
        };
        validate_string_length(value, field, minimum_bytes, maximum_bytes)
    }

    /// Remove an optional bounded string.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::required_string`] for a present
    /// field.
    pub fn optional_string(
        &mut self,
        field: &'static str,
        minimum_bytes: usize,
        maximum_bytes: usize,
    ) -> Result<Option<String>, ParamError> {
        let Some(value) = self.fields.remove(field) else {
            return Ok(None);
        };
        let Value::String(value) = value else {
            return Err(invalid_removed(value, field));
        };
        validate_string_length(value, field, minimum_bytes, maximum_bytes).map(Some)
    }

    /// Remove a required sensitive string into zeroizing ownership.
    ///
    /// # Errors
    ///
    /// Returns a safe invalid/limit failure without retaining the value.
    pub fn required_sensitive_string(
        &mut self,
        field: &'static str,
        minimum_bytes: usize,
        maximum_bytes: usize,
    ) -> Result<Zeroizing<String>, ParamError> {
        let value = sensitive::take_string(&mut self.fields, field)?;
        validate_sensitive_length(value, field, minimum_bytes, maximum_bytes)
    }

    /// Remove an optional sensitive string into zeroizing ownership.
    ///
    /// # Errors
    ///
    /// Returns a safe invalid/limit failure for a present invalid value.
    pub fn optional_sensitive_string(
        &mut self,
        field: &'static str,
        minimum_bytes: usize,
        maximum_bytes: usize,
    ) -> Result<Option<Zeroizing<String>>, ParamError> {
        sensitive::take_optional_string(&mut self.fields, field)?
            .map(|value| validate_sensitive_length(value, field, minimum_bytes, maximum_bytes))
            .transpose()
    }

    /// Remove a required nested object for exact nested-schema extraction.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when absent or not an object.
    pub fn required_object(&mut self, field: &'static str) -> Result<Self, ParamError> {
        let value = self.take_required(field)?;
        let Value::Object(fields) = value else {
            return Err(invalid_removed(value, field));
        };
        Ok(Self::from_fields(fields))
    }

    /// Remove an optional nested object for exact nested-schema extraction.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when a present field is not an object.
    pub fn optional_object(&mut self, field: &'static str) -> Result<Option<Self>, ParamError> {
        let Some(value) = self.fields.remove(field) else {
            return Ok(None);
        };
        let Value::Object(fields) = value else {
            return Err(invalid_removed(value, field));
        };
        Ok(Some(Self::from_fields(fields)))
    }

    /// Require a string to equal one public protocol constant exactly.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a missing, wrongly typed, or unequal value.
    pub fn required_exact_string(
        &mut self,
        field: &'static str,
        expected: &'static str,
    ) -> Result<(), ParamError> {
        let value = self.take_required(field)?;
        let Value::String(mut actual) = value else {
            return Err(invalid_removed(value, field));
        };
        let matches = actual == expected;
        actual.zeroize();
        if matches {
            Ok(())
        } else {
            Err(ParamError::invalid(Some(field)))
        }
    }

    /// Require the create-only precondition string `"*"` exactly.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` unless the field is the exact string `"*"`.
    pub fn required_star(&mut self, field: &'static str) -> Result<(), ParamError> {
        self.required_exact_string(field, "*")
    }

    /// Remove a required Boolean.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when absent or not a Boolean.
    pub fn required_bool(&mut self, field: &'static str) -> Result<bool, ParamError> {
        let value = self.take_required(field)?;
        let Value::Bool(value) = value else {
            return Err(invalid_removed(value, field));
        };
        Ok(value)
    }

    /// Remove an optional Boolean.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when a present field is not a Boolean.
    pub fn optional_bool(&mut self, field: &'static str) -> Result<Option<bool>, ParamError> {
        let Some(value) = self.fields.remove(field) else {
            return Ok(None);
        };
        let Value::Bool(value) = value else {
            return Err(invalid_removed(value, field));
        };
        Ok(Some(value))
    }

    /// Remove a required bounded unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a missing/non-integer/below-minimum value,
    /// and `LimitExceeded` for a value above `maximum`.
    pub fn required_u64(
        &mut self,
        field: &'static str,
        minimum: u64,
        maximum: u64,
    ) -> Result<u64, ParamError> {
        let value = self.take_required(field)?;
        parse_u64(value, field, minimum, maximum)
    }

    /// Remove an optional bounded unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::required_u64`] for a present field.
    pub fn optional_u64(
        &mut self,
        field: &'static str,
        minimum: u64,
        maximum: u64,
    ) -> Result<Option<u64>, ParamError> {
        self.fields
            .remove(field)
            .map(|value| parse_u64(value, field, minimum, maximum))
            .transpose()
    }

    /// Remove a required bounded signed integer.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a missing/non-integer/below-minimum value,
    /// and `LimitExceeded` for a value above `maximum`.
    pub fn required_i64(
        &mut self,
        field: &'static str,
        minimum: i64,
        maximum: i64,
    ) -> Result<i64, ParamError> {
        let value = self.take_required(field)?;
        parse_i64(value, field, minimum, maximum)
    }

    /// Remove an optional bounded signed integer.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::required_i64`] for a present field.
    pub fn optional_i64(
        &mut self,
        field: &'static str,
        minimum: i64,
        maximum: i64,
    ) -> Result<Option<i64>, ParamError> {
        self.fields
            .remove(field)
            .map(|value| parse_i64(value, field, minimum, maximum))
            .transpose()
    }

    /// Remove a required canonical lowercase, hyphenated UUID string.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for any other spelling or value type.
    pub fn required_uuid(&mut self, field: &'static str) -> Result<CanonicalUuid, ParamError> {
        let value = self.required_string(field, 36, 36)?;
        parse_uuid(value, field)
    }

    /// Remove an optional canonical lowercase, hyphenated UUID string.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a present non-canonical value.
    pub fn optional_uuid(
        &mut self,
        field: &'static str,
    ) -> Result<Option<CanonicalUuid>, ParamError> {
        self.optional_string(field, 36, 36)?
            .map(|value| parse_uuid(value, field))
            .transpose()
    }

    /// Remove and validate a required canonical logical Markdown path.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a non-canonical or profile-invalid path.
    pub fn required_logical_path(
        &mut self,
        field: &'static str,
    ) -> Result<LogicalPath, ParamError> {
        let value = self.required_string(field, 1, inex_core::path::MAX_LOGICAL_PATH_BYTES)?;
        LogicalPath::parse_canonical(&value).map_err(|_| ParamError::invalid(Some(field)))
    }

    /// Remove and validate an optional canonical logical Markdown path.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a present non-canonical/profile-invalid
    /// path.
    pub fn optional_logical_path(
        &mut self,
        field: &'static str,
    ) -> Result<Option<LogicalPath>, ParamError> {
        self.optional_string(field, 1, inex_core::path::MAX_LOGICAL_PATH_BYTES)?
            .map(|value| {
                LogicalPath::parse_canonical(&value).map_err(|_| ParamError::invalid(Some(field)))
            })
            .transpose()
    }

    /// Remove and validate a required canonical opaque-asset path.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a non-canonical path, a Markdown path, or
    /// any value outside the opaque-asset path profile.
    pub fn required_asset_path(&mut self, field: &'static str) -> Result<AssetPath, ParamError> {
        let value = self.required_string(field, 1, inex_core::path::MAX_LOGICAL_PATH_BYTES)?;
        AssetPath::parse_canonical(&value).map_err(|_| ParamError::invalid(Some(field)))
    }

    /// Remove and validate a required canonical logical directory.
    ///
    /// The empty string is accepted as the logical vault root.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a non-canonical/profile-invalid directory.
    pub fn required_logical_dir(&mut self, field: &'static str) -> Result<LogicalDir, ParamError> {
        let value = self.required_string(field, 0, inex_core::path::MAX_LOGICAL_PATH_BYTES)?;
        LogicalDir::parse_canonical(&value).map_err(|_| ParamError::invalid(Some(field)))
    }

    /// Remove and validate an optional canonical logical directory.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a present non-canonical/profile-invalid
    /// directory.
    pub fn optional_logical_dir(
        &mut self,
        field: &'static str,
    ) -> Result<Option<LogicalDir>, ParamError> {
        self.optional_string(field, 0, inex_core::path::MAX_LOGICAL_PATH_BYTES)?
            .map(|value| {
                LogicalDir::parse_canonical(&value).map_err(|_| ParamError::invalid(Some(field)))
            })
            .transpose()
    }

    /// Remove and decode required canonical unpadded base64url data.
    ///
    /// The encoded string and decoded allocation both receive zeroizing
    /// ownership.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for invalid/non-canonical base64url and
    /// `LimitExceeded` when the decoded value exceeds the supplied bound.
    pub fn required_base64url(
        &mut self,
        field: &'static str,
        maximum_decoded_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ParamError> {
        let encoded = sensitive::take_string(&mut self.fields, field)?;
        sensitive::decode_base64url(encoded, field, maximum_decoded_bytes).map_err(Into::into)
    }

    /// Remove and decode optional canonical unpadded base64url data.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::required_base64url`] for a present
    /// field.
    pub fn optional_base64url(
        &mut self,
        field: &'static str,
        maximum_decoded_bytes: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ParamError> {
        sensitive::take_optional_string(&mut self.fields, field)?
            .map(|encoded| {
                sensitive::decode_base64url(encoded, field, maximum_decoded_bytes)
                    .map_err(ParamError::from)
            })
            .transpose()
    }

    /// Remove and validate a required canonical SHA-256 etag.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for any other spelling or value type.
    pub fn required_etag(&mut self, field: &'static str) -> Result<CanonicalEtag, ParamError> {
        let value = self.required_string(field, 71, 71)?;
        parse_etag(value, field)
    }

    /// Remove and validate an optional canonical SHA-256 etag.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` for a present malformed etag.
    pub fn optional_etag(
        &mut self,
        field: &'static str,
    ) -> Result<Option<CanonicalEtag>, ParamError> {
        self.optional_string(field, 71, 71)?
            .map(|value| parse_etag(value, field))
            .transpose()
    }

    /// Prove that every field in this exact schema was consumed.
    ///
    /// Unknown fields are recursively scrubbed before returning.
    ///
    /// # Errors
    ///
    /// Returns `InvalidParams` when one or more unknown fields remain.
    pub fn finish(mut self) -> Result<(), ParamError> {
        if self.fields.is_empty() {
            return Ok(());
        }
        sensitive::scrub_object(&mut self.fields);
        Err(ParamError::invalid(None))
    }

    fn take_required(&mut self, field: &'static str) -> Result<Value, ParamError> {
        self.fields
            .remove(field)
            .ok_or_else(|| ParamError::invalid(Some(field)))
    }
}

impl fmt::Debug for ParamObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParamObject")
            .field("members", &self.fields.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl Drop for ParamObject {
    fn drop(&mut self) {
        sensitive::scrub_object(&mut self.fields);
    }
}

fn invalid_removed(mut value: Value, field: &'static str) -> ParamError {
    sensitive::scrub_value(&mut value);
    ParamError::invalid(Some(field))
}

fn validate_string_length(
    mut value: String,
    field: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<String, ParamError> {
    if minimum > maximum || value.len() < minimum {
        value.zeroize();
        return Err(ParamError::invalid(Some(field)));
    }
    if value.len() > maximum {
        value.zeroize();
        return Err(ParamError::limit(field));
    }
    Ok(value)
}

fn validate_sensitive_length(
    value: Zeroizing<String>,
    field: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<Zeroizing<String>, ParamError> {
    if minimum > maximum || value.len() < minimum {
        return Err(ParamError::invalid(Some(field)));
    }
    if value.len() > maximum {
        return Err(ParamError::limit(field));
    }
    Ok(value)
}

fn parse_u64(
    mut value: Value,
    field: &'static str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ParamError> {
    let Some(number) = value.as_u64() else {
        sensitive::scrub_value(&mut value);
        return Err(ParamError::invalid(Some(field)));
    };
    if minimum > maximum || number < minimum {
        return Err(ParamError::invalid(Some(field)));
    }
    if number > maximum {
        return Err(ParamError::limit(field));
    }
    Ok(number)
}

fn parse_i64(
    mut value: Value,
    field: &'static str,
    minimum: i64,
    maximum: i64,
) -> Result<i64, ParamError> {
    let Some(number) = value.as_i64() else {
        sensitive::scrub_value(&mut value);
        return Err(ParamError::invalid(Some(field)));
    };
    if minimum > maximum || number < minimum {
        return Err(ParamError::invalid(Some(field)));
    }
    if number > maximum {
        return Err(ParamError::limit(field));
    }
    Ok(number)
}

fn parse_uuid(mut value: String, field: &'static str) -> Result<CanonicalUuid, ParamError> {
    let canonical = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        });
    if canonical {
        Ok(CanonicalUuid(value))
    } else {
        value.zeroize();
        Err(ParamError::invalid(Some(field)))
    }
}

fn parse_etag(mut value: String, field: &'static str) -> Result<CanonicalEtag, ParamError> {
    let canonical = value
        .strip_prefix("sha256:")
        .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(is_lower_hex));
    if canonical {
        Ok(CanonicalEtag(value))
    } else {
        value.zeroize();
        Err(ParamError::invalid(Some(field)))
    }
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

#[cfg(test)]
mod tests {
    use inex_core::format::MAX_PLAINTEXT_LEN;
    use serde_json::{Map, Value, json};

    use super::{CanonicalEtag, ParamErrorKind, ParamObject};
    use crate::protocol::{ErrorCode, parse_request};

    fn parameters(mut value: Value) -> crate::protocol::Params {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "system.ping",
            "params": std::mem::take(&mut value),
        });
        let object = request
            .as_object()
            .cloned()
            .unwrap_or_else(Map::<String, Value>::new);
        let request = parse_request(object)
            .unwrap_or_else(|error| panic!("test request parsing failed: {error}"));
        let (_, _, params) = request.into_parts();
        params
    }

    fn object(value: Value) -> ParamObject {
        ParamObject::new(parameters(value))
    }

    #[test]
    fn finish_accepts_empty_and_rejects_unknown_fields() {
        assert_eq!(object(json!({})).finish(), Ok(()));
        let error = object(json!({"surprise": {"secret": "canary"}}))
            .finish()
            .expect_err("unknown field must fail");
        assert_eq!(error.kind(), ParamErrorKind::InvalidParams);
        assert_eq!(error.field(), None);
        assert!(!format!("{error:?}").contains("canary"));
    }

    #[test]
    fn ordinary_strings_are_required_optional_and_bounded() {
        let mut params = object(json!({"client": "vscode", "version": "1"}));
        assert_eq!(
            params.required_string("client", 1, 16).as_deref(),
            Ok("vscode")
        );
        assert_eq!(
            params.optional_string("version", 1, 8),
            Ok(Some("1".to_owned()))
        );
        assert_eq!(params.optional_string("absent", 0, 1), Ok(None));
        assert_eq!(params.finish(), Ok(()));

        for (value, kind) in [
            (json!({}), ParamErrorKind::InvalidParams),
            (json!({"field": false}), ParamErrorKind::InvalidParams),
            (json!({"field": ""}), ParamErrorKind::InvalidParams),
            (json!({"field": "too-long"}), ParamErrorKind::LimitExceeded),
        ] {
            let error = object(value)
                .required_string("field", 1, 3)
                .expect_err("invalid string must fail");
            assert_eq!(error.kind(), kind);
        }
    }

    #[test]
    fn sensitive_strings_transfer_ownership_and_never_format_values() {
        let mut params = object(json!({"password": "secret-canary", "session": "token"}));
        assert_eq!(
            params
                .required_sensitive_string("password", 1, 32)
                .map(|value| value.to_string()),
            Ok("secret-canary".to_owned())
        );
        assert_eq!(
            params
                .optional_sensitive_string("session", 1, 32)
                .map(|value| value.map(|text| text.to_string())),
            Ok(Some("token".to_owned()))
        );
        assert_eq!(params.finish(), Ok(()));

        let mut invalid = object(json!({"password": {"secret-canary": true}}));
        let error = invalid
            .required_sensitive_string("password", 1, 32)
            .expect_err("wrong sensitive type must fail");
        assert_eq!(error.code(), ErrorCode::InvalidParams);
        assert!(!format!("{error:?}").contains("secret-canary"));
        assert!(!error.to_string().contains("secret-canary"));
    }

    #[test]
    fn nested_objects_are_exact_and_scrubbed() {
        let mut params = object(json!({
            "kdf": {"opsLimit": 3, "memLimitBytes": 67_108_864}
        }));
        let mut kdf = params
            .optional_object("kdf")
            .unwrap_or_else(|error| panic!("nested object failed: {error}"))
            .unwrap_or_else(|| panic!("nested object missing"));
        assert_eq!(kdf.required_u64("opsLimit", 1, 20), Ok(3));
        assert_eq!(
            kdf.required_u64("memLimitBytes", 8 * 1024, 1024 * 1024 * 1024),
            Ok(67_108_864)
        );
        assert_eq!(kdf.finish(), Ok(()));
        assert_eq!(params.finish(), Ok(()));

        assert_eq!(
            object(json!({"kdf": []}))
                .optional_object("kdf")
                .expect_err("array is not object")
                .kind(),
            ParamErrorKind::InvalidParams
        );
    }

    #[test]
    fn exact_strings_booleans_and_numbers_are_strict() {
        let mut params = object(json!({
            "star": "*",
            "recursive": false,
            "limit": 50,
            "offset": -2
        }));
        assert_eq!(params.required_star("star"), Ok(()));
        assert_eq!(params.required_bool("recursive"), Ok(false));
        assert_eq!(params.required_u64("limit", 1, 1000), Ok(50));
        assert_eq!(params.required_i64("offset", -10, 10), Ok(-2));
        assert_eq!(params.finish(), Ok(()));

        assert_eq!(
            object(json!({"star": "**"}))
                .required_star("star")
                .expect_err("wrong sentinel")
                .kind(),
            ParamErrorKind::InvalidParams
        );
        assert_eq!(
            object(json!({"flag": 1}))
                .optional_bool("flag")
                .expect_err("numeric Boolean")
                .kind(),
            ParamErrorKind::InvalidParams
        );
        assert_eq!(
            object(json!({"number": 1.5}))
                .required_u64("number", 0, 10)
                .expect_err("float integer")
                .kind(),
            ParamErrorKind::InvalidParams
        );
        assert_eq!(
            object(json!({"number": 11}))
                .required_u64("number", 0, 10)
                .expect_err("over-bound integer")
                .code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn uuid_and_etag_require_exact_canonical_spelling() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let etag = format!("sha256:{}", "ab".repeat(32));
        let mut params = object(json!({"slotId": uuid, "ifMatch": etag}));
        let parsed_uuid = params
            .required_uuid("slotId")
            .unwrap_or_else(|error| panic!("UUID failed: {error}"));
        assert_eq!(parsed_uuid.as_str(), uuid);
        let parsed_etag = params
            .required_etag("ifMatch")
            .unwrap_or_else(|error| panic!("etag failed: {error}"));
        assert_eq!(parsed_etag.as_str(), etag);
        assert!(!format!("{parsed_uuid:?}").contains(uuid));
        assert!(!format!("{parsed_etag:?}").contains(&etag));
        assert_eq!(params.finish(), Ok(()));

        for invalid in [
            "123E4567-e89b-12d3-a456-426614174000",
            "123e4567e89b12d3a456426614174000",
            "123e4567-e89b-12d3-a456-42661417400z",
        ] {
            assert!(object(json!({"id": invalid})).required_uuid("id").is_err());
        }
        let upper_etag = format!("sha256:{}", "AB".repeat(32));
        assert!(
            object(json!({"etag": upper_etag}))
                .required_etag("etag")
                .is_err()
        );
    }

    #[test]
    fn logical_paths_and_directories_must_already_be_canonical() {
        let mut params = object(json!({
            "logicalPath": "notes/café.md",
            "assetPath": "images/café.png",
            "logicalDir": "notes",
            "root": ""
        }));
        assert_eq!(
            params
                .required_asset_path("assetPath")
                .map(inex_core::path::AssetPath::into_string),
            Ok("images/café.png".to_owned())
        );
        assert_eq!(
            params
                .required_logical_path("logicalPath")
                .map(inex_core::path::LogicalPath::into_string),
            Ok("notes/café.md".to_owned())
        );
        assert_eq!(
            params
                .required_logical_dir("logicalDir")
                .map(|directory| directory.as_str().to_owned()),
            Ok("notes".to_owned())
        );
        assert!(
            params
                .required_logical_dir("root")
                .is_ok_and(|directory| directory.is_root())
        );
        assert_eq!(params.finish(), Ok(()));

        assert!(
            object(json!({"path": "notes/cafe\u{301}.md"}))
                .required_logical_path("path")
                .is_err()
        );
        assert!(
            object(json!({"path": "../secret.md"}))
                .required_logical_path("path")
                .is_err()
        );
        assert!(
            object(json!({"path": "notes/café.md"}))
                .required_asset_path("path")
                .is_err()
        );
        assert!(
            object(json!({"path": "images/cafe\u{301}.png"}))
                .required_asset_path("path")
                .is_err()
        );
    }

    #[test]
    fn base64url_is_canonical_zeroizing_and_bounded() {
        let mut params = object(json!({"contentBase64": "c2VjcmV0"}));
        assert_eq!(
            params
                .required_base64url("contentBase64", MAX_PLAINTEXT_LEN)
                .map(|value| value.to_vec()),
            Ok(b"secret".to_vec())
        );
        assert_eq!(params.finish(), Ok(()));

        assert_eq!(
            object(json!({"contentBase64": "c2VjcmV0=="}))
                .required_base64url("contentBase64", 16)
                .expect_err("padded base64url")
                .kind(),
            ParamErrorKind::InvalidParams
        );
        assert_eq!(
            object(json!({"contentBase64": "c2VjcmV0"}))
                .required_base64url("contentBase64", 2)
                .expect_err("oversized content")
                .kind(),
            ParamErrorKind::LimitExceeded
        );
        assert_eq!(
            object(json!({}))
                .optional_base64url("contentBase64", 2)
                .unwrap_or_else(|error| panic!("optional field failed: {error}")),
            None
        );
    }

    #[test]
    fn optional_extractors_accept_absence() {
        let mut params = object(json!({}));
        assert_eq!(params.optional_bool("bool"), Ok(None));
        assert_eq!(params.optional_u64("u64", 0, 1), Ok(None));
        assert_eq!(params.optional_i64("i64", -1, 1), Ok(None));
        assert_eq!(params.optional_uuid("uuid"), Ok(None));
        assert_eq!(params.optional_logical_path("path"), Ok(None));
        assert_eq!(params.optional_logical_dir("dir"), Ok(None));
        assert_eq!(params.optional_etag("etag"), Ok(None));
        assert_eq!(
            params
                .optional_object("object")
                .map(|value| value.is_none()),
            Ok(true)
        );
        assert_eq!(params.finish(), Ok(()));
    }

    #[test]
    fn diagnostics_are_redacted() {
        let params = object(json!({
            "vaultPath": "/private/canary/vault",
            "password": "secret-canary"
        }));
        let diagnostic = format!("{params:?}");
        assert!(!diagnostic.contains("/private/canary/vault"));
        assert!(!diagnostic.contains("secret-canary"));

        let malformed = CanonicalEtag("sha256:canary".to_owned());
        assert!(!format!("{malformed:?}").contains("canary"));
        assert!(!malformed.to_string().contains("canary"));
    }
}
