//! Strict, transport-neutral JSON-RPC 2.0 request and response types.
//!
//! Framing has already established that an input is one JSON object. This
//! module validates the frozen Inex v1 request shape, rejects notifications
//! and unknown methods, and applies a second resource budget to the parsed
//! value tree before a handler can inspect it. Request parameters are redacted
//! from diagnostics and their string values are wiped on a best-effort basis
//! when the owned parameter object is dropped.

use std::fmt;

use inex_core::path::LogicalPath;
use serde_json::{Map, Number, Value};
use zeroize::Zeroize;

use crate::framing::{JsonObject, MAX_FRAME_BYTES};

/// Largest accepted string request identifier.
pub const MAX_REQUEST_ID_BYTES: usize = 4 * 1024;
/// Largest nesting depth below the required `params` object.
pub const MAX_PARAMS_DEPTH: usize = 64;
/// Largest number of JSON values, including the `params` object itself.
pub const MAX_PARAMS_VALUES: usize = 100_000;
/// Largest cumulative number of members across parameter objects.
pub const MAX_PARAMS_OBJECT_MEMBERS: usize = 50_000;
/// Largest cumulative number of elements across parameter arrays.
pub const MAX_PARAMS_ARRAY_ELEMENTS: usize = 100_000;
/// Largest individual parameter-object key.
pub const MAX_PARAMS_KEY_BYTES: usize = 4 * 1024;
/// Largest cumulative parameter-object key storage.
pub const MAX_PARAMS_TOTAL_KEY_BYTES: usize = 1024 * 1024;
/// Largest cumulative JSON string storage in parameters.
pub const MAX_PARAMS_STRING_BYTES: usize = MAX_FRAME_BYTES;

const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// One method frozen into the local protocol v1 allowlist.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Method {
    SystemHello,
    SystemPing,
    SystemShutdown,
    VaultCreate,
    VaultUnlock,
    VaultLock,
    VaultStatus,
    UmbraStatus,
    UmbraInitialize,
    UmbraUnlock,
    UmbraLock,
    UmbraEnable,
    UmbraDocumentOpen,
    UmbraDocumentConvert,
    UmbraAnnotationApply,
    UmbraAnnotationEdit,
    UmbraAnnotationRemove,
    UmbraConfigGet,
    UmbraTagCreate,
    UmbraTagRename,
    UmbraTagArchive,
    UmbraTagReorder,
    VaultListTree,
    FileStat,
    FileRead,
    FileWrite,
    FileMkdir,
    FileRename,
    FileDelete,
    DocumentOpen,
    DocumentClose,
    AssetOpen,
    AssetReadChunk,
    AssetClose,
    DraftEncrypt,
    DraftDecrypt,
    SearchQuery,
    CacheEvict,
}

impl Method {
    const ALL: [Self; 38] = [
        Self::SystemHello,
        Self::SystemPing,
        Self::SystemShutdown,
        Self::VaultCreate,
        Self::VaultUnlock,
        Self::VaultLock,
        Self::VaultStatus,
        Self::UmbraStatus,
        Self::UmbraInitialize,
        Self::UmbraUnlock,
        Self::UmbraLock,
        Self::UmbraEnable,
        Self::UmbraDocumentOpen,
        Self::UmbraDocumentConvert,
        Self::UmbraAnnotationApply,
        Self::UmbraAnnotationEdit,
        Self::UmbraAnnotationRemove,
        Self::UmbraConfigGet,
        Self::UmbraTagCreate,
        Self::UmbraTagRename,
        Self::UmbraTagArchive,
        Self::UmbraTagReorder,
        Self::VaultListTree,
        Self::FileStat,
        Self::FileRead,
        Self::FileWrite,
        Self::FileMkdir,
        Self::FileRename,
        Self::FileDelete,
        Self::DocumentOpen,
        Self::DocumentClose,
        Self::AssetOpen,
        Self::AssetReadChunk,
        Self::AssetClose,
        Self::DraftEncrypt,
        Self::DraftDecrypt,
        Self::SearchQuery,
        Self::CacheEvict,
    ];

    /// Return the exact wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemHello => "system.hello",
            Self::SystemPing => "system.ping",
            Self::SystemShutdown => "system.shutdown",
            Self::VaultCreate => "vault.create",
            Self::VaultUnlock => "vault.unlock",
            Self::VaultLock => "vault.lock",
            Self::VaultStatus => "vault.status",
            Self::UmbraStatus => "umbra.status",
            Self::UmbraInitialize => "umbra.initialize",
            Self::UmbraUnlock => "umbra.unlock",
            Self::UmbraLock => "umbra.lock",
            Self::UmbraEnable => "umbra.enable",
            Self::UmbraDocumentOpen => "umbra.document.open",
            Self::UmbraDocumentConvert => "umbra.document.convert",
            Self::UmbraAnnotationApply => "umbra.annotation.apply",
            Self::UmbraAnnotationEdit => "umbra.annotation.edit",
            Self::UmbraAnnotationRemove => "umbra.annotation.remove",
            Self::UmbraConfigGet => "umbra.config.get",
            Self::UmbraTagCreate => "umbra.tag.create",
            Self::UmbraTagRename => "umbra.tag.rename",
            Self::UmbraTagArchive => "umbra.tag.archive",
            Self::UmbraTagReorder => "umbra.tag.reorder",
            Self::VaultListTree => "vault.listTree",
            Self::FileStat => "file.stat",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileMkdir => "file.mkdir",
            Self::FileRename => "file.rename",
            Self::FileDelete => "file.delete",
            Self::DocumentOpen => "document.open",
            Self::DocumentClose => "document.close",
            Self::AssetOpen => "asset.open",
            Self::AssetReadChunk => "asset.readChunk",
            Self::AssetClose => "asset.close",
            Self::DraftEncrypt => "draft.encrypt",
            Self::DraftDecrypt => "draft.decrypt",
            Self::SearchQuery => "search.query",
            Self::CacheEvict => "cache.evict",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == value)
    }

    const fn bit(self) -> u64 {
        1_u64 << self as u8
    }
}

const _: () = assert!(Method::ALL.len() <= u64::BITS as usize);

/// Set of known methods for which a dispatcher currently has handlers.
///
/// Unknown and known-but-unregistered names deliberately produce the same
/// `METHOD_NOT_FOUND` response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MethodRegistry {
    bits: u64,
}

impl MethodRegistry {
    /// Construct an empty handler registry.
    #[must_use]
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Construct a registry containing every protocol-v1 method.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bits: if Method::ALL.len() == u64::BITS as usize {
                u64::MAX
            } else {
                (1_u64 << Method::ALL.len()) - 1
            },
        }
    }

    /// Mark a known method as handled.
    pub const fn register(&mut self, method: Method) {
        self.bits |= method.bit();
    }

    /// Remove one method from the handled set.
    pub const fn unregister(&mut self, method: Method) {
        self.bits &= !method.bit();
    }

    /// Return whether this registry has a handler for `method`.
    #[must_use]
    pub const fn contains(self, method: Method) -> bool {
        self.bits & method.bit() != 0
    }
}

/// Required JSON-RPC request identifier.
#[derive(Clone, Eq, PartialEq)]
pub enum RequestId {
    Integer(i64),
    String(String),
}

impl RequestId {
    /// Convert the identifier to its JSON wire value.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::Integer(value) => Value::Number(Number::from(*value)),
            Self::String(value) => Value::String(value.clone()),
        }
    }

    /// Return the integer form, when this is a numeric identifier.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::String(_) => None,
        }
    }

    /// Borrow the string form, when this is a string identifier.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Integer(_) => None,
            Self::String(value) => Some(value),
        }
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(_) => formatter.write_str("RequestId::Integer(..)"),
            Self::String(_) => formatter.write_str("RequestId::String(<redacted>)"),
        }
    }
}

impl Drop for RequestId {
    fn drop(&mut self) {
        if let Self::String(value) = self {
            value.zeroize();
        }
    }
}

/// Owned, complexity-checked request parameters.
pub struct Params(JsonObject);

impl Params {
    /// Borrow the required parameter object.
    #[must_use]
    pub const fn as_object(&self) -> &JsonObject {
        &self.0
    }

    /// Borrow one named parameter.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    /// Transfer the checked object to a method-specific parser.
    #[must_use]
    pub fn into_object(mut self) -> JsonObject {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Params")
            .field("members", &self.0.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

impl Drop for Params {
    fn drop(&mut self) {
        wipe_object(&mut self.0);
    }
}

/// One fully validated, non-notification JSON-RPC request.
pub struct Request {
    id: RequestId,
    method: Method,
    params: Params,
}

impl Request {
    /// Borrow the response-correlating request identifier.
    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// Return the registered v1 method.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Borrow the redacted, complexity-checked parameter object.
    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Consume the request for dispatch.
    #[must_use]
    pub fn into_parts(self) -> (RequestId, Method, Params) {
        (self.id, self.method, self.params)
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &"<redacted>")
            .finish()
    }
}

/// Resource budget exceeded by an otherwise structurally valid request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplexityLimit {
    RequestIdBytes,
    NestingDepth,
    Values,
    ObjectMembers,
    ArrayElements,
    KeyBytes,
    StringBytes,
}

/// Safe request-validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    LimitExceeded(ComplexityLimit),
}

impl ProtocolError {
    /// Error code used for the JSON-RPC error response.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::InvalidRequest => ErrorCode::InvalidRequest,
            Self::MethodNotFound => ErrorCode::MethodNotFound,
            Self::InvalidParams => ErrorCode::InvalidParams,
            Self::LimitExceeded(_) => ErrorCode::LimitExceeded,
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code().safe_message())
    }
}

impl std::error::Error for ProtocolError {}

/// Rejected request together with any valid identifier recovered before the
/// failure.
///
/// Method and parameter failures retain the identifier so their JSON-RPC
/// response can be correlated. Invalid top-level shapes and invalid ids use a
/// null response id. Diagnostics redact string identifiers.
pub struct RequestRejection {
    id: Option<RequestId>,
    error: ProtocolError,
}

impl RequestRejection {
    /// Return the safe validation failure.
    #[must_use]
    pub const fn error(&self) -> ProtocolError {
        self.error
    }

    /// Borrow a valid response identifier recovered before rejection.
    #[must_use]
    pub const fn id(&self) -> Option<&RequestId> {
        self.id.as_ref()
    }

    /// Convert directly to a correlated JSON-RPC error response.
    #[must_use]
    pub fn into_response(self) -> Response {
        Response::error(self.id, ErrorObject::from_protocol(self.error))
    }
}

impl fmt::Debug for RequestRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestRejection")
            .field("id", &self.id)
            .field("error", &self.error)
            .finish()
    }
}

impl fmt::Display for RequestRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for RequestRejection {}

/// Parse one framed JSON object against the complete v1 method set.
///
/// # Errors
///
/// Returns a safe error for an invalid version/id/shape, missing object
/// parameters, unknown method, or exceeded complexity budget. Rejected
/// request values are never included in the error.
pub fn parse_request(object: JsonObject) -> Result<Request, RequestRejection> {
    parse_request_with_registry(object, MethodRegistry::all())
}

/// Parse one request and additionally require a registered method handler.
///
/// # Errors
///
/// Returns the same safe errors as [`parse_request`]. A known but unregistered
/// method is indistinguishable from an unknown method.
pub fn parse_request_with_registry(
    mut object: JsonObject,
    registry: MethodRegistry,
) -> Result<Request, RequestRejection> {
    let mut response_id = None;
    let result = (|| {
        if object.len() != 4
            || object
                .keys()
                .any(|key| !matches!(key.as_str(), "jsonrpc" | "id" | "method" | "params"))
        {
            return Err(ProtocolError::InvalidRequest);
        }

        match object.remove("jsonrpc") {
            Some(Value::String(version)) if version == "2.0" => {}
            _ => return Err(ProtocolError::InvalidRequest),
        }
        let id = parse_request_id(object.remove("id").ok_or(ProtocolError::InvalidRequest)?)?;
        response_id = Some(id.clone());
        let method = match object.remove("method") {
            Some(Value::String(name)) => {
                Method::parse(&name).ok_or(ProtocolError::MethodNotFound)?
            }
            _ => return Err(ProtocolError::InvalidRequest),
        };
        if !registry.contains(method) {
            return Err(ProtocolError::MethodNotFound);
        }
        let Some(params_value) = object.remove("params") else {
            return Err(ProtocolError::InvalidParams);
        };
        let Value::Object(mut params) = params_value else {
            let mut rejected = params_value;
            wipe_value(&mut rejected);
            return Err(ProtocolError::InvalidParams);
        };
        if let Err(error) = validate_params_complexity(&params) {
            wipe_object(&mut params);
            return Err(error);
        }
        Ok(Request {
            id,
            method,
            params: Params(params),
        })
    })();
    if result.is_err() {
        wipe_object(&mut object);
    }
    result.map_err(|error| RequestRejection {
        id: response_id,
        error,
    })
}

fn parse_request_id(value: Value) -> Result<RequestId, ProtocolError> {
    match value {
        Value::String(value) if value.len() <= MAX_REQUEST_ID_BYTES => Ok(RequestId::String(value)),
        Value::String(mut value) => {
            value.zeroize();
            Err(ProtocolError::LimitExceeded(
                ComplexityLimit::RequestIdBytes,
            ))
        }
        Value::Number(value) => value
            .as_i64()
            .filter(|integer| (-MAX_SAFE_JSON_INTEGER..=MAX_SAFE_JSON_INTEGER).contains(integer))
            .map(RequestId::Integer)
            .ok_or(ProtocolError::InvalidRequest),
        mut other => {
            wipe_value(&mut other);
            Err(ProtocolError::InvalidRequest)
        }
    }
}

fn validate_params_complexity(params: &JsonObject) -> Result<(), ProtocolError> {
    let mut values = 1_usize;
    let mut object_members = 0_usize;
    let mut array_elements = 0_usize;
    let mut key_bytes = 0_usize;
    let mut string_bytes = 0_usize;
    let mut pending = Vec::with_capacity(params.len().min(1024));

    count_object_keys(params, &mut object_members, &mut key_bytes)?;
    pending.extend(params.values().map(|value| (value, 1_usize)));
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_PARAMS_DEPTH {
            return Err(limit(ComplexityLimit::NestingDepth));
        }
        values = checked_budget_add(values, 1, MAX_PARAMS_VALUES, ComplexityLimit::Values)?;
        match value {
            Value::Object(object) => {
                count_object_keys(object, &mut object_members, &mut key_bytes)?;
                pending.extend(object.values().map(|child| (child, depth + 1)));
            }
            Value::Array(array) => {
                array_elements = checked_budget_add(
                    array_elements,
                    array.len(),
                    MAX_PARAMS_ARRAY_ELEMENTS,
                    ComplexityLimit::ArrayElements,
                )?;
                pending.extend(array.iter().map(|child| (child, depth + 1)));
            }
            Value::String(string) => {
                string_bytes = checked_budget_add(
                    string_bytes,
                    string.len(),
                    MAX_PARAMS_STRING_BYTES,
                    ComplexityLimit::StringBytes,
                )?;
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn count_object_keys(
    object: &JsonObject,
    object_members: &mut usize,
    key_bytes: &mut usize,
) -> Result<(), ProtocolError> {
    *object_members = checked_budget_add(
        *object_members,
        object.len(),
        MAX_PARAMS_OBJECT_MEMBERS,
        ComplexityLimit::ObjectMembers,
    )?;
    for key in object.keys() {
        if key.len() > MAX_PARAMS_KEY_BYTES {
            return Err(limit(ComplexityLimit::KeyBytes));
        }
        *key_bytes = checked_budget_add(
            *key_bytes,
            key.len(),
            MAX_PARAMS_TOTAL_KEY_BYTES,
            ComplexityLimit::KeyBytes,
        )?;
    }
    Ok(())
}

fn checked_budget_add(
    current: usize,
    additional: usize,
    maximum: usize,
    kind: ComplexityLimit,
) -> Result<usize, ProtocolError> {
    current
        .checked_add(additional)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| limit(kind))
}

const fn limit(kind: ComplexityLimit) -> ProtocolError {
    ProtocolError::LimitExceeded(kind)
}

/// Stable standard and application JSON-RPC error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ErrorCode {
    ParseError = -32_700,
    InvalidRequest = -32_600,
    MethodNotFound = -32_601,
    InvalidParams = -32_602,
    InternalError = -32_603,
    AuthFailed = -32_000,
    SessionInvalid = -32_001,
    VaultInvalid = -32_002,
    PathInvalid = -32_003,
    NotFound = -32_004,
    AlreadyExists = -32_005,
    EtagConflict = -32_006,
    IntegrityFailed = -32_007,
    LimitExceeded = -32_008,
    IoFailed = -32_009,
    KdfPolicy = -32_010,
    Unsupported = -32_011,
    Busy = -32_012,
    PublicationReconcileRequired = -32_013,
    PublicationManualAuditRequired = -32_014,
}

impl ErrorCode {
    /// Return the signed JSON-RPC numeric code.
    #[must_use]
    pub const fn number(self) -> i32 {
        self as i32
    }

    /// Return the frozen machine-readable name.
    #[must_use]
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::ParseError => "PARSE_ERROR",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::MethodNotFound => "METHOD_NOT_FOUND",
            Self::InvalidParams => "INVALID_PARAMS",
            Self::InternalError => "INTERNAL_ERROR",
            Self::AuthFailed => "AUTH_FAILED",
            Self::SessionInvalid => "SESSION_INVALID",
            Self::VaultInvalid => "VAULT_INVALID",
            Self::PathInvalid => "PATH_INVALID",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::EtagConflict => "ETAG_CONFLICT",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::IoFailed => "IO_FAILED",
            Self::KdfPolicy => "KDF_POLICY",
            Self::Unsupported => "UNSUPPORTED",
            Self::Busy => "BUSY",
            Self::PublicationReconcileRequired => "PUBLICATION_RECONCILE_REQUIRED",
            Self::PublicationManualAuditRequired => "PUBLICATION_MANUAL_AUDIT_REQUIRED",
        }
    }

    /// Return the fixed human-safe response message.
    #[must_use]
    pub const fn safe_message(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::AuthFailed => "Authentication failed",
            Self::SessionInvalid => "Session is invalid or expired",
            Self::VaultInvalid => "Vault configuration is invalid",
            Self::PathInvalid => "Logical path is invalid",
            Self::NotFound => "Logical entry was not found",
            Self::AlreadyExists => "Logical entry already exists",
            Self::EtagConflict => "Ciphertext etag conflict",
            Self::IntegrityFailed => "Encrypted document integrity check failed",
            Self::LimitExceeded => "Request exceeds the configured limit",
            Self::IoFailed => "Storage operation failed",
            Self::KdfPolicy => "KDF parameters violate policy",
            Self::Unsupported => "Feature is unsupported",
            Self::Busy => "Vault mutation is busy",
            Self::PublicationReconcileRequired => {
                "Repository publication reconciliation is required"
            }
            Self::PublicationManualAuditRequired => {
                "Repository publication marker requires manual audit"
            }
        }
    }
}

/// Closed set of non-sensitive error response details.
pub struct ErrorDetail {
    key: &'static str,
    value: Value,
}

impl ErrorDetail {
    /// Include a validated logical path.
    #[must_use]
    pub fn logical_path(path: &LogicalPath) -> Self {
        Self {
            key: "logicalPath",
            value: Value::String(path.as_str().to_owned()),
        }
    }

    /// Include a current ciphertext digest as a canonical etag.
    #[must_use]
    pub fn current_etag(digest: [u8; 32]) -> Self {
        Self {
            key: "currentEtag",
            value: Value::String(encode_etag(digest)),
        }
    }

    /// Include the intended ciphertext digest after an indeterminate commit.
    #[must_use]
    pub fn expected_etag(digest: [u8; 32]) -> Self {
        Self {
            key: "expectedEtag",
            value: Value::String(encode_etag(digest)),
        }
    }

    /// Include public numeric resource usage and its maximum.
    #[must_use]
    pub fn limit(actual: u64, maximum: u64) -> [Self; 2] {
        [
            Self {
                key: "actual",
                value: Value::Number(Number::from(actual)),
            },
            Self {
                key: "maximum",
                value: Value::Number(Number::from(maximum)),
            },
        ]
    }
}

impl fmt::Debug for ErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorDetail")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// JSON-RPC error object with a fixed message and closed safe-data schema.
pub struct ErrorObject {
    code: ErrorCode,
    details: Vec<ErrorDetail>,
}

impl ErrorObject {
    /// Construct an error carrying only its stable name in `data`.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            details: Vec::new(),
        }
    }

    /// Construct an error from request validation.
    #[must_use]
    pub const fn from_protocol(error: ProtocolError) -> Self {
        Self::new(error.code())
    }

    /// Add one closed, non-sensitive detail.
    #[must_use]
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        self.details.retain(|existing| existing.key != detail.key);
        self.details.push(detail);
        self
    }

    /// Add multiple closed, non-sensitive details.
    #[must_use]
    pub fn with_details(mut self, details: impl IntoIterator<Item = ErrorDetail>) -> Self {
        for detail in details {
            self = self.with_detail(detail);
        }
        self
    }

    /// Return the stable error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    fn into_json_value(self) -> Value {
        let mut data = Map::new();
        data.insert(
            "name".to_owned(),
            Value::String(self.code.stable_name().to_owned()),
        );
        for detail in self.details {
            data.insert(detail.key.to_owned(), detail.value);
        }
        let mut object = Map::new();
        object.insert(
            "code".to_owned(),
            Value::Number(Number::from(self.code.number())),
        );
        object.insert(
            "message".to_owned(),
            Value::String(self.code.safe_message().to_owned()),
        );
        object.insert("data".to_owned(), Value::Object(data));
        Value::Object(object)
    }
}

impl fmt::Debug for ErrorObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ErrorObject")
            .field("code", &self.code)
            .field("detail_count", &self.details.len())
            .finish()
    }
}

enum ResponsePayload {
    Result(Value),
    Error(ErrorObject),
}

/// One serializable JSON-RPC 2.0 success or error response.
pub struct Response {
    id: Option<RequestId>,
    payload: ResponsePayload,
}

impl Response {
    /// Construct a success response for a validated request.
    #[must_use]
    pub const fn success(id: RequestId, result: Value) -> Self {
        Self {
            id: Some(id),
            payload: ResponsePayload::Result(result),
        }
    }

    /// Construct an error response. `None` emits a null id for failures where
    /// no valid request identifier could be recovered.
    #[must_use]
    pub const fn error(id: Option<RequestId>, error: ErrorObject) -> Self {
        Self {
            id,
            payload: ResponsePayload::Error(error),
        }
    }

    /// Serialize this response to the object expected by framing.
    #[must_use]
    pub fn into_json_object(self) -> JsonObject {
        let mut object = Map::new();
        object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        object.insert(
            "id".to_owned(),
            self.id.map_or(Value::Null, |id| id.to_json_value()),
        );
        match self.payload {
            ResponsePayload::Result(result) => {
                object.insert("result".to_owned(), result);
            }
            ResponsePayload::Error(error) => {
                object.insert("error".to_owned(), error.into_json_value());
            }
        }
        object
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("id", &self.id)
            .field(
                "payload",
                &match self.payload {
                    ResponsePayload::Result(_) => "Result(<redacted>)",
                    ResponsePayload::Error(_) => "Error(<safe>)",
                },
            )
            .finish()
    }
}

fn encode_etag(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn wipe_object(object: &mut JsonObject) {
    for (mut key, mut value) in std::mem::take(object) {
        key.zeroize();
        wipe_value(&mut value);
    }
}

fn wipe_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(array) => {
            for child in array {
                wipe_value(child);
            }
        }
        Value::Object(object) => wipe_object(object),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object(value: Value) -> JsonObject {
        match value {
            Value::Object(object) => object,
            _ => panic!("test value must be an object"),
        }
    }

    fn request(method: &str, id: Value, params: Value) -> JsonObject {
        let mut object = Map::new();
        object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        object.insert("id".to_owned(), id);
        object.insert("method".to_owned(), Value::String(method.to_owned()));
        object.insert("params".to_owned(), params);
        object
    }

    fn rejection(result: Result<Request, RequestRejection>) -> ProtocolError {
        result.unwrap_err().error()
    }

    #[test]
    fn parses_every_frozen_method_and_required_id_form() {
        for (index, method) in Method::ALL.into_iter().enumerate() {
            let parsed = parse_request(request(
                method.as_str(),
                json!(i64::try_from(index).unwrap()),
                json!({}),
            ))
            .unwrap();
            assert_eq!(parsed.method(), method);
            assert_eq!(
                parsed.id().as_integer(),
                Some(i64::try_from(index).unwrap())
            );
        }
        let parsed = parse_request(request("system.ping", json!("opaque-id"), json!({}))).unwrap();
        assert_eq!(parsed.id().as_str(), Some("opaque-id"));
    }

    #[test]
    fn registry_hides_known_but_unregistered_methods() {
        let mut registry = MethodRegistry::new();
        registry.register(Method::SystemPing);
        assert!(
            parse_request_with_registry(request("system.ping", json!(1), json!({})), registry)
                .is_ok()
        );
        assert_eq!(
            rejection(parse_request_with_registry(
                request("file.read", json!(1), json!({})),
                registry,
            )),
            ProtocolError::MethodNotFound
        );
        registry.unregister(Method::SystemPing);
        assert!(!registry.contains(Method::SystemPing));
    }

    #[test]
    fn rejects_unknown_method_and_noncanonical_top_level_shape() {
        assert_eq!(
            rejection(parse_request(request(
                "unknown.method",
                json!(1),
                json!({}),
            ))),
            ProtocolError::MethodNotFound
        );
        for invalid in [
            json!({"jsonrpc":"1.0","id":1,"method":"system.ping","params":{}}),
            json!({"jsonrpc":"2.0","method":"system.ping","params":{}}),
            json!({"jsonrpc":"2.0","id":1,"method":"system.ping","params":{},"extra":0}),
            json!({"jsonrpc":"2.0","id":1,"method":1,"params":{}}),
        ] {
            assert_eq!(
                rejection(parse_request(object(invalid))),
                ProtocolError::InvalidRequest
            );
        }
    }

    #[test]
    fn rejects_notifications_floats_unsafe_integers_and_nonobject_params() {
        for id in [
            Value::Null,
            json!(true),
            json!(1.5),
            json!(9_007_199_254_740_992_u64),
            json!(-9_007_199_254_740_992_i64),
        ] {
            assert_eq!(
                rejection(parse_request(request("system.ping", id, json!({})))),
                ProtocolError::InvalidRequest
            );
        }
        for params in [Value::Null, json!([]), json!("secret"), json!(1)] {
            assert_eq!(
                rejection(parse_request(request("system.ping", json!(1), params))),
                ProtocolError::InvalidParams
            );
        }
    }

    #[test]
    fn accepts_exact_safe_integer_boundaries_and_limits_string_ids() {
        for id in [-MAX_SAFE_JSON_INTEGER, MAX_SAFE_JSON_INTEGER] {
            assert!(parse_request(request("system.ping", json!(id), json!({}))).is_ok());
        }
        assert_eq!(
            rejection(parse_request(request(
                "system.ping",
                Value::String("x".repeat(MAX_REQUEST_ID_BYTES + 1)),
                json!({})
            ))),
            ProtocolError::LimitExceeded(ComplexityLimit::RequestIdBytes)
        );
    }

    #[test]
    fn rejects_deep_large_array_and_oversized_key_params() {
        let mut nested = Value::Null;
        for _ in 0..=MAX_PARAMS_DEPTH {
            nested = json!({"child": nested});
        }
        assert_eq!(
            rejection(parse_request(request(
                "system.ping",
                json!(1),
                json!({"root":nested}),
            ))),
            ProtocolError::LimitExceeded(ComplexityLimit::NestingDepth)
        );

        let array = vec![Value::Null; MAX_PARAMS_ARRAY_ELEMENTS + 1];
        assert_eq!(
            rejection(parse_request(request(
                "system.ping",
                json!(1),
                json!({"items":array}),
            ))),
            ProtocolError::LimitExceeded(ComplexityLimit::ArrayElements)
        );

        let mut params = Map::new();
        params.insert("k".repeat(MAX_PARAMS_KEY_BYTES + 1), Value::Null);
        assert_eq!(
            rejection(parse_request(request(
                "system.ping",
                json!(1),
                Value::Object(params),
            ))),
            ProtocolError::LimitExceeded(ComplexityLimit::KeyBytes)
        );
    }

    #[test]
    fn request_and_error_diagnostics_never_echo_input() {
        let parsed = parse_request(request(
            "vault.unlock",
            json!("secret-request-id"),
            json!({"password":"do-not-log", "session":"also-secret"}),
        ))
        .unwrap();
        let diagnostic = format!("{parsed:?}");
        assert!(!diagnostic.contains("secret-request-id"));
        assert!(!diagnostic.contains("do-not-log"));
        assert!(!diagnostic.contains("also-secret"));

        let error = ProtocolError::LimitExceeded(ComplexityLimit::StringBytes);
        assert_eq!(error.to_string(), "Request exceeds the configured limit");
        assert!(!format!("{error:?} {error}").contains("do-not-log"));
    }

    #[test]
    fn serializes_success_and_safe_error_objects() {
        let success =
            Response::success(RequestId::Integer(7), json!({"ok":true})).into_json_object();
        assert_eq!(
            success,
            object(json!({
                "jsonrpc":"2.0", "id":7, "result":{"ok":true}
            }))
        );

        let path = LogicalPath::parse_canonical("notes/entry.md").unwrap();
        let error = ErrorObject::new(ErrorCode::EtagConflict)
            .with_detail(ErrorDetail::logical_path(&path))
            .with_detail(ErrorDetail::current_etag([0xab; 32]));
        let response =
            Response::error(Some(RequestId::String("r1".to_owned())), error).into_json_object();
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], "r1");
        assert_eq!(response["error"]["code"], -32_006);
        assert_eq!(response["error"]["message"], "Ciphertext etag conflict");
        assert_eq!(response["error"]["data"]["name"], "ETAG_CONFLICT");
        assert_eq!(response["error"]["data"]["logicalPath"], "notes/entry.md");
        assert_eq!(
            response["error"]["data"]["currentEtag"],
            format!("sha256:{}", "ab".repeat(32))
        );

        let null_id =
            Response::error(None, ErrorObject::new(ErrorCode::ParseError)).into_json_object();
        assert!(null_id["id"].is_null());
    }

    #[test]
    fn all_codes_have_frozen_numbers_names_and_safe_messages() {
        let expected = [
            (ErrorCode::ParseError, -32_700, "PARSE_ERROR"),
            (ErrorCode::InvalidRequest, -32_600, "INVALID_REQUEST"),
            (ErrorCode::MethodNotFound, -32_601, "METHOD_NOT_FOUND"),
            (ErrorCode::InvalidParams, -32_602, "INVALID_PARAMS"),
            (ErrorCode::InternalError, -32_603, "INTERNAL_ERROR"),
            (ErrorCode::AuthFailed, -32_000, "AUTH_FAILED"),
            (ErrorCode::SessionInvalid, -32_001, "SESSION_INVALID"),
            (ErrorCode::VaultInvalid, -32_002, "VAULT_INVALID"),
            (ErrorCode::PathInvalid, -32_003, "PATH_INVALID"),
            (ErrorCode::NotFound, -32_004, "NOT_FOUND"),
            (ErrorCode::AlreadyExists, -32_005, "ALREADY_EXISTS"),
            (ErrorCode::EtagConflict, -32_006, "ETAG_CONFLICT"),
            (ErrorCode::IntegrityFailed, -32_007, "INTEGRITY_FAILED"),
            (ErrorCode::LimitExceeded, -32_008, "LIMIT_EXCEEDED"),
            (ErrorCode::IoFailed, -32_009, "IO_FAILED"),
            (ErrorCode::KdfPolicy, -32_010, "KDF_POLICY"),
            (ErrorCode::Unsupported, -32_011, "UNSUPPORTED"),
            (ErrorCode::Busy, -32_012, "BUSY"),
            (
                ErrorCode::PublicationReconcileRequired,
                -32_013,
                "PUBLICATION_RECONCILE_REQUIRED",
            ),
            (
                ErrorCode::PublicationManualAuditRequired,
                -32_014,
                "PUBLICATION_MANUAL_AUDIT_REQUIRED",
            ),
        ];
        for (code, number, name) in expected {
            assert_eq!(code.number(), number);
            assert_eq!(code.stable_name(), name);
            assert!(!code.safe_message().is_empty());
        }
    }

    #[test]
    fn response_debug_redacts_results_and_error_detail_values() {
        let response = Response::success(
            RequestId::String("secret-id".to_owned()),
            json!({"content":"do-not-log"}),
        );
        let debug = format!("{response:?}");
        assert!(!debug.contains("secret-id"));
        assert!(!debug.contains("do-not-log"));

        let detail = ErrorDetail::current_etag([0xcd; 32]);
        assert!(!format!("{detail:?}").contains(&"cd".repeat(32)));
    }
}
