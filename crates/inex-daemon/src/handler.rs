//! Transport-neutral JSON-RPC dispatch for one Inex sidecar process.
//!
//! The dispatcher owns the single-vault session store, enforces protocol
//! negotiation before protected calls, parses every method through the
//! zeroizing parameter layer, and returns only fixed safe errors. Transport
//! code remains responsible for framing and for scrubbing response JSON after
//! it has been written.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inex_core::atomic::ParentSyncStatus;
use inex_core::crypto::{CryptoError, DecryptedDocument, EncryptedDocument};
use inex_core::format::{EdryHeader, MAX_PLAINTEXT_LEN};
use inex_core::path::{LogicalDir, LogicalPath};
use inex_core::search::{
    CaseSensitivity, DEFAULT_SEARCH_RESULTS, DEFAULT_SEARCH_SNIPPET_BYTES, MAX_SEARCH_QUERY_BYTES,
    MAX_SEARCH_RESULTS, MAX_SEARCH_SNIPPET_BYTES, SearchQuery,
};
use inex_core::sodium::{
    Argon2idParams, DEFAULT_ARGON2ID_PARAMS, MAX_PASSWORD_BYTES, VAULT_ARGON2ID_READER_LIMITS,
};
use inex_core::tree::{TreeEntryKind, TreeError};
use inex_core::vault::{
    DocumentMetadata, MAX_EDRY_ENVELOPE_BYTES, RenameOutcome, Vault, VaultError,
};
use inex_core::vault_config::{ConfigError, ConfigWarning, KdfPolicy};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::PROTOCOL_MAJOR;
use crate::framing::{JsonObject, MAX_FRAME_BYTES};
use crate::params::{CanonicalEtag, CanonicalUuid, ParamError, ParamObject};
use crate::protocol::{ErrorCode, ErrorObject, Method, Params, Request, Response, parse_request};
use crate::sensitive::encode_base64url;
use crate::session::{MonotonicClock, SessionError, SessionStore, SystemClock};

const MAX_PHYSICAL_PATH_BYTES: usize = 64 * 1024;
const MAX_CLIENT_NAME_BYTES: usize = 256;
const MAX_CLIENT_VERSION_BYTES: usize = 256;
const MAX_CAPABILITY_TEXT_BYTES: usize = 128;
const TREE_RESPONSE_RESERVE_BYTES: usize = 16 * 1024;
const TREE_ENTRY_JSON_OVERHEAD_BYTES: usize = 64;

type RpcResult = Result<Value, ErrorObject>;

/// Request dispatcher and sensitive process state for one sidecar child.
pub struct RpcService<C = SystemClock> {
    sessions: SessionStore<C>,
    kdf_policy: KdfPolicy,
    started: Instant,
    hello_complete: bool,
    shutdown_requested: bool,
}

impl RpcService<SystemClock> {
    /// Construct a production dispatcher with the default KDF policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock_and_policy(SystemClock::new(), KdfPolicy::default())
    }
}

impl Default for RpcService<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: MonotonicClock> RpcService<C> {
    /// Construct a dispatcher with an injected clock and KDF policy.
    ///
    /// This constructor supports deterministic expiry and inexpensive vault
    /// fixtures in tests. Production callers should use [`Self::new`].
    #[must_use]
    pub fn with_clock_and_policy(clock: C, kdf_policy: KdfPolicy) -> Self {
        Self {
            sessions: SessionStore::with_clock(clock),
            kdf_policy,
            started: Instant::now(),
            hello_complete: false,
            shutdown_requested: false,
        }
    }

    /// Parse and dispatch one framed request object.
    #[must_use]
    pub fn handle_object(&mut self, object: JsonObject) -> Response {
        match parse_request(object) {
            Ok(request) => self.handle_request(request),
            Err(rejection) => rejection.into_response(),
        }
    }

    /// Expire an idle session without waiting for another client request.
    ///
    /// A stdio transport must call this on a bounded timer while its reader is
    /// blocked so the master key and search index do not outlive the timeout.
    pub fn expire_idle_session(&mut self) -> bool {
        self.sessions.expire()
    }

    /// Return whether `system.shutdown` or a failed major negotiation asked
    /// the transport to terminate after writing the current response.
    #[must_use]
    pub const fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Report whether an unexpired session is currently held.
    pub fn session_active(&mut self) -> bool {
        self.sessions.is_active()
    }

    fn handle_request(&mut self, request: Request) -> Response {
        let (id, method, params) = request.into_parts();
        let unavailable = self.shutdown_requested
            || (!self.hello_complete
                && !matches!(method, Method::SystemHello | Method::SystemShutdown));
        let result = if unavailable {
            Err(ErrorObject::new(ErrorCode::Unsupported))
        } else {
            self.dispatch(method, params)
        };
        match result {
            Ok(value) => Response::success(id, value),
            Err(error) => Response::error(Some(id), error),
        }
    }

    fn dispatch(&mut self, method: Method, params: Params) -> RpcResult {
        match method {
            Method::SystemHello => self.system_hello(params),
            Method::SystemPing => self.system_ping(params),
            Method::SystemShutdown => self.system_shutdown(params),
            Method::VaultCreate => self.vault_create(params),
            Method::VaultUnlock => self.vault_unlock(params),
            Method::VaultLock => self.vault_lock(params),
            Method::VaultStatus => self.vault_status(params),
            Method::VaultListTree => self.vault_list_tree(params),
            Method::FileStat => self.file_stat(params),
            Method::FileRead => self.file_read(params),
            Method::FileWrite => self.file_write(params),
            Method::FileMkdir => self.file_mkdir(params),
            Method::FileRename => self.file_rename(params),
            Method::FileDelete => self.file_delete(params),
            Method::DocumentOpen => self.document_open(params),
            Method::DocumentClose => self.document_close(params),
            Method::DraftEncrypt => self.draft_encrypt(params),
            Method::DraftDecrypt => self.draft_decrypt(params),
            Method::SearchQuery => self.search_query(params),
            Method::CacheEvict => self.cache_evict(params),
        }
    }

    fn system_hello(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let client = params.required_sensitive_string("client", 1, MAX_CLIENT_NAME_BYTES)?;
        let client_version =
            params.required_sensitive_string("clientVersion", 1, MAX_CLIENT_VERSION_BYTES)?;
        let protocol_major = params.required_u64("protocolMajor", 0, u64::from(u32::MAX))?;
        params.finish()?;
        drop(client);
        drop(client_version);

        if protocol_major != u64::from(PROTOCOL_MAJOR) {
            self.sessions.shutdown();
            self.shutdown_requested = true;
            return Err(ErrorObject::new(ErrorCode::Unsupported));
        }
        self.hello_complete = true;
        Ok(json!({
            "server": "inexd",
            "serverVersion": env!("CARGO_PKG_VERSION"),
            "protocolMajor": PROTOCOL_MAJOR,
            "capabilities": ["vault", "files", "documents", "encryptedDrafts", "search"],
        }))
    }

    fn system_ping(&mut self, params: Params) -> RpcResult {
        ParamObject::new(params).finish()?;
        let uptime_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(json!({
            "ok": true,
            "uptimeMs": uptime_ms,
            "sessionActive": self.sessions.is_active(),
        }))
    }

    fn system_shutdown(&mut self, params: Params) -> RpcResult {
        ParamObject::new(params).finish()?;
        self.sessions.shutdown();
        self.shutdown_requested = true;
        Ok(acknowledgement())
    }

    fn vault_create(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let vault_path =
            params.required_sensitive_string("vaultPath", 1, MAX_PHYSICAL_PATH_BYTES)?;
        let password = params.required_sensitive_string("password", 1, MAX_PASSWORD_BYTES)?;
        let kdf = parse_optional_kdf(&mut params, self.kdf_policy)?;
        params.finish()?;
        if self.sessions.is_active() {
            return Err(ErrorObject::new(ErrorCode::Busy));
        }
        let vault_path = validated_vault_path(&vault_path)?;
        let vault = Vault::create_with_params(
            vault_path,
            password.as_bytes(),
            unix_time_ms()?,
            kdf,
            self.kdf_policy,
        )
        .map_err(|error| map_vault_error(error, ErrorContext::Authentication))?;
        drop(password);
        let vault_id = vault.config().vault_id;
        let warnings = warnings_value(vault.warnings());
        drop(vault);
        Ok(json!({
            "vaultId": vault_id.to_string(),
            "warnings": warnings,
        }))
    }

    fn vault_unlock(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let vault_path =
            params.required_sensitive_string("vaultPath", 1, MAX_PHYSICAL_PATH_BYTES)?;
        let password = params.required_sensitive_string("password", 1, MAX_PASSWORD_BYTES)?;
        let slot_id = params.optional_uuid("slotId")?;
        params.finish()?;
        if self.sessions.is_active() {
            return Err(ErrorObject::new(ErrorCode::Busy));
        }
        let vault_path = validated_vault_path(&vault_path)?;
        let slot_id = slot_id.as_ref().map(parse_uuid).transpose()?;
        let vault = Vault::unlock(vault_path, password.as_bytes(), slot_id, self.kdf_policy)
            .map_err(|error| map_vault_error(error, ErrorContext::Authentication))?;
        drop(password);
        let vault_id = vault.config().vault_id;
        let warnings = warnings_value(vault.warnings());
        let token = self.sessions.unlock(vault).map_err(map_session_error)?;
        let expires_in = self
            .sessions
            .idle_remaining(token.expose_secret())
            .map_err(map_session_error)?;
        Ok(json!({
            "session": token.expose_secret(),
            "vaultId": vault_id.to_string(),
            "idleTimeoutMs": duration_ms(expires_in),
            "warnings": warnings,
        }))
    }

    fn vault_lock(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        params.finish()?;
        self.sessions
            .lock(session.as_str())
            .map_err(map_session_error)?;
        Ok(acknowledgement())
    }

    fn vault_status(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        params.finish()?;

        let (vault_id, slots, entries, files, directories) = {
            let vault = self
                .sessions
                .vault_mut(session.as_str())
                .map_err(map_session_error)?;
            let vault_id = vault.config().vault_id;
            let slots = vault.config().key_slots.len();
            let tree = vault
                .list()
                .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
            let files = tree
                .entries()
                .iter()
                .filter(|entry| entry.kind() == TreeEntryKind::File)
                .count();
            let directories = tree.len().saturating_sub(files);
            (vault_id, slots, tree.len(), files, directories)
        };
        let open_documents = self
            .sessions
            .document_count(session.as_str())
            .map_err(map_session_error)?;
        let remaining = self
            .sessions
            .idle_remaining(session.as_str())
            .map_err(map_session_error)?;
        Ok(json!({
            "vaultId": vault_id.to_string(),
            "keySlots": slots,
            "entries": entries,
            "files": files,
            "directories": directories,
            "openDocuments": open_documents,
            "idleTimeoutMs": duration_ms(remaining),
        }))
    }

    fn vault_list_tree(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let prefix = params.optional_logical_dir("prefix")?;
        params.finish()?;
        let tree = self
            .sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?
            .list()
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        let mut estimated_bytes = TREE_RESPONSE_RESERVE_BYTES;
        let mut entries = Vec::new();
        for entry in tree
            .entries()
            .iter()
            .filter(|entry| prefix_matches(prefix.as_ref(), entry.logical_path()))
        {
            estimated_bytes = estimated_bytes
                .checked_add(entry.logical_path().len())
                .and_then(|value| value.checked_add(TREE_ENTRY_JSON_OVERHEAD_BYTES))
                .filter(|value| *value <= MAX_FRAME_BYTES)
                .ok_or_else(|| ErrorObject::new(ErrorCode::LimitExceeded))?;
            entries.push(json!({
                "kind": match entry.kind() {
                    TreeEntryKind::Directory => "directory",
                    TreeEntryKind::File => "file",
                },
                "logicalPath": entry.logical_path(),
            }));
        }
        Ok(json!({"entries": entries}))
    }

    fn file_stat(&mut self, params: Params) -> RpcResult {
        let (session, logical_path) = parse_session_path(params)?;
        let document = self
            .sessions
            .vault(session.as_str())
            .map_err(map_session_error)?
            .read(&logical_path)
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(stat_value(&document))
    }

    fn file_read(&mut self, params: Params) -> RpcResult {
        let (session, logical_path) = parse_session_path(params)?;
        let document = self
            .sessions
            .vault(session.as_str())
            .map_err(map_session_error)?
            .read(&logical_path)
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(decrypted_document_value(&document))
    }

    fn file_write(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let logical_path = params.required_logical_path("logicalPath")?;
        let plaintext = params.required_base64url("contentBase64", MAX_PLAINTEXT_LEN)?;
        let if_match = params.optional_etag("ifMatch")?;
        let if_none_match = params.optional_sensitive_string("ifNoneMatch", 1, 1)?;
        params.finish()?;
        let create_only = match if_none_match.as_ref().map(|value| value.as_str()) {
            None => false,
            Some("*") => true,
            Some(_) => return Err(ErrorObject::new(ErrorCode::InvalidParams)),
        };
        if create_only == if_match.is_some() {
            return Err(ErrorObject::new(ErrorCode::InvalidParams));
        }
        let modified_at = unix_time_ms()?;
        let vault = self
            .sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?;
        let metadata = if create_only {
            vault.create_document(&logical_path, plaintext.as_slice(), modified_at)
        } else {
            let expected = if_match
                .as_ref()
                .ok_or_else(|| ErrorObject::new(ErrorCode::InvalidParams))?;
            vault.save_document(
                &logical_path,
                plaintext.as_slice(),
                expected.as_str(),
                modified_at,
            )
        }
        .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(document_metadata_value(&metadata))
    }

    fn file_mkdir(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let logical_path = params.required_logical_dir("logicalPath")?;
        params.finish()?;
        self.sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?
            .create_directory(&logical_path)
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(acknowledgement())
    }

    fn file_rename(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let source = params.required_logical_path("from")?;
        let destination = params.required_logical_path("to")?;
        let source_etag = params.required_etag("sourceEtag")?;
        params.required_star("destinationIfNoneMatch")?;
        params.finish()?;
        let renamed = self
            .sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?
            .rename_document(&source, &destination, source_etag.as_str(), unix_time_ms()?)
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(rename_value(&renamed))
    }

    fn file_delete(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let logical_path = params.required_logical_path("logicalPath")?;
        let expected = params.required_etag("ifMatch")?;
        let recursive = params.required_bool("recursive")?;
        params.finish()?;
        if recursive {
            return Err(ErrorObject::new(ErrorCode::Unsupported));
        }
        let durability = self
            .sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?
            .delete_document(&logical_path, expected.as_str())
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(json!({
            "ok": true,
            "durability": durability_name(durability),
        }))
    }

    fn document_open(&mut self, params: Params) -> RpcResult {
        let (session, logical_path) = parse_session_path(params)?;
        let document = self
            .sessions
            .vault(session.as_str())
            .map_err(map_session_error)?
            .read(&logical_path)
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        let handle = self
            .sessions
            .open_document(session.as_str(), logical_path, document.etag.clone())
            .map_err(map_session_error)?;
        let mut value = decrypted_document_value(&document);
        value
            .as_object_mut()
            .ok_or_else(|| ErrorObject::new(ErrorCode::InternalError))?
            .insert(
                "handle".to_owned(),
                Value::String(handle.expose_secret().to_owned()),
            );
        Ok(value)
    }

    fn document_close(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let handle = params.required_sensitive_string("handle", 1, MAX_CAPABILITY_TEXT_BYTES)?;
        params.finish()?;
        self.sessions
            .close_document(session.as_str(), handle.as_str())
            .map_err(map_session_error)?;
        Ok(acknowledgement())
    }

    fn draft_encrypt(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let handle = params.optional_sensitive_string("handle", 1, MAX_CAPABILITY_TEXT_BYTES)?;
        let supplied_path = params.optional_logical_path("logicalPath")?;
        let supplied_base = params.optional_etag("baseEtag")?;
        let plaintext = params.required_base64url("contentBase64", MAX_PLAINTEXT_LEN)?;
        params.finish()?;
        if handle.is_some() == supplied_path.is_some() {
            return Err(ErrorObject::new(ErrorCode::InvalidParams));
        }
        let (logical_path, handle_base) = if let Some(handle) = handle.as_ref() {
            let binding = self
                .sessions
                .document(session.as_str(), handle.as_str())
                .map_err(map_session_error)?;
            (
                binding.logical_path().clone(),
                Some(binding.base_etag().to_owned()),
            )
        } else {
            (
                supplied_path.ok_or_else(|| ErrorObject::new(ErrorCode::InvalidParams))?,
                None,
            )
        };
        let supplied_base = supplied_base.map(CanonicalEtag::into_string);
        if let (Some(handle_base), Some(supplied_base)) = (&handle_base, &supplied_base)
            && handle_base != supplied_base
        {
            return Err(ErrorObject::new(ErrorCode::EtagConflict));
        }
        let base = supplied_base.or(handle_base);
        let encrypted = self
            .sessions
            .vault(session.as_str())
            .map_err(map_session_error)?
            .encrypt_draft(
                &logical_path,
                plaintext.as_slice(),
                base.as_deref(),
                unix_time_ms()?,
            )
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(encrypted_draft_value(&encrypted))
    }

    fn draft_decrypt(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let logical_path = params.required_logical_path("logicalPath")?;
        let encrypted = params.required_base64url("draftBase64", MAX_EDRY_ENVELOPE_BYTES)?;
        params.finish()?;
        let document = self
            .sessions
            .vault(session.as_str())
            .map_err(map_session_error)?
            .decrypt_draft(&logical_path, encrypted.as_slice())
            .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
        Ok(json!({
            "contentBase64": encode_base64url(document.plaintext.as_slice()).as_str(),
            "baseEtag": document.header.base_etag.map(etag_from_digest),
            "metadata": header_metadata_value(&document.header),
        }))
    }

    fn search_query(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let query = params.required_sensitive_string("query", 1, MAX_SEARCH_QUERY_BYTES)?;
        let limit = params
            .optional_u64(
                "limit",
                1,
                u64::try_from(MAX_SEARCH_RESULTS).unwrap_or(u64::MAX),
            )?
            .unwrap_or(u64::try_from(DEFAULT_SEARCH_RESULTS).unwrap_or(u64::MAX));
        let snippet_limit = params
            .optional_u64(
                "snippetByteLimit",
                0,
                u64::try_from(MAX_SEARCH_SNIPPET_BYTES).unwrap_or(u64::MAX),
            )?
            .unwrap_or(u64::try_from(DEFAULT_SEARCH_SNIPPET_BYTES).unwrap_or(u64::MAX));
        let case_sensitive = params.optional_bool("caseSensitive")?.unwrap_or(false);
        params.finish()?;
        let sensitivity = if case_sensitive {
            CaseSensitivity::Sensitive
        } else {
            CaseSensitivity::UnicodeInsensitive
        };
        let query = SearchQuery::new(
            query,
            sensitivity,
            usize::try_from(limit).map_err(|_| ErrorObject::new(ErrorCode::LimitExceeded))?,
            usize::try_from(snippet_limit)
                .map_err(|_| ErrorObject::new(ErrorCode::LimitExceeded))?,
        )
        .map_err(|_| ErrorObject::new(ErrorCode::LimitExceeded))?;
        let vault = self
            .sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?;
        let hits = match vault.search(&query) {
            Ok(hits) => hits,
            Err(VaultError::SearchIndexNotReady) => {
                vault
                    .rebuild_search_index()
                    .map_err(|error| map_vault_error(error, ErrorContext::Document))?;
                vault
                    .search(&query)
                    .map_err(|error| map_vault_error(error, ErrorContext::Document))?
            }
            Err(error) => return Err(map_vault_error(error, ErrorContext::Document)),
        };
        let results = hits
            .iter()
            .map(|hit| {
                let range = hit.byte_range();
                json!({
                    "logicalPath": hit.logical_path().as_str(),
                    "startByte": range.start,
                    "endByte": range.end,
                    "line": hit.line(),
                    "utf16Column": hit.utf16_column(),
                    "snippet": hit.snippet(),
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({"results": results}))
    }

    fn cache_evict(&mut self, params: Params) -> RpcResult {
        let mut params = ParamObject::new(params);
        let session = required_session(&mut params)?;
        let logical_path = params.optional_logical_path("logicalPath")?;
        params.finish()?;
        let handles = self
            .sessions
            .evict_documents(session.as_str(), logical_path.as_ref())
            .map_err(map_session_error)?;
        self.sessions
            .vault_mut(session.as_str())
            .map_err(map_session_error)?
            .clear_search_index();
        Ok(json!({"ok": true, "evictedHandles": handles}))
    }
}

impl<C> fmt::Debug for RpcService<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcService")
            .field("sessions", &self.sessions)
            .field("hello_complete", &self.hello_complete)
            .field("shutdown_requested", &self.shutdown_requested)
            .finish_non_exhaustive()
    }
}

impl From<ParamError> for ErrorObject {
    fn from(error: ParamError) -> Self {
        Self::new(error.code())
    }
}

fn required_session(params: &mut ParamObject) -> Result<zeroize::Zeroizing<String>, ErrorObject> {
    params
        .required_sensitive_string("session", 1, MAX_CAPABILITY_TEXT_BYTES)
        .map_err(|_| ErrorObject::new(ErrorCode::SessionInvalid))
}

fn parse_session_path(
    params: Params,
) -> Result<(zeroize::Zeroizing<String>, LogicalPath), ErrorObject> {
    let mut params = ParamObject::new(params);
    let session = required_session(&mut params)?;
    let logical_path = params.required_logical_path("logicalPath")?;
    params.finish()?;
    Ok((session, logical_path))
}

fn parse_optional_kdf(
    params: &mut ParamObject,
    policy: KdfPolicy,
) -> Result<Argon2idParams, ErrorObject> {
    let Some(mut kdf) = params.optional_object("kdf")? else {
        return Ok(DEFAULT_ARGON2ID_PARAMS);
    };
    let ops_limit = kdf.required_u64(
        "opsLimit",
        VAULT_ARGON2ID_READER_LIMITS.min_ops_limit,
        policy.max_unlock_ops_limit,
    )?;
    let mem_limit_bytes = kdf.required_u64(
        "memLimitBytes",
        VAULT_ARGON2ID_READER_LIMITS.min_mem_limit_bytes,
        policy.max_unlock_mem_limit_bytes,
    )?;
    kdf.finish()?;
    Ok(Argon2idParams {
        ops_limit,
        mem_limit_bytes,
    })
}

fn validated_vault_path(value: &str) -> Result<PathBuf, ErrorObject> {
    if value.contains('\0') {
        return Err(ErrorObject::new(ErrorCode::InvalidParams));
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(ErrorObject::new(ErrorCode::InvalidParams));
    }
    Ok(path.to_path_buf())
}

fn parse_uuid(value: &CanonicalUuid) -> Result<Uuid, ErrorObject> {
    Uuid::parse_str(value.as_str()).map_err(|_| ErrorObject::new(ErrorCode::InternalError))
}

fn acknowledgement() -> Value {
    json!({"ok": true})
}

fn prefix_matches(prefix: Option<&LogicalDir>, logical_path: &str) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    if prefix.is_root() {
        return true;
    }
    logical_path == prefix.as_str()
        || logical_path
            .strip_prefix(prefix.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn stat_value(document: &DecryptedDocument) -> Value {
    json!({
        "type": "file",
        "size": document.plaintext.len(),
        "etag": document.etag,
        "metadata": header_metadata_value(&document.header),
    })
}

fn decrypted_document_value(document: &DecryptedDocument) -> Value {
    json!({
        "contentBase64": encode_base64url(document.plaintext.as_slice()).as_str(),
        "etag": document.etag,
        "metadata": header_metadata_value(&document.header),
    })
}

fn document_metadata_value(metadata: &DocumentMetadata) -> Value {
    json!({
        "etag": metadata.etag,
        "metadata": header_metadata_value(&metadata.header),
        "durability": durability_name(metadata.parent_sync),
    })
}

fn rename_value(renamed: &RenameOutcome) -> Value {
    json!({
        "etag": renamed.document.etag,
        "metadata": header_metadata_value(&renamed.document.header),
        "destinationDurability": durability_name(renamed.document.parent_sync),
        "sourceDurability": durability_name(renamed.source_parent_sync),
    })
}

fn encrypted_draft_value(document: &EncryptedDocument) -> Value {
    json!({
        "draftBase64": encode_base64url(&document.bytes).as_str(),
        "etag": document.etag,
        "metadata": header_metadata_value(&document.header),
    })
}

fn header_metadata_value(header: &EdryHeader) -> Value {
    json!({
        "fileId": header.file_id.to_string(),
        "logicalPath": header.logical_path,
        "createdAt": header.created_at_ms,
        "modifiedAt": header.modified_at_ms,
        "flags": header.content_flags.bits(),
    })
}

fn warnings_value(warnings: &[ConfigWarning]) -> Vec<Value> {
    warnings
        .iter()
        .map(|warning| match warning {
            ConfigWarning::WeakKdf { slot_id } => json!({
                "name": "WEAK_KDF",
                "slotId": slot_id.to_string(),
            }),
        })
        .collect()
}

const fn durability_name(status: ParentSyncStatus) -> &'static str {
    match status {
        ParentSyncStatus::Synced => "synced",
        ParentSyncStatus::NotSynced => "notSynced",
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_time_ms() -> Result<i64, ErrorObject> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorObject::new(ErrorCode::InternalError))?;
    i64::try_from(duration.as_millis()).map_err(|_| ErrorObject::new(ErrorCode::InternalError))
}

fn etag_from_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone, Copy)]
enum ErrorContext {
    Authentication,
    Document,
}

fn map_session_error(error: SessionError) -> ErrorObject {
    let code = match error {
        SessionError::InvalidSession | SessionError::StoreShutdown => ErrorCode::SessionInvalid,
        SessionError::SecurityUnavailable => ErrorCode::InternalError,
        SessionError::DocumentHandleLimit => ErrorCode::LimitExceeded,
        SessionError::InvalidDocumentHandle => ErrorCode::InvalidParams,
    };
    ErrorObject::new(code)
}

fn map_vault_error(error: VaultError, context: ErrorContext) -> ErrorObject {
    let code = match error {
        VaultError::Crypto(error) => map_crypto_error(error, context),
        VaultError::Config(error) => map_config_error(&error, context),
        VaultError::Path(_) => ErrorCode::PathInvalid,
        VaultError::Tree(error) => map_tree_error(&error),
        VaultError::UnsafeFilesystemEntry => ErrorCode::VaultInvalid,
        VaultError::Search(_) | VaultError::FileTooLarge | VaultError::EnvelopeTooLarge => {
            ErrorCode::LimitExceeded
        }
        VaultError::Io { .. }
        | VaultError::NamespaceCommitIndeterminate { .. }
        | VaultError::PasswordCommitVerificationFailed => ErrorCode::IoFailed,
        VaultError::UnsupportedFilesystem => ErrorCode::Unsupported,
        VaultError::AlreadyInitialized
        | VaultError::AlreadyExists
        | VaultError::CaseFoldCollision => ErrorCode::AlreadyExists,
        VaultError::NotInitialized
        | VaultError::ParentDirectoryMissing
        | VaultError::DocumentNotFound => ErrorCode::NotFound,
        VaultError::InvalidEtag => ErrorCode::InvalidParams,
        VaultError::Conflict { .. } => ErrorCode::EtagConflict,
        VaultError::SearchIndexNotReady | VaultError::RenameRecoveryPending { .. } => {
            ErrorCode::Busy
        }
        VaultError::SearchUtf8Invariant | VaultError::AtomicVerificationFailed => {
            ErrorCode::IntegrityFailed
        }
        VaultError::RenameRecoveryConflict => ErrorCode::IntegrityFailed,
    };
    ErrorObject::new(code)
}

fn map_tree_error(error: &TreeError) -> ErrorCode {
    match error {
        TreeError::DepthLimitExceeded { .. }
        | TreeError::EntryLimitExceeded { .. }
        | TreeError::PathByteLimitExceeded { .. } => ErrorCode::LimitExceeded,
        TreeError::Io { .. } => ErrorCode::IoFailed,
        TreeError::LinkLikeRoot
        | TreeError::RootNotDirectory
        | TreeError::LinkLikeEntry { .. }
        | TreeError::UnsupportedFileType { .. }
        | TreeError::ReservedEntryAlias { .. }
        | TreeError::FilesystemBoundary { .. }
        | TreeError::InvalidEntry { .. }
        | TreeError::NonCanonicalCiphertextName { .. }
        | TreeError::PlaintextMarkdown { .. }
        | TreeError::DuplicateLogicalPath { .. }
        | TreeError::CaseFoldCollision { .. } => ErrorCode::VaultInvalid,
    }
}

fn map_crypto_error(error: CryptoError, context: ErrorContext) -> ErrorCode {
    match error {
        CryptoError::Config(error) => map_config_error(&error, context),
        CryptoError::InvalidMarkdownUtf8 | CryptoError::CannotRemoveLastSlot => {
            ErrorCode::InvalidParams
        }
        CryptoError::PlaintextTooLarge => ErrorCode::LimitExceeded,
        CryptoError::Sodium(_) => ErrorCode::InternalError,
        CryptoError::VaultAuthenticationFailed
        | CryptoError::MetadataAuthenticationFailed
        | CryptoError::SlotSelectionRequired => match context {
            ErrorContext::Authentication => ErrorCode::AuthFailed,
            ErrorContext::Document => ErrorCode::IntegrityFailed,
        },
        CryptoError::Format(_)
        | CryptoError::InvalidWrappedKeyLength
        | CryptoError::DocumentContextMismatch
        | CryptoError::DocumentAuthenticationFailed => ErrorCode::IntegrityFailed,
    }
}

fn map_config_error(error: &ConfigError, context: ErrorContext) -> ErrorCode {
    match error {
        ConfigError::KdfOutsideReaderBounds | ConfigError::KdfBelowCreationPolicy => {
            ErrorCode::KdfPolicy
        }
        ConfigError::InvalidPasswordLength | ConfigError::InvalidPasswordUtf8 => {
            ErrorCode::InvalidParams
        }
        ConfigError::MetadataTooLarge | ConfigError::TooManyKeySlots => ErrorCode::LimitExceeded,
        ConfigError::UnsupportedVersion
        | ConfigError::UnsupportedRequiredFeature
        | ConfigError::UnsupportedFeature => ErrorCode::Unsupported,
        ConfigError::KeySlotNotFound if matches!(context, ErrorContext::Authentication) => {
            ErrorCode::AuthFailed
        }
        ConfigError::InvalidJson(_)
        | ConfigError::InvalidVaultId
        | ConfigError::InvalidTimestamp
        | ConfigError::NonCanonicalRequiredFeatures
        | ConfigError::NoKeySlots
        | ConfigError::InvalidKeySlotId
        | ConfigError::InvalidKeySlotTimestamp
        | ConfigError::CborEncoding
        | ConfigError::KeySlotNotFound => ErrorCode::VaultInvalid,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use inex_core::sodium::Argon2idParams;
    use serde_json::{Map, Value, json};
    use zeroize::{Zeroize, Zeroizing};

    use super::*;
    use crate::sensitive::scrub_object;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            Self(std::env::temp_dir().join(format!(
                "inex-handler-{}-{nanos}-{sequence}",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_policy() -> KdfPolicy {
        KdfPolicy {
            min_creation_ops_limit: 1,
            min_creation_mem_limit_bytes: 8 * 1024,
            max_unlock_ops_limit: 4,
            max_unlock_mem_limit_bytes: 64 * 1024 * 1024,
        }
    }

    fn request(id: i64, method: &str, params: Value) -> JsonObject {
        let mut object = Map::new();
        object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        object.insert("id".to_owned(), Value::from(id));
        object.insert("method".to_owned(), Value::String(method.to_owned()));
        object.insert("params".to_owned(), params);
        object
    }

    fn response<C: MonotonicClock>(
        service: &mut RpcService<C>,
        id: i64,
        method: &str,
        params: Value,
    ) -> JsonObject {
        service
            .handle_object(request(id, method, params))
            .into_json_object()
    }

    fn hello<C: MonotonicClock>(service: &mut RpcService<C>) {
        let mut result = response(
            service,
            1,
            "system.hello",
            json!({"client":"test", "clientVersion":"1", "protocolMajor":1}),
        );
        assert_eq!(result["result"]["protocolMajor"], 1);
        scrub_object(&mut result);
    }

    #[test]
    fn negotiation_is_required_and_mismatch_requests_shutdown() {
        let mut service = RpcService::with_clock_and_policy(SystemClock::new(), test_policy());
        let mut before = response(&mut service, 1, "system.ping", json!({}));
        assert_eq!(before["error"]["code"], ErrorCode::Unsupported.number());
        scrub_object(&mut before);

        let mut mismatch = response(
            &mut service,
            2,
            "system.hello",
            json!({"client":"test", "clientVersion":"1", "protocolMajor":2}),
        );
        assert_eq!(mismatch["error"]["code"], ErrorCode::Unsupported.number());
        assert!(service.shutdown_requested());
        scrub_object(&mut mismatch);
    }

    #[test]
    fn shutdown_is_a_fail_closed_handler_terminal_state() {
        let directory = TestDirectory::new();
        let mut service = RpcService::with_clock_and_policy(SystemClock::new(), test_policy());
        hello(&mut service);
        let mut shutdown = response(&mut service, 2, "system.shutdown", json!({}));
        assert_eq!(shutdown["result"]["ok"], true);
        scrub_object(&mut shutdown);

        let mut after = response(
            &mut service,
            3,
            "vault.create",
            json!({
                "vaultPath": directory.path().to_string_lossy(),
                "password": "must-not-create",
            }),
        );
        assert_eq!(after["error"]["code"], ErrorCode::Unsupported.number());
        assert!(!directory.path().exists());
        scrub_object(&mut after);
    }

    #[test]
    fn malformed_missing_and_unknown_sessions_share_one_error() {
        let mut service = RpcService::with_clock_and_policy(SystemClock::new(), test_policy());
        hello(&mut service);
        for (id, session) in [
            (2, None),
            (3, Some(Value::Null)),
            (4, Some(Value::String(String::new()))),
            (
                5,
                Some(Value::String("x".repeat(MAX_CAPABILITY_TEXT_BYTES + 1))),
            ),
            (6, Some(Value::String("unknown-session".to_owned()))),
        ] {
            let mut params = serde_json::Map::new();
            params.insert(
                "logicalPath".to_owned(),
                Value::String("entry.md".to_owned()),
            );
            if let Some(session) = session {
                params.insert("session".to_owned(), session);
            }
            let mut rejected = response(&mut service, id, "file.stat", Value::Object(params));
            assert_eq!(
                rejected["error"]["code"],
                ErrorCode::SessionInvalid.number()
            );
            scrub_object(&mut rejected);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end lifecycle is clearer as a single scenario.
    fn unlock_write_read_search_draft_and_lock_flow() {
        let directory = TestDirectory::new();
        let password = b"handler test password";
        drop(
            Vault::create_with_params(
                directory.path(),
                password,
                1_783_699_200_000,
                Argon2idParams {
                    ops_limit: 1,
                    mem_limit_bytes: 8 * 1024,
                },
                test_policy(),
            )
            .unwrap_or_else(|error| panic!("fixture vault failed: {error}")),
        );
        let mut service = RpcService::with_clock_and_policy(SystemClock::new(), test_policy());
        hello(&mut service);

        let mut unlocked = response(
            &mut service,
            2,
            "vault.unlock",
            json!({
                "vaultPath": directory.path().to_string_lossy(),
                "password": String::from_utf8_lossy(password),
            }),
        );
        let mut session = Zeroizing::new(
            unlocked["result"]["session"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        );
        assert!(!session.is_empty());
        scrub_object(&mut unlocked);

        let mut replacement = response(
            &mut service,
            20,
            "vault.unlock",
            json!({
                "vaultPath": directory.path().to_string_lossy(),
                "password": String::from_utf8_lossy(password),
            }),
        );
        assert_eq!(replacement["error"]["code"], ErrorCode::Busy.number());
        scrub_object(&mut replacement);

        let plaintext = b"# Secret\nneedle here\n";
        let mut written = response(
            &mut service,
            3,
            "file.write",
            json!({
                "session": session.as_str(),
                "logicalPath": "entry.md",
                "contentBase64": encode_base64url(plaintext).as_str(),
                "ifNoneMatch": "*",
            }),
        );
        let etag = written["result"]["etag"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(etag.starts_with("sha256:"));
        scrub_object(&mut written);

        let mut read = response(
            &mut service,
            4,
            "file.read",
            json!({"session":session.as_str(), "logicalPath":"entry.md"}),
        );
        assert_eq!(
            read["result"]["contentBase64"],
            encode_base64url(plaintext).as_str()
        );
        scrub_object(&mut read);

        let mut search = response(
            &mut service,
            5,
            "search.query",
            json!({"session":session.as_str(), "query":"needle", "limit":10}),
        );
        assert_eq!(search["result"]["results"][0]["logicalPath"], "entry.md");
        scrub_object(&mut search);

        let mut opened = response(
            &mut service,
            6,
            "document.open",
            json!({"session":session.as_str(), "logicalPath":"entry.md"}),
        );
        let mut handle = Zeroizing::new(
            opened["result"]["handle"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        );
        scrub_object(&mut opened);
        let mut draft = response(
            &mut service,
            7,
            "draft.encrypt",
            json!({
                "session": session.as_str(),
                "handle": handle.as_str(),
                "contentBase64": encode_base64url(b"draft text").as_str(),
                "baseEtag": etag,
            }),
        );
        assert!(draft["result"]["draftBase64"].as_str().is_some());
        scrub_object(&mut draft);

        let mut locked = response(
            &mut service,
            8,
            "vault.lock",
            json!({"session":session.as_str()}),
        );
        assert_eq!(locked["result"]["ok"], true);
        assert!(!service.session_active());
        scrub_object(&mut locked);
        session.zeroize();
        handle.zeroize();
    }

    #[test]
    fn malformed_params_never_survive_into_diagnostics() {
        let mut service = RpcService::with_clock_and_policy(SystemClock::new(), test_policy());
        hello(&mut service);
        let response = service.handle_object(request(
            2,
            "vault.unlock",
            json!({"password":"canary-password", "unknown":"canary-content"}),
        ));
        let debug = format!("{response:?}");
        assert!(!debug.contains("canary"));
        let mut object = response.into_json_object();
        assert_eq!(object["error"]["code"], ErrorCode::InvalidParams.number());
        scrub_object(&mut object);
    }

    #[test]
    fn tree_errors_map_to_actionable_safe_categories() {
        assert_eq!(
            map_tree_error(&TreeError::EntryLimitExceeded { maximum: 1 }),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            map_tree_error(&TreeError::Io {
                operation: inex_core::tree::TreeIoOperation::ReadDirectory,
                kind: std::io::ErrorKind::PermissionDenied,
            }),
            ErrorCode::IoFailed
        );
        assert_eq!(
            map_tree_error(&TreeError::LinkLikeRoot),
            ErrorCode::VaultInvalid
        );
    }
}
