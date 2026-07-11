//! Single-vault capability sessions and document-handle ownership.
//!
//! A daemon process owns at most one unlocked [`Vault`]. The active session is
//! addressed by a random 256-bit capability, expires after fifteen minutes of
//! inactivity, and is dropped on lock, expiry, replacement, shutdown, or store
//! destruction. Document handles contain no plaintext; they only bind a random
//! per-session identifier to a logical path and its base ciphertext etag.

use std::fmt;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use inex_core::path::LogicalPath;
use inex_core::sodium;
use inex_core::vault::Vault;
use zeroize::Zeroizing;

/// Idle duration after which an unlocked session is destroyed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(15);

/// Maximum number of live document handles owned by one session.
pub const MAX_DOCUMENT_HANDLES: usize = 128;

const SESSION_TOKEN_BYTES: usize = 32;
const DOCUMENT_HANDLE_BYTES: usize = 16;
const MAX_CAPABILITY_GENERATION_ATTEMPTS: usize = 32;

/// Source of monotonic elapsed time used by [`SessionStore`].
///
/// Values may use any private epoch, but must not move backwards during normal
/// operation. A duration is used instead of wall-clock time so clock changes
/// cannot extend or prematurely expire an unlocked session.
pub trait MonotonicClock: Send + Sync + 'static {
    /// Return the current duration from this clock's private monotonic epoch.
    fn now(&self) -> Duration;
}

/// Production monotonic clock backed by [`Instant`].
#[derive(Clone, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Start a new monotonic clock epoch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Random 256-bit capability authorizing one unlocked daemon session.
///
/// The canonical wire representation is unpadded base64url. Owned copies wipe
/// their allocation on drop, and formatting is always redacted. Callers should
/// expose the value only while constructing a protected protocol response.
#[derive(Clone)]
pub struct SessionToken {
    encoded: Zeroizing<String>,
}

impl SessionToken {
    fn generate() -> Result<Self, SessionError> {
        Ok(Self {
            encoded: random_base64url::<SESSION_TOKEN_BYTES>()?,
        })
    }

    fn matches(&self, presented: &str) -> Result<bool, SessionError> {
        constant_time_text_eq(&self.encoded, presented)
    }

    /// Borrow the canonical token text for protocol serialization.
    ///
    /// This deliberately explicit accessor is the only non-redacted view.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.encoded.as_str()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED SESSION TOKEN]")
    }
}

/// Random per-session identifier for one open logical document.
///
/// Handles are meaningful only together with the session that issued them.
/// Owned copies are zeroized on drop and never reveal their value through
/// formatting.
#[derive(Clone)]
pub struct DocumentHandle {
    encoded: Zeroizing<String>,
}

impl DocumentHandle {
    fn generate() -> Result<Self, SessionError> {
        Ok(Self {
            encoded: random_base64url::<DOCUMENT_HANDLE_BYTES>()?,
        })
    }

    fn matches(&self, presented: &str) -> Result<bool, SessionError> {
        constant_time_text_eq(&self.encoded, presented)
    }

    /// Borrow the canonical handle text for protocol serialization.
    ///
    /// This deliberately explicit accessor is the only non-redacted view.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.encoded.as_str()
    }
}

impl fmt::Debug for DocumentHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DocumentHandle([REDACTED])")
    }
}

impl fmt::Display for DocumentHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED DOCUMENT HANDLE]")
    }
}

/// Non-plaintext state bound to an open document handle.
pub struct DocumentBinding {
    logical_path: LogicalPath,
    base_etag: String,
}

impl DocumentBinding {
    /// Borrow the logical document path.
    #[must_use]
    pub fn logical_path(&self) -> &LogicalPath {
        &self.logical_path
    }

    /// Borrow the ciphertext etag on which the editor buffer is based.
    #[must_use]
    pub fn base_etag(&self) -> &str {
        &self.base_etag
    }
}

impl fmt::Debug for DocumentBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocumentBinding")
            .field("logical_path", &"[REDACTED]")
            .field("base_etag", &"[REDACTED]")
            .finish()
    }
}

/// Safe, non-secret failure classification for session operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// A token was missing, unknown, expired, locked, or from an old session.
    InvalidSession,
    /// The daemon store has entered its terminal shutdown state.
    StoreShutdown,
    /// Secure random generation or constant-time comparison was unavailable.
    SecurityUnavailable,
    /// The active session already owns the maximum document-handle count.
    DocumentHandleLimit,
    /// A document handle was unknown or belonged to another session.
    InvalidDocumentHandle,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSession => "session is invalid",
            Self::StoreShutdown => "session store is shut down",
            Self::SecurityUnavailable => "secure session operation is unavailable",
            Self::DocumentHandleLimit => "document handle limit reached",
            Self::InvalidDocumentHandle => "document handle is invalid",
        })
    }
}

impl std::error::Error for SessionError {}

struct OpenDocument {
    handle: DocumentHandle,
    binding: DocumentBinding,
}

struct ActiveSession {
    capability: SessionToken,
    vault: Vault,
    last_activity: Duration,
    documents: Vec<OpenDocument>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.documents.clear();
        self.vault.clear_search_index();
        // Field drop then wipes the capability, guarded master key, and all
        // remaining Vault-owned state.
    }
}

/// Owns at most one unlocked vault and its process-local capabilities.
///
/// `SessionStore` contains no document plaintext cache. Closing or evicting a
/// document therefore removes only its random handle, logical path, and base
/// etag. Dropping an active session explicitly clears the Vault search index
/// before the guarded master key is released by [`Vault`]'s field drops.
pub struct SessionStore<C = SystemClock> {
    clock: C,
    active: Option<ActiveSession>,
    shutdown: bool,
}

impl SessionStore<SystemClock> {
    /// Construct an empty production session store.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(SystemClock::new())
    }
}

impl Default for SessionStore<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: MonotonicClock> SessionStore<C> {
    /// Construct an empty store using an injected monotonic clock.
    #[must_use]
    pub fn with_clock(clock: C) -> Self {
        Self {
            clock,
            active: None,
            shutdown: false,
        }
    }

    /// Install an unlocked vault and return a freshly rotated capability.
    ///
    /// Any previous session, document handles, search index, and key ownership
    /// are destroyed only after generation of the replacement capability has
    /// succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::StoreShutdown`] after terminal shutdown, or
    /// [`SessionError::SecurityUnavailable`] when capability generation fails.
    pub fn unlock(&mut self, vault: Vault) -> Result<SessionToken, SessionError> {
        if self.shutdown {
            return Err(SessionError::StoreShutdown);
        }
        let capability = SessionToken::generate()?;
        let replacement = ActiveSession {
            capability: capability.clone(),
            vault,
            last_activity: self.clock.now(),
            documents: Vec::new(),
        };
        self.active = Some(replacement);
        Ok(capability)
    }

    /// Validate a capability without extending its idle deadline.
    ///
    /// Expired state is destroyed before returning the same error used for an
    /// unknown token.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidSession`] for missing, expired, locked,
    /// shutdown, or unknown sessions. A constant-time primitive failure returns
    /// [`SessionError::SecurityUnavailable`].
    pub fn validate(&mut self, presented: &str) -> Result<(), SessionError> {
        let now = self.clock.now();
        self.validate_at(presented, now)
    }

    /// Validate a capability and extend its idle deadline.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn touch(&mut self, presented: &str) -> Result<(), SessionError> {
        let now = self.clock.now();
        self.validate_at(presented, now)?;
        self.active
            .as_mut()
            .ok_or(SessionError::InvalidSession)?
            .last_activity = now;
        Ok(())
    }

    /// Validate and touch a session, then return its renewed idle allowance.
    ///
    /// A successful call is itself protected activity, so it always returns
    /// the complete [`DEFAULT_IDLE_TIMEOUT`] rather than a wall-clock expiry.
    /// RPC status responses can report this duration without exposing the
    /// clock's private epoch.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn idle_remaining(&mut self, presented: &str) -> Result<Duration, SessionError> {
        self.touch(presented)?;
        Ok(DEFAULT_IDLE_TIMEOUT)
    }

    /// Borrow the unlocked vault after validating and touching the session.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn vault(&mut self, presented: &str) -> Result<&Vault, SessionError> {
        Ok(&self.validated_session_mut(presented)?.vault)
    }

    /// Mutably borrow the unlocked vault after validating and touching it.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn vault_mut(&mut self, presented: &str) -> Result<&mut Vault, SessionError> {
        Ok(&mut self.validated_session_mut(presented)?.vault)
    }

    /// Explicitly lock and destroy the active session.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidSession`] for an expired, missing, or
    /// unknown capability, or [`SessionError::SecurityUnavailable`] if token
    /// comparison is unavailable.
    pub fn lock(&mut self, presented: &str) -> Result<(), SessionError> {
        let now = self.clock.now();
        self.validate_at(presented, now)?;
        drop(self.active.take());
        Ok(())
    }

    /// Destroy an idle session when its deadline has elapsed.
    ///
    /// Returns whether an active session was expired by this call.
    pub fn expire(&mut self) -> bool {
        self.expire_at(self.clock.now())
    }

    /// Destroy session state and permanently prevent another unlock.
    ///
    /// Returns whether a live session was destroyed by this call. Shutdown is
    /// idempotent.
    pub fn shutdown(&mut self) -> bool {
        self.shutdown = true;
        self.active.take().is_some()
    }

    /// Return whether terminal shutdown has been requested.
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Expire due state and report whether a session remains active.
    pub fn is_active(&mut self) -> bool {
        self.expire();
        self.active.is_some()
    }

    /// Create a random handle bound to one logical path and base etag.
    ///
    /// No plaintext is retained. This protected operation touches the session.
    ///
    /// # Errors
    ///
    /// Returns a session validation error, [`SessionError::DocumentHandleLimit`]
    /// at 128 live handles, or [`SessionError::SecurityUnavailable`] if a
    /// collision-free random handle cannot be generated.
    pub fn open_document(
        &mut self,
        presented: &str,
        logical_path: LogicalPath,
        base_etag: String,
    ) -> Result<DocumentHandle, SessionError> {
        let session = self.validated_session_mut(presented)?;
        if session.documents.len() >= MAX_DOCUMENT_HANDLES {
            return Err(SessionError::DocumentHandleLimit);
        }
        let handle = unique_document_handle(&session.documents)?;
        session.documents.push(OpenDocument {
            handle: handle.clone(),
            binding: DocumentBinding {
                logical_path,
                base_etag,
            },
        });
        Ok(handle)
    }

    /// Resolve a document handle owned by the active session.
    ///
    /// This protected operation touches the session.
    ///
    /// # Errors
    ///
    /// Returns a session validation error or
    /// [`SessionError::InvalidDocumentHandle`] for unknown/old-session handles.
    pub fn document(
        &mut self,
        presented: &str,
        handle: &str,
    ) -> Result<&DocumentBinding, SessionError> {
        let session = self.validated_session_mut(presented)?;
        let index = find_document_index(&session.documents, handle)?;
        Ok(&session.documents[index].binding)
    }

    /// Close and zeroize one document handle.
    ///
    /// # Errors
    ///
    /// Returns a session validation error or
    /// [`SessionError::InvalidDocumentHandle`] for unknown/old-session handles.
    pub fn close_document(&mut self, presented: &str, handle: &str) -> Result<(), SessionError> {
        let session = self.validated_session_mut(presented)?;
        let index = find_document_index(&session.documents, handle)?;
        drop(session.documents.swap_remove(index));
        Ok(())
    }

    /// Evict handles for one path, or every handle when `logical_path` is none.
    ///
    /// Returns the number of handles destroyed. This protected operation
    /// touches the session.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn evict_documents(
        &mut self,
        presented: &str,
        logical_path: Option<&LogicalPath>,
    ) -> Result<usize, SessionError> {
        let session = self.validated_session_mut(presented)?;
        let before = session.documents.len();
        if let Some(logical_path) = logical_path {
            session
                .documents
                .retain(|document| document.binding.logical_path() != logical_path);
        } else {
            session.documents.clear();
        }
        Ok(before.saturating_sub(session.documents.len()))
    }

    /// Return the active session's document-handle count.
    ///
    /// This protected operation touches the session.
    ///
    /// # Errors
    ///
    /// Returns the same safe errors as [`Self::validate`].
    pub fn document_count(&mut self, presented: &str) -> Result<usize, SessionError> {
        Ok(self.validated_session_mut(presented)?.documents.len())
    }

    fn validated_session_mut(
        &mut self,
        presented: &str,
    ) -> Result<&mut ActiveSession, SessionError> {
        let now = self.clock.now();
        self.validate_at(presented, now)?;
        let session = self.active.as_mut().ok_or(SessionError::InvalidSession)?;
        session.last_activity = now;
        Ok(session)
    }

    fn validate_at(&mut self, presented: &str, now: Duration) -> Result<(), SessionError> {
        self.expire_at(now);
        let Some(active) = self.active.as_ref() else {
            return Err(SessionError::InvalidSession);
        };
        if active.capability.matches(presented)? {
            Ok(())
        } else {
            Err(SessionError::InvalidSession)
        }
    }

    fn expire_at(&mut self, now: Duration) -> bool {
        let expired = self
            .active
            .as_ref()
            .is_some_and(|active| now.saturating_sub(active.last_activity) >= DEFAULT_IDLE_TIMEOUT);
        if expired {
            drop(self.active.take());
        }
        expired
    }
}

impl<C> fmt::Debug for SessionStore<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = if self.shutdown {
            "shutdown"
        } else if self.active.is_some() {
            "active"
        } else {
            "locked"
        };
        formatter
            .debug_struct("SessionStore")
            .field("state", &state)
            .field(
                "document_handle_count",
                &self
                    .active
                    .as_ref()
                    .map_or(0, |active| active.documents.len()),
            )
            .finish_non_exhaustive()
    }
}

impl<C> Drop for SessionStore<C> {
    fn drop(&mut self) {
        self.shutdown = true;
        drop(self.active.take());
    }
}

fn random_base64url<const N: usize>() -> Result<Zeroizing<String>, SessionError> {
    let mut random = Zeroizing::new([0_u8; N]);
    sodium::random_bytes(&mut random[..]).map_err(|_| SessionError::SecurityUnavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_slice())))
}

fn constant_time_text_eq(expected: &str, presented: &str) -> Result<bool, SessionError> {
    sodium::constant_time_eq(expected.as_bytes(), presented.as_bytes())
        .map_err(|_| SessionError::SecurityUnavailable)
}

fn unique_document_handle(documents: &[OpenDocument]) -> Result<DocumentHandle, SessionError> {
    for _ in 0..MAX_CAPABILITY_GENERATION_ATTEMPTS {
        let candidate = DocumentHandle::generate()?;
        let mut duplicate = false;
        for document in documents {
            duplicate |= document.handle.matches(candidate.expose_secret())?;
        }
        if !duplicate {
            return Ok(candidate);
        }
    }
    Err(SessionError::SecurityUnavailable)
}

fn find_document_index(documents: &[OpenDocument], presented: &str) -> Result<usize, SessionError> {
    let mut found = None;
    for (index, document) in documents.iter().enumerate() {
        if document.handle.matches(presented)? {
            found = Some(index);
        }
    }
    found.ok_or(SessionError::InvalidDocumentHandle)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use inex_core::path::LogicalPath;
    use inex_core::sodium::Argon2idParams;
    use inex_core::vault::Vault;
    use inex_core::vault_config::KdfPolicy;

    use super::{
        DEFAULT_IDLE_TIMEOUT, MAX_DOCUMENT_HANDLES, MonotonicClock, SessionError, SessionStore,
    };

    #[derive(Clone, Default)]
    struct ManualClock {
        nanoseconds: Arc<AtomicU64>,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            let nanoseconds = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
            self.nanoseconds.fetch_add(nanoseconds, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanoseconds.load(Ordering::SeqCst))
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "inex-session-{label}-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path)
                .unwrap_or_else(|error| panic!("test directory creation failed: {error}"));
            Self(path)
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

    fn test_vault(directory: &TestDirectory) -> Vault {
        Vault::create_with_params(
            directory.path(),
            b"test password",
            1_783_699_200_000,
            Argon2idParams {
                ops_limit: 1,
                mem_limit_bytes: 8 * 1024,
            },
            test_policy(),
        )
        .unwrap_or_else(|error| panic!("test vault creation failed: {error}"))
    }

    fn logical(value: &str) -> LogicalPath {
        LogicalPath::parse_canonical(value)
            .unwrap_or_else(|error| panic!("logical path failed: {error}"))
    }

    #[test]
    fn capability_is_256_bit_canonical_and_always_redacted() {
        let directory = TestDirectory::new("token");
        let mut store = SessionStore::with_clock(ManualClock::default());
        let token = store
            .unlock(test_vault(&directory))
            .unwrap_or_else(|error| panic!("session unlock failed: {error}"));
        let decoded = URL_SAFE_NO_PAD
            .decode(token.expose_secret())
            .unwrap_or_else(|error| panic!("token decode failed: {error}"));
        assert_eq!(decoded.len(), 32);
        assert!(!token.expose_secret().contains('='));
        assert!(!format!("{token:?}").contains(token.expose_secret()));
        assert!(!token.to_string().contains(token.expose_secret()));
        assert!(!format!("{store:?}").contains(token.expose_secret()));
    }

    #[test]
    fn invalid_and_expired_tokens_are_indistinguishable() {
        let directory = TestDirectory::new("expiry");
        let clock = ManualClock::default();
        let mut store = SessionStore::with_clock(clock.clone());
        let token = store
            .unlock(test_vault(&directory))
            .unwrap_or_else(|error| panic!("session unlock failed: {error}"));
        let invalid = store.validate("not-a-session-token");
        assert_eq!(invalid, Err(SessionError::InvalidSession));
        assert!(store.is_active());

        clock.advance(DEFAULT_IDLE_TIMEOUT);
        let expired = store.validate(token.expose_secret());
        assert_eq!(expired, invalid);
        assert!(!store.is_active());
    }

    #[test]
    fn touch_extends_the_idle_deadline() {
        let directory = TestDirectory::new("touch");
        let clock = ManualClock::default();
        let mut store = SessionStore::with_clock(clock.clone());
        let token = store
            .unlock(test_vault(&directory))
            .unwrap_or_else(|error| panic!("session unlock failed: {error}"));

        let just_before_timeout = DEFAULT_IDLE_TIMEOUT
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_default();
        clock.advance(just_before_timeout);
        store
            .touch(token.expose_secret())
            .unwrap_or_else(|error| panic!("touch failed: {error}"));
        assert_eq!(
            store.idle_remaining(token.expose_secret()),
            Ok(DEFAULT_IDLE_TIMEOUT)
        );
        clock.advance(just_before_timeout);
        assert!(store.validate(token.expose_secret()).is_ok());
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            store.validate(token.expose_secret()),
            Err(SessionError::InvalidSession)
        );
    }

    #[test]
    fn rotation_lock_and_shutdown_destroy_owned_state() {
        let first_directory = TestDirectory::new("rotation-first");
        let second_directory = TestDirectory::new("rotation-second");
        let third_directory = TestDirectory::new("rotation-third");
        let mut store = SessionStore::with_clock(ManualClock::default());
        let first = store
            .unlock(test_vault(&first_directory))
            .unwrap_or_else(|error| panic!("first unlock failed: {error}"));
        let handle = store
            .open_document(
                first.expose_secret(),
                logical("first.md"),
                "etag-one".to_owned(),
            )
            .unwrap_or_else(|error| panic!("document open failed: {error}"));

        let second = store
            .unlock(test_vault(&second_directory))
            .unwrap_or_else(|error| panic!("second unlock failed: {error}"));
        assert_ne!(first.expose_secret(), second.expose_secret());
        assert_eq!(
            store.validate(first.expose_secret()),
            Err(SessionError::InvalidSession)
        );
        assert!(matches!(
            store.document(second.expose_secret(), handle.expose_secret()),
            Err(SessionError::InvalidDocumentHandle)
        ));

        store
            .lock(second.expose_secret())
            .unwrap_or_else(|error| panic!("lock failed: {error}"));
        assert_eq!(
            store.validate(second.expose_secret()),
            Err(SessionError::InvalidSession)
        );
        let third = store
            .unlock(test_vault(&third_directory))
            .unwrap_or_else(|error| panic!("third unlock failed: {error}"));
        assert!(store.shutdown());
        assert!(!store.shutdown());
        assert!(store.is_shutdown());
        assert_eq!(
            store.validate(third.expose_secret()),
            Err(SessionError::InvalidSession)
        );
    }

    #[test]
    fn document_handles_are_bounded_bound_and_evictable() {
        let directory = TestDirectory::new("handles");
        let mut store = SessionStore::with_clock(ManualClock::default());
        let token = store
            .unlock(test_vault(&directory))
            .unwrap_or_else(|error| panic!("session unlock failed: {error}"));
        let path = logical("notes/entry.md");
        let mut handles = Vec::new();
        for index in 0..MAX_DOCUMENT_HANDLES {
            handles.push(
                store
                    .open_document(token.expose_secret(), path.clone(), format!("etag-{index}"))
                    .unwrap_or_else(|error| panic!("document open failed: {error}")),
            );
        }
        assert_eq!(
            store.document_count(token.expose_secret()),
            Ok(MAX_DOCUMENT_HANDLES)
        );
        assert!(matches!(
            store.open_document(token.expose_secret(), path.clone(), "over-limit".to_owned(),),
            Err(SessionError::DocumentHandleLimit)
        ));

        let first = store
            .document(token.expose_secret(), handles[0].expose_secret())
            .unwrap_or_else(|error| panic!("document lookup failed: {error}"));
        assert_eq!(first.logical_path(), &path);
        assert_eq!(first.base_etag(), "etag-0");
        store
            .close_document(token.expose_secret(), handles[0].expose_secret())
            .unwrap_or_else(|error| panic!("document close failed: {error}"));
        assert!(matches!(
            store.document(token.expose_secret(), handles[0].expose_secret()),
            Err(SessionError::InvalidDocumentHandle)
        ));
        assert_eq!(
            store.evict_documents(token.expose_secret(), Some(&path)),
            Ok(MAX_DOCUMENT_HANDLES - 1)
        );
        assert_eq!(store.document_count(token.expose_secret()), Ok(0));
    }

    #[test]
    fn errors_never_echo_tokens_paths_or_passwords() {
        let path = "private/secret.md";
        let token = "token-canary";
        let password = "password-canary";
        for error in [
            SessionError::InvalidSession,
            SessionError::StoreShutdown,
            SessionError::SecurityUnavailable,
            SessionError::DocumentHandleLimit,
            SessionError::InvalidDocumentHandle,
        ] {
            let display = error.to_string();
            let debug = format!("{error:?}");
            for canary in [path, token, password] {
                assert!(!display.contains(canary));
                assert!(!debug.contains(canary));
            }
        }
    }
}
