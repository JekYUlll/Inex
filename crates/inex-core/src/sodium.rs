//! Audited, narrow wrappers around the libsodium FFI.
//!
//! Raw pointers and libsodium constants are deliberately confined to this
//! module. Secret key material should normally live in [`LockedBytes`], whose
//! allocation is guarded and best-effort page locked by libsodium. Access is
//! closure-scoped so the allocation can remain `noaccess` between operations.

use std::cell::Cell;
use std::ffi::CStr;
use std::fmt;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// The official libsodium 1.0.22 MinGW static archive references the Win32
// random provider directly and was built against a C library that exports the
// C23 `memset_explicit` symbol. Older cross-MinGW runtimes provide neither
// transitively. Keep the compatibility surface confined to this audited FFI
// module; native MSVC and all non-MinGW builds do not compile it.
#[cfg(all(windows, target_env = "gnu"))]
#[link(name = "advapi32")]
unsafe extern "system" {
    #[link_name = "SystemFunction036"]
    fn windows_rtl_gen_random(buffer: *mut std::ffi::c_void, length: u32) -> u8;
}

// Make the import library observable before the static libsodium archive is
// scanned. GNU linkers otherwise discard `advapi32` as unused, then encounter
// libsodium's late `SystemFunction036` reference after its link position.
#[cfg(all(windows, target_env = "gnu"))]
#[used]
static FORCE_WINDOWS_RTL_GEN_RANDOM_LINK: unsafe extern "system" fn(
    *mut std::ffi::c_void,
    u32,
) -> u8 = windows_rtl_gen_random;

#[cfg(all(windows, target_env = "gnu"))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memset_explicit(
    destination: *mut std::ffi::c_void,
    value: i32,
    length: usize,
) -> *mut std::ffi::c_void {
    let bytes = destination.cast::<u8>();
    let byte = u8::try_from(value.rem_euclid(i32::from(u8::MAX) + 1)).unwrap_or_default();
    for offset in 0..length {
        // SAFETY: this function has the C `memset` contract. Libsodium passes
        // one writable region of `length` bytes, and every offset is in-bounds.
        unsafe { bytes.add(offset).write_volatile(byte) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    destination
}

/// Size of an Inex master key, password-derived KEK, or file key.
pub const KEY_BYTES: usize = 32;
/// Size of an XChaCha20-Poly1305-IETF nonce.
pub const XCHACHA20_NONCE_BYTES: usize = 24;
/// Size of an XChaCha20-Poly1305-IETF authentication tag.
pub const XCHACHA20_TAG_BYTES: usize = 16;
/// Size of an Argon2id salt accepted by libsodium.
pub const ARGON2ID_SALT_BYTES: usize = 16;
/// Exact libsodium release reviewed and bundled by this Inex version.
pub const EXPECTED_LIBSODIUM_VERSION: &str = "1.0.22";
/// Exact libsodium ABI major reviewed for the bundled release.
pub const EXPECTED_LIBSODIUM_LIBRARY_MAJOR: i32 = 26;
/// Exact libsodium ABI minor reviewed for the bundled release.
pub const EXPECTED_LIBSODIUM_LIBRARY_MINOR: i32 = 4;
/// Exact Rust target family compiled into this executable.
pub const COMPILED_RUST_TARGET: &str = if cfg!(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu"
)) {
    "x86_64-unknown-linux-gnu"
} else if cfg!(all(
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu"
)) {
    "aarch64-unknown-linux-gnu"
} else if cfg!(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "msvc"
)) {
    "x86_64-pc-windows-msvc"
} else if cfg!(all(
    target_os = "windows",
    target_arch = "aarch64",
    target_env = "msvc"
)) {
    "aarch64-pc-windows-msvc"
} else if cfg!(all(
    target_os = "windows",
    target_arch = "x86_64",
    target_env = "gnu"
)) {
    "x86_64-pc-windows-gnu"
} else if cfg!(all(
    target_os = "windows",
    target_arch = "aarch64",
    target_env = "gnu"
)) {
    "aarch64-pc-windows-gnullvm"
} else {
    "unsupported"
};
/// Whether the executable was compiled with Rust debug assertions enabled.
pub const COMPILED_WITH_DEBUG_ASSERTIONS: bool = cfg!(debug_assertions);

/// Maximum v1 Markdown plaintext size.
pub const MAX_AEAD_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
/// Generous bound for authenticated headers and key-wrap associated data.
pub const MAX_AEAD_ASSOCIATED_DATA_BYTES: usize = 64 * 1024;
/// Maximum input accepted by one-shot `BLAKE2b` helpers.
pub const MAX_BLAKE2B_INPUT_BYTES: usize =
    MAX_AEAD_PLAINTEXT_BYTES + MAX_AEAD_ASSOCIATED_DATA_BYTES;

/// Smallest password accepted by the vault v1 format.
pub const MIN_PASSWORD_BYTES: usize = 1;
/// Largest password accepted by the vault v1 format.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// The v1 creation floor and lowest possible calibrated password-slot cost.
pub const MINIMUM_ARGON2ID_PARAMS: Argon2idParams = Argon2idParams {
    ops_limit: 3,
    mem_limit_bytes: 64 * 1024 * 1024,
};

/// Fixed Argon2id memory cost for calibrated v1 vault creation.
pub const V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Fixed Argon2id parallelism recorded for calibrated v1 vault creation.
pub const V1_ARGON2ID_CALIBRATION_PARALLELISM: u32 = 1;
/// Smallest Argon2id operations cost considered by v1 calibration.
pub const V1_ARGON2ID_CALIBRATION_MIN_OPS_LIMIT: u64 = 3;
/// Largest Argon2id operations cost considered by v1 calibration.
pub const V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT: u64 = 20;
/// Lower edge of the preferred v1 password-KDF latency window.
pub const V1_ARGON2ID_CALIBRATION_TARGET_MIN: Duration = Duration::from_millis(250);
/// Upper edge of the preferred v1 password-KDF latency window.
pub const V1_ARGON2ID_CALIBRATION_TARGET_MAX: Duration = Duration::from_millis(750);

/// Vault v1 reader limits, including the metadata-triggered resource ceiling.
///
/// These limits intentionally permit parameters below the new-vault policy so
/// compatibility and inexpensive tests can use libsodium's supported floor.
pub const VAULT_ARGON2ID_READER_LIMITS: Argon2idLimits = Argon2idLimits {
    min_ops_limit: 1,
    max_ops_limit: 20,
    min_mem_limit_bytes: 8 * 1024,
    max_mem_limit_bytes: 1024 * 1024 * 1024,
};

static SODIUM_INIT: OnceLock<Result<SodiumVersion, SodiumError>> = OnceLock::new();
static ARGON2ID_CALIBRATION: OnceLock<Result<Argon2idCalibration, SodiumError>> = OnceLock::new();

/// Errors raised by the narrow libsodium boundary.
///
/// Variants carry only public sizes, limits, and operation names. Passwords,
/// keys, plaintext, nonces, salts, and ciphertext are never included.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SodiumError {
    /// The process-wide libsodium initialization failed.
    #[error("libsodium initialization failed")]
    InitializationFailed,
    /// The linked runtime does not match the exact reviewed bundled release.
    #[error("libsodium runtime version does not match the reviewed release")]
    UnexpectedRuntimeVersion,
    /// Libsodium returned a missing or non-UTF-8 version string.
    #[error("libsodium returned an invalid version string")]
    InvalidVersionString,
    /// Secure allocation failed.
    #[error("secure memory allocation failed")]
    AllocationFailed,
    /// Strict secure-memory construction required page locking.
    #[error("secure memory page locking is unavailable")]
    MemoryLockRequired,
    /// A secure-memory protection transition failed.
    #[error("secure memory protection failed during {operation}")]
    MemoryProtectionFailed {
        /// Public name of the protection transition.
        operation: &'static str,
    },
    /// A nested or concurrent access attempted to reuse one protected region.
    #[error("secure memory is already being accessed")]
    SecureMemoryBusy,
    /// A previous protection failure left the region unavailable for access.
    #[error("secure memory is unavailable after a protection failure")]
    SecureMemoryFaulted,
    /// An input length is outside the format or primitive bounds.
    #[error("invalid {field} length {actual}; expected {min}..={max} bytes")]
    InvalidLength {
        /// Public field name.
        field: &'static str,
        /// Supplied byte length.
        actual: usize,
        /// Inclusive minimum byte length.
        min: usize,
        /// Inclusive maximum byte length.
        max: usize,
    },
    /// A numeric parameter is outside the selected resource policy.
    #[error("invalid {field} value {actual}; expected {min}..={max}")]
    InvalidParameter {
        /// Public parameter name.
        field: &'static str,
        /// Supplied value.
        actual: u64,
        /// Inclusive minimum value.
        min: u64,
        /// Inclusive maximum value.
        max: u64,
    },
    /// A platform integer cannot represent a validated wire value.
    #[error("{field} is not representable on this platform")]
    PlatformLimitExceeded {
        /// Public field name.
        field: &'static str,
    },
    /// Argon2id could not derive a key with the requested resources.
    #[error("Argon2id13 key derivation failed")]
    PasswordHashFailed,
    /// XChaCha20-Poly1305 encryption failed.
    #[error("XChaCha20-Poly1305 encryption failed")]
    EncryptionFailed,
    /// XChaCha20-Poly1305 authentication failed.
    #[error("XChaCha20-Poly1305 authentication failed")]
    AuthenticationFailed,
    /// `BLAKE2b` hashing failed.
    #[error("BLAKE2b hashing failed")]
    HashFailed,
    /// A successful FFI call returned an impossible output length.
    #[error("libsodium returned an invalid output length for {operation}")]
    InvalidOutputLength {
        /// Public operation name.
        operation: &'static str,
    },
}

/// Runtime version information for the linked libsodium library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SodiumVersion {
    /// Human-readable upstream version, for example `1.0.22`.
    pub version: String,
    /// Libsodium ABI library major version.
    pub library_major: i32,
    /// Libsodium ABI library minor version.
    pub library_minor: i32,
    /// Whether the linked library was built in minimal mode.
    pub minimal: bool,
}

/// Argon2id work factors stored in a password key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Computation cost passed to libsodium as `opslimit`.
    pub ops_limit: u64,
    /// Memory cost in bytes, represented as a wire-friendly `u64`.
    pub mem_limit_bytes: u64,
}

/// Public evidence captured by one bounded Argon2id v1 calibration decision.
///
/// The timed input is the fixed public v1 dummy profile, never a caller
/// password. `selected_elapsed` is the observation used for the selected
/// decision point; it is not an end-to-end vault-operation service level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idCalibration {
    /// Selected operations and fixed-memory work factors.
    params: Argon2idParams,
    /// Observed duration for the selected public-dummy KDF measurement.
    selected_elapsed: Duration,
    /// Number of public-dummy KDF measurements made by the bounded search.
    measurement_count: u32,
    /// Classification of the selected point relative to the target window.
    outcome: Argon2idCalibrationOutcome,
}

/// Why the bounded Argon2id v1 search selected its reported point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2idCalibrationOutcome {
    /// The selected observation was inside the inclusive target window.
    TargetWindow,
    /// The permitted minimum was already above the target window.
    MinimumAboveWindow,
    /// The selected interior fallback observation was above the window.
    InteriorAboveWindow,
    /// The permitted maximum was selected above the window.
    MaximumAboveWindow,
    /// Every measured point through the permitted maximum was below the window.
    MaximumBelowWindow,
}

impl Argon2idCalibrationOutcome {
    /// Stable report spelling used by the CLI and release evidence tooling.
    #[must_use]
    pub const fn report_name(self) -> &'static str {
        match self {
            Self::TargetWindow => "target-window",
            Self::MinimumAboveWindow => "minimum-above-window",
            Self::InteriorAboveWindow => "interior-above-window",
            Self::MaximumAboveWindow => "maximum-above-window",
            Self::MaximumBelowWindow => "maximum-below-window",
        }
    }
}

impl Argon2idCalibration {
    /// Selected operations and fixed-memory work factors.
    #[must_use]
    pub const fn params(self) -> Argon2idParams {
        self.params
    }

    /// Observed duration used for the selected public-dummy decision point.
    #[must_use]
    pub const fn selected_elapsed(self) -> Duration {
        self.selected_elapsed
    }

    /// Number of public-dummy KDF measurements made by the bounded search.
    #[must_use]
    pub const fn measurement_count(self) -> u32 {
        self.measurement_count
    }

    /// Classification of the selected point relative to the target window.
    #[must_use]
    pub const fn outcome(self) -> Argon2idCalibrationOutcome {
        self.outcome
    }
}

/// Caller-selected validation policy for Argon2id work factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idLimits {
    /// Inclusive minimum operations limit.
    pub min_ops_limit: u64,
    /// Inclusive maximum operations limit.
    pub max_ops_limit: u64,
    /// Inclusive minimum memory limit in bytes.
    pub min_mem_limit_bytes: u64,
    /// Inclusive maximum memory limit in bytes.
    pub max_mem_limit_bytes: u64,
}

impl Argon2idParams {
    /// Validates these parameters against both caller policy and libsodium.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy or primitive bounds are exceeded, or
    /// when libsodium cannot be initialized.
    pub fn validate(self, limits: Argon2idLimits) -> Result<(), SodiumError> {
        validate_range(
            "Argon2id operations limit",
            self.ops_limit,
            limits.min_ops_limit,
            limits.max_ops_limit,
        )?;
        validate_range(
            "Argon2id memory limit",
            self.mem_limit_bytes,
            limits.min_mem_limit_bytes,
            limits.max_mem_limit_bytes,
        )?;

        initialize()?;
        let library_ops_min = u64::from(libsodium_sys::crypto_pwhash_argon2id_OPSLIMIT_MIN);
        let library_memory_min = u64::from(libsodium_sys::crypto_pwhash_argon2id_MEMLIMIT_MIN);
        // SAFETY: These accessors take no pointers, require only initialized
        // libsodium, and return immutable primitive limits.
        let (library_ops_max, library_memory_max) = unsafe {
            (
                libsodium_sys::crypto_pwhash_opslimit_max(),
                libsodium_sys::crypto_pwhash_memlimit_max(),
            )
        };
        let library_ops_max =
            u64::try_from(library_ops_max).map_err(|_| SodiumError::PlatformLimitExceeded {
                field: "Argon2id operations limit",
            })?;
        let library_memory_max =
            u64::try_from(library_memory_max).map_err(|_| SodiumError::PlatformLimitExceeded {
                field: "Argon2id memory limit",
            })?;

        validate_range(
            "Argon2id operations limit",
            self.ops_limit,
            library_ops_min,
            library_ops_max,
        )?;
        validate_range(
            "Argon2id memory limit",
            self.mem_limit_bytes,
            library_memory_min,
            library_memory_max,
        )
    }

    /// Returns whether these costs satisfy the v1 new-vault policy floor.
    #[must_use]
    pub const fn satisfies_new_vault_minimum(self) -> bool {
        self.ops_limit >= MINIMUM_ARGON2ID_PARAMS.ops_limit
            && self.mem_limit_bytes >= MINIMUM_ARGON2ID_PARAMS.mem_limit_bytes
    }
}

impl Argon2idLimits {
    /// Validates that this policy describes nonempty, libsodium-compatible
    /// ranges. Actual parameters still need [`Argon2idParams::validate`].
    ///
    /// # Errors
    ///
    /// Returns an error for inverted ranges, unsupported primitive bounds, or
    /// libsodium initialization failure.
    pub fn validate(self) -> Result<(), SodiumError> {
        if self.min_ops_limit > self.max_ops_limit {
            return Err(SodiumError::InvalidParameter {
                field: "Argon2id minimum operations limit",
                actual: self.min_ops_limit,
                min: 0,
                max: self.max_ops_limit,
            });
        }
        if self.min_mem_limit_bytes > self.max_mem_limit_bytes {
            return Err(SodiumError::InvalidParameter {
                field: "Argon2id minimum memory limit",
                actual: self.min_mem_limit_bytes,
                min: 0,
                max: self.max_mem_limit_bytes,
            });
        }

        Argon2idParams {
            ops_limit: self.min_ops_limit,
            mem_limit_bytes: self.min_mem_limit_bytes,
        }
        .validate(self)?;
        Argon2idParams {
            ops_limit: self.max_ops_limit,
            mem_limit_bytes: self.max_mem_limit_bytes,
        }
        .validate(self)
    }
}

/// Best-effort operating-system health of a secure allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureMemoryHealth {
    /// `true` when an explicit `sodium_mlock` probe succeeded.
    pub memory_locked: bool,
    /// `true` when `sodium_mprotect_*` transitions are available.
    pub page_protection: bool,
}

impl SecureMemoryHealth {
    /// Returns whether both page locking and no-access guards are active.
    #[must_use]
    pub const fn fully_hardened(self) -> bool {
        self.memory_locked && self.page_protection
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessState {
    NoAccess,
    ReadOnly,
    ReadWrite,
    Faulted,
}

/// Fixed-size secret bytes backed by `sodium_malloc`.
///
/// This type intentionally implements neither `Clone` nor serialization.
/// Debug formatting is redacted. The allocation is moved between threads but
/// is not shareable without an external mutex, preventing overlapping page
/// protection transitions.
pub struct LockedBytes<const N: usize> {
    ptr: NonNull<u8>,
    health: SecureMemoryHealth,
    state: Cell<AccessState>,
}

impl<const N: usize> LockedBytes<N> {
    /// Allocates a zeroed protected region.
    ///
    /// # Errors
    ///
    /// Returns an error when `N` is zero, libsodium initialization fails, or
    /// the secure allocation cannot be created.
    pub fn new() -> Result<Self, SodiumError> {
        initialize()?;
        if N == 0 {
            return Err(SodiumError::InvalidLength {
                field: "secure allocation",
                actual: 0,
                min: 1,
                max: usize::MAX,
            });
        }

        // SAFETY: libsodium is initialized, `N` is nonzero and the returned
        // pointer is checked for null before it is stored.
        let raw = unsafe { libsodium_sys::sodium_malloc(N) }.cast::<u8>();
        let ptr = NonNull::new(raw).ok_or(SodiumError::AllocationFailed)?;

        // `sodium_malloc` already attempts page locking, but does not surface
        // failure. This explicit probe records whether the user byte range is
        // locked so strict callers can fail closed.
        // SAFETY: `ptr` names a live writable allocation of exactly `N` user
        // bytes returned by `sodium_malloc`.
        let memory_locked = unsafe { libsodium_sys::sodium_mlock(ptr.as_ptr().cast(), N) == 0 };

        // SAFETY: the allocation is writable and valid for `N` bytes.
        unsafe { libsodium_sys::sodium_memzero(ptr.as_ptr().cast(), N) };

        // SAFETY: the pointer came directly from `sodium_malloc`, as required
        // by the `sodium_mprotect_*` family.
        let page_protection =
            unsafe { libsodium_sys::sodium_mprotect_noaccess(ptr.as_ptr().cast()) == 0 };

        Ok(Self {
            ptr,
            health: SecureMemoryHealth {
                memory_locked,
                page_protection,
            },
            state: Cell::new(AccessState::NoAccess),
        })
    }

    /// Allocates secure bytes and fails if page locking was unavailable.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::new`] or [`SodiumError::MemoryLockRequired`].
    pub fn new_strict() -> Result<Self, SodiumError> {
        let value = Self::new()?;
        if value.health.memory_locked {
            Ok(value)
        } else {
            Err(SodiumError::MemoryLockRequired)
        }
    }

    /// Copies an exact-length byte slice into a protected allocation.
    ///
    /// # Errors
    ///
    /// Returns an error for a length mismatch, allocation failure, or memory
    /// protection transition failure.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SodiumError> {
        if bytes.len() != N {
            return Err(SodiumError::InvalidLength {
                field: "secret",
                actual: bytes.len(),
                min: N,
                max: N,
            });
        }
        let mut value = Self::new()?;
        value.with_write(|destination| destination.copy_from_slice(bytes))?;
        Ok(value)
    }

    /// Moves an array into protected memory and wipes the Rust-owned source.
    ///
    /// # Errors
    ///
    /// Returns an error when secure allocation or a protection transition fails.
    pub fn from_array(mut bytes: [u8; N]) -> Result<Self, SodiumError> {
        let result = Self::from_slice(&bytes);
        bytes.zeroize();
        result
    }

    /// Creates a protected allocation filled from libsodium's CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error when secure allocation or a protection transition fails.
    pub fn random() -> Result<Self, SodiumError> {
        let mut value = Self::new()?;
        value.with_write(|bytes| {
            // SAFETY: `bytes` is a live writable `N`-byte region. Libsodium is
            // initialized by `Self::new`.
            unsafe { libsodium_sys::randombytes_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
        })?;
        Ok(value)
    }

    /// Reports whether the OS page-lock and page-protection defenses succeeded.
    #[must_use]
    pub const fn health(&self) -> SecureMemoryHealth {
        self.health
    }

    /// Runs a closure while the secret region is read-only.
    ///
    /// The higher-ranked closure bound prevents returning a reference into the
    /// allocation after it has transitioned back to `noaccess`.
    ///
    /// # Errors
    ///
    /// Returns an error for nested access or a failed protection transition.
    pub fn with_read<R, F>(&self, operation: F) -> Result<R, SodiumError>
    where
        F: for<'a> FnOnce(&'a [u8; N]) -> R,
    {
        let ptr = self.ptr;
        let guard = self.begin_access(AccessState::ReadOnly)?;
        // SAFETY: the guard made the live `N`-byte allocation readable, and
        // the reference cannot escape due to the higher-ranked closure bound.
        let result = unsafe { operation(&*ptr.as_ptr().cast::<[u8; N]>()) };
        guard.restore()?;
        Ok(result)
    }

    /// Runs a closure while the secret region is readable and writable.
    ///
    /// The higher-ranked closure bound prevents returning a reference into the
    /// allocation after it has transitioned back to `noaccess`.
    ///
    /// # Errors
    ///
    /// Returns an error for nested access or a failed protection transition.
    pub fn with_write<R, F>(&mut self, operation: F) -> Result<R, SodiumError>
    where
        F: for<'a> FnOnce(&'a mut [u8; N]) -> R,
    {
        let ptr = self.ptr;
        let guard = self.begin_access(AccessState::ReadWrite)?;
        // SAFETY: `&mut self` guarantees unique access, the guard made the live
        // `N`-byte allocation writable, and the reference cannot escape the
        // higher-ranked closure.
        let result = unsafe { operation(&mut *ptr.as_ptr().cast::<[u8; N]>()) };
        guard.restore()?;
        Ok(result)
    }

    /// Explicitly wipes the secret while retaining the allocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected allocation cannot be made writable
    /// or restored to `noaccess`.
    pub fn try_zeroize(&mut self) -> Result<(), SodiumError> {
        self.with_write(Zeroize::zeroize)
    }

    fn begin_access(&self, requested: AccessState) -> Result<AccessGuard<'_>, SodiumError> {
        match self.state.get() {
            AccessState::NoAccess => {}
            AccessState::Faulted => return Err(SodiumError::SecureMemoryFaulted),
            AccessState::ReadOnly | AccessState::ReadWrite => {
                return Err(SodiumError::SecureMemoryBusy);
            }
        }

        if self.health.page_protection {
            // SAFETY: the pointer came directly from `sodium_malloc`. Calls are
            // serialized by the access state and `LockedBytes` is not `Sync`.
            let result = unsafe {
                match requested {
                    AccessState::ReadOnly => {
                        libsodium_sys::sodium_mprotect_readonly(self.ptr.as_ptr().cast())
                    }
                    AccessState::ReadWrite => {
                        libsodium_sys::sodium_mprotect_readwrite(self.ptr.as_ptr().cast())
                    }
                    AccessState::NoAccess | AccessState::Faulted => -1,
                }
            };
            if result != 0 {
                self.state.set(AccessState::Faulted);
                return Err(SodiumError::MemoryProtectionFailed {
                    operation: "access transition",
                });
            }
        }

        self.state.set(requested);
        Ok(AccessGuard {
            ptr: self.ptr,
            page_protection: self.health.page_protection,
            state: &self.state,
            armed: true,
        })
    }
}

impl<const N: usize> fmt::Debug for LockedBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LockedBytes")
            .field("length", &N)
            .field("contents", &"<redacted>")
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> Zeroize for LockedBytes<N> {
    fn zeroize(&mut self) {
        let _result = self.try_zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for LockedBytes<N> {}

impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        let writable = if self.health.page_protection {
            // SAFETY: the pointer came from `sodium_malloc` and remains live
            // until the `sodium_free` call below. Drop has unique ownership.
            unsafe { libsodium_sys::sodium_mprotect_readwrite(self.ptr.as_ptr().cast()) == 0 }
        } else {
            true
        };

        if writable {
            // SAFETY: the allocation is writable and valid for `N` bytes.
            unsafe { libsodium_sys::sodium_memzero(self.ptr.as_ptr().cast(), N) };
        }

        // SAFETY: this is the unique original pointer returned by
        // `sodium_malloc`. `sodium_free` also changes protections, wipes the
        // full allocation, unlocks it, checks canaries, and releases it.
        unsafe { libsodium_sys::sodium_free(self.ptr.as_ptr().cast()) };
    }
}

// SAFETY: ownership of the unique sodium allocation moves with the value. The
// type is deliberately not `Sync` (`Cell` enforces this), so protection changes
// and access to the pointed-to bytes cannot overlap across threads.
unsafe impl<const N: usize> Send for LockedBytes<N> {}

struct AccessGuard<'a> {
    ptr: NonNull<u8>,
    page_protection: bool,
    state: &'a Cell<AccessState>,
    armed: bool,
}

impl AccessGuard<'_> {
    fn restore(mut self) -> Result<(), SodiumError> {
        let result = self.restore_inner();
        self.armed = false;
        result
    }

    fn restore_inner(&self) -> Result<(), SodiumError> {
        if self.page_protection {
            // SAFETY: the pointer came from `sodium_malloc` and the guard owns
            // the sole active protection transition for this allocation.
            let result =
                unsafe { libsodium_sys::sodium_mprotect_noaccess(self.ptr.as_ptr().cast()) };
            if result != 0 {
                self.state.set(AccessState::Faulted);
                return Err(SodiumError::MemoryProtectionFailed {
                    operation: "noaccess restore",
                });
            }
        }
        self.state.set(AccessState::NoAccess);
        Ok(())
    }
}

impl Drop for AccessGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _result = self.restore_inner();
        }
    }
}

/// Initializes libsodium exactly once for this process.
///
/// # Errors
///
/// Returns an error if libsodium cannot initialize or if the linked runtime is
/// not the exact reviewed, non-minimal release.
pub fn initialize() -> Result<(), SodiumError> {
    initialized_runtime().map(|_| ())
}

fn initialized_runtime() -> Result<SodiumVersion, SodiumError> {
    SODIUM_INIT
        .get_or_init(|| {
            // SAFETY: `sodium_init` takes no pointers and is documented as
            // thread-safe. `OnceLock` additionally calls it only once here.
            let result = unsafe { libsodium_sys::sodium_init() };
            if result < 0 {
                return Err(SodiumError::InitializationFailed);
            }

            runtime_version_after_initialization()
        })
        .clone()
}

fn runtime_version_after_initialization() -> Result<SodiumVersion, SodiumError> {
    // SAFETY: initialized libsodium returns a process-lifetime NUL-terminated
    // version string, or null on an invalid library build (checked below).
    let raw_version = unsafe { libsodium_sys::sodium_version_string() };
    if raw_version.is_null() {
        return Err(SodiumError::InvalidVersionString);
    }
    // SAFETY: the non-null pointer is guaranteed by libsodium to reference a
    // process-lifetime NUL-terminated string.
    let version = unsafe { CStr::from_ptr(raw_version) }
        .to_str()
        .map_err(|_| SodiumError::InvalidVersionString)?
        .to_owned();

    // SAFETY: these accessors take no pointers and return immutable build/ABI
    // metadata after initialization.
    let (library_major, library_minor, minimal) = unsafe {
        (
            libsodium_sys::sodium_library_version_major(),
            libsodium_sys::sodium_library_version_minor(),
            libsodium_sys::sodium_library_minimal() != 0,
        )
    };
    let version = SodiumVersion {
        version,
        library_major,
        library_minor,
        minimal,
    };
    if version.version != EXPECTED_LIBSODIUM_VERSION
        || version.library_major != EXPECTED_LIBSODIUM_LIBRARY_MAJOR
        || version.library_minor != EXPECTED_LIBSODIUM_LIBRARY_MINOR
        || version.minimal
    {
        return Err(SodiumError::UnexpectedRuntimeVersion);
    }
    Ok(version)
}

/// Returns runtime version details for diagnostics and release manifests.
///
/// # Errors
///
/// Returns an error when libsodium cannot initialize or does not match the
/// exact reviewed, non-minimal runtime.
pub fn version() -> Result<SodiumVersion, SodiumError> {
    initialized_runtime()
}

/// Fills a caller-owned buffer from libsodium's CSPRNG.
///
/// # Errors
///
/// Returns an error if libsodium cannot initialize or does not match the exact
/// reviewed runtime.
pub fn random_bytes(output: &mut [u8]) -> Result<(), SodiumError> {
    initialize()?;
    if output.is_empty() {
        return Ok(());
    }
    // SAFETY: `output` is a live writable region of `output.len()` bytes.
    unsafe { libsodium_sys::randombytes_buf(output.as_mut_ptr().cast(), output.len()) };
    Ok(())
}

/// Returns a fixed-size array filled from libsodium's CSPRNG.
///
/// # Errors
///
/// Returns an error if the exact reviewed libsodium runtime cannot be established.
pub fn random_array<const N: usize>() -> Result<[u8; N], SodiumError> {
    let mut output = [0_u8; N];
    random_bytes(&mut output)?;
    Ok(output)
}

/// Derives a 32-byte KEK using explicit Argon2id version 1.3.
///
/// This never uses libsodium's mutable `ALG_DEFAULT`. Callers choose a policy
/// so untrusted metadata is bounded before the expensive allocation begins.
///
/// # Errors
///
/// Returns an error for invalid password length or resource parameters,
/// initialization/allocation failure, or an unsuccessful Argon2id operation.
pub fn derive_kek_argon2id13(
    password: &[u8],
    salt: &[u8; ARGON2ID_SALT_BYTES],
    params: Argon2idParams,
    limits: Argon2idLimits,
) -> Result<LockedBytes<KEY_BYTES>, SodiumError> {
    validate_length(
        "password",
        password.len(),
        MIN_PASSWORD_BYTES,
        MAX_PASSWORD_BYTES,
    )?;
    limits.validate()?;
    params.validate(limits)?;
    let password_len =
        u64::try_from(password.len()).map_err(|_| SodiumError::PlatformLimitExceeded {
            field: "password length",
        })?;
    let memory_limit = usize::try_from(params.mem_limit_bytes).map_err(|_| {
        SodiumError::PlatformLimitExceeded {
            field: "Argon2id memory limit",
        }
    })?;

    let mut output = LockedBytes::<KEY_BYTES>::new()?;
    let status = output.with_write(|destination| {
        // SAFETY: all pointers reference live buffers of the exact validated
        // lengths. The output is 32 bytes, the salt is 16 bytes, integer
        // conversions were checked, and the algorithm id is explicitly
        // Argon2id13 rather than `ALG_DEFAULT`.
        unsafe {
            libsodium_sys::crypto_pwhash(
                destination.as_mut_ptr(),
                KEY_BYTES as u64,
                password.as_ptr().cast(),
                password_len,
                salt.as_ptr(),
                params.ops_limit,
                memory_limit,
                libsodium_sys::crypto_pwhash_ALG_ARGON2ID13.cast_signed(),
            )
        }
    })?;
    if status == 0 {
        Ok(output)
    } else {
        Err(SodiumError::PasswordHashFailed)
    }
}

/// Return the process-cached public evidence for v1 creation calibration.
///
/// The only measured input is a fixed, public dummy password and salt. The
/// result (including a calibration failure) is initialized at most once per
/// process. No caller password is observed by the timing loop.
pub(crate) fn calibrated_argon2id_calibration() -> Result<Argon2idCalibration, SodiumError> {
    ARGON2ID_CALIBRATION.get_or_init(calibrate_argon2id).clone()
}

fn calibrate_argon2id() -> Result<Argon2idCalibration, SodiumError> {
    calibrate_argon2id_calibration_in_range(
        V1_ARGON2ID_CALIBRATION_MIN_OPS_LIMIT,
        V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT,
    )
}

pub(crate) fn calibrate_argon2id_calibration_in_range(
    min_ops_limit: u64,
    max_ops_limit: u64,
) -> Result<Argon2idCalibration, SodiumError> {
    const DUMMY_PASSWORD: &[u8] = b"Inex Argon2id calibration";
    const DUMMY_SALT: [u8; ARGON2ID_SALT_BYTES] = *b"INEX-CALIB-V1!!!";

    let limits = Argon2idLimits {
        min_ops_limit,
        max_ops_limit,
        min_mem_limit_bytes: V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES,
        max_mem_limit_bytes: V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES,
    };
    calibrate_argon2id_calibration_with(min_ops_limit, max_ops_limit, |params| {
        let started = Instant::now();
        let derived = derive_kek_argon2id13(DUMMY_PASSWORD, &DUMMY_SALT, params, limits)?;
        let elapsed = started.elapsed();
        drop(derived);
        Ok(elapsed)
    })
}

/// Select calibrated v1 parameters using an injected duration measurement.
///
/// The search assumes KDF time is broadly monotonic in `opslimit`, but remains
/// bounded even under noisy measurements. It prefers any measured point in the
/// 250--750 ms window. If the complete permitted range is too fast it selects
/// its maximum; if the minimum is already slow it selects that minimum. When a
/// discrete step jumps over the complete window, the first measured point at
/// or above the lower target is retained rather than weakening below 250 ms.
#[cfg(test)]
pub(crate) fn calibrate_argon2id_params_with(
    min_ops_limit: u64,
    max_ops_limit: u64,
    measure: impl FnMut(Argon2idParams) -> Result<Duration, SodiumError>,
) -> Result<Argon2idParams, SodiumError> {
    Ok(calibrate_argon2id_calibration_with(min_ops_limit, max_ops_limit, measure)?.params)
}

pub(crate) fn calibrate_argon2id_calibration_with(
    min_ops_limit: u64,
    max_ops_limit: u64,
    mut measure: impl FnMut(Argon2idParams) -> Result<Duration, SodiumError>,
) -> Result<Argon2idCalibration, SodiumError> {
    validate_range(
        "Argon2id calibration minimum operations limit",
        min_ops_limit,
        V1_ARGON2ID_CALIBRATION_MIN_OPS_LIMIT,
        V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT,
    )?;
    validate_range(
        "Argon2id calibration maximum operations limit",
        max_ops_limit,
        min_ops_limit,
        V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT,
    )?;

    let minimum = Argon2idParams {
        ops_limit: min_ops_limit,
        mem_limit_bytes: V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES,
    };
    let minimum_elapsed = measure(minimum)?;
    let mut measurement_count = 1;
    if minimum_elapsed >= V1_ARGON2ID_CALIBRATION_TARGET_MIN {
        let outcome = if minimum_elapsed <= V1_ARGON2ID_CALIBRATION_TARGET_MAX {
            Argon2idCalibrationOutcome::TargetWindow
        } else {
            Argon2idCalibrationOutcome::MinimumAboveWindow
        };
        return Ok(Argon2idCalibration {
            params: minimum,
            selected_elapsed: minimum_elapsed,
            measurement_count,
            outcome,
        });
    }

    let mut low = min_ops_limit + 1;
    let mut high = max_ops_limit;
    let mut lowest_measured_above_window = None;
    let mut last_below_window = (minimum, minimum_elapsed);
    while low <= high {
        let ops_limit = low + (high - low) / 2;
        let params = Argon2idParams {
            ops_limit,
            mem_limit_bytes: V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES,
        };
        let elapsed = measure(params)?;
        measurement_count += 1;
        if elapsed < V1_ARGON2ID_CALIBRATION_TARGET_MIN {
            last_below_window = (params, elapsed);
            low = ops_limit + 1;
        } else if elapsed <= V1_ARGON2ID_CALIBRATION_TARGET_MAX {
            return Ok(Argon2idCalibration {
                params,
                selected_elapsed: elapsed,
                measurement_count,
                outcome: Argon2idCalibrationOutcome::TargetWindow,
            });
        } else {
            lowest_measured_above_window = Some((params, elapsed));
            high = ops_limit - 1;
        }
    }

    let (params, selected_elapsed, outcome) = lowest_measured_above_window.map_or_else(
        || {
            let (params, elapsed) = last_below_window;
            (
                params,
                elapsed,
                Argon2idCalibrationOutcome::MaximumBelowWindow,
            )
        },
        |(params, elapsed)| {
            let outcome = if params.ops_limit == max_ops_limit {
                Argon2idCalibrationOutcome::MaximumAboveWindow
            } else {
                Argon2idCalibrationOutcome::InteriorAboveWindow
            };
            (params, elapsed, outcome)
        },
    );
    Ok(Argon2idCalibration {
        params,
        selected_elapsed,
        measurement_count,
        outcome,
    })
}

/// Encrypts a message in libsodium's combined XChaCha20-Poly1305-IETF mode.
///
/// # Errors
///
/// Returns an error for oversized input, initialization failure, or an
/// unsuccessful encryption operation.
pub fn xchacha20poly1305_encrypt(
    plaintext: &[u8],
    associated_data: &[u8],
    nonce: &[u8; XCHACHA20_NONCE_BYTES],
    key: &[u8; KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, SodiumError> {
    initialize()?;
    validate_length(
        "AEAD plaintext",
        plaintext.len(),
        0,
        MAX_AEAD_PLAINTEXT_BYTES,
    )?;
    validate_length(
        "AEAD associated data",
        associated_data.len(),
        0,
        MAX_AEAD_ASSOCIATED_DATA_BYTES,
    )?;
    let output_len = plaintext.len().checked_add(XCHACHA20_TAG_BYTES).ok_or(
        SodiumError::PlatformLimitExceeded {
            field: "AEAD ciphertext length",
        },
    )?;
    let plaintext_len = usize_to_u64(plaintext.len(), "AEAD plaintext length")?;
    let associated_data_len = usize_to_u64(associated_data.len(), "AEAD associated data length")?;
    let mut output = Zeroizing::new(vec![0_u8; output_len]);
    let mut actual_len = 0_u64;

    // SAFETY: output capacity includes the fixed authentication tag; all input
    // pointers and exact key/nonce arrays remain live for the call; both input
    // lengths were checked before conversion to C's `unsigned long long`.
    let status = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
            output.as_mut_ptr(),
            &raw mut actual_len,
            plaintext.as_ptr(),
            plaintext_len,
            associated_data.as_ptr(),
            associated_data_len,
            ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if status != 0 {
        output.zeroize();
        return Err(SodiumError::EncryptionFailed);
    }
    if actual_len != usize_to_u64(output_len, "AEAD ciphertext length")? {
        output.zeroize();
        return Err(SodiumError::InvalidOutputLength {
            operation: "XChaCha20-Poly1305 encryption",
        });
    }
    Ok(output)
}

/// Decrypts and authenticates combined XChaCha20-Poly1305-IETF ciphertext.
///
/// Authentication failure returns no partial plaintext and wipes the temporary
/// Rust allocation before returning.
///
/// # Errors
///
/// Returns an error for invalid input length, initialization failure,
/// authentication failure, or an invalid primitive output length.
pub fn xchacha20poly1305_decrypt(
    ciphertext: &[u8],
    associated_data: &[u8],
    nonce: &[u8; XCHACHA20_NONCE_BYTES],
    key: &[u8; KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, SodiumError> {
    initialize()?;
    validate_length(
        "AEAD ciphertext",
        ciphertext.len(),
        XCHACHA20_TAG_BYTES,
        MAX_AEAD_PLAINTEXT_BYTES + XCHACHA20_TAG_BYTES,
    )?;
    validate_length(
        "AEAD associated data",
        associated_data.len(),
        0,
        MAX_AEAD_ASSOCIATED_DATA_BYTES,
    )?;
    let output_len = ciphertext.len() - XCHACHA20_TAG_BYTES;
    let ciphertext_len = usize_to_u64(ciphertext.len(), "AEAD ciphertext length")?;
    let associated_data_len = usize_to_u64(associated_data.len(), "AEAD associated data length")?;
    let mut output = Zeroizing::new(vec![0_u8; output_len]);
    let mut actual_len = 0_u64;

    // SAFETY: output has the exact maximum plaintext size for combined mode;
    // all pointers and fixed-size key/nonce arrays remain live for the call;
    // both lengths were checked before conversion.
    let status = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
            output.as_mut_ptr(),
            &raw mut actual_len,
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext_len,
            associated_data.as_ptr(),
            associated_data_len,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    if status != 0 {
        output.zeroize();
        return Err(SodiumError::AuthenticationFailed);
    }
    if actual_len != usize_to_u64(output_len, "AEAD plaintext length")? {
        output.zeroize();
        return Err(SodiumError::InvalidOutputLength {
            operation: "XChaCha20-Poly1305 decryption",
        });
    }
    Ok(output)
}

/// Computes unkeyed `BLAKE2b` with a fixed 32-byte output.
///
/// # Errors
///
/// Returns an error for oversized input, initialization failure, or a hashing
/// operation failure.
pub fn blake2b_256(input: &[u8]) -> Result<[u8; KEY_BYTES], SodiumError> {
    blake2b_256_inner(input, None)
}

/// Computes keyed `BLAKE2b` with a fixed 32-byte output.
///
/// # Errors
///
/// Returns an error for an invalid key or input length, initialization failure,
/// or a hashing operation failure.
pub fn blake2b_256_keyed(key: &[u8], input: &[u8]) -> Result<[u8; KEY_BYTES], SodiumError> {
    validate_length(
        "BLAKE2b key",
        key.len(),
        libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MIN as usize,
        libsodium_sys::crypto_generichash_blake2b_KEYBYTES_MAX as usize,
    )?;
    blake2b_256_inner(input, Some(key))
}

fn blake2b_256_inner(input: &[u8], key: Option<&[u8]>) -> Result<[u8; KEY_BYTES], SodiumError> {
    initialize()?;
    validate_length("BLAKE2b input", input.len(), 0, MAX_BLAKE2B_INPUT_BYTES)?;
    let input_len = usize_to_u64(input.len(), "BLAKE2b input length")?;
    let (key_ptr, key_len) = key.map_or((ptr::null(), 0), |value| (value.as_ptr(), value.len()));
    let mut output = [0_u8; KEY_BYTES];

    // SAFETY: the output array is exactly 32 bytes, input and optional key
    // pointers remain live for their checked lengths, and null/zero is the
    // documented representation of unkeyed BLAKE2b.
    let status = unsafe {
        libsodium_sys::crypto_generichash_blake2b(
            output.as_mut_ptr(),
            output.len(),
            input.as_ptr(),
            input_len,
            key_ptr,
            key_len,
        )
    };
    if status == 0 {
        Ok(output)
    } else {
        output.zeroize();
        Err(SodiumError::HashFailed)
    }
}

/// Compares equal-length byte strings in constant time.
///
/// Length itself is not treated as secret; different lengths return `false`
/// without reading either buffer.
///
/// # Errors
///
/// Returns an error if the exact reviewed libsodium runtime cannot be established.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> Result<bool, SodiumError> {
    initialize()?;
    if left.len() != right.len() {
        return Ok(false);
    }
    if left.is_empty() {
        return Ok(true);
    }
    // SAFETY: both pointers are valid for the same nonzero byte length.
    Ok(unsafe {
        libsodium_sys::sodium_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) == 0
    })
}

fn validate_length(
    field: &'static str,
    actual: usize,
    min: usize,
    max: usize,
) -> Result<(), SodiumError> {
    if (min..=max).contains(&actual) {
        Ok(())
    } else {
        Err(SodiumError::InvalidLength {
            field,
            actual,
            min,
            max,
        })
    }
}

fn validate_range(field: &'static str, actual: u64, min: u64, max: u64) -> Result<(), SodiumError> {
    if min <= max && (min..=max).contains(&actual) {
        Ok(())
    } else {
        Err(SodiumError::InvalidParameter {
            field,
            actual,
            min,
            max,
        })
    }
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, SodiumError> {
    u64::try_from(value).map_err(|_| SodiumError::PlatformLimitExceeded { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_and_reports_pinned_runtime_version() -> Result<(), SodiumError> {
        initialize()?;
        initialize()?;
        let runtime = version()?;
        assert_eq!(runtime.version, EXPECTED_LIBSODIUM_VERSION);
        assert_eq!(runtime.library_major, EXPECTED_LIBSODIUM_LIBRARY_MAJOR);
        assert_eq!(runtime.library_minor, EXPECTED_LIBSODIUM_LIBRARY_MINOR);
        assert!(!runtime.minimal);
        Ok(())
    }

    #[test]
    fn random_arrays_are_filled_independently() -> Result<(), SodiumError> {
        let first = random_array::<32>()?;
        let second = random_array::<32>()?;
        assert!(!constant_time_eq(&first, &second)?);
        Ok(())
    }

    #[test]
    fn locked_bytes_scope_access_and_redact_debug() -> Result<(), SodiumError> {
        let secret = [0x5a_u8; KEY_BYTES];
        let mut locked = LockedBytes::from_slice(&secret)?;
        let observed = locked.with_read(|bytes| *bytes)?;
        assert_eq!(observed, secret);

        locked.with_write(|bytes| bytes[0] = 0xa5)?;
        assert_eq!(locked.with_read(|bytes| bytes[0])?, 0xa5);
        let debug = format!("{locked:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("5a5a"));
        let _health = locked.health();

        locked.try_zeroize()?;
        assert!(locked.with_read(|bytes| bytes.iter().all(|byte| *byte == 0))?);
        Ok(())
    }

    #[test]
    fn argon2id13_derives_deterministic_kek_with_test_cost() -> Result<(), SodiumError> {
        let params = Argon2idParams {
            ops_limit: 1,
            mem_limit_bytes: 8 * 1024,
        };
        let limits = Argon2idLimits {
            min_ops_limit: 1,
            max_ops_limit: 2,
            min_mem_limit_bytes: 8 * 1024,
            max_mem_limit_bytes: 64 * 1024,
        };
        let salt = [0x11_u8; ARGON2ID_SALT_BYTES];
        let first = derive_kek_argon2id13(b"test password", &salt, params, limits)?;
        let second = derive_kek_argon2id13(b"test password", &salt, params, limits)?;
        let equal = first
            .with_read(|left| second.with_read(|right| constant_time_eq(left, right)))???;
        assert!(equal);
        assert!(!params.satisfies_new_vault_minimum());
        assert!(MINIMUM_ARGON2ID_PARAMS.satisfies_new_vault_minimum());
        Ok(())
    }

    #[test]
    fn argon2id_rejects_password_and_resource_policy_violations() {
        let salt = [0_u8; ARGON2ID_SALT_BYTES];
        let empty = derive_kek_argon2id13(
            b"",
            &salt,
            MINIMUM_ARGON2ID_PARAMS,
            VAULT_ARGON2ID_READER_LIMITS,
        );
        assert!(matches!(empty, Err(SodiumError::InvalidLength { .. })));

        let excessive = derive_kek_argon2id13(
            b"password",
            &salt,
            Argon2idParams {
                ops_limit: 21,
                mem_limit_bytes: 64 * 1024 * 1024,
            },
            VAULT_ARGON2ID_READER_LIMITS,
        );
        assert!(matches!(
            excessive,
            Err(SodiumError::InvalidParameter { .. })
        ));
    }

    #[test]
    fn argon2id_calibration_selects_a_measured_point_in_target_window() {
        let mut measured = Vec::new();
        let selected = calibrate_argon2id_params_with(3, 20, |params| {
            measured.push(params);
            Ok(Duration::from_millis(params.ops_limit * 30))
        })
        .expect("synthetic calibration succeeds");

        assert_eq!(selected.ops_limit, 12);
        assert_eq!(selected.mem_limit_bytes, 64 * 1024 * 1024);
        assert_eq!(
            measured
                .iter()
                .map(|params| params.ops_limit)
                .collect::<Vec<_>>(),
            vec![3, 12]
        );
        assert!(
            measured.iter().all(|params| {
                params.mem_limit_bytes == V1_ARGON2ID_CALIBRATION_MEM_LIMIT_BYTES
            })
        );
    }

    #[test]
    fn argon2id_calibration_has_deterministic_fast_slow_and_gap_fallbacks() {
        let too_fast = calibrate_argon2id_params_with(3, 20, |params| {
            Ok(Duration::from_millis(params.ops_limit * 5))
        })
        .expect("synthetic fast calibration succeeds");
        assert_eq!(too_fast.ops_limit, 20);

        let mut slow_measurements = 0;
        let too_slow = calibrate_argon2id_params_with(3, 20, |_| {
            slow_measurements += 1;
            Ok(Duration::from_millis(900))
        })
        .expect("synthetic slow calibration succeeds");
        assert_eq!(too_slow.ops_limit, 3);
        assert_eq!(slow_measurements, 1);

        let mut gap_ops = Vec::new();
        let gap = calibrate_argon2id_params_with(3, 20, |params| {
            gap_ops.push(params.ops_limit);
            if params.ops_limit <= 5 {
                Ok(Duration::from_millis(100))
            } else {
                Ok(Duration::from_millis(900))
            }
        })
        .expect("synthetic gap calibration succeeds");
        assert_eq!(gap.ops_limit, 6);
        assert_eq!(gap_ops, vec![3, 12, 7, 5, 6]);
    }

    #[test]
    fn argon2id_calibration_evidence_preserves_selected_observation_and_outcome() {
        let target = calibrate_argon2id_calibration_with(3, 20, |params| {
            Ok(Duration::from_millis(params.ops_limit * 30))
        })
        .expect("synthetic target-window calibration succeeds");
        assert_eq!(target.params().ops_limit, 12);
        assert_eq!(target.selected_elapsed(), Duration::from_millis(360));
        assert_eq!(target.measurement_count(), 2);
        assert_eq!(target.outcome(), Argon2idCalibrationOutcome::TargetWindow);

        let minimum_above =
            calibrate_argon2id_calibration_with(3, 20, |_| Ok(Duration::from_millis(900)))
                .expect("synthetic minimum-above calibration succeeds");
        assert_eq!(minimum_above.params().ops_limit, 3);
        assert_eq!(minimum_above.selected_elapsed(), Duration::from_millis(900));
        assert_eq!(minimum_above.measurement_count(), 1);
        assert_eq!(
            minimum_above.outcome(),
            Argon2idCalibrationOutcome::MinimumAboveWindow
        );

        let maximum_below =
            calibrate_argon2id_calibration_with(3, 20, |_| Ok(Duration::from_millis(100)))
                .expect("synthetic maximum-below calibration succeeds");
        assert_eq!(maximum_below.params().ops_limit, 20);
        assert_eq!(maximum_below.selected_elapsed(), Duration::from_millis(100));
        assert_eq!(maximum_below.measurement_count(), 6);
        assert_eq!(
            maximum_below.outcome(),
            Argon2idCalibrationOutcome::MaximumBelowWindow
        );

        let maximum_above = calibrate_argon2id_calibration_with(3, 20, |params| {
            Ok(if params.ops_limit == 20 {
                Duration::from_millis(900)
            } else {
                Duration::from_millis(100)
            })
        })
        .expect("synthetic maximum-above calibration succeeds");
        assert_eq!(maximum_above.params().ops_limit, 20);
        assert_eq!(maximum_above.selected_elapsed(), Duration::from_millis(900));
        assert_eq!(maximum_above.measurement_count(), 6);
        assert_eq!(
            maximum_above.outcome(),
            Argon2idCalibrationOutcome::MaximumAboveWindow
        );

        let interior_above = calibrate_argon2id_calibration_with(3, 20, |params| {
            Ok(if params.ops_limit <= 5 {
                Duration::from_millis(100)
            } else {
                Duration::from_millis(900)
            })
        })
        .expect("synthetic interior-above calibration succeeds");
        assert_eq!(interior_above.params().ops_limit, 6);
        assert_eq!(
            interior_above.selected_elapsed(),
            Duration::from_millis(900)
        );
        assert_eq!(interior_above.measurement_count(), 5);
        assert_eq!(
            interior_above.outcome(),
            Argon2idCalibrationOutcome::InteriorAboveWindow
        );
    }

    #[test]
    fn argon2id_calibration_target_window_is_inclusive() {
        for elapsed in [
            V1_ARGON2ID_CALIBRATION_TARGET_MIN,
            V1_ARGON2ID_CALIBRATION_TARGET_MAX,
        ] {
            let evidence = calibrate_argon2id_calibration_with(3, 20, |_| Ok(elapsed))
                .expect("target boundary calibration succeeds");
            assert_eq!(evidence.params().ops_limit, 3);
            assert_eq!(evidence.selected_elapsed(), elapsed);
            assert_eq!(evidence.measurement_count(), 1);
            assert_eq!(evidence.outcome(), Argon2idCalibrationOutcome::TargetWindow);
        }
    }

    #[test]
    fn argon2id_calibration_preserves_the_selected_observation_under_noisy_timings() {
        let mut measured = Vec::new();
        let evidence = calibrate_argon2id_calibration_with(3, 20, |params| {
            measured.push(params.ops_limit);
            Ok(Duration::from_millis(match params.ops_limit {
                3 => 100,
                7 => 200,
                8 => 150,
                9 => 1_000,
                12 => 900,
                other => panic!("unexpected synthetic measurement at ops {other}"),
            }))
        })
        .expect("bounded calibration tolerates noisy observations");

        assert_eq!(measured, vec![3, 12, 7, 9, 8]);
        assert_eq!(evidence.params().ops_limit, 9);
        assert_eq!(evidence.selected_elapsed(), Duration::from_secs(1));
        assert_eq!(evidence.measurement_count(), 5);
        assert_eq!(
            evidence.outcome(),
            Argon2idCalibrationOutcome::InteriorAboveWindow
        );
    }

    #[test]
    fn argon2id_calibration_does_not_infer_unmeasured_nonmonotonic_candidates() {
        let mut measured = Vec::new();
        let evidence = calibrate_argon2id_calibration_with(3, 20, |params| {
            measured.push(params.ops_limit);
            Ok(if params.ops_limit == 4 {
                Duration::from_millis(500)
            } else {
                Duration::from_millis(100)
            })
        })
        .expect("bounded calibration classifies only measured observations");

        assert_eq!(measured, vec![3, 12, 16, 18, 19, 20]);
        assert!(!measured.contains(&4));
        assert_eq!(evidence.params().ops_limit, 20);
        assert_eq!(evidence.selected_elapsed(), Duration::from_millis(100));
        assert_eq!(evidence.measurement_count(), 6);
        assert_eq!(
            evidence.outcome(),
            Argon2idCalibrationOutcome::MaximumBelowWindow
        );
    }

    #[test]
    fn argon2id_calibration_rejects_invalid_bounds_before_measurement() {
        let mut measurements = 0;
        let result = calibrate_argon2id_params_with(2, 20, |_| {
            measurements += 1;
            Ok(Duration::ZERO)
        });
        assert!(matches!(result, Err(SodiumError::InvalidParameter { .. })));
        assert_eq!(measurements, 0);
    }

    #[test]
    fn xchacha20poly1305_round_trips_and_rejects_tampering() -> Result<(), SodiumError> {
        let key = [0x22_u8; KEY_BYTES];
        let nonce = [0x33_u8; XCHACHA20_NONCE_BYTES];
        let associated_data = b"INEX test AAD";
        let plaintext = "Unicode round trip: 雪と冰 🧊".as_bytes();
        let ciphertext = xchacha20poly1305_encrypt(plaintext, associated_data, &nonce, &key)?;
        let decrypted = xchacha20poly1305_decrypt(&ciphertext, associated_data, &nonce, &key)?;
        assert_eq!(decrypted.as_slice(), plaintext);
        assert_eq!(
            xchacha20poly1305_decrypt(&ciphertext, b"wrong AAD", &nonce, &key),
            Err(SodiumError::AuthenticationFailed)
        );

        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert_eq!(
            xchacha20poly1305_decrypt(&tampered, associated_data, &nonce, &key),
            Err(SodiumError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn blake2b_helpers_are_deterministic_and_explicit() -> Result<(), SodiumError> {
        let empty = blake2b_256(b"")?;
        assert_eq!(
            empty,
            [
                0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
                0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
                0xf1, 0x2f, 0xe3, 0xa8,
            ]
        );

        let key = [0x44_u8; KEY_BYTES];
        let first = blake2b_256_keyed(&key, b"INEX-FILE-V1\0input")?;
        let second = blake2b_256_keyed(&key, b"INEX-FILE-V1\0input")?;
        assert_eq!(first, second);
        assert_ne!(first, blake2b_256(b"INEX-FILE-V1\0input")?);
        Ok(())
    }
}
