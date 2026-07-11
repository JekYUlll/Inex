//! Cross-platform logical paths for vault Markdown files.
//!
//! Logical paths deliberately use the intersection of Windows and Linux path
//! rules.  They are independent of the host on which they are parsed, so a
//! vault checkout has one meaning on every supported platform.

use std::borrow::Borrow;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use unicode_normalization::{UnicodeNormalization, is_nfc};

const _: () = {
    let (major, minor, patch) = unicode_normalization::UNICODE_VERSION;
    assert!(major == 17 && minor == 0 && patch == 0);
    let (major, minor, patch) = char::UNICODE_VERSION;
    assert!(major == 17 && minor == 0 && patch == 0);
};

/// Maximum UTF-8 byte length of a complete logical path.
pub const MAX_LOGICAL_PATH_BYTES: usize = 1024;

/// Maximum UTF-8 byte length of one logical path component.
pub const MAX_LOGICAL_COMPONENT_BYTES: usize = 255;

const MARKDOWN_SUFFIX: &str = ".md";
const CIPHERTEXT_SUFFIX: &str = ".enc";

/// Maximum UTF-8 bytes in the final logical Markdown filename component.
///
/// Four bytes are reserved for the physical `.enc` suffix so the resulting
/// ciphertext component remains within the 255-byte/unit cross-platform
/// profile.
pub const MAX_LOGICAL_FILE_COMPONENT_BYTES: usize =
    MAX_LOGICAL_COMPONENT_BYTES - CIPHERTEXT_SUFFIX.len();

/// A failure to construct or map a cross-platform logical path.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PathError {
    /// A file path was empty.
    #[error("logical file path is empty")]
    Empty,

    /// A caller supplied an absolute path.
    #[error("logical paths must be relative")]
    Absolute,

    /// A canonical-format parser received text that was not NFC.
    #[error("logical path is not Unicode NFC")]
    NotNfc,

    /// The complete normalized logical path exceeded the v1 limit.
    #[error("logical path is {actual} UTF-8 bytes; maximum is {maximum}")]
    PathTooLong { actual: usize, maximum: usize },

    /// A component exceeded the v1 limit.
    #[error(
        "logical path component {component_index} is {actual} UTF-8 bytes; maximum is {maximum}"
    )]
    ComponentTooLong {
        component_index: usize,
        actual: usize,
        maximum: usize,
    },

    /// A slash introduced an empty component.
    #[error("logical path component {component_index} is empty")]
    EmptyComponent { component_index: usize },

    /// A `.` component was supplied.
    #[error("logical path component {component_index} is `.`")]
    CurrentDirectory { component_index: usize },

    /// A `..` component was supplied.
    #[error("logical path component {component_index} is `..`")]
    ParentDirectory { component_index: usize },

    /// A backslash was supplied instead of the canonical slash separator.
    #[error("logical paths use `/`, not backslash")]
    Backslash,

    /// A NUL or Unicode control character was supplied.
    #[error(
        "logical path component {component_index} contains control character U+{character:04X}"
    )]
    ControlCharacter {
        component_index: usize,
        character: u32,
    },

    /// A character forbidden by the Windows/Linux intersection was supplied.
    #[error("logical path component {component_index} contains forbidden character `{character}`")]
    ForbiddenCharacter {
        component_index: usize,
        character: char,
    },

    /// A component ended in a dot or ASCII space.
    #[error("logical path component {component_index} has a trailing dot or space")]
    TrailingDotOrSpace { component_index: usize },

    /// A component began with ASCII space, which Win32 strips on creation.
    #[error("logical path component {component_index} begins with an ASCII space")]
    LeadingSpace { component_index: usize },

    /// A component used a Windows device basename.
    #[error(
        "logical path component {component_index} uses reserved Windows device basename `{basename}`"
    )]
    WindowsDeviceName {
        component_index: usize,
        basename: String,
    },

    /// A basename used the DOS 8.3 truncated `~digit` form rejected by Git for Windows.
    #[error("logical path component {component_index} resembles a DOS 8.3 short name")]
    NtfsShortName { component_index: usize },

    /// A component would enter Inex or Git private storage.
    #[error("logical path component {component_index} is reserved: `{name}`")]
    ReservedComponent {
        component_index: usize,
        name: String,
    },

    /// A root entry would collide with the vault metadata file.
    #[error("logical path cannot use the root `vault.json` entry")]
    ReservedVaultMetadata,

    /// A file path did not end in exact lowercase `.md`.
    #[error("logical file path must end in lowercase `.md`")]
    MissingMarkdownSuffix,

    /// A join operation was given more than one component.
    #[error("a logical child name must be exactly one component")]
    ExpectedSingleComponent,

    /// A physical path was not a normal relative filesystem path.
    #[error("ciphertext path must be a normal relative filesystem path")]
    InvalidCiphertextPath,

    /// A physical path contained a non-UTF-8 component.
    #[error("ciphertext path contains a non-UTF-8 component")]
    NonUtf8CiphertextPath,

    /// A physical path did not use the exact `.md.enc` suffix mapping.
    #[error("ciphertext path must end in lowercase `.md.enc`")]
    MissingCiphertextSuffix,
}

/// A validated NFC logical path to one Markdown document.
///
/// The stored string includes the lowercase `.md` suffix and never includes
/// the physical `.enc` suffix.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalPath(String);

impl LogicalPath {
    /// Normalize user input to NFC and validate it against the v1 profile.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the normalized path violates any v1 path
    /// invariant.
    pub fn parse(input: &str) -> Result<Self, PathError> {
        let normalized: String = input.nfc().collect();
        Self::validate(normalized)
    }

    /// Validate a path that must already be canonical NFC.
    ///
    /// EDRY and other authenticated-format readers should use this constructor
    /// so a non-canonical serialized path is rejected instead of rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NotNfc`] for non-NFC text, or another
    /// [`PathError`] when the path violates the v1 profile.
    pub fn parse_canonical(input: &str) -> Result<Self, PathError> {
        if !is_nfc(input) {
            return Err(PathError::NotNfc);
        }
        Self::validate(input.to_owned())
    }

    fn validate(path: String) -> Result<Self, PathError> {
        validate_common(&path)?;
        if !path.ends_with(MARKDOWN_SUFFIX) {
            return Err(PathError::MissingMarkdownSuffix);
        }
        let file_name = path.rsplit('/').next().ok_or(PathError::Empty)?;
        if file_name.len() > MAX_LOGICAL_FILE_COMPONENT_BYTES {
            return Err(PathError::ComponentTooLong {
                component_index: path.matches('/').count(),
                actual: file_name.len(),
                maximum: MAX_LOGICAL_FILE_COMPONENT_BYTES,
            });
        }
        Ok(Self(path))
    }

    /// Convert a discovered physical `*.md.enc` relative path back to a
    /// canonical logical path.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] if the physical path is absolute, contains a
    /// non-normal or non-UTF-8 component, lacks exact `.md.enc`, or maps to an
    /// invalid/non-canonical logical path.
    pub fn from_ciphertext_relative_path(path: &Path) -> Result<Self, PathError> {
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(value) => {
                    let value = value.to_str().ok_or(PathError::NonUtf8CiphertextPath)?;
                    parts.push(value);
                }
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => return Err(PathError::InvalidCiphertextPath),
            }
        }

        let Some(last) = parts.last_mut() else {
            return Err(PathError::Empty);
        };
        let Some(logical_name) = last.strip_suffix(CIPHERTEXT_SUFFIX) else {
            return Err(PathError::MissingCiphertextSuffix);
        };
        if !logical_name.ends_with(MARKDOWN_SUFFIX) {
            return Err(PathError::MissingCiphertextSuffix);
        }
        *last = logical_name;

        Self::parse_canonical(&parts.join("/"))
    }

    /// Return the canonical logical path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume this path and return its canonical logical path text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Iterate over validated path components.
    #[must_use]
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('/')
    }

    /// Return the final component, including `.md`.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(self.0.as_str())
    }

    /// Return the final component without `.md`.
    #[must_use]
    pub fn file_stem(&self) -> &str {
        self.file_name()
            .strip_suffix(MARKDOWN_SUFFIX)
            .unwrap_or(self.file_name())
    }

    /// Return this document's logical parent directory.
    #[must_use]
    pub fn parent(&self) -> LogicalDir {
        match self.0.rsplit_once('/') {
            Some((parent, _)) => LogicalDir(parent.to_owned()),
            None => LogicalDir::root(),
        }
    }

    /// Map the logical path to its host-relative physical ciphertext path.
    ///
    /// The mapping preserves every directory and appends `.enc` to the final
    /// `.md` component.  The returned path is always relative.
    #[must_use]
    pub fn to_ciphertext_relative_path(&self) -> PathBuf {
        let mut result = PathBuf::new();
        let mut components = self.components().peekable();
        while let Some(component) = components.next() {
            if components.peek().is_some() {
                result.push(component);
            } else {
                result.push(format!("{component}{CIPHERTEXT_SUFFIX}"));
            }
        }
        result
    }

    /// Return a deterministic Unicode case-folded collision key.
    #[must_use]
    pub fn case_fold_key(&self) -> CaseFoldKey {
        CaseFoldKey(portable_case_fold(&self.0))
    }

    /// Test whether two logical paths are aliases under case folding.
    #[must_use]
    pub fn case_collides_with(&self, other: &Self) -> bool {
        self != other && self.case_fold_key() == other.case_fold_key()
    }
}

/// A validated NFC logical directory.
///
/// The empty string is the vault root. Non-root values use the same component
/// profile as [`LogicalPath`] but do not have a filename-suffix requirement.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogicalDir(String);

impl LogicalDir {
    /// Return the logical vault root.
    #[must_use]
    pub const fn root() -> Self {
        Self(String::new())
    }

    /// Normalize user input to NFC and validate it as a logical directory.
    /// An empty input denotes the vault root.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the normalized directory violates any v1
    /// path invariant.
    pub fn parse(input: &str) -> Result<Self, PathError> {
        let normalized: String = input.nfc().collect();
        Self::validate(normalized)
    }

    /// Validate a directory that must already be canonical NFC.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NotNfc`] for non-NFC text, or another
    /// [`PathError`] when the directory violates the v1 profile.
    pub fn parse_canonical(input: &str) -> Result<Self, PathError> {
        if !is_nfc(input) {
            return Err(PathError::NotNfc);
        }
        Self::validate(input.to_owned())
    }

    fn validate(path: String) -> Result<Self, PathError> {
        if path.is_empty() {
            return Ok(Self::root());
        }
        validate_common(&path)?;
        Ok(Self(path))
    }

    /// Return the canonical directory text; root is the empty string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return whether this directory is the vault root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over components. The root yields no components.
    #[must_use]
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('/').filter(|component| !component.is_empty())
    }

    /// Return the final component, or `None` for root.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.components().next_back()
    }

    /// Return the parent directory, or `None` for root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            None
        } else {
            Some(match self.0.rsplit_once('/') {
                Some((parent, _)) => Self(parent.to_owned()),
                None => Self::root(),
            })
        }
    }

    /// Append one Markdown filename and validate the resulting logical path.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] if `file_name` is not exactly one valid component
    /// or the joined path exceeds a v1 limit.
    pub fn join_file(&self, file_name: &str) -> Result<LogicalPath, PathError> {
        require_single_component(file_name)?;
        if self.is_root() {
            LogicalPath::parse(file_name)
        } else {
            LogicalPath::parse(&format!("{}/{file_name}", self.0))
        }
    }

    /// Append one directory name and validate the resulting directory.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] if `directory_name` is not exactly one valid
    /// component or the joined path exceeds a v1 limit.
    pub fn join_dir(&self, directory_name: &str) -> Result<Self, PathError> {
        require_single_component(directory_name)?;
        if self.is_root() {
            Self::parse(directory_name)
        } else {
            Self::parse(&format!("{}/{directory_name}", self.0))
        }
    }

    /// Return whether this directory contains the given logical document.
    #[must_use]
    pub fn contains(&self, path: &LogicalPath) -> bool {
        self.is_root()
            || path
                .as_str()
                .strip_prefix(self.as_str())
                .is_some_and(|remainder| remainder.starts_with('/'))
    }

    /// Return a deterministic Unicode case-folded collision key.
    #[must_use]
    pub fn case_fold_key(&self) -> CaseFoldKey {
        CaseFoldKey(portable_case_fold(&self.0))
    }
}

/// A deterministic key used to reject case-fold aliases in one vault.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaseFoldKey(String);

impl CaseFoldKey {
    /// Borrow the folded key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn require_single_component(name: &str) -> Result<(), PathError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(PathError::ExpectedSingleComponent);
    }
    Ok(())
}

fn validate_common(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if path.starts_with('/') {
        return Err(PathError::Absolute);
    }
    if path.contains('\\') {
        return Err(PathError::Backslash);
    }

    let path_length = path.len();
    if path_length > MAX_LOGICAL_PATH_BYTES {
        return Err(PathError::PathTooLong {
            actual: path_length,
            maximum: MAX_LOGICAL_PATH_BYTES,
        });
    }

    for (index, component) in path.split('/').enumerate() {
        validate_component(component, index)?;
        if index == 0 && component.eq_ignore_ascii_case("vault.json") {
            return Err(PathError::ReservedVaultMetadata);
        }
    }

    Ok(())
}

fn validate_component(component: &str, index: usize) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent {
            component_index: index,
        });
    }
    if component == "." {
        return Err(PathError::CurrentDirectory {
            component_index: index,
        });
    }
    if component == ".." {
        return Err(PathError::ParentDirectory {
            component_index: index,
        });
    }

    let component_length = component.len();
    if component_length > MAX_LOGICAL_COMPONENT_BYTES {
        return Err(PathError::ComponentTooLong {
            component_index: index,
            actual: component_length,
            maximum: MAX_LOGICAL_COMPONENT_BYTES,
        });
    }
    if component.ends_with(['.', ' ']) {
        return Err(PathError::TrailingDotOrSpace {
            component_index: index,
        });
    }
    if component.starts_with(' ') {
        return Err(PathError::LeadingSpace {
            component_index: index,
        });
    }

    for character in component.chars() {
        if character.is_control() {
            return Err(PathError::ControlCharacter {
                component_index: index,
                character: u32::from(character),
            });
        }
        if matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
            return Err(PathError::ForbiddenCharacter {
                component_index: index,
                character,
            });
        }
    }

    if component.eq_ignore_ascii_case(".git") || component.eq_ignore_ascii_case(".vault-local") {
        return Err(PathError::ReservedComponent {
            component_index: index,
            name: component.to_owned(),
        });
    }

    let basename = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    if is_windows_device_basename(basename) {
        return Err(PathError::WindowsDeviceName {
            component_index: index,
            basename: basename.to_owned(),
        });
    }
    let basename_bytes = basename.as_bytes();
    if matches!(basename_bytes.last(), Some(b'0'..=b'9'))
        && basename_bytes.get(basename_bytes.len().saturating_sub(2)) == Some(&b'~')
    {
        return Err(PathError::NtfsShortName {
            component_index: index,
        });
    }

    Ok(())
}

fn is_windows_device_basename(basename: &str) -> bool {
    if basename.eq_ignore_ascii_case("CON")
        || basename.eq_ignore_ascii_case("PRN")
        || basename.eq_ignore_ascii_case("AUX")
        || basename.eq_ignore_ascii_case("NUL")
        || basename.eq_ignore_ascii_case("CONIN$")
        || basename.eq_ignore_ascii_case("CONOUT$")
    {
        return true;
    }

    let Some(prefix) = basename.get(..3) else {
        return false;
    };
    let Some(suffix) = basename.get(3..) else {
        return false;
    };
    (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
        && (matches!(suffix.as_bytes(), [b'1'..=b'9']) || matches!(suffix, "¹" | "²" | "³"))
}

/// Produce a full, locale-independent case fold and restore NFC afterwards.
///
/// Rust exposes Unicode lower/upper mappings but not the `CaseFolding` table.
/// Applying lower → upper → lower reproduces full default folding, including
/// expansions such as `ß` → `ss`; the two Unicode exceptions are dotless I and
/// Cherokee, handled explicitly below. NFC is restored because case folding
/// itself is not normalization-preserving.
pub(crate) fn portable_case_fold(input: &str) -> String {
    let mut folded = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            // Full default case folding preserves LATIN SMALL LETTER DOTLESS I.
            // Cherokee folds to uppercase, unlike all other cased scripts.
            '\u{0131}' | '\u{13a0}'..='\u{13f5}' => folded.push(character),
            '\u{13f8}'..='\u{13fd}' => {
                if let Some(mapped) = char::from_u32(u32::from(character) - 8) {
                    folded.push(mapped);
                }
            }
            '\u{ab70}'..='\u{abbf}' => {
                if let Some(mapped) = char::from_u32(u32::from(character) - 0x97d0) {
                    folded.push(mapped);
                }
            }
            _ => {
                for lowercase in character.to_lowercase() {
                    for uppercase in lowercase.to_uppercase() {
                        folded.extend(uppercase.to_lowercase());
                    }
                }
            }
        }
    }
    folded.nfc().collect()
}

impl fmt::Debug for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("LogicalPath").field(&self.0).finish()
    }
}

impl fmt::Display for LogicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for LogicalPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for LogicalPath {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for LogicalPath {
    type Err = PathError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl Serialize for LogicalPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LogicalPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_canonical(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for LogicalDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("LogicalDir").field(&self.0).finish()
    }
}

impl fmt::Display for LogicalDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for LogicalDir {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for LogicalDir {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for LogicalDir {
    type Err = PathError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl Serialize for LogicalDir {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LogicalDir {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_canonical(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_path(input: &str) -> LogicalPath {
        match LogicalPath::parse(input) {
            Ok(path) => path,
            Err(error) => panic!("expected valid logical path `{input}`: {error}"),
        }
    }

    fn valid_dir(input: &str) -> LogicalDir {
        match LogicalDir::parse(input) {
            Ok(path) => path,
            Err(error) => panic!("expected valid logical directory `{input}`: {error}"),
        }
    }

    #[test]
    fn accepts_nested_chinese_and_maps_physical_suffix() {
        let logical = valid_path("日记/二〇二六/七月十一日.md");
        assert_eq!(logical.as_str(), "日记/二〇二六/七月十一日.md");
        assert_eq!(logical.file_name(), "七月十一日.md");
        assert_eq!(logical.file_stem(), "七月十一日");
        assert_eq!(logical.parent(), valid_dir("日记/二〇二六"));
        assert_eq!(
            logical.to_ciphertext_relative_path(),
            PathBuf::from("日记/二〇二六/七月十一日.md.enc")
        );
        assert_eq!(
            LogicalPath::from_ciphertext_relative_path(Path::new(
                "日记/二〇二六/七月十一日.md.enc"
            )),
            Ok(logical)
        );
    }

    #[test]
    fn user_parser_normalizes_but_canonical_parser_rejects_decomposed_text() {
        let decomposed = "cafe\u{301}.md";
        assert_eq!(valid_path(decomposed).as_str(), "caf\u{e9}.md");
        assert_eq!(
            LogicalPath::parse_canonical(decomposed),
            Err(PathError::NotNfc)
        );
        assert_eq!(
            LogicalPath::parse_canonical("caf\u{e9}.md").map(LogicalPath::into_string),
            Ok("caf\u{e9}.md".to_owned())
        );
    }

    #[test]
    fn rejects_absolute_traversal_empty_and_backslash_paths() {
        assert_eq!(LogicalPath::parse("/secret.md"), Err(PathError::Absolute));
        assert_eq!(
            LogicalPath::parse("../secret.md"),
            Err(PathError::ParentDirectory { component_index: 0 })
        );
        assert_eq!(
            LogicalPath::parse("safe/./secret.md"),
            Err(PathError::CurrentDirectory { component_index: 1 })
        );
        assert_eq!(
            LogicalPath::parse("safe//secret.md"),
            Err(PathError::EmptyComponent { component_index: 1 })
        );
        assert_eq!(
            LogicalPath::parse("safe\\secret.md"),
            Err(PathError::Backslash)
        );
        assert_eq!(LogicalPath::parse(""), Err(PathError::Empty));
    }

    #[test]
    fn rejects_windows_device_names_with_extensions() {
        for input in [
            "CON.md",
            "prn.md",
            "folder/AuX.notes.md",
            "nul.anything.md",
            "COM1.md",
            "com9.notes.md",
            "LPT1.md",
            "lPt9.backup.md",
            "COM¹.md",
            "com².notes.md",
            "LPT³.md",
            "CONIN$.md",
            "conout$.notes.md",
            "CON .md",
            "LPT1 .md",
        ] {
            assert!(
                matches!(
                    LogicalPath::parse(input),
                    Err(PathError::WindowsDeviceName { .. })
                ),
                "device path should fail: {input}"
            );
        }

        assert!(LogicalPath::parse("COM0.md").is_ok());
        assert!(LogicalPath::parse("COM10.md").is_ok());
        assert!(LogicalPath::parse("LPT0.md").is_ok());
        assert!(LogicalPath::parse("COM⁴.md").is_ok());
        for input in ["mydocu~1.md", "folder/ABCDEF~9.notes.md", "x~0.md"] {
            assert!(matches!(
                LogicalPath::parse(input),
                Err(PathError::NtfsShortName { .. })
            ));
        }
    }

    #[test]
    fn rejects_windows_characters_controls_and_trailing_dot_or_space() {
        for character in ['<', '>', ':', '"', '|', '?', '*'] {
            let input = format!("bad{character}name.md");
            assert!(
                matches!(
                    LogicalPath::parse(&input),
                    Err(PathError::ForbiddenCharacter { .. })
                ),
                "forbidden character should fail: {character}"
            );
        }
        assert!(matches!(
            LogicalPath::parse("bad\nname.md"),
            Err(PathError::ControlCharacter { .. })
        ));
        assert!(matches!(
            LogicalPath::parse("bad\0name.md"),
            Err(PathError::ControlCharacter { .. })
        ));
        assert!(matches!(
            LogicalPath::parse("folder./name.md"),
            Err(PathError::TrailingDotOrSpace { .. })
        ));
        assert!(matches!(
            LogicalPath::parse("folder /name.md"),
            Err(PathError::TrailingDotOrSpace { .. })
        ));
        assert!(matches!(
            LogicalPath::parse(" leading/name.md"),
            Err(PathError::LeadingSpace { .. })
        ));
        assert!(matches!(
            LogicalPath::parse("folder/ leading.md"),
            Err(PathError::LeadingSpace { .. })
        ));
    }

    #[test]
    fn rejects_reserved_storage_entries_case_insensitively() {
        for input in [
            ".git/entry.md",
            "notes/.GIT/entry.md",
            ".vault-local/entry.md",
            "notes/.VAULT-LOCAL/entry.md",
        ] {
            assert!(
                matches!(
                    LogicalPath::parse(input),
                    Err(PathError::ReservedComponent { .. })
                ),
                "reserved storage path should fail: {input}"
            );
        }
        for input in ["vault.json/entry.md", "VAULT.JSON/entry.md"] {
            assert_eq!(
                LogicalPath::parse(input),
                Err(PathError::ReservedVaultMetadata)
            );
        }
        assert!(LogicalPath::parse("notes/vault.json.md").is_ok());
    }

    #[test]
    fn requires_exact_logical_markdown_suffix() {
        for input in ["entry", "entry.MD", "entry.md.enc", "folder"] {
            assert_eq!(
                LogicalPath::parse(input),
                Err(PathError::MissingMarkdownSuffix)
            );
        }
        assert!(LogicalPath::parse("entry.md").is_ok());
        assert!(LogicalPath::parse("archive.md/entry.md").is_ok());
    }

    #[test]
    fn enforces_utf8_byte_limits_for_components_and_paths() {
        let file_component_251 = format!("{}.md", "a".repeat(248));
        assert_eq!(file_component_251.len(), MAX_LOGICAL_FILE_COMPONENT_BYTES);
        assert!(LogicalPath::parse(&file_component_251).is_ok());
        assert_eq!(
            LogicalPath::parse(&format!("{}.md", "a".repeat(249))),
            Err(PathError::ComponentTooLong {
                component_index: 0,
                actual: 252,
                maximum: MAX_LOGICAL_FILE_COMPONENT_BYTES,
            })
        );

        let directory_255 = "a".repeat(MAX_LOGICAL_COMPONENT_BYTES);
        assert!(LogicalDir::parse(&directory_255).is_ok());

        let component_256 = format!("{}.md", "a".repeat(253));
        assert_eq!(
            LogicalPath::parse(&component_256),
            Err(PathError::ComponentTooLong {
                component_index: 0,
                actual: 256,
                maximum: MAX_LOGICAL_COMPONENT_BYTES,
            })
        );

        let long_path = format!(
            "{}/{}/{}/{}/{}.md",
            "a".repeat(250),
            "b".repeat(250),
            "c".repeat(250),
            "d".repeat(250),
            "e".repeat(20)
        );
        assert!(long_path.len() > MAX_LOGICAL_PATH_BYTES);
        assert!(matches!(
            LogicalPath::parse(&long_path),
            Err(PathError::PathTooLong { .. })
        ));

        let chinese_component = format!("{}.md", "日".repeat(82));
        assert_eq!(chinese_component.len(), 249);
        assert!(LogicalPath::parse(&chinese_component).is_ok());
        assert!(matches!(
            LogicalPath::parse(&format!("{}.md", "日".repeat(83))),
            Err(PathError::ComponentTooLong {
                maximum: MAX_LOGICAL_FILE_COMPONENT_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn collision_keys_cover_ascii_and_full_unicode_case_folding() {
        let upper = valid_path("Journal/STRASSE.md");
        let lower = valid_path("journal/Stra\u{df}e.md");
        assert_ne!(upper, lower);
        assert_eq!(upper.case_fold_key(), lower.case_fold_key());
        assert!(upper.case_collides_with(&lower));

        let sigma = valid_path("\u{3c3}.md");
        let final_sigma = valid_path("\u{3c2}.md");
        assert_eq!(sigma.case_fold_key(), final_sigma.case_fold_key());

        let dotless_i = valid_path("\u{131}.md");
        let ascii_i = valid_path("i.md");
        assert_ne!(dotless_i.case_fold_key(), ascii_i.case_fold_key());
    }

    #[test]
    fn canonical_equivalents_share_one_collision_key() {
        let composed = valid_path("caf\u{e9}.md");
        let normalized_from_decomposed = valid_path("cafe\u{301}.md");
        assert_eq!(composed, normalized_from_decomposed);
        assert_eq!(
            composed.case_fold_key(),
            normalized_from_decomposed.case_fold_key()
        );
    }

    #[test]
    fn logical_directories_support_root_join_parent_and_containment() {
        let root = LogicalDir::root();
        let notes = match root.join_dir("笔记") {
            Ok(directory) => directory,
            Err(error) => panic!("join directory failed: {error}"),
        };
        let year = match notes.join_dir("2026") {
            Ok(directory) => directory,
            Err(error) => panic!("join directory failed: {error}"),
        };
        let document = match year.join_file("七月.md") {
            Ok(path) => path,
            Err(error) => panic!("join file failed: {error}"),
        };

        assert!(root.contains(&document));
        assert!(notes.contains(&document));
        assert!(year.contains(&document));
        assert_eq!(year.parent(), Some(notes));
        assert_eq!(root.parent(), None);
        assert_eq!(root.name(), None);
        assert_eq!(document.as_str(), "笔记/2026/七月.md");
        assert_eq!(root.join_dir(""), Err(PathError::ExpectedSingleComponent));
        assert_eq!(year.join_dir(""), Err(PathError::ExpectedSingleComponent));
        assert_eq!(year.join_file(""), Err(PathError::ExpectedSingleComponent));
        assert_eq!(
            year.join_file("nested/escape.md"),
            Err(PathError::ExpectedSingleComponent)
        );
    }

    #[test]
    fn ciphertext_reverse_mapping_rejects_noncanonical_physical_paths() {
        assert_eq!(
            LogicalPath::from_ciphertext_relative_path(Path::new("entry.md")),
            Err(PathError::MissingCiphertextSuffix)
        );
        assert_eq!(
            LogicalPath::from_ciphertext_relative_path(Path::new("entry.MD.enc")),
            Err(PathError::MissingCiphertextSuffix)
        );
        assert_eq!(
            LogicalPath::from_ciphertext_relative_path(Path::new("../entry.md.enc")),
            Err(PathError::InvalidCiphertextPath)
        );
        assert_eq!(
            LogicalPath::from_ciphertext_relative_path(Path::new("/entry.md.enc")),
            Err(PathError::InvalidCiphertextPath)
        );
    }

    #[test]
    fn serde_round_trip_is_canonical_and_rejects_non_nfc() {
        let logical = valid_path("日记/caf\u{e9}.md");
        let json = match serde_json::to_string(&logical) {
            Ok(json) => json,
            Err(error) => panic!("serialization failed: {error}"),
        };
        assert_eq!(json, "\"日记/caf\u{e9}.md\"");
        match serde_json::from_str::<LogicalPath>(&json) {
            Ok(decoded) => assert_eq!(decoded, logical),
            Err(error) => panic!("deserialization failed: {error}"),
        }
        assert!(serde_json::from_str::<LogicalPath>("\"cafe\\u0301.md\"").is_err());
    }
}
