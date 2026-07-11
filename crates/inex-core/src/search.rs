//! Bounded, memory-only full-text search over decrypted vault documents.
//!
//! Search bodies, queries, generated case-folded text, and snippets are held in
//! [`Zeroizing`] allocations.  The index has no persistence API: callers must
//! rebuild it after unlock and call [`MemorySearchIndex::clear`] on lock.

use std::fmt;
use std::ops::Range;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::path::LogicalPath;

/// Maximum UTF-8 byte length of one indexed plaintext document.
pub const MAX_SEARCH_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum total UTF-8 plaintext bytes held by one search index.
pub const MAX_SEARCH_INDEX_BYTES: usize = 256 * 1024 * 1024;

/// Maximum number of documents held by one search index.
pub const MAX_SEARCH_DOCUMENTS: usize = 100_000;

/// Maximum UTF-8 byte length of a search query.
pub const MAX_SEARCH_QUERY_BYTES: usize = 4 * 1024;

/// Maximum number of hits returned by one search.
pub const MAX_SEARCH_RESULTS: usize = 1_000;

/// Maximum UTF-8 byte length of one returned snippet.
pub const MAX_SEARCH_SNIPPET_BYTES: usize = 4 * 1024;

/// Default number of hits returned by a search query.
pub const DEFAULT_SEARCH_RESULTS: usize = 50;

/// Default maximum UTF-8 byte length of one snippet.
pub const DEFAULT_SEARCH_SNIPPET_BYTES: usize = 240;

/// A failure to construct or operate a bounded memory search index.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SearchError {
    /// A plaintext document exceeded the per-document hard limit.
    #[error("document is {actual} UTF-8 bytes; maximum is {maximum}")]
    DocumentTooLarge { actual: usize, maximum: usize },

    /// A configured document-count limit exceeded the v1 hard limit.
    #[error("index document limit is {actual}; maximum is {maximum}")]
    DocumentLimitTooLarge { actual: usize, maximum: usize },

    /// A configured index-byte limit exceeded the v1 hard limit.
    #[error("index plaintext limit is {actual} bytes; maximum is {maximum}")]
    IndexLimitTooLarge { actual: usize, maximum: usize },

    /// An insert would exceed the configured document-count limit.
    #[error("index would contain {actual} documents; configured maximum is {maximum}")]
    TooManyDocuments { actual: usize, maximum: usize },

    /// An insert would exceed the configured total plaintext-byte limit.
    #[error("index would contain {actual} plaintext bytes; configured maximum is {maximum}")]
    IndexTooLarge { actual: usize, maximum: usize },

    /// The query text was empty.
    #[error("search query is empty")]
    EmptyQuery,

    /// The query text exceeded the UTF-8 byte limit.
    #[error("search query is {actual} UTF-8 bytes; maximum is {maximum}")]
    QueryTooLarge { actual: usize, maximum: usize },

    /// The requested result count was zero.
    #[error("search result limit must be at least one")]
    ZeroResultLimit,

    /// The requested result count exceeded the v1 hard limit.
    #[error("search result limit is {actual}; maximum is {maximum}")]
    ResultLimitTooLarge { actual: usize, maximum: usize },

    /// The requested snippet size exceeded the v1 hard limit.
    #[error("search snippet limit is {actual} bytes; maximum is {maximum}")]
    SnippetLimitTooLarge { actual: usize, maximum: usize },
}

/// Case comparison performed by a search query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseSensitivity {
    /// Match the query's UTF-8 text byte-for-byte.
    Sensitive,

    /// Match using a locale-independent Unicode case fold.
    ///
    /// Each scalar uses Rust's lowercase, uppercase, then lowercase mappings,
    /// with the default-fold exceptions for dotless I and Cherokee.  This
    /// supports multi-scalar mappings such as `ß` to `ss` and maps hits back to
    /// the original document byte range.  It intentionally does not apply
    /// Unicode normalization: canonically equivalent but differently encoded
    /// text is not considered equal unless its folded scalars match.
    UnicodeInsensitive,
}

/// One decrypted document owned by a memory search index.
pub struct Document {
    logical_path: LogicalPath,
    plaintext: Zeroizing<String>,
}

impl Document {
    /// Construct a document from an already protected plaintext allocation.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::DocumentTooLarge`] when `plaintext` exceeds
    /// [`MAX_SEARCH_DOCUMENT_BYTES`] UTF-8 bytes.  Rejected plaintext is
    /// zeroized when this function returns.
    pub fn new(
        logical_path: LogicalPath,
        plaintext: Zeroizing<String>,
    ) -> Result<Self, SearchError> {
        let actual = plaintext.len();
        if actual > MAX_SEARCH_DOCUMENT_BYTES {
            return Err(SearchError::DocumentTooLarge {
                actual,
                maximum: MAX_SEARCH_DOCUMENT_BYTES,
            });
        }
        Ok(Self {
            logical_path,
            plaintext,
        })
    }

    /// Return the document's validated logical path.
    #[must_use]
    pub fn logical_path(&self) -> &LogicalPath {
        &self.logical_path
    }

    /// Borrow the in-memory plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        self.plaintext.as_str()
    }

    /// Return the exact UTF-8 plaintext byte length.
    #[must_use]
    pub fn plaintext_bytes(&self) -> usize {
        self.plaintext.len()
    }

    /// Zeroize and empty this document's plaintext allocation.
    pub fn clear(&mut self) {
        self.plaintext.zeroize();
    }
}

impl Zeroize for Document {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for Document {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Document")
            .field("logical_path", &self.logical_path)
            .field("plaintext", &"[REDACTED]")
            .field("plaintext_bytes", &self.plaintext.len())
            .finish()
    }
}

/// A validated, resource-bounded memory search request.
pub struct SearchQuery {
    text: Zeroizing<String>,
    case_sensitivity: CaseSensitivity,
    result_limit: usize,
    snippet_byte_limit: usize,
}

impl SearchQuery {
    /// Construct a query from an already protected text allocation.
    ///
    /// `snippet_byte_limit` may be zero to suppress snippet text.  Snippets are
    /// always cut at UTF-8 scalar boundaries and can therefore be shorter than
    /// the requested byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::EmptyQuery`] for empty text,
    /// [`SearchError::QueryTooLarge`] for text over
    /// [`MAX_SEARCH_QUERY_BYTES`], [`SearchError::ZeroResultLimit`] for a zero
    /// result limit, or the corresponding limit error when a requested result
    /// or snippet limit exceeds its v1 hard maximum.
    pub fn new(
        text: Zeroizing<String>,
        case_sensitivity: CaseSensitivity,
        result_limit: usize,
        snippet_byte_limit: usize,
    ) -> Result<Self, SearchError> {
        validate_query(&text, result_limit, snippet_byte_limit)?;
        Ok(Self {
            text,
            case_sensitivity,
            result_limit,
            snippet_byte_limit,
        })
    }

    /// Construct a query with the v1 default result and snippet limits.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::EmptyQuery`] or [`SearchError::QueryTooLarge`]
    /// when the text violates the v1 query bounds.
    pub fn with_defaults(
        text: Zeroizing<String>,
        case_sensitivity: CaseSensitivity,
    ) -> Result<Self, SearchError> {
        Self::new(
            text,
            case_sensitivity,
            DEFAULT_SEARCH_RESULTS,
            DEFAULT_SEARCH_SNIPPET_BYTES,
        )
    }

    /// Borrow the in-memory query text.
    #[must_use]
    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    /// Return the selected comparison mode.
    #[must_use]
    pub const fn case_sensitivity(&self) -> CaseSensitivity {
        self.case_sensitivity
    }

    /// Return the exact maximum number of hits to return.
    #[must_use]
    pub const fn result_limit(&self) -> usize {
        self.result_limit
    }

    /// Return the exact maximum UTF-8 byte length of each snippet.
    #[must_use]
    pub const fn snippet_byte_limit(&self) -> usize {
        self.snippet_byte_limit
    }

    /// Zeroize and empty the query text.
    ///
    /// A cleared query is no longer valid and is rejected by
    /// [`MemorySearchIndex::search`].
    pub fn clear(&mut self) {
        self.text.zeroize();
    }
}

impl Zeroize for SearchQuery {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for SearchQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchQuery")
            .field("text", &"[REDACTED]")
            .field("text_bytes", &self.text.len())
            .field("case_sensitivity", &self.case_sensitivity)
            .field("result_limit", &self.result_limit)
            .field("snippet_byte_limit", &self.snippet_byte_limit)
            .finish()
    }
}

/// One bounded search result mapped to original document coordinates.
///
/// `line` and `utf16_column` are zero-based.  `byte_range` is a half-open
/// UTF-8 byte range in the original plaintext.  CRLF is one line break, and an
/// astral Unicode scalar contributes two UTF-16 code units to the column.
pub struct SearchHit {
    logical_path: LogicalPath,
    byte_range: Range<usize>,
    line: usize,
    utf16_column: usize,
    snippet: Zeroizing<String>,
}

impl SearchHit {
    /// Return the document containing this hit.
    #[must_use]
    pub fn logical_path(&self) -> &LogicalPath {
        &self.logical_path
    }

    /// Return the half-open UTF-8 byte range in the original plaintext.
    #[must_use]
    pub fn byte_range(&self) -> Range<usize> {
        self.byte_range.clone()
    }

    /// Return the zero-based line containing the match start.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// Return the zero-based UTF-16 column of the match start.
    #[must_use]
    pub const fn utf16_column(&self) -> usize {
        self.utf16_column
    }

    /// Borrow the bounded, newline-free snippet around the match start.
    #[must_use]
    pub fn snippet(&self) -> &str {
        self.snippet.as_str()
    }

    /// Zeroize and empty the snippet allocation.
    pub fn clear(&mut self) {
        self.snippet.zeroize();
    }
}

impl Zeroize for SearchHit {
    fn zeroize(&mut self) {
        self.clear();
        self.byte_range = 0..0;
        self.line.zeroize();
        self.utf16_column.zeroize();
    }
}

impl fmt::Debug for SearchHit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchHit")
            .field("logical_path", &self.logical_path)
            .field("byte_range", &self.byte_range)
            .field("line", &self.line)
            .field("utf16_column", &self.utf16_column)
            .field("snippet", &"[REDACTED]")
            .field("snippet_bytes", &self.snippet.len())
            .finish()
    }
}

/// A deterministic, bounded index of decrypted documents held only in memory.
pub struct MemorySearchIndex {
    documents: Zeroizing<Vec<Document>>,
    plaintext_bytes: usize,
    document_limit: usize,
    plaintext_byte_limit: usize,
}

impl MemorySearchIndex {
    /// Construct an empty index with the v1 hard resource limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            documents: Zeroizing::new(Vec::new()),
            plaintext_bytes: 0,
            document_limit: MAX_SEARCH_DOCUMENTS,
            plaintext_byte_limit: MAX_SEARCH_INDEX_BYTES,
        }
    }

    /// Construct an empty index with lower caller-selected resource limits.
    ///
    /// Zero is accepted for either limit and creates an index that cannot hold
    /// documents or plaintext respectively.  This is useful for fail-closed
    /// configurations and exact boundary tests.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::DocumentLimitTooLarge`] or
    /// [`SearchError::IndexLimitTooLarge`] when a requested limit exceeds the
    /// corresponding v1 hard maximum.
    pub fn with_limits(
        document_limit: usize,
        plaintext_byte_limit: usize,
    ) -> Result<Self, SearchError> {
        if document_limit > MAX_SEARCH_DOCUMENTS {
            return Err(SearchError::DocumentLimitTooLarge {
                actual: document_limit,
                maximum: MAX_SEARCH_DOCUMENTS,
            });
        }
        if plaintext_byte_limit > MAX_SEARCH_INDEX_BYTES {
            return Err(SearchError::IndexLimitTooLarge {
                actual: plaintext_byte_limit,
                maximum: MAX_SEARCH_INDEX_BYTES,
            });
        }
        Ok(Self {
            documents: Zeroizing::new(Vec::new()),
            plaintext_bytes: 0,
            document_limit,
            plaintext_byte_limit,
        })
    }

    /// Insert or replace a document, preserving logical-path sort order.
    ///
    /// The limit check is atomic from the caller's perspective: on error the
    /// existing index is unchanged and the rejected document is zeroized on
    /// drop.  Replacing a document does not consume another document slot.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::TooManyDocuments`] or
    /// [`SearchError::IndexTooLarge`] when the resulting index would exceed a
    /// configured limit.
    pub fn upsert(&mut self, document: Document) -> Result<(), SearchError> {
        let search = self
            .documents
            .binary_search_by(|existing| existing.logical_path.cmp(&document.logical_path));
        let replaced_bytes = search
            .ok()
            .map_or(0, |index| self.documents[index].plaintext.len());
        let resulting_documents = self.documents.len() + usize::from(search.is_err());
        if resulting_documents > self.document_limit {
            return Err(SearchError::TooManyDocuments {
                actual: resulting_documents,
                maximum: self.document_limit,
            });
        }

        let resulting_bytes = self.plaintext_bytes - replaced_bytes + document.plaintext.len();
        if resulting_bytes > self.plaintext_byte_limit {
            return Err(SearchError::IndexTooLarge {
                actual: resulting_bytes,
                maximum: self.plaintext_byte_limit,
            });
        }

        match search {
            Ok(index) => {
                let replaced = std::mem::replace(&mut self.documents[index], document);
                drop(replaced);
            }
            Err(index) => self.documents.insert(index, document),
        }
        self.plaintext_bytes = resulting_bytes;
        Ok(())
    }

    /// Remove and zeroize the document at `logical_path`.
    ///
    /// Returns whether a document was present.
    pub fn remove(&mut self, logical_path: &LogicalPath) -> bool {
        let Ok(index) = self
            .documents
            .binary_search_by(|document| document.logical_path.cmp(logical_path))
        else {
            return false;
        };
        let removed = self.documents.remove(index);
        self.plaintext_bytes -= removed.plaintext.len();
        drop(removed);
        true
    }

    /// Return whether `logical_path` is indexed.
    #[must_use]
    pub fn contains(&self, logical_path: &LogicalPath) -> bool {
        self.documents
            .binary_search_by(|document| document.logical_path.cmp(logical_path))
            .is_ok()
    }

    /// Return the number of indexed documents.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    /// Return the exact total UTF-8 plaintext bytes currently indexed.
    #[must_use]
    pub const fn plaintext_bytes(&self) -> usize {
        self.plaintext_bytes
    }

    /// Zeroize and remove every indexed document.
    pub fn clear(&mut self) {
        self.documents.zeroize();
        self.plaintext_bytes = 0;
    }

    /// Search all documents in logical-path then byte-offset order.
    ///
    /// The returned [`Zeroizing<Vec<_>>`] clears every snippet when dropped.
    /// The requested result count and snippet byte limit are exact upper
    /// bounds.  No index or result is written to disk by this module.
    ///
    /// # Errors
    ///
    /// Returns a query validation error if a previously valid query was
    /// cleared before use.  All other query invariants are checked again
    /// defensively.
    pub fn search(&self, query: &SearchQuery) -> Result<Zeroizing<Vec<SearchHit>>, SearchError> {
        validate_query(&query.text, query.result_limit, query.snippet_byte_limit)?;

        let folded_query = match query.case_sensitivity {
            CaseSensitivity::Sensitive => None,
            CaseSensitivity::UnicodeInsensitive => Some(fold_query(query.text.as_str())),
        };
        let mut hits = Zeroizing::new(Vec::new());

        for document in self.documents.iter() {
            if hits.len() == query.result_limit {
                break;
            }
            match query.case_sensitivity {
                CaseSensitivity::Sensitive => {
                    search_sensitive_document(document, query, &mut hits);
                }
                CaseSensitivity::UnicodeInsensitive => search_folded_document(
                    document,
                    query,
                    folded_query.as_ref().map_or("", |text| text.as_str()),
                    &mut hits,
                ),
            }
        }

        Ok(hits)
    }
}

impl Default for MemorySearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MemorySearchIndex {
    fn drop(&mut self) {
        self.clear();
    }
}

impl fmt::Debug for MemorySearchIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemorySearchIndex")
            .field("document_count", &self.documents.len())
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("document_limit", &self.document_limit)
            .field("plaintext_byte_limit", &self.plaintext_byte_limit)
            .finish()
    }
}

fn validate_query(
    text: &str,
    result_limit: usize,
    snippet_byte_limit: usize,
) -> Result<(), SearchError> {
    if text.is_empty() {
        return Err(SearchError::EmptyQuery);
    }
    if text.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(SearchError::QueryTooLarge {
            actual: text.len(),
            maximum: MAX_SEARCH_QUERY_BYTES,
        });
    }
    if result_limit == 0 {
        return Err(SearchError::ZeroResultLimit);
    }
    if result_limit > MAX_SEARCH_RESULTS {
        return Err(SearchError::ResultLimitTooLarge {
            actual: result_limit,
            maximum: MAX_SEARCH_RESULTS,
        });
    }
    if snippet_byte_limit > MAX_SEARCH_SNIPPET_BYTES {
        return Err(SearchError::SnippetLimitTooLarge {
            actual: snippet_byte_limit,
            maximum: MAX_SEARCH_SNIPPET_BYTES,
        });
    }
    Ok(())
}

fn search_sensitive_document(
    document: &Document,
    query: &SearchQuery,
    hits: &mut Zeroizing<Vec<SearchHit>>,
) {
    let mut position = PositionCursor::default();
    for (start, matched) in document.plaintext.match_indices(query.text.as_str()) {
        push_hit(
            document,
            start..start + matched.len(),
            query,
            &mut position,
            hits,
        );
        if hits.len() == query.result_limit {
            return;
        }
    }
}

fn search_folded_document(
    document: &Document,
    query: &SearchQuery,
    folded_query: &str,
    hits: &mut Zeroizing<Vec<SearchHit>>,
) {
    let mut matcher = StreamingFoldMatcher::new(folded_query.as_bytes());
    let mut folded_scalar = Zeroizing::new(String::with_capacity(128));
    let mut previous_range = None;
    let mut position = PositionCursor::default();
    for (original_start, character) in document.plaintext.char_indices() {
        let original_end = original_start + character.len_utf8();
        folded_scalar.clear();
        fold_character_into(character, &mut folded_scalar);
        for &byte in folded_scalar.as_bytes() {
            let Some(original_range) = matcher.feed(byte, original_start, original_end) else {
                continue;
            };
            if previous_range.as_ref() == Some(&original_range) {
                continue;
            }
            previous_range = Some(original_range.clone());
            push_hit(document, original_range, query, &mut position, hits);
            if hits.len() == query.result_limit {
                return;
            }
        }
    }
}

fn push_hit(
    document: &Document,
    byte_range: Range<usize>,
    query: &SearchQuery,
    position: &mut PositionCursor,
    hits: &mut Zeroizing<Vec<SearchHit>>,
) {
    let plaintext = document.plaintext.as_str();
    let (line, utf16_column) = position.advance_to(plaintext, byte_range.start);
    let (line_start, line_end) = position.line_bounds(plaintext);
    let snippet = make_snippet(
        plaintext,
        byte_range.start,
        query.snippet_byte_limit,
        line_start,
        line_end,
    );
    hits.push(SearchHit {
        logical_path: document.logical_path.clone(),
        byte_range,
        line,
        utf16_column,
        snippet,
    });
}

#[derive(Default)]
struct PositionCursor {
    byte_offset: usize,
    line: usize,
    utf16_column: usize,
    line_start: usize,
    line_end: Option<usize>,
}

impl PositionCursor {
    fn advance_to(&mut self, text: &str, target: usize) -> (usize, usize) {
        debug_assert!(target >= self.byte_offset && text.is_char_boundary(target));
        let bytes = text.as_bytes();
        while self.byte_offset < target {
            match bytes[self.byte_offset] {
                b'\r' if bytes.get(self.byte_offset + 1) == Some(&b'\n') => {
                    if self.byte_offset + 2 <= target {
                        self.byte_offset += 2;
                        self.line += 1;
                        self.utf16_column = 0;
                        self.line_start = self.byte_offset;
                        self.line_end = None;
                    } else {
                        self.byte_offset += 1;
                    }
                }
                b'\r' | b'\n' => {
                    self.byte_offset += 1;
                    self.line += 1;
                    self.utf16_column = 0;
                    self.line_start = self.byte_offset;
                    self.line_end = None;
                }
                _ => {
                    let character = text[self.byte_offset..]
                        .chars()
                        .next()
                        .unwrap_or_else(|| unreachable!("valid UTF-8 cursor invariant"));
                    self.byte_offset += character.len_utf8();
                    self.utf16_column += character.len_utf16();
                }
            }
        }
        (self.line, self.utf16_column)
    }

    fn line_bounds(&mut self, text: &str) -> (usize, usize) {
        let line_end = *self.line_end.get_or_insert_with(|| {
            text[self.line_start..]
                .find(['\r', '\n'])
                .map_or(text.len(), |offset| self.line_start + offset)
        });
        (self.line_start, line_end)
    }
}

fn make_snippet(
    text: &str,
    match_start: usize,
    byte_limit: usize,
    line_start: usize,
    line_end: usize,
) -> Zeroizing<String> {
    if byte_limit == 0 {
        return Zeroizing::new(String::new());
    }

    let line_text = &text[line_start..line_end];
    if line_text.len() <= byte_limit {
        let mut snippet = Zeroizing::new(String::with_capacity(line_text.len()));
        snippet.push_str(line_text);
        return snippet;
    }

    let match_in_line = match_start - line_start;
    let candidate_start = match_in_line.saturating_sub(byte_limit / 2);
    let window_start = next_char_boundary(line_text, candidate_start, match_in_line);
    let window_end = previous_char_boundary(
        line_text,
        window_start.saturating_add(byte_limit).min(line_text.len()),
        window_start,
    );
    let window = &line_text[window_start..window_end];
    let mut snippet = Zeroizing::new(String::with_capacity(window.len()));
    snippet.push_str(window);
    snippet
}

fn next_char_boundary(text: &str, mut offset: usize, ceiling: usize) -> usize {
    while offset < ceiling && !text.is_char_boundary(offset) {
        offset += 1;
    }
    offset
}

fn previous_char_boundary(text: &str, mut offset: usize, floor: usize) -> usize {
    while offset > floor && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

#[derive(Clone, Copy, Default, Zeroize)]
struct CompactOriginalRange {
    start: u32,
    end: u32,
}

struct StreamingFoldMatcher<'a> {
    pattern: &'a [u8],
    prefix: Zeroizing<Vec<usize>>,
    recent_ranges: Zeroizing<Vec<CompactOriginalRange>>,
    matched: usize,
    folded_position: usize,
}

impl<'a> StreamingFoldMatcher<'a> {
    fn new(pattern: &'a [u8]) -> Self {
        let mut prefix = Zeroizing::new(vec![0; pattern.len()]);
        let mut matched = 0;
        for index in 1..pattern.len() {
            while matched > 0 && pattern[index] != pattern[matched] {
                matched = prefix[matched - 1];
            }
            if pattern[index] == pattern[matched] {
                matched += 1;
            }
            prefix[index] = matched;
        }
        Self {
            pattern,
            prefix,
            recent_ranges: Zeroizing::new(vec![CompactOriginalRange::default(); pattern.len()]),
            matched: 0,
            folded_position: 0,
        }
    }

    fn feed(
        &mut self,
        byte: u8,
        original_start: usize,
        original_end: usize,
    ) -> Option<Range<usize>> {
        let pattern_length = self.pattern.len();
        debug_assert!(pattern_length > 0);
        self.recent_ranges[self.folded_position % pattern_length] = CompactOriginalRange {
            start: u32::try_from(original_start).unwrap_or(u32::MAX),
            end: u32::try_from(original_end).unwrap_or(u32::MAX),
        };
        while self.matched > 0 && byte != self.pattern[self.matched] {
            self.matched = self.prefix[self.matched - 1];
        }
        if byte == self.pattern[self.matched] {
            self.matched += 1;
        }
        self.folded_position += 1;
        if self.matched != pattern_length {
            return None;
        }

        let first = self.recent_ranges[(self.folded_position - pattern_length) % pattern_length];
        let last = self.recent_ranges[(self.folded_position - 1) % pattern_length];
        // Match `str::match_indices` semantics used by sensitive search:
        // results are non-overlapping, even when the pattern has a prefix
        // that could begin another match at the previous end.
        self.matched = 0;
        Some(
            usize::try_from(first.start).unwrap_or(usize::MAX)
                ..usize::try_from(last.end).unwrap_or(usize::MAX),
        )
    }
}

fn fold_query(text: &str) -> Zeroizing<String> {
    let mut folded = Zeroizing::new(String::with_capacity(
        text.chars().count().saturating_mul(128),
    ));
    for character in text.chars() {
        fold_character_into(character, &mut folded);
    }
    folded
}

fn fold_character_into(character: char, folded: &mut String) {
    let initial_length = folded.len();
    match character {
        // Full default case folding preserves LATIN SMALL LETTER DOTLESS I.
        // Cherokee folds to uppercase, unlike all other cased scripts.
        '\u{0131}' | '\u{13a0}'..='\u{13f5}' => {
            folded.push(character);
        }
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
                    for mapped in uppercase.to_lowercase() {
                        folded.push(mapped);
                    }
                }
            }
        }
    }
    debug_assert!(folded.len() - initial_length <= 128);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> LogicalPath {
        LogicalPath::parse(text).unwrap_or_else(|error| panic!("invalid test path: {error}"))
    }

    fn document(path_text: &str, plaintext: &str) -> Document {
        Document::new(path(path_text), Zeroizing::new(plaintext.to_owned()))
            .unwrap_or_else(|error| panic!("invalid test document: {error}"))
    }

    fn query(
        text: &str,
        case_sensitivity: CaseSensitivity,
        result_limit: usize,
        snippet_limit: usize,
    ) -> SearchQuery {
        SearchQuery::new(
            Zeroizing::new(text.to_owned()),
            case_sensitivity,
            result_limit,
            snippet_limit,
        )
        .unwrap_or_else(|error| panic!("invalid test query: {error}"))
    }

    #[test]
    fn searches_chinese_and_reports_original_byte_coordinates() {
        let plaintext = "# 日记\n今天学习强化学习。\n";
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("日记/七月.md", plaintext)).is_ok());

        let hits = index
            .search(&query("强化学习", CaseSensitivity::Sensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        let start = plaintext.find("强化学习").unwrap_or(usize::MAX);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].logical_path().as_str(), "日记/七月.md");
        assert_eq!(hits[0].byte_range(), start..start + "强化学习".len());
        assert_eq!(hits[0].line(), 1);
        assert_eq!(hits[0].utf16_column(), 4);
        assert_eq!(hits[0].snippet(), "今天学习强化学习。");
    }

    #[test]
    fn emoji_uses_two_utf16_columns_but_original_utf8_byte_range() {
        let plaintext = "a😀B emoji";
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("emoji.md", plaintext)).is_ok());
        let hits = index
            .search(&query("b", CaseSensitivity::UnicodeInsensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].byte_range(), 5..6);
        assert_eq!(hits[0].line(), 0);
        assert_eq!(hits[0].utf16_column(), 3);
    }

    #[test]
    fn unicode_insensitive_search_uses_expanding_case_fold() {
        let mut index = MemorySearchIndex::new();
        assert!(
            index
                .upsert(document("unicode.md", "Straße; ς; ı; İ"))
                .is_ok()
        );

        let street = index
            .search(&query(
                "STRASSE",
                CaseSensitivity::UnicodeInsensitive,
                10,
                200,
            ))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(street.len(), 1);
        assert_eq!(street[0].byte_range(), 0.."Straße".len());

        let sigma = index
            .search(&query("Σ", CaseSensitivity::UnicodeInsensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(sigma.len(), 1);
        assert_eq!(sigma[0].snippet(), "Straße; ς; ı; İ");

        let dotless = index
            .search(&query("I", CaseSensitivity::UnicodeInsensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(dotless.len(), 1);
        assert_eq!(dotless[0].byte_range(), 17..19);
    }

    #[test]
    fn sensitive_and_folded_modes_share_non_overlapping_match_semantics() {
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("overlap.md", "aaa Straße")).is_ok());
        for sensitivity in [
            CaseSensitivity::Sensitive,
            CaseSensitivity::UnicodeInsensitive,
        ] {
            let hits = index
                .search(&query("aa", sensitivity, 10, 32))
                .unwrap_or_else(|error| panic!("overlap search failed: {error}"));
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].byte_range(), 0..2);
        }
        let expanded = index
            .search(&query("SS", CaseSensitivity::UnicodeInsensitive, 10, 32))
            .unwrap_or_else(|error| panic!("expansion search failed: {error}"));
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].byte_range(), 8..10);
        let single_expansion = index
            .search(&query("s", CaseSensitivity::UnicodeInsensitive, 10, 32))
            .unwrap_or_else(|error| panic!("single expansion search failed: {error}"));
        assert_eq!(
            single_expansion
                .iter()
                .filter(|hit| hit.byte_range() == (8..10))
                .count(),
            1
        );
    }

    #[test]
    fn canonical_equivalence_is_not_implicit_normalization() {
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("accent.md", "cafe\u{301}")).is_ok());
        let hits = index
            .search(&query(
                "caf\u{e9}",
                CaseSensitivity::UnicodeInsensitive,
                10,
                200,
            ))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert!(hits.is_empty());
    }

    #[test]
    fn treats_crlf_as_one_line_break_and_excludes_it_from_snippets() {
        let plaintext = "first\r\n第二😀行\r\nlast";
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("crlf.md", plaintext)).is_ok());
        let second = index
            .search(&query("😀", CaseSensitivity::Sensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].line(), 1);
        assert_eq!(second[0].utf16_column(), 2);
        assert_eq!(second[0].snippet(), "第二😀行");

        let last = index
            .search(&query("last", CaseSensitivity::Sensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(last[0].line(), 2);
        assert_eq!(last[0].utf16_column(), 0);
    }

    #[test]
    fn searches_multiple_documents_in_logical_path_order() {
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("z.md", "needle z")).is_ok());
        assert!(index.upsert(document("a.md", "needle a")).is_ok());
        assert!(index.upsert(document("m.md", "nothing")).is_ok());
        let hits = index
            .search(&query("needle", CaseSensitivity::Sensitive, 10, 200))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].logical_path().as_str(), "a.md");
        assert_eq!(hits[1].logical_path().as_str(), "z.md");
    }

    #[test]
    fn max_size_adversarial_search_uses_streaming_work_state() {
        let suffix_hits = MAX_SEARCH_RESULTS;
        let prefix_bytes = MAX_SEARCH_DOCUMENT_BYTES - suffix_hits;
        let mut plaintext = String::with_capacity(MAX_SEARCH_DOCUMENT_BYTES);
        plaintext.push_str(&"a".repeat(prefix_bytes));
        plaintext.push_str(&"x".repeat(suffix_hits));
        let mut index = MemorySearchIndex::new();
        assert!(
            index
                .upsert(
                    Document::new(path("maximum.md"), Zeroizing::new(plaintext))
                        .unwrap_or_else(|error| panic!("max document rejected: {error}"))
                )
                .is_ok()
        );

        let absent = index
            .search(&query("z", CaseSensitivity::UnicodeInsensitive, 1, 0))
            .unwrap_or_else(|error| panic!("streaming fold failed: {error}"));
        assert!(absent.is_empty());

        let dense = index
            .search(&query(
                "x",
                CaseSensitivity::Sensitive,
                MAX_SEARCH_RESULTS,
                DEFAULT_SEARCH_SNIPPET_BYTES,
            ))
            .unwrap_or_else(|error| panic!("dense streaming positions failed: {error}"));
        assert_eq!(dense.len(), MAX_SEARCH_RESULTS);
        assert_eq!(dense[0].utf16_column(), prefix_bytes);
        assert_eq!(
            dense[MAX_SEARCH_RESULTS - 1].utf16_column(),
            MAX_SEARCH_DOCUMENT_BYTES - 1
        );
    }

    #[test]
    fn streaming_fold_matches_reference_mapping_corpus() {
        let alphabet = [
            "a", "A", "ß", "Σ", "ς", "ı", "İ", "😀", "日", "\r", "\n", " ",
        ];
        let alphabet_length = u64::try_from(alphabet.len()).unwrap_or(1);
        let mut state = 0x5eed_cafe_d15c_a11e_u64;
        for case_index in 0..64 {
            let mut plaintext = String::new();
            for _ in 0..48 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let index = usize::try_from(state % alphabet_length).unwrap_or(0);
                plaintext.push_str(alphabet[index]);
            }
            let mut query_text = String::new();
            for _ in 0..=case_index % 4 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let index = usize::try_from(state % alphabet_length).unwrap_or(0);
                query_text.push_str(alphabet[index]);
            }

            let expected = reference_folded_ranges(&plaintext, &query_text);
            let mut index = MemorySearchIndex::new();
            assert!(
                index
                    .upsert(document("differential.md", &plaintext))
                    .is_ok()
            );
            let actual = index
                .search(&query(
                    &query_text,
                    CaseSensitivity::UnicodeInsensitive,
                    MAX_SEARCH_RESULTS,
                    0,
                ))
                .unwrap_or_else(|error| panic!("case {case_index} failed: {error}"))
                .iter()
                .map(SearchHit::byte_range)
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "case {case_index}");
        }
    }

    fn reference_folded_ranges(text: &str, query_text: &str) -> Vec<Range<usize>> {
        let mut folded = String::new();
        let mut mapping = Vec::new();
        for (original_start, character) in text.char_indices() {
            let original_end = original_start + character.len_utf8();
            let folded_start = folded.len();
            fold_character_into(character, &mut folded);
            for (offset, mapped) in folded[folded_start..].char_indices() {
                let start = folded_start + offset;
                mapping.push((
                    start,
                    start + mapped.len_utf8(),
                    original_start,
                    original_end,
                ));
            }
        }
        let folded_query = fold_query(query_text);
        let mut ranges = Vec::new();
        for (start, matched) in folded.match_indices(folded_query.as_str()) {
            let end = start + matched.len();
            let first = mapping.partition_point(|entry| entry.1 <= start);
            let after_last = mapping.partition_point(|entry| entry.0 < end);
            if first < after_last {
                let range = mapping[first].2..mapping[after_last - 1].3;
                if ranges.last() != Some(&range) {
                    ranges.push(range);
                }
            }
        }
        ranges
    }

    #[test]
    fn enforces_exact_result_and_utf8_snippet_limits() {
        let plaintext = "😀0123456789 needle needle needle";
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("limits.md", plaintext)).is_ok());
        let hits = index
            .search(&query("needle", CaseSensitivity::Sensitive, 2, 10))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|hit| hit.snippet().len() <= 10));
        assert!(
            hits.iter()
                .all(|hit| std::str::from_utf8(hit.snippet().as_bytes()).is_ok())
        );

        let no_snippet = index
            .search(&query("needle", CaseSensitivity::Sensitive, 1, 0))
            .unwrap_or_else(|error| panic!("search failed: {error}"));
        assert_eq!(no_snippet[0].snippet(), "");
    }

    #[test]
    fn enforces_exact_index_byte_and_document_limits_atomically() {
        let mut index = MemorySearchIndex::with_limits(2, 8)
            .unwrap_or_else(|error| panic!("index construction failed: {error}"));
        assert!(index.upsert(document("a.md", "1234")).is_ok());
        assert!(index.upsert(document("b.md", "5678")).is_ok());
        assert_eq!(index.document_count(), 2);
        assert_eq!(index.plaintext_bytes(), 8);

        assert_eq!(
            index.upsert(document("c.md", "")),
            Err(SearchError::TooManyDocuments {
                actual: 3,
                maximum: 2,
            })
        );
        assert_eq!(
            index.upsert(document("a.md", "12345")),
            Err(SearchError::IndexTooLarge {
                actual: 9,
                maximum: 8,
            })
        );
        assert_eq!(index.document_count(), 2);
        assert_eq!(index.plaintext_bytes(), 8);
        assert_eq!(
            index
                .search(&query("1234", CaseSensitivity::Sensitive, 10, 200))
                .map(|hits| hits.len()),
            Ok(1)
        );
    }

    #[test]
    fn validates_query_bounds_in_utf8_bytes() {
        assert!(
            SearchQuery::new(
                Zeroizing::new("x".repeat(MAX_SEARCH_QUERY_BYTES)),
                CaseSensitivity::Sensitive,
                MAX_SEARCH_RESULTS,
                MAX_SEARCH_SNIPPET_BYTES,
            )
            .is_ok()
        );
        assert!(matches!(
            SearchQuery::new(
                Zeroizing::new("x".repeat(MAX_SEARCH_QUERY_BYTES + 1)),
                CaseSensitivity::Sensitive,
                1,
                1,
            ),
            Err(SearchError::QueryTooLarge {
                actual,
                maximum: MAX_SEARCH_QUERY_BYTES,
            }) if actual == MAX_SEARCH_QUERY_BYTES + 1
        ));
        assert!(matches!(
            SearchQuery::new(
                Zeroizing::new("查".to_owned()),
                CaseSensitivity::Sensitive,
                0,
                1,
            ),
            Err(SearchError::ZeroResultLimit)
        ));
        assert!(matches!(
            SearchQuery::new(
                Zeroizing::new("查".to_owned()),
                CaseSensitivity::Sensitive,
                1,
                MAX_SEARCH_SNIPPET_BYTES + 1,
            ),
            Err(SearchError::SnippetLimitTooLarge {
                actual,
                maximum: MAX_SEARCH_SNIPPET_BYTES,
            }) if actual == MAX_SEARCH_SNIPPET_BYTES + 1
        ));
        assert!(matches!(
            SearchQuery::new(
                Zeroizing::new("查".to_owned()),
                CaseSensitivity::Sensitive,
                MAX_SEARCH_RESULTS + 1,
                1,
            ),
            Err(SearchError::ResultLimitTooLarge {
                actual,
                maximum: MAX_SEARCH_RESULTS,
            }) if actual == MAX_SEARCH_RESULTS + 1
        ));
    }

    #[test]
    fn enforces_document_limit_at_exact_utf8_byte_boundary() {
        let accepted = Document::new(
            path("maximum.md"),
            Zeroizing::new("x".repeat(MAX_SEARCH_DOCUMENT_BYTES)),
        );
        assert!(accepted.is_ok());

        let rejected = Document::new(
            path("too-large.md"),
            Zeroizing::new("x".repeat(MAX_SEARCH_DOCUMENT_BYTES + 1)),
        );
        assert!(matches!(
            rejected,
            Err(SearchError::DocumentTooLarge {
                actual,
                maximum: MAX_SEARCH_DOCUMENT_BYTES,
            }) if actual == MAX_SEARCH_DOCUMENT_BYTES + 1
        ));
    }

    #[test]
    fn clear_evicts_documents_and_invalidates_cleared_queries() {
        let mut standalone = document("standalone.md", "secret");
        standalone.clear();
        assert_eq!(standalone.plaintext(), "");

        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document("secret.md", "do not retain")).is_ok());
        index.clear();
        assert_eq!(index.document_count(), 0);
        assert_eq!(index.plaintext_bytes(), 0);

        let mut cleared_query = query("retain", CaseSensitivity::Sensitive, 10, 200);
        cleared_query.clear();
        assert!(matches!(
            index.search(&cleared_query),
            Err(SearchError::EmptyQuery)
        ));
    }

    #[test]
    fn debug_output_redacts_all_plaintext_fields() {
        let document = document("debug.md", "document-secret query-secret");
        let query = query("query-secret", CaseSensitivity::Sensitive, 10, 200);
        let mut index = MemorySearchIndex::new();
        assert!(index.upsert(document).is_ok());
        let hits = index
            .search(&query)
            .unwrap_or_else(|error| panic!("search failed: {error}"));

        assert!(!format!("{index:?}").contains("document-secret"));
        assert!(!format!("{query:?}").contains("query-secret"));
        assert!(!format!("{:?}", hits[0]).contains("document-secret"));
        assert!(format!("{:?}", hits[0]).contains("[REDACTED]"));
    }
}
