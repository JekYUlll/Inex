//! Search-query acquisition from a hidden TTY or allocation-bounded stdin.
//!
//! `rpassword` 7.5.4 does not expose a caller-bounded hidden-TTY reader. The
//! TTY path therefore validates the byte limit immediately after Enter; the
//! explicit-stdin path enforces the limit while reading.

use std::fmt;
use std::io::{self, BufRead, Read};

use inex_core::search::MAX_SEARCH_QUERY_BYTES;
use zeroize::Zeroizing;

const QUERY_STDIN_ENV: &str = "INEX_QUERY_STDIN";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryInput {
    Tty,
    ExplicitStdin,
}

impl QueryInput {
    pub(crate) fn from_environment() -> Result<Self, QueryError> {
        match std::env::var_os(QUERY_STDIN_ENV) {
            None => Ok(Self::Tty),
            Some(value) if value == "1" => Ok(Self::ExplicitStdin),
            Some(_) => Err(QueryError::InvalidStdinOptIn),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryError {
    InvalidStdinOptIn,
    ReadFailed(io::ErrorKind),
    MissingQuery,
    QueryTooLong,
    QueryNotUtf8,
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStdinOptIn => formatter.write_str(
                "INEX_QUERY_STDIN must be absent or exactly `1`; search-query values are forbidden in environment variables",
            ),
            Self::ReadFailed(kind) => write!(formatter, "search-query input failed: {kind:?}"),
            Self::MissingQuery => {
                formatter.write_str("search-query input ended before a value was read")
            }
            Self::QueryTooLong => {
                formatter.write_str("search query exceeds the supported byte limit")
            }
            Self::QueryNotUtf8 => formatter.write_str("search-query input must be valid UTF-8"),
        }
    }
}

impl std::error::Error for QueryError {}

pub(crate) fn read_query(input: QueryInput) -> Result<Zeroizing<String>, QueryError> {
    let query = match input {
        QueryInput::Tty => {
            // No public rpassword API combines terminal echo suppression with
            // a caller-controlled read bound. Validate immediately below.
            Zeroizing::new(
                rpassword::prompt_password("Search query (hidden): ")
                    .map_err(|error| QueryError::ReadFailed(error.kind()))?,
            )
        }
        QueryInput::ExplicitStdin => {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();
            read_query_line(&mut stdin)?
        }
    };
    validate_query_input(&query)?;
    Ok(query)
}

fn read_query_line<R: BufRead>(reader: &mut R) -> Result<Zeroizing<String>, QueryError> {
    let maximum_read = u64::try_from(MAX_SEARCH_QUERY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SEARCH_QUERY_BYTES.min(256)));
    reader
        .take(maximum_read)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| QueryError::ReadFailed(error.kind()))?;
    if bytes.is_empty() {
        return Err(QueryError::MissingQuery);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(QueryError::QueryTooLong);
    }
    let query = std::str::from_utf8(bytes.as_slice()).map_err(|_| QueryError::QueryNotUtf8)?;
    let query = Zeroizing::new(query.to_owned());
    validate_query_input(&query)?;
    Ok(query)
}

fn validate_query_input(query: &str) -> Result<(), QueryError> {
    if query.is_empty() {
        return Err(QueryError::MissingQuery);
    }
    if query.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(QueryError::QueryTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn explicit_line_strips_only_line_terminators() {
        let mut input = Cursor::new(b" search words \r\nnext\n".to_vec());
        let first = read_query_line(&mut input)
            .unwrap_or_else(|error| panic!("first read failed: {error}"));
        let second = read_query_line(&mut input)
            .unwrap_or_else(|error| panic!("second read failed: {error}"));
        assert_eq!(first.as_str(), " search words ");
        assert_eq!(second.as_str(), "next");
    }

    #[test]
    fn explicit_line_accepts_maximum_utf8_query() {
        let text = "x".repeat(MAX_SEARCH_QUERY_BYTES);
        let mut input = Cursor::new(format!("{text}\r\n").into_bytes());
        let query =
            read_query_line(&mut input).unwrap_or_else(|error| panic!("read failed: {error}"));
        assert_eq!(query.len(), MAX_SEARCH_QUERY_BYTES);
    }

    #[test]
    fn explicit_line_rejects_missing_oversize_and_non_utf8() {
        let mut missing = Cursor::new(b"\n".to_vec());
        assert!(matches!(
            read_query_line(&mut missing),
            Err(QueryError::MissingQuery)
        ));

        let mut oversized = Cursor::new(vec![b'x'; MAX_SEARCH_QUERY_BYTES + 1]);
        assert!(matches!(
            read_query_line(&mut oversized),
            Err(QueryError::QueryTooLong)
        ));

        let mut non_utf8 = Cursor::new(vec![0xff, b'\n']);
        assert!(matches!(
            read_query_line(&mut non_utf8),
            Err(QueryError::QueryNotUtf8)
        ));
    }

    #[test]
    fn errors_never_retain_query_text() {
        let error = QueryError::MissingQuery;
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("search-canary-secret"));
        assert!(!debug.contains("search-canary-secret"));
    }
}
