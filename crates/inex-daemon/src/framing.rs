//! Strict Content-Length framing for the daemon's protocol-only stdio stream.
//!
//! This module deliberately keeps request bodies out of diagnostics. A caller
//! can map [`FramingError`] to a safe JSON-RPC error through its code, stable
//! name, and fixed display message without logging untrusted plaintext.

use std::fmt;
use std::io::{self, BufRead, Write};

use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Maximum accepted or emitted JSON body size: 24 MiB.
pub const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;

/// Maximum framing-header size, including its terminating blank line.
///
/// Version 1 has exactly one short header. This bound prevents an unterminated
/// or malicious header from causing unbounded allocation.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// A JSON object carried by one protocol frame.
pub type JsonObject = Map<String, Value>;

/// The I/O operation that failed while reading or writing a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOperation {
    /// Reading a framing header.
    ReadHeader,
    /// Reading a JSON body.
    ReadBody,
    /// Writing a canonical frame.
    Write,
    /// Flushing a written frame.
    Flush,
}

/// Safe, body-free errors produced by strict frame decoding and encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FramingError {
    /// The stream ended after part of a header had arrived.
    UnexpectedEofHeader,
    /// The stream ended before the declared body length arrived.
    UnexpectedEofBody,
    /// Header bytes did not follow the ASCII `name: value\r\n` grammar.
    InvalidHeader,
    /// The header exceeded [`MAX_HEADER_BYTES`].
    HeaderTooLarge,
    /// No Content-Length header was present.
    MissingContentLength,
    /// More than one Content-Length header was present.
    DuplicateContentLength,
    /// A header other than Content-Length was present.
    UnknownHeader,
    /// Content-Length was empty, signed, non-decimal, or not representable.
    InvalidContentLength,
    /// The declared or serialized body exceeded [`MAX_FRAME_BYTES`].
    FrameTooLarge,
    /// The declared body was not valid UTF-8.
    InvalidUtf8,
    /// The body was not valid JSON.
    InvalidJson,
    /// The JSON value was not an object; batches are intentionally unsupported.
    JsonObjectRequired,
    /// A body-free I/O failure occurred.
    Io {
        /// Which framing operation failed.
        operation: IoOperation,
        /// The safe standard category of the I/O failure.
        kind: io::ErrorKind,
    },
}

impl FramingError {
    /// JSON-RPC/application error code suitable for a response with a null id.
    #[must_use]
    pub const fn json_rpc_code(&self) -> i32 {
        match self {
            Self::FrameTooLarge | Self::HeaderTooLarge => -32_008,
            Self::JsonObjectRequired => -32_600,
            Self::Io { .. } => -32_009,
            Self::UnexpectedEofHeader
            | Self::UnexpectedEofBody
            | Self::InvalidHeader
            | Self::MissingContentLength
            | Self::DuplicateContentLength
            | Self::UnknownHeader
            | Self::InvalidContentLength
            | Self::InvalidUtf8
            | Self::InvalidJson => -32_700,
        }
    }

    /// Stable machine-readable error name that never contains request data.
    #[must_use]
    pub const fn stable_name(&self) -> &'static str {
        match self {
            Self::FrameTooLarge | Self::HeaderTooLarge => "LIMIT_EXCEEDED",
            Self::JsonObjectRequired => "INVALID_REQUEST",
            Self::Io { .. } => "IO_FAILED",
            Self::UnexpectedEofHeader => "UNEXPECTED_EOF_HEADER",
            Self::UnexpectedEofBody => "UNEXPECTED_EOF_BODY",
            Self::InvalidHeader => "INVALID_HEADER",
            Self::MissingContentLength => "MISSING_CONTENT_LENGTH",
            Self::DuplicateContentLength => "DUPLICATE_CONTENT_LENGTH",
            Self::UnknownHeader => "UNKNOWN_HEADER",
            Self::InvalidContentLength => "INVALID_CONTENT_LENGTH",
            Self::InvalidUtf8 => "INVALID_UTF8",
            Self::InvalidJson => "INVALID_JSON",
        }
    }

    const fn safe_message(&self) -> &'static str {
        match self {
            Self::FrameTooLarge | Self::HeaderTooLarge => {
                "Request exceeds the configured protocol limit"
            }
            Self::JsonObjectRequired => "JSON-RPC request must be one object",
            Self::Io { .. } => "Protocol I/O failed",
            Self::UnexpectedEofHeader
            | Self::UnexpectedEofBody
            | Self::InvalidHeader
            | Self::MissingContentLength
            | Self::DuplicateContentLength
            | Self::UnknownHeader
            | Self::InvalidContentLength
            | Self::InvalidUtf8
            | Self::InvalidJson => "Invalid protocol frame",
        }
    }

    fn io(operation: IoOperation, error: &io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

impl fmt::Display for FramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for FramingError {}

/// Read one strict Content-Length framed JSON object.
///
/// A clean EOF before any header byte returns `Ok(None)`. EOF after a frame has
/// started is an error. The reader consumes exactly the declared body bytes, so
/// a subsequent call starts at the next frame.
///
/// # Errors
///
/// Returns [`FramingError`] for malformed or oversized framing, incomplete
/// input, non-UTF-8/invalid JSON bodies, non-object JSON values, or safe I/O
/// failures.
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<JsonObject>, FramingError> {
    let Some(content_length) = read_content_length(reader)? else {
        return Ok(None);
    };

    if content_length > MAX_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge);
    }

    let mut body = Zeroizing::new(vec![0_u8; content_length]);
    read_body_exact(reader, &mut body)?;
    let text = std::str::from_utf8(&body).map_err(|_| FramingError::InvalidUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(|_| FramingError::InvalidJson)?;
    match value {
        Value::Object(object) => Ok(Some(object)),
        _ => Err(FramingError::JsonObjectRequired),
    }
}

/// Write one JSON object with the canonical v1 Content-Length header and flush.
///
/// The body is compact UTF-8 JSON. This function accepts only a JSON object,
/// preventing accidental emission of unsupported batch arrays.
///
/// # Errors
///
/// Returns [`FramingError::FrameTooLarge`] when serialization exceeds the v1
/// limit, or a body-free [`FramingError::Io`] for write/flush failures.
pub fn write_frame<W: Write>(writer: &mut W, object: &JsonObject) -> Result<(), FramingError> {
    // Serialization of serde_json::Value is infallible in practice, but keep a
    // safe fixed error if that contract ever changes.
    let body = Zeroizing::new(serde_json::to_vec(object).map_err(|_| FramingError::InvalidJson)?);
    if body.len() > MAX_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge);
    }

    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer
        .write_all(header.as_bytes())
        .map_err(|error| FramingError::io(IoOperation::Write, &error))?;
    writer
        .write_all(&body)
        .map_err(|error| FramingError::io(IoOperation::Write, &error))?;
    writer
        .flush()
        .map_err(|error| FramingError::io(IoOperation::Flush, &error))
}

fn read_content_length<R: BufRead>(reader: &mut R) -> Result<Option<usize>, FramingError> {
    let mut header_bytes = 0_usize;
    let mut saw_any_bytes = false;
    let mut content_length = None;
    let mut line = Vec::new();

    loop {
        line.clear();
        let line_present = read_header_line(reader, &mut line, &mut header_bytes)?;
        if !line_present {
            return if saw_any_bytes || !line.is_empty() {
                Err(FramingError::UnexpectedEofHeader)
            } else {
                Ok(None)
            };
        }
        saw_any_bytes = true;

        if !line.ends_with(b"\r\n") {
            return Err(FramingError::InvalidHeader);
        }
        line.truncate(line.len() - 2);
        if line.is_empty() {
            return content_length
                .ok_or(FramingError::MissingContentLength)
                .map(Some);
        }

        if !line.is_ascii() {
            return Err(FramingError::InvalidHeader);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(FramingError::InvalidHeader);
        };
        let (name, value_with_colon) = line.split_at(colon);
        let value = trim_optional_whitespace(&value_with_colon[1..]);
        if name.is_empty() || name.iter().any(|byte| !is_header_name_byte(*byte)) {
            return Err(FramingError::InvalidHeader);
        }
        if !name.eq_ignore_ascii_case(b"Content-Length") {
            return Err(FramingError::UnknownHeader);
        }
        if content_length.is_some() {
            return Err(FramingError::DuplicateContentLength);
        }
        content_length = Some(parse_content_length(value)?);
    }
}

fn read_header_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    header_bytes: &mut usize,
) -> Result<bool, FramingError> {
    loop {
        let available = loop {
            match reader.fill_buf() {
                Ok(available) => break available,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(FramingError::io(IoOperation::ReadHeader, &error));
                }
            }
        };
        if available.is_empty() {
            return Ok(false);
        }

        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if header_bytes.saturating_add(take) > MAX_HEADER_BYTES {
            return Err(FramingError::HeaderTooLarge);
        }
        let found_newline = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        *header_bytes += take;
        if found_newline {
            return Ok(true);
        }
    }
}

fn read_body_exact<R: BufRead>(reader: &mut R, mut body: &mut [u8]) -> Result<(), FramingError> {
    while !body.is_empty() {
        match reader.read(body) {
            Ok(0) => return Err(FramingError::UnexpectedEofBody),
            Ok(read) => body = &mut body[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(FramingError::io(IoOperation::ReadBody, &error)),
        }
    }
    Ok(())
}

fn parse_content_length(value: &[u8]) -> Result<usize, FramingError> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(FramingError::InvalidContentLength);
    }

    value.iter().try_fold(0_usize, |length, byte| {
        length
            .checked_mul(10)
            .and_then(|current| current.checked_add(usize::from(*byte - b'0')))
            .ok_or(FramingError::InvalidContentLength)
    })
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

const fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{BufReader, Cursor, Read};

    fn framed(header_name: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = format!("{header_name}: {}\r\n\r\n", body.len()).into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn read_bytes(bytes: &[u8]) -> Result<Option<JsonObject>, FramingError> {
        read_frame(&mut Cursor::new(bytes))
    }

    #[test]
    fn reads_object_and_case_insensitive_header() {
        let object = read_bytes(&framed("cOnTeNt-LeNgTh", br#"{"jsonrpc":"2.0","id":1}"#))
            .unwrap()
            .unwrap();
        assert_eq!(object["jsonrpc"], "2.0");
        assert_eq!(object["id"], 1);
    }

    #[test]
    fn accepts_optional_header_whitespace_and_zero_padded_decimal() {
        let bytes = b"Content-Length:\t 0002 \t\r\n\r\n{}";
        assert_eq!(read_bytes(bytes).unwrap().unwrap(), JsonObject::new());
    }

    #[test]
    fn clean_eof_is_not_a_truncated_frame() {
        assert_eq!(read_bytes(b"").unwrap(), None);
        assert_eq!(
            read_bytes(b"Content-Length: 2\r\n").unwrap_err(),
            FramingError::UnexpectedEofHeader
        );
    }

    #[test]
    fn rejects_duplicate_header_regardless_of_case() {
        let bytes = b"Content-Length: 2\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(
            read_bytes(bytes).unwrap_err(),
            FramingError::DuplicateContentLength
        );
    }

    #[test]
    fn rejects_unknown_missing_and_malformed_headers() {
        for (bytes, expected) in [
            (&b"X-Trace: 2\r\n\r\n{}"[..], FramingError::UnknownHeader),
            (&b"\r\n{}"[..], FramingError::MissingContentLength),
            (
                &b"Content-Length 2\r\n\r\n{}"[..],
                FramingError::InvalidHeader,
            ),
            (
                &b"Content Length: 2\r\n\r\n{}"[..],
                FramingError::InvalidHeader,
            ),
            (&b"Content-Length: 2\n\n{}"[..], FramingError::InvalidHeader),
            (
                &b"Content-Length: 2\rX"[..],
                FramingError::UnexpectedEofHeader,
            ),
            (
                &b"Cont\xffent-Length: 2\r\n\r\n{}"[..],
                FramingError::InvalidHeader,
            ),
        ] {
            assert_eq!(read_bytes(bytes).unwrap_err(), expected);
        }
    }

    #[test]
    fn rejects_signed_nondecimal_empty_and_overflowing_lengths() {
        for value in [
            "+2",
            "-2",
            "2.0",
            "2 0",
            "",
            "18446744073709551616000000000000000000",
        ] {
            let bytes = format!("Content-Length: {value}\r\n\r\n{{}}");
            assert_eq!(
                read_bytes(bytes.as_bytes()).unwrap_err(),
                FramingError::InvalidContentLength,
                "value {value:?}"
            );
        }
    }

    #[test]
    fn rejects_oversized_body_before_allocating_or_reading_it() {
        let bytes = format!("Content-Length: {}\r\n\r\n", MAX_FRAME_BYTES + 1);
        assert_eq!(
            read_bytes(bytes.as_bytes()).unwrap_err(),
            FramingError::FrameTooLarge
        );
    }

    #[test]
    fn rejects_unbounded_header() {
        let bytes = vec![b'A'; MAX_HEADER_BYTES + 1];
        assert_eq!(
            read_bytes(&bytes).unwrap_err(),
            FramingError::HeaderTooLarge
        );
    }

    #[test]
    fn body_must_be_exact_utf8_json_object() {
        for (body, expected) in [
            (&b"{"[..], FramingError::InvalidJson),
            (&b"\xff"[..], FramingError::InvalidUtf8),
            (&b"[]"[..], FramingError::JsonObjectRequired),
            (&b"null"[..], FramingError::JsonObjectRequired),
            (&b"\"value\""[..], FramingError::JsonObjectRequired),
        ] {
            assert_eq!(
                read_bytes(&framed("Content-Length", body)).unwrap_err(),
                expected
            );
        }
        let truncated = b"Content-Length: 3\r\n\r\n{}";
        assert_eq!(
            read_bytes(truncated).unwrap_err(),
            FramingError::UnexpectedEofBody
        );
    }

    #[test]
    fn consumes_exact_body_and_leaves_next_frame() {
        let mut bytes = framed("Content-Length", br#"{"id":1}"#);
        bytes.extend_from_slice(&framed("Content-Length", br#"{"id":2}"#));
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_frame(&mut reader).unwrap().unwrap()["id"], 1);
        assert_eq!(read_frame(&mut reader).unwrap().unwrap()["id"], 2);
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[derive(Debug)]
    struct ChunkedRead {
        bytes: Cursor<Vec<u8>>,
        chunk_size: usize,
        interrupt_next: bool,
    }

    impl Read for ChunkedRead {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let length = buffer.len().min(self.chunk_size);
            self.bytes.read(&mut buffer[..length])
        }
    }

    #[test]
    fn handles_partial_and_interrupted_reads() {
        let source = ChunkedRead {
            bytes: Cursor::new(framed("Content-Length", br#"{"ok":true}"#)),
            chunk_size: 1,
            interrupt_next: true,
        };
        let mut reader = BufReader::with_capacity(2, source);
        let object = read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(object["ok"], true);
    }

    #[derive(Debug, Default)]
    struct ChunkedWrite {
        bytes: Vec<u8>,
        chunk_size: usize,
        outcomes: VecDeque<io::ErrorKind>,
        flushed: bool,
    }

    impl Write for ChunkedWrite {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.outcomes.pop_front() {
                return Err(io::Error::new(kind, "sensitive injected detail"));
            }
            let length = buffer.len().min(self.chunk_size);
            self.bytes.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn writer_is_canonical_and_handles_partial_interrupted_writes() {
        let mut object = JsonObject::new();
        object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        let mut writer = ChunkedWrite {
            chunk_size: 2,
            outcomes: VecDeque::from([io::ErrorKind::Interrupted]),
            ..ChunkedWrite::default()
        };
        write_frame(&mut writer, &object).unwrap();
        assert!(writer.flushed);
        assert_eq!(
            writer.bytes,
            b"Content-Length: 17\r\n\r\n{\"jsonrpc\":\"2.0\"}"
        );
    }

    #[test]
    fn writer_rejects_oversized_object_before_output() {
        let mut object = JsonObject::new();
        object.insert(
            "content".to_owned(),
            Value::String("x".repeat(MAX_FRAME_BYTES)),
        );
        let mut output = Vec::new();
        assert_eq!(
            write_frame(&mut output, &object).unwrap_err(),
            FramingError::FrameTooLarge
        );
        assert!(output.is_empty());
    }

    #[test]
    fn io_errors_and_diagnostics_do_not_echo_sensitive_details() {
        let mut object = JsonObject::new();
        object.insert("secret".to_owned(), Value::String("do-not-log".to_owned()));
        let mut writer = ChunkedWrite {
            chunk_size: usize::MAX,
            outcomes: VecDeque::from([io::ErrorKind::BrokenPipe]),
            ..ChunkedWrite::default()
        };
        let error = write_frame(&mut writer, &object).unwrap_err();
        assert_eq!(
            error,
            FramingError::Io {
                operation: IoOperation::Write,
                kind: io::ErrorKind::BrokenPipe,
            }
        );
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("do-not-log"));
        assert!(!diagnostic.contains("sensitive injected detail"));
        assert_eq!(error.json_rpc_code(), -32_009);
        assert_eq!(error.stable_name(), "IO_FAILED");
    }

    #[test]
    fn errors_have_stable_safe_json_rpc_classification() {
        assert_eq!(FramingError::InvalidJson.json_rpc_code(), -32_700);
        assert_eq!(FramingError::InvalidJson.stable_name(), "INVALID_JSON");
        assert_eq!(FramingError::JsonObjectRequired.json_rpc_code(), -32_600);
        assert_eq!(FramingError::FrameTooLarge.json_rpc_code(), -32_008);
        assert!(!FramingError::InvalidJson.to_string().contains("json"));
    }
}
