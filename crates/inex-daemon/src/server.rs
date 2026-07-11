//! Bounded, protocol-only stdio transport for the Inex sidecar.
//!
//! Frame decoding runs on a detached reader thread because a blocking stdin
//! read must not keep an idle vault session alive. A zero-capacity channel
//! applies rendezvous backpressure: while the dispatcher handles one request,
//! the reader can parse at most one additional frame and then blocks before it
//! can consume another. The dispatcher wakes on a bounded timer to expire
//! session state even when no client bytes arrive.

use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Duration;

use crate::framing::{FramingError, JsonObject, read_frame, write_frame};
use crate::handler::RpcService;
use crate::protocol::{ErrorCode, ErrorObject, Response};
use crate::sensitive::scrub_object;
use crate::session::MonotonicClock;

/// Maximum time an idle stdin read may delay a session-expiry check.
pub const IDLE_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Normal reason that a server loop stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerExit {
    /// The client cleanly closed stdin before starting another frame.
    CleanEof,
    /// A successful `system.shutdown` response was flushed.
    ShutdownRequested,
    /// A framing failure left the byte stream at an unknown boundary.
    Desynchronized(FramingError),
}

/// Safe transport failure that never contains request data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerError {
    /// The bounded reader thread could not be started.
    ReaderStart(io::ErrorKind),
    /// The reader stopped without delivering a terminal event.
    ReaderStopped,
    /// A response could not be serialized, written, or flushed.
    ResponseWrite(FramingError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReaderStart(_) => "protocol reader could not start",
            Self::ReaderStopped => "protocol reader stopped unexpectedly",
            Self::ResponseWrite(_) => "protocol response could not be written",
        })
    }
}

impl std::error::Error for ServerError {}

/// Run the production sidecar over process stdin and stdout.
///
/// Stdout is used exclusively for framed responses. This function does not
/// log request objects, parameters, or transport errors.
///
/// # Errors
///
/// Returns a safe [`ServerError`] if the reader cannot start or a response
/// cannot be written and flushed.
pub fn run_stdio() -> Result<ServerExit, ServerError> {
    let reader = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    run_transport(reader, &mut writer, RpcService::new())
}

/// Run one sidecar service over an owned reader and caller-owned writer.
///
/// The reader is moved to a detached thread and therefore must be owned,
/// sendable, and `'static`. The service is consumed so every exit path drops
/// its session store and wipes the unlocked vault state. No reader-thread join
/// is attempted: joining a thread blocked on stdin would deadlock shutdown.
///
/// # Errors
///
/// Returns a safe [`ServerError`] if the reader cannot start, stops without a
/// terminal event, or a response cannot be written and flushed.
pub fn run_transport<R, W, C>(
    reader: R,
    writer: &mut W,
    service: RpcService<C>,
) -> Result<ServerExit, ServerError>
where
    R: BufRead + Send + 'static,
    W: Write,
    C: MonotonicClock,
{
    run_service(reader, writer, service, IDLE_EXPIRY_POLL_INTERVAL)
}

trait RequestService {
    fn handle_object(&mut self, object: JsonObject) -> Response;
    fn expire_idle_session(&mut self) -> bool;
    fn shutdown_requested(&self) -> bool;
}

impl<C: MonotonicClock> RequestService for RpcService<C> {
    fn handle_object(&mut self, object: JsonObject) -> Response {
        Self::handle_object(self, object)
    }

    fn expire_idle_session(&mut self) -> bool {
        Self::expire_idle_session(self)
    }

    fn shutdown_requested(&self) -> bool {
        Self::shutdown_requested(self)
    }
}

fn run_service<R, W, S>(
    reader: R,
    writer: &mut W,
    mut service: S,
    poll_interval: Duration,
) -> Result<ServerExit, ServerError>
where
    R: BufRead + Send + 'static,
    W: Write,
    S: RequestService,
{
    let events = spawn_reader(reader)?;
    loop {
        // Running this before every wait also covers sustained request traffic;
        // recv_timeout provides the bounded wake-up while stdin is quiet.
        service.expire_idle_session();
        match events.recv_timeout(poll_interval) {
            Ok(ReaderEvent::Frame(object)) => {
                let response = service.handle_object(object);
                let should_shutdown = service.shutdown_requested();
                write_response(writer, response)?;
                if should_shutdown {
                    return Ok(ServerExit::ShutdownRequested);
                }
            }
            Ok(ReaderEvent::CleanEof) => return Ok(ServerExit::CleanEof),
            Ok(ReaderEvent::Error(error)) if stream_is_aligned(&error) => {
                write_response(writer, framing_error_response(&error))?;
            }
            Ok(ReaderEvent::Error(error)) => {
                return Ok(ServerExit::Desynchronized(error));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(ServerError::ReaderStopped),
        }
    }
}

fn write_response<W: Write>(writer: &mut W, response: Response) -> Result<(), ServerError> {
    let mut object = response.into_json_object();
    write_scrubbed_object(writer, &mut object).map_err(ServerError::ResponseWrite)
}

fn write_scrubbed_object<W: Write>(
    writer: &mut W,
    object: &mut JsonObject,
) -> Result<(), FramingError> {
    let result = write_frame(writer, object);
    scrub_object(object);
    result
}

const fn stream_is_aligned(error: &FramingError) -> bool {
    matches!(
        error,
        FramingError::InvalidUtf8 | FramingError::InvalidJson | FramingError::JsonObjectRequired
    )
}

fn framing_error_response(error: &FramingError) -> Response {
    let code = match error {
        FramingError::JsonObjectRequired => ErrorCode::InvalidRequest,
        FramingError::FrameTooLarge | FramingError::HeaderTooLarge => ErrorCode::LimitExceeded,
        FramingError::Io { .. } => ErrorCode::IoFailed,
        FramingError::UnexpectedEofHeader
        | FramingError::UnexpectedEofBody
        | FramingError::InvalidHeader
        | FramingError::MissingContentLength
        | FramingError::DuplicateContentLength
        | FramingError::UnknownHeader
        | FramingError::InvalidContentLength
        | FramingError::InvalidUtf8
        | FramingError::InvalidJson => ErrorCode::ParseError,
    };
    Response::error(None, ErrorObject::new(code))
}

enum ReaderEvent {
    Frame(JsonObject),
    CleanEof,
    Error(FramingError),
}

fn spawn_reader<R>(reader: R) -> Result<Receiver<ReaderEvent>, ServerError>
where
    R: BufRead + Send + 'static,
{
    // A rendezvous channel holds no queued event. Once the dispatcher accepts
    // an event, the reader may parse one successor and then blocks delivering
    // it, so no more than one fully parsed frame can be pending.
    let (sender, receiver) = mpsc::sync_channel(0);
    thread::Builder::new()
        .name("inex-stdio-reader".to_owned())
        .spawn(move || reader_loop(reader, &sender))
        .map_err(|error| ServerError::ReaderStart(error.kind()))?;
    Ok(receiver)
}

fn reader_loop<R: BufRead>(mut reader: R, sender: &SyncSender<ReaderEvent>) {
    loop {
        let (event, terminal) = match read_frame(&mut reader) {
            Ok(Some(object)) => (ReaderEvent::Frame(object), false),
            Ok(None) => (ReaderEvent::CleanEof, true),
            Err(error) => {
                let terminal = !stream_is_aligned(&error);
                (ReaderEvent::Error(error), terminal)
            }
        };
        if let Err(error) = sender.send(event) {
            scrub_undelivered_event(error.0);
            return;
        }
        if terminal {
            return;
        }
    }
}

fn scrub_undelivered_event(mut event: ReaderEvent) {
    if let ReaderEvent::Frame(object) = &mut event {
        scrub_object(object);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufReader, Cursor, Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::framing::{JsonObject, read_frame};
    use crate::protocol::RequestId;

    fn object(value: Value) -> JsonObject {
        match value {
            Value::Object(object) => object,
            _ => panic!("test value must be an object"),
        }
    }

    fn request(id: i64, method: &str, params: &Value) -> JsonObject {
        object(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
    }

    fn framed(object: &JsonObject) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, object)
            .unwrap_or_else(|error| panic!("test frame failed: {error}"));
        bytes
    }

    fn parse_frames(bytes: Vec<u8>) -> Vec<JsonObject> {
        let mut reader = BufReader::new(Cursor::new(bytes));
        let mut objects = Vec::new();
        while let Some(object) =
            read_frame(&mut reader).unwrap_or_else(|error| panic!("response frame failed: {error}"))
        {
            objects.push(object);
        }
        objects
    }

    #[test]
    fn clean_eof_drops_service_without_writing() {
        let dropped = Arc::new(AtomicBool::new(false));
        let service = TestService::new(Arc::clone(&dropped));
        let mut output = Vec::new();
        let exit = run_service(
            BufReader::new(Cursor::new(Vec::<u8>::new())),
            &mut output,
            service,
            Duration::from_millis(1),
        )
        .unwrap_or_else(|error| panic!("server failed: {error}"));
        assert_eq!(exit, ServerExit::CleanEof);
        assert!(output.is_empty());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn blocked_reader_does_not_prevent_idle_expiry() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (expired_sender, expired_receiver) = mpsc::sync_channel(0);
        let dropped = Arc::new(AtomicBool::new(false));
        let expiry_calls = Arc::new(AtomicUsize::new(0));
        let service = TestService {
            dropped: Arc::clone(&dropped),
            expiry_calls: Arc::clone(&expiry_calls),
            first_expiry: Some(expired_sender),
            shutdown: false,
        };

        let server = thread::spawn(move || {
            let reader = BufReader::new(ReleaseThenEof::new(release_receiver));
            let mut output = Vec::new();
            let result = run_service(reader, &mut output, service, Duration::from_millis(1));
            (result, output)
        });

        expired_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("idle expiry was not polled: {error}"));
        assert!(expiry_calls.load(Ordering::SeqCst) >= 1);
        release_sender
            .send(())
            .unwrap_or_else(|error| panic!("reader release failed: {error}"));
        let (result, output) = server
            .join()
            .unwrap_or_else(|_| panic!("server test thread panicked"));
        assert_eq!(
            result.unwrap_or_else(|error| panic!("server failed: {error}")),
            ServerExit::CleanEof
        );
        assert!(output.is_empty());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn shutdown_response_is_flushed_before_exit() {
        let mut input = framed(&request(
            1,
            "system.hello",
            &json!({"client":"test","clientVersion":"1","protocolMajor":1}),
        ));
        input.extend(framed(&request(2, "system.shutdown", &json!({}))));
        let mut output = Vec::new();
        let exit = run_service(
            BufReader::new(Cursor::new(input)),
            &mut output,
            RpcService::new(),
            Duration::from_millis(1),
        )
        .unwrap_or_else(|error| panic!("server failed: {error}"));
        assert_eq!(exit, ServerExit::ShutdownRequested);
        let responses = parse_frames(output);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["ok"], true);
    }

    #[test]
    fn malformed_body_gets_null_error_and_next_frame_continues() {
        let mut input = b"Content-Length: 1\r\n\r\n{".to_vec();
        input.extend(framed(&request(
            1,
            "system.hello",
            &json!({"client":"test","clientVersion":"1","protocolMajor":1}),
        )));
        input.extend(framed(&request(2, "system.shutdown", &json!({}))));
        let mut output = Vec::new();
        let exit = run_service(
            BufReader::new(Cursor::new(input)),
            &mut output,
            RpcService::new(),
            Duration::from_millis(1),
        )
        .unwrap_or_else(|error| panic!("server failed: {error}"));
        assert_eq!(exit, ServerExit::ShutdownRequested);

        let responses = parse_frames(output);
        assert_eq!(responses.len(), 3);
        assert!(responses[0]["id"].is_null());
        assert_eq!(responses[0]["error"]["code"], -32_700);
        assert_eq!(responses[0]["error"]["data"]["name"], "PARSE_ERROR");
        assert_eq!(responses[1]["id"], 1);
        assert_eq!(responses[2]["id"], 2);
    }

    #[test]
    fn malformed_header_terminates_without_guessing_a_boundary() {
        let mut input = b"X-Unknown: 2\r\n\r\n{}".to_vec();
        input.extend(framed(&request(
            1,
            "system.hello",
            &json!({"client":"test","clientVersion":"1","protocolMajor":1}),
        )));
        let mut output = Vec::new();
        let exit = run_service(
            BufReader::new(Cursor::new(input)),
            &mut output,
            RpcService::new(),
            Duration::from_millis(1),
        )
        .unwrap_or_else(|error| panic!("server failed: {error}"));
        assert_eq!(
            exit,
            ServerExit::Desynchronized(FramingError::UnknownHeader)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn response_objects_are_scrubbed_after_success_and_failure() {
        let mut success = object(json!({"secret-key":"secret-value"}));
        let mut bytes = Vec::new();
        write_scrubbed_object(&mut bytes, &mut success)
            .unwrap_or_else(|error| panic!("response write failed: {error}"));
        assert!(success.is_empty());
        assert!(!bytes.is_empty());

        let mut failure = object(json!({"secret-key":"secret-value"}));
        let error = write_scrubbed_object(&mut FailingWriter, &mut failure)
            .expect_err("failing writer must fail");
        assert!(matches!(error, FramingError::Io { .. }));
        assert!(failure.is_empty());
    }

    struct TestService {
        dropped: Arc<AtomicBool>,
        expiry_calls: Arc<AtomicUsize>,
        first_expiry: Option<mpsc::SyncSender<()>>,
        shutdown: bool,
    }

    impl TestService {
        fn new(dropped: Arc<AtomicBool>) -> Self {
            Self {
                dropped,
                expiry_calls: Arc::new(AtomicUsize::new(0)),
                first_expiry: None,
                shutdown: false,
            }
        }
    }

    impl RequestService for TestService {
        fn handle_object(&mut self, _object: JsonObject) -> Response {
            Response::success(RequestId::Integer(1), json!({"ok": true}))
        }

        fn expire_idle_session(&mut self) -> bool {
            let call = self.expiry_calls.fetch_add(1, Ordering::SeqCst) + 1;
            // The first check happens before the initial wait. Requiring a
            // second call makes the test prove that recv_timeout woke the
            // dispatcher while the reader was still blocked.
            if call >= 2
                && let Some(sender) = self.first_expiry.take()
            {
                let _ = sender.send(());
            }
            true
        }

        fn shutdown_requested(&self) -> bool {
            self.shutdown
        }
    }

    impl Drop for TestService {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct ReleaseThenEof {
        release: Mutex<mpsc::Receiver<()>>,
        released: bool,
    }

    impl ReleaseThenEof {
        fn new(release: mpsc::Receiver<()>) -> Self {
            Self {
                release: Mutex::new(release),
                released: false,
            }
        }
    }

    impl Read for ReleaseThenEof {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            if !self.released {
                let receiver = self
                    .release
                    .lock()
                    .map_err(|_| io::Error::other("test release lock poisoned"))?;
                receiver
                    .recv()
                    .map_err(|_| io::Error::other("test release sender dropped"))?;
                self.released = true;
            }
            Ok(0)
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected test failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("injected test failure"))
        }
    }
}
