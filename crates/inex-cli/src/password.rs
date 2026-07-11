//! Password acquisition from a hidden TTY or allocation-bounded stdin lines.
//!
//! `rpassword` 7.5.4 does not expose a caller-bounded hidden-TTY reader. The
//! TTY path therefore validates the byte limit immediately after Enter; the
//! explicit-stdin path enforces the limit while reading.

use std::fmt;
use std::io::{self, BufRead, Read};

use inex_core::vault_config::{MAX_PASSWORD_BYTES, validate_password};
use zeroize::Zeroizing;

const PASSWORD_STDIN_ENV: &str = "INEX_PASSWORD_STDIN";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PasswordInput {
    Tty,
    ExplicitStdin,
}

impl PasswordInput {
    pub(crate) fn from_environment() -> Result<Self, PasswordError> {
        match std::env::var_os(PASSWORD_STDIN_ENV) {
            None => Ok(Self::Tty),
            Some(value) if value == "1" => Ok(Self::ExplicitStdin),
            Some(_) => Err(PasswordError::InvalidStdinOptIn),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PasswordError {
    InvalidStdinOptIn,
    ReadFailed(io::ErrorKind),
    MissingPassword,
    PasswordTooLong,
    PasswordNotUtf8,
    InvalidPassword,
    ConfirmationMismatch,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStdinOptIn => formatter.write_str(
                "INEX_PASSWORD_STDIN must be absent or exactly `1`; password values are forbidden in environment variables",
            ),
            Self::ReadFailed(kind) => write!(formatter, "password input failed: {kind:?}"),
            Self::MissingPassword => formatter.write_str("password input ended before a value was read"),
            Self::PasswordTooLong => formatter.write_str("password exceeds the supported byte limit"),
            Self::PasswordNotUtf8 => formatter.write_str("password input must be valid UTF-8"),
            Self::InvalidPassword => formatter.write_str("password length is outside the supported range"),
            Self::ConfirmationMismatch => formatter.write_str("new password confirmation does not match"),
        }
    }
}

impl std::error::Error for PasswordError {}

pub(crate) fn read_password(
    input: PasswordInput,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let password = match input {
        PasswordInput::Tty => {
            // No public rpassword API combines terminal echo suppression with
            // a caller-controlled read bound. Validate immediately below.
            Zeroizing::new(
                rpassword::prompt_password(prompt)
                    .map_err(|error| PasswordError::ReadFailed(error.kind()))?
                    .into_bytes(),
            )
        }
        PasswordInput::ExplicitStdin => {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();
            read_password_line(&mut stdin)?
        }
    };
    validate_password(password.as_slice()).map_err(|_| PasswordError::InvalidPassword)?;
    Ok(password)
}

pub(crate) fn read_confirmed_password(
    input: PasswordInput,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let password = read_password(input, prompt)?;
    let confirmation = read_password(input, "Confirm password: ")?;
    if password.as_slice() != confirmation.as_slice() {
        return Err(PasswordError::ConfirmationMismatch);
    }
    Ok(password)
}

fn read_password_line<R: BufRead>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let maximum_read = u64::try_from(MAX_PASSWORD_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES.min(128)));
    reader
        .take(maximum_read)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| PasswordError::ReadFailed(error.kind()))?;
    if bytes.is_empty() {
        return Err(PasswordError::MissingPassword);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::PasswordTooLong);
    }
    std::str::from_utf8(bytes.as_slice()).map_err(|_| PasswordError::PasswordNotUtf8)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn explicit_lines_strip_only_line_terminators() {
        let mut input = Cursor::new(b" first password \r\nsecond\n".to_vec());
        let first = read_password_line(&mut input)
            .unwrap_or_else(|error| panic!("first read failed: {error}"));
        let second = read_password_line(&mut input)
            .unwrap_or_else(|error| panic!("second read failed: {error}"));
        assert_eq!(first.as_slice(), b" first password ");
        assert_eq!(second.as_slice(), b"second");
    }

    #[test]
    fn explicit_line_accepts_eof_without_newline() {
        let mut input = Cursor::new(b"password".to_vec());
        let password =
            read_password_line(&mut input).unwrap_or_else(|error| panic!("read failed: {error}"));
        assert_eq!(password.as_slice(), b"password");
    }

    #[test]
    fn explicit_line_rejects_oversize_and_non_utf8() {
        let mut oversized = Cursor::new(vec![b'x'; MAX_PASSWORD_BYTES + 1]);
        assert!(matches!(
            read_password_line(&mut oversized),
            Err(PasswordError::PasswordTooLong)
        ));
        let mut non_utf8 = Cursor::new(vec![0xff, b'\n']);
        assert!(matches!(
            read_password_line(&mut non_utf8),
            Err(PasswordError::PasswordNotUtf8)
        ));
    }

    #[test]
    fn errors_never_retain_password_text() {
        let error = PasswordError::ConfirmationMismatch;
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("canary-password"));
        assert!(!debug.contains("canary-password"));
    }
}
