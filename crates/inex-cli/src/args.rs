//! Small, strict command-line parser with redacted diagnostics.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use inex_core::search::{DEFAULT_SEARCH_RESULTS, MAX_SEARCH_RESULTS};
use uuid::Uuid;

pub(crate) const USAGE: &str = "\
Usage:
  inex init <vault>
  inex import <plaintext-source> <new-vault> [--dry-run]
  inex verify <vault>
  inex password add <vault> [--slot <current-slot-uuid>]
  inex password remove <vault> <slot-to-remove> --slot <retained-slot-uuid>
  inex password change <vault> [--slot <old-slot-uuid>]
  inex search <vault> [--slot <uuid>] [--case-sensitive] [--limit <count>]
  inex merge-driver <ancestor> <current> <incoming> <logical-path>
  inex git install-driver <vault>
  inex git merge <vault> [--slot <uuid>]
  inex git recover <vault> [--slot <uuid>]
  inex serve
  inex runtime-info
  inex kdf-calibration-info
  inex --help
  inex --version

Passwords are never accepted in argv or environment variables. By default
Inex prompts on the controlling TTY with echo disabled. For explicit pipe use,
set INEX_PASSWORD_STDIN=1 and provide one line per prompt. The line order is
current, then new and confirmation where applicable.

Search queries follow the same rule: they are read from a hidden TTY prompt,
or one bounded stdin line with INEX_QUERY_STDIN=1. If both stdin opt-ins are
set for `search`, provide the password line first and the query line second.

The rpassword 7.5.4 hidden-TTY backend has no caller-supplied input bound, so
TTY byte limits are checked immediately after Enter. The explicit stdin modes
apply their byte bounds while reading and are the hard allocation-bounded path.

`import` is copy-only: it never changes or removes the plaintext source, and
the final vault path must be absent. `--dry-run` only scans and validates; it
does not prompt for a password, create a staging directory, or unlock a vault.
A real import prompts for and confirms a new password, builds and re-opens a
complete encrypted `.inex-import-staging-*` sibling, then atomically publishes
it with a no-replace rename. The staging name is printed only after create-only
reservation. A strict physical allowlist rejects `.git`, plaintext, links, and
all unrelated entries. Failures leave the final path absent or report an
indeterminate identity-checked OS post-state; staging is retained for recovery.
Destructive in-place conversion and import into an existing vault are unsupported.
Only exact lowercase UTF-8 `.md` files are imported; portable paths are NFC
normalized, while other regular files are skipped and explicitly counted.
Links, reparse points, special entries, collisions, and unsafe paths fail.
Limits are 100000 source entries/files, depth 128, 32 MiB of source/target path
storage, 16 MiB per Markdown file, and 256 MiB total Markdown plaintext.

`verify` performs locked structural validation only. It does not authenticate
vault metadata or document ciphertext. It acquires the vault mutation lock and
may recover a pending ciphertext transaction; it is not a pure read-only scan.

`merge-driver` is deliberately locked-safe: it never reads any of its four
paths, never requests a password or starts a sidecar, leaves the current file
byte-for-byte and metadata-for-metadata unchanged, and exits with Git conflict.
The repository installer uses the equivalent zero-argument form with a fixed
absolute Inex executable path, eliminating merge-time PATH and placeholder
shell expansion; the four-path form remains accepted for compatibility tests.
Run `inex git install-driver <vault>` explicitly in each clone. The installer
writes only repository-local Git config plus the tracked `.gitattributes` and
`.gitignore` rules. `inex git merge` and `inex git recover` prompt for a vault
password and keep all three-way plaintext in memory; their Git subprocesses
receive ciphertext and path metadata only.
";

pub(crate) struct Cli {
    pub(crate) command: Command,
}

impl fmt::Debug for Cli {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cli")
            .field("command", &self.command.redacted_name())
            .finish()
    }
}

pub(crate) enum Command {
    Init {
        vault: PathBuf,
    },
    Verify {
        vault: PathBuf,
    },
    Import {
        source: PathBuf,
        vault: PathBuf,
        dry_run: bool,
    },
    Password(PasswordCommand),
    Search {
        vault: PathBuf,
        slot: Option<Uuid>,
        case_sensitive: bool,
        limit: usize,
    },
    MergeDriver {
        inputs: Option<[PathBuf; 4]>,
    },
    Git(GitCommand),
    Serve,
    RuntimeInfo,
    KdfCalibrationInfo,
    Help,
    Version,
}

impl Command {
    const fn redacted_name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Verify { .. } => "verify",
            Self::Import { .. } => "import",
            Self::Password(PasswordCommand::Add { .. }) => "password add",
            Self::Password(PasswordCommand::Remove { .. }) => "password remove",
            Self::Password(PasswordCommand::Change { .. }) => "password change",
            Self::Search { .. } => "search <query-from-secure-input>",
            Self::MergeDriver { .. } => "merge-driver <locked-safe>",
            Self::Git(GitCommand::InstallDriver { .. }) => "git install-driver",
            Self::Git(GitCommand::Merge { .. }) => "git merge",
            Self::Git(GitCommand::Recover { .. }) => "git recover",
            Self::Serve => "serve",
            Self::RuntimeInfo => "runtime-info",
            Self::KdfCalibrationInfo => "kdf-calibration-info",
            Self::Help => "help",
            Self::Version => "version",
        }
    }
}

pub(crate) enum GitCommand {
    InstallDriver { vault: PathBuf },
    Merge { vault: PathBuf, slot: Option<Uuid> },
    Recover { vault: PathBuf, slot: Option<Uuid> },
}

pub(crate) enum PasswordCommand {
    Add {
        vault: PathBuf,
        slot: Option<Uuid>,
    },
    Remove {
        vault: PathBuf,
        slot_to_remove: Uuid,
        retained_slot: Uuid,
    },
    Change {
        vault: PathBuf,
        old_slot: Option<Uuid>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArgumentError {
    MissingCommand,
    UnknownCommand,
    MissingSource,
    MissingVault,
    MissingPasswordSubcommand,
    UnknownPasswordSubcommand,
    MissingGitSubcommand,
    UnknownGitSubcommand,
    MissingMergeDriverPath,
    MissingSlotToRemove,
    RetainedSlotRequired,
    MissingOptionValue,
    InvalidSlot,
    InvalidLimit,
    SearchLimitTooLarge,
    UnexpectedArgument,
    NonUnicodeCommand,
    ForbiddenPasswordArgument,
    UnsupportedInPlaceImport,
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingCommand => "a command is required",
            Self::UnknownCommand => "unknown command",
            Self::MissingSource => "plaintext source path is required",
            Self::MissingVault => "vault path is required",
            Self::MissingPasswordSubcommand => "password subcommand is required",
            Self::UnknownPasswordSubcommand => "unknown password subcommand",
            Self::MissingGitSubcommand => "git subcommand is required",
            Self::UnknownGitSubcommand => "unknown git subcommand",
            Self::MissingMergeDriverPath => "merge-driver requires exactly four path arguments",
            Self::MissingSlotToRemove => "slot-to-remove UUID is required",
            Self::RetainedSlotRequired => "password remove requires --slot <retained-slot-uuid>",
            Self::MissingOptionValue => "command-line option requires a value",
            Self::InvalidSlot => "slot must be a canonical UUID",
            Self::InvalidLimit => "search limit must be a positive decimal integer",
            Self::SearchLimitTooLarge => "search limit exceeds the supported maximum",
            Self::UnexpectedArgument => "unexpected command-line argument",
            Self::NonUnicodeCommand => "command and option names must be valid Unicode",
            Self::ForbiddenPasswordArgument => {
                "passwords cannot be supplied through command-line arguments"
            }
            Self::UnsupportedInPlaceImport => {
                "destructive in-place import is unsupported; use copy import"
            }
        })
    }
}

impl std::error::Error for ArgumentError {}

impl Cli {
    pub(crate) fn parse<I, S>(arguments: I) -> Result<Self, ArgumentError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut arguments = Arguments::new(arguments);
        let command = arguments.pop_text()?.ok_or(ArgumentError::MissingCommand)?;
        let command = match command.as_str() {
            "init" => Command::Init {
                vault: arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?,
            },
            "verify" => Command::Verify {
                vault: arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?,
            },
            "import" => parse_import(&mut arguments)?,
            "password" => Command::Password(parse_password(&mut arguments)?),
            "search" => parse_search(&mut arguments)?,
            "merge-driver" => parse_merge_driver(&mut arguments)?,
            "git" => Command::Git(parse_git(&mut arguments)?),
            "serve" => Command::Serve,
            "runtime-info" | "--runtime-info" => Command::RuntimeInfo,
            "kdf-calibration-info" => Command::KdfCalibrationInfo,
            "help" | "--help" | "-h" => Command::Help,
            "--version" | "-V" => Command::Version,
            "--password" | "--passphrase" => {
                return Err(ArgumentError::ForbiddenPasswordArgument);
            }
            _ => return Err(ArgumentError::UnknownCommand),
        };
        reject_remaining(arguments)?;
        Ok(Self { command })
    }
}

fn parse_merge_driver(arguments: &mut Arguments) -> Result<Command, ArgumentError> {
    let Some(ancestor) = arguments.pop_path()? else {
        return Ok(Command::MergeDriver { inputs: None });
    };
    let current = arguments
        .pop_path()?
        .ok_or(ArgumentError::MissingMergeDriverPath)?;
    let incoming = arguments
        .pop_path()?
        .ok_or(ArgumentError::MissingMergeDriverPath)?;
    let logical_path = arguments
        .pop_path()?
        .ok_or(ArgumentError::MissingMergeDriverPath)?;
    Ok(Command::MergeDriver {
        inputs: Some([ancestor, current, incoming, logical_path]),
    })
}

fn parse_git(arguments: &mut Arguments) -> Result<GitCommand, ArgumentError> {
    let subcommand = arguments
        .pop_text()?
        .ok_or(ArgumentError::MissingGitSubcommand)?;
    match subcommand.as_str() {
        "install-driver" => Ok(GitCommand::InstallDriver {
            vault: arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?,
        }),
        "merge" => {
            let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
            let options = parse_options(arguments, true, false, false)?;
            Ok(GitCommand::Merge {
                vault,
                slot: options.slot,
            })
        }
        "recover" => {
            let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
            let options = parse_options(arguments, true, false, false)?;
            Ok(GitCommand::Recover {
                vault,
                slot: options.slot,
            })
        }
        "--password" | "--passphrase" => Err(ArgumentError::ForbiddenPasswordArgument),
        _ => Err(ArgumentError::UnknownGitSubcommand),
    }
}

fn parse_password(arguments: &mut Arguments) -> Result<PasswordCommand, ArgumentError> {
    let subcommand = arguments
        .pop_text()?
        .ok_or(ArgumentError::MissingPasswordSubcommand)?;
    match subcommand.as_str() {
        "add" => {
            let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
            let options = parse_options(arguments, true, false, false)?;
            Ok(PasswordCommand::Add {
                vault,
                slot: options.slot,
            })
        }
        "remove" => {
            let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
            let slot_to_remove_text = arguments
                .pop_text()?
                .ok_or(ArgumentError::MissingSlotToRemove)?;
            let slot_to_remove = parse_uuid(&slot_to_remove_text)?;
            let options = parse_options(arguments, true, false, false)?;
            let retained_slot = options.slot.ok_or(ArgumentError::RetainedSlotRequired)?;
            Ok(PasswordCommand::Remove {
                vault,
                slot_to_remove,
                retained_slot,
            })
        }
        "change" => {
            let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
            let options = parse_options(arguments, true, false, false)?;
            Ok(PasswordCommand::Change {
                vault,
                old_slot: options.slot,
            })
        }
        "--password" | "--passphrase" => Err(ArgumentError::ForbiddenPasswordArgument),
        _ => Err(ArgumentError::UnknownPasswordSubcommand),
    }
}

fn parse_import(arguments: &mut Arguments) -> Result<Command, ArgumentError> {
    let source = arguments.pop_path()?.ok_or(ArgumentError::MissingSource)?;
    let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
    let options = parse_options(arguments, false, false, true)?;
    Ok(Command::Import {
        source,
        vault,
        dry_run: options.dry_run,
    })
}

fn parse_search(arguments: &mut Arguments) -> Result<Command, ArgumentError> {
    let vault = arguments.pop_path()?.ok_or(ArgumentError::MissingVault)?;
    let options = parse_options(arguments, true, true, false)?;
    Ok(Command::Search {
        vault,
        slot: options.slot,
        case_sensitive: options.case_sensitive,
        limit: options.limit.unwrap_or(DEFAULT_SEARCH_RESULTS),
    })
}

#[derive(Default)]
struct Options {
    slot: Option<Uuid>,
    case_sensitive: bool,
    limit: Option<usize>,
    dry_run: bool,
}

fn parse_options(
    arguments: &mut Arguments,
    slot_options: bool,
    search_options: bool,
    import_options: bool,
) -> Result<Options, ArgumentError> {
    let mut options = Options::default();
    while let Some(option) = arguments.pop_text()? {
        match option.as_str() {
            "--slot" if slot_options && options.slot.is_none() => {
                let slot_text = arguments
                    .pop_text()?
                    .ok_or(ArgumentError::MissingOptionValue)?;
                options.slot = Some(parse_uuid(&slot_text)?);
            }
            "--case-sensitive" if search_options && !options.case_sensitive => {
                options.case_sensitive = true;
            }
            "--limit" if search_options && options.limit.is_none() => {
                let limit = arguments
                    .pop_text()?
                    .ok_or(ArgumentError::MissingOptionValue)?;
                let limit = limit
                    .parse::<usize>()
                    .map_err(|_| ArgumentError::InvalidLimit)?;
                if limit == 0 {
                    return Err(ArgumentError::InvalidLimit);
                }
                if limit > MAX_SEARCH_RESULTS {
                    return Err(ArgumentError::SearchLimitTooLarge);
                }
                options.limit = Some(limit);
            }
            "--dry-run" if import_options && !options.dry_run => {
                options.dry_run = true;
            }
            "--in-place" | "--in-place-convert" => {
                return Err(ArgumentError::UnsupportedInPlaceImport);
            }
            "--password" | "--passphrase" => {
                return Err(ArgumentError::ForbiddenPasswordArgument);
            }
            _ => return Err(ArgumentError::UnexpectedArgument),
        }
    }
    Ok(options)
}

fn parse_uuid(value: &str) -> Result<Uuid, ArgumentError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ArgumentError::InvalidSlot)?;
    if parsed.to_string() != value {
        return Err(ArgumentError::InvalidSlot);
    }
    Ok(parsed)
}

fn reject_remaining(mut arguments: Arguments) -> Result<(), ArgumentError> {
    if let Some(value) = arguments.pop_text()? {
        if matches!(value.as_str(), "--password" | "--passphrase") {
            Err(ArgumentError::ForbiddenPasswordArgument)
        } else {
            Err(ArgumentError::UnexpectedArgument)
        }
    } else {
        Ok(())
    }
}

struct Arguments {
    values: VecDeque<OsString>,
}

impl Arguments {
    fn new<I, S>(arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            values: arguments.into_iter().map(Into::into).collect(),
        }
    }

    fn pop_os(&mut self) -> Option<OsString> {
        self.values.pop_front()
    }

    fn pop_text(&mut self) -> Result<Option<String>, ArgumentError> {
        self.pop_os()
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| ArgumentError::NonUnicodeCommand)
            })
            .transpose()
    }

    fn pop_path(&mut self) -> Result<Option<PathBuf>, ArgumentError> {
        let value = self.pop_os();
        if value
            .as_ref()
            .is_some_and(|value| matches!(value.to_str(), Some("--password" | "--passphrase")))
        {
            return Err(ArgumentError::ForbiddenPasswordArgument);
        }
        Ok(value.map(PathBuf::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_A: &str = "00112233-4455-4677-8899-aabbccddeeff";
    const SLOT_B: &str = "10213243-5465-4768-9aab-bccddeeff001";

    #[test]
    fn parses_baseline_commands() {
        assert!(matches!(
            Cli::parse(["init", "/vault"]),
            Ok(Cli {
                command: Command::Init { .. }
            })
        ));
        assert!(matches!(
            Cli::parse(["verify", "/vault"]),
            Ok(Cli {
                command: Command::Verify { .. }
            })
        ));
        assert!(matches!(
            Cli::parse(["import", "/source", "/new-vault", "--dry-run"]),
            Ok(Cli {
                command: Command::Import { dry_run: true, .. }
            })
        ));
        assert!(matches!(
            Cli::parse(["serve"]),
            Ok(Cli {
                command: Command::Serve
            })
        ));
        assert!(matches!(
            Cli::parse(["runtime-info"]),
            Ok(Cli {
                command: Command::RuntimeInfo
            })
        ));
        assert!(matches!(
            Cli::parse(["kdf-calibration-info"]),
            Ok(Cli {
                command: Command::KdfCalibrationInfo
            })
        ));
        assert!(matches!(
            Cli::parse(["git", "install-driver", "/vault"]),
            Ok(Cli {
                command: Command::Git(GitCommand::InstallDriver { .. })
            })
        ));
        assert!(matches!(
            Cli::parse(["git", "merge", "/vault", "--slot", SLOT_A]),
            Ok(Cli {
                command: Command::Git(GitCommand::Merge { slot: Some(_), .. })
            })
        ));
        assert!(matches!(
            Cli::parse(["merge-driver", "base", "ours", "theirs", "entry.md.enc"]),
            Ok(Cli {
                command: Command::MergeDriver { .. }
            })
        ));
        assert!(matches!(
            Cli::parse(["merge-driver"]),
            Ok(Cli {
                command: Command::MergeDriver { inputs: None }
            })
        ));
    }

    #[test]
    fn kdf_calibration_info_rejects_every_argument() {
        assert_eq!(
            Cli::parse(["kdf-calibration-info", "/absent-vault"])
                .expect_err("diagnostic must not accept a vault path"),
            ArgumentError::UnexpectedArgument
        );
        assert_eq!(
            Cli::parse(["kdf-calibration-info", "--password"])
                .expect_err("diagnostic must reject password arguments"),
            ArgumentError::ForbiddenPasswordArgument
        );
        assert_eq!(
            Cli::parse(["kdf-calibration-info", "--ops", "7"])
                .expect_err("diagnostic must not accept policy overrides"),
            ArgumentError::UnexpectedArgument
        );
    }

    #[test]
    fn parses_password_commands_and_requires_retained_slot() {
        assert!(matches!(
            Cli::parse(["password", "add", "/vault", "--slot", SLOT_A]),
            Ok(Cli {
                command: Command::Password(PasswordCommand::Add { slot: Some(_), .. })
            })
        ));
        assert!(matches!(
            Cli::parse(["password", "remove", "/vault", SLOT_A]),
            Err(ArgumentError::RetainedSlotRequired)
        ));
        assert!(matches!(
            Cli::parse(["password", "remove", "/vault", SLOT_A, "--slot", SLOT_B,]),
            Ok(Cli {
                command: Command::Password(PasswordCommand::Remove { .. })
            })
        ));
    }

    #[test]
    fn parses_search_options_without_query_argv() {
        let cli = Cli::parse([
            "search",
            "/vault",
            "--case-sensitive",
            "--limit",
            "3",
            "--slot",
            SLOT_A,
        ])
        .unwrap_or_else(|error| panic!("parse failed: {error}"));
        assert!(matches!(
            cli.command,
            Command::Search {
                case_sensitive: true,
                limit: 3,
                slot: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn rejects_password_and_extra_arguments() {
        assert!(matches!(
            Cli::parse(["init", "/vault", "--password", "secret"]),
            Err(ArgumentError::ForbiddenPasswordArgument)
        ));
        assert!(matches!(
            Cli::parse(["serve", "secret"]),
            Err(ArgumentError::UnexpectedArgument)
        ));
        assert!(matches!(
            Cli::parse(["merge-driver", "base", "ours", "theirs"]),
            Err(ArgumentError::MissingMergeDriverPath)
        ));
        assert!(matches!(
            Cli::parse(["search", "/vault", "query-must-not-be-in-argv"]),
            Err(ArgumentError::UnexpectedArgument)
        ));
        assert!(matches!(
            Cli::parse(["--password", "secret"]),
            Err(ArgumentError::ForbiddenPasswordArgument)
        ));
        assert!(matches!(
            Cli::parse(["import", "/source", "/vault", "--in-place"]),
            Err(ArgumentError::UnsupportedInPlaceImport)
        ));
        assert!(matches!(
            Cli::parse(["import", "/source", "/vault", "--slot", SLOT_A]),
            Err(ArgumentError::UnexpectedArgument)
        ));
    }

    #[test]
    fn rejects_noncanonical_uuid_and_zero_limit() {
        assert!(matches!(
            Cli::parse([
                "password",
                "add",
                "/vault",
                "--slot",
                &SLOT_A.to_uppercase()
            ]),
            Err(ArgumentError::InvalidSlot)
        ));
        assert!(matches!(
            Cli::parse(["search", "/vault", "--limit", "0"]),
            Err(ArgumentError::InvalidLimit)
        ));

        let excessive_limit = (MAX_SEARCH_RESULTS + 1).to_string();
        assert!(matches!(
            Cli::parse(["search", "/vault", "--limit", excessive_limit.as_str()]),
            Err(ArgumentError::SearchLimitTooLarge)
        ));
    }
}
