//! Administrative command-line interface for Inex encrypted vaults.
//!
//! Passwords are accepted only from a hidden terminal prompt or, when the
//! caller explicitly sets `INEX_PASSWORD_STDIN=1`, one bounded stdin line per
//! prompt. They are never accepted as command-line arguments or environment
//! variable values.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod args;
mod import;
mod password;
mod query;
mod verify;

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use inex_core::atomic::ParentSyncStatus;
use inex_core::crypto::{calibrated_creation_params, creation_calibration_evidence};
use inex_core::search::{CaseSensitivity, DEFAULT_SEARCH_SNIPPET_BYTES, SearchQuery};
use inex_core::sodium;
use inex_core::vault::{PasswordSlotCommit, Vault, VaultError};
use inex_core::vault_config::{ConfigWarning, KdfPolicy};
use uuid::Uuid;

use crate::args::{Cli, Command, GitCommand, PasswordCommand};
use crate::password::{PasswordInput, read_confirmed_password, read_password};
use crate::query::{QueryInput, read_query};

/// Run the CLI using process arguments and standard streams.
///
/// This is the library entry point used by the `inex` binary. It returns a
/// process exit code instead of terminating directly, keeping cleanup and
/// zeroizing destructors deterministic.
#[must_use]
pub fn main_entry() -> ExitCode {
    match run_from_environment() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("inex: {error}");
            error.exit_code()
        }
    }
}

fn run_from_environment() -> Result<ExitCode, AppError> {
    let cli = Cli::parse(std::env::args_os().skip(1))?;
    if matches!(cli.command, Command::Help) {
        print!("{}", args::USAGE);
        io::stdout()
            .flush()
            .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
        return Ok(ExitCode::SUCCESS);
    }
    if matches!(cli.command, Command::Version) {
        println!("inex {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    if matches!(cli.command, Command::RuntimeInfo) {
        write_runtime_info("inex")?;
        return Ok(ExitCode::SUCCESS);
    }
    if matches!(cli.command, Command::KdfCalibrationInfo) {
        write_kdf_calibration_info()?;
        return Ok(ExitCode::SUCCESS);
    }

    execute(cli.command)
}

fn execute(command: Command) -> Result<ExitCode, AppError> {
    match command {
        Command::Init { vault } => command_init(&vault, PasswordInput::from_environment()?),
        Command::Verify { vault } => command_verify(&vault),
        Command::Import {
            source,
            vault,
            dry_run,
        } => command_import(&source, &vault, dry_run),
        Command::Password(command) => command_password(command, PasswordInput::from_environment()?),
        Command::Search {
            vault,
            slot,
            case_sensitive,
            limit,
        } => {
            let password_input = PasswordInput::from_environment()?;
            let query_input = QueryInput::from_environment()?;
            command_search(
                &vault,
                slot,
                case_sensitive,
                limit,
                password_input,
                query_input,
            )
        }
        Command::MergeDriver { inputs } => Ok(command_merge_driver(inputs)),
        Command::Git(command) => command_git(command),
        Command::Serve => command_serve(),
        Command::Help | Command::Version | Command::RuntimeInfo | Command::KdfCalibrationInfo => {
            unreachable!("handled before password input setup")
        }
    }
}

fn write_runtime_info(product: &str) -> Result<(), AppError> {
    let runtime = sodium::version()?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "runtime-info-schema: inex-runtime-v1")
        .and_then(|()| writeln!(stdout, "product: {product}"))
        .and_then(|()| writeln!(stdout, "version: {}", env!("CARGO_PKG_VERSION")))
        .and_then(|()| writeln!(stdout, "rust-target: {}", sodium::COMPILED_RUST_TARGET))
        .and_then(|()| {
            writeln!(
                stdout,
                "rust-debug-assertions: {}",
                sodium::COMPILED_WITH_DEBUG_ASSERTIONS
            )
        })
        .and_then(|()| writeln!(stdout, "libsodium-version: {}", runtime.version))
        .and_then(|()| writeln!(stdout, "libsodium-library-major: {}", runtime.library_major))
        .and_then(|()| writeln!(stdout, "libsodium-library-minor: {}", runtime.library_minor))
        .and_then(|()| writeln!(stdout, "libsodium-minimal: {}", runtime.minimal))
        .and_then(|()| stdout.flush())
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))
}

fn write_kdf_calibration_info() -> Result<(), AppError> {
    let evidence = creation_calibration_evidence(KdfPolicy::default()).map_err(VaultError::from)?;
    let params = evidence.params();
    let report = format!(
        "kdf-calibration-info-schema: inex-kdf-calibration-v1\n\
         product: inex\n\
         version: {}\n\
         rust-target: {}\n\
         rust-debug-assertions: {}\n\
         algorithm: argon2id13\n\
         measurement-input: inex-public-dummy-v1\n\
         cache-scope: process\n\
         sample-mode: single-per-candidate\n\
         min-ops-limit: {}\n\
         max-ops-limit: {}\n\
         selected-ops-limit: {}\n\
         mem-limit-bytes: {}\n\
         parallelism: {}\n\
         target-min-ns: {}\n\
         target-max-ns: {}\n\
         selected-observed-ns: {}\n\
         measurement-count: {}\n\
         outcome: {}\n\
         end-to-end-sla: false\n",
        env!("CARGO_PKG_VERSION"),
        sodium::COMPILED_RUST_TARGET,
        sodium::COMPILED_WITH_DEBUG_ASSERTIONS,
        sodium::V1_ARGON2ID_CALIBRATION_MIN_OPS_LIMIT,
        sodium::V1_ARGON2ID_CALIBRATION_MAX_OPS_LIMIT,
        params.ops_limit,
        params.mem_limit_bytes,
        sodium::V1_ARGON2ID_CALIBRATION_PARALLELISM,
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MIN.as_nanos(),
        sodium::V1_ARGON2ID_CALIBRATION_TARGET_MAX.as_nanos(),
        evidence.selected_elapsed().as_nanos(),
        evidence.measurement_count(),
        evidence.outcome().report_name(),
    );
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(report.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))
}

fn command_merge_driver(inputs: Option<[PathBuf; 4]>) -> ExitCode {
    // These argv values are intentionally never inspected, canonicalized, or
    // opened. Dropping their owned representations preserves `%A` bytes and
    // metadata while guaranteeing this locked Git hook cannot reach a key,
    // password prompt, sidecar, or plaintext path.
    drop(inputs);
    eprintln!(
        "inex: locked merge driver preserved all inputs; run `inex git merge <vault>` after explicit unlock"
    );
    ExitCode::FAILURE
}

fn command_git(command: GitCommand) -> Result<ExitCode, AppError> {
    match command {
        GitCommand::InstallDriver { vault } => {
            let report = inex_git::install_driver(&vault)?;
            println!(
                "gitattributes: {}",
                if report.attributes_changed {
                    "updated"
                } else {
                    "already-configured"
                }
            );
            println!(
                "gitignore: {}",
                if report.ignore_changed {
                    "updated"
                } else {
                    "already-configured"
                }
            );
            println!("git-config-scope: repository-local");
            println!("merge-driver: locked-safe");
            println!("local-config-verified: yes");
            #[cfg(windows)]
            println!("core.longPaths: repository-local-true");
            Ok(ExitCode::SUCCESS)
        }
        GitCommand::Merge { vault, slot } => {
            let password_input = PasswordInput::from_environment()?;
            let password = read_password(password_input, "Vault password: ")?;
            let unlocked = Vault::unlock(&vault, password.as_slice(), slot, KdfPolicy::default());
            drop(password);
            let vault = unlocked?;
            print_warnings(vault.warnings());
            let report = inex_git::merge(&vault, unix_time_ms()?)?;
            println!(
                "recovered-encrypted-transactions: {}",
                report.recovered_transactions
            );
            println!("clean-encrypted-results: {}", report.clean_results);
            println!(
                "unresolved-encrypted-results: {}",
                report.unresolved_results
            );
            println!("plaintext-files-written: 0");
            Ok(if report.unresolved_results == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        GitCommand::Recover { vault, slot } => {
            let password_input = PasswordInput::from_environment()?;
            let password = read_password(password_input, "Vault password: ")?;
            let unlocked = Vault::unlock(&vault, password.as_slice(), slot, KdfPolicy::default());
            drop(password);
            let vault = unlocked?;
            print_warnings(vault.warnings());
            let report = inex_git::recover(&vault)?;
            println!(
                "recovered-encrypted-transactions: {}",
                report.recovered_transactions
            );
            println!("plaintext-files-written: 0");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn command_import(source: &Path, vault_path: &Path, dry_run: bool) -> Result<ExitCode, AppError> {
    let plan = import::scan_source(source, vault_path)?;
    println!("import-mode: {}", if dry_run { "dry-run" } else { "copy" });
    println!("source-policy: preserved-copy-only");
    println!("destination-policy: new-vault-atomic-no-replace");
    println!("inspected-entries: {}", plan.inspected_entries());
    println!("source-directories: {}", plan.directory_count());
    println!("markdown-files: {}", plan.file_count());
    println!("plaintext-bytes: {}", plan.total_plaintext_bytes());
    println!("normalized-path-entries: {}", plan.normalized_entries());
    println!(
        "skipped-non-markdown-files: {}",
        plan.skipped_non_markdown()
    );
    println!("directories-to-create: {}", plan.directory_count());

    if dry_run {
        println!("source-preserved: yes");
        println!("import-writes: none");
        println!("password-prompted: no");
        println!("destination-created: no");
        println!("result: staged copy import plan valid");
        return Ok(ExitCode::SUCCESS);
    }

    let creation_params =
        calibrated_creation_params(KdfPolicy::default()).map_err(VaultError::from)?;
    let password_input = PasswordInput::from_environment()?;
    let password = read_confirmed_password(password_input, "New vault password: ")?;
    let staging = import::create_staging_root(&plan)?;
    println!(
        "staging-vault: {}",
        staging
            .path()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("[non-unicode-staging-name]")
    );
    io::stdout()
        .flush()
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
    let mut vault = Vault::create_with_params(
        staging.path(),
        password.as_slice(),
        unix_time_ms()?,
        creation_params,
        KdfPolicy::default(),
    )
    .map_err(|_| import::ImportError::StagingCreateFailed)?;
    let mut summary = import::populate_staging(&plan, &staging, &mut vault, unix_time_ms()?)?;
    drop(vault);

    let mut reopened = Vault::unlock(
        staging.path(),
        password.as_slice(),
        None,
        KdfPolicy::default(),
    )
    .map_err(|_| import::ImportError::StagingVerificationFailed)?;
    let (warnings, seal) = import::verify_reopened_staging(&plan, &staging, &mut reopened)?;
    drop(reopened);
    drop(password);
    print_warnings(&warnings);
    summary.publish_parent_sync = import::publish_staging(&plan, &staging, &seal)?;

    println!("committed-directories: {}", summary.committed_directories);
    println!("committed-encrypted-files: {}", summary.committed_files);
    println!(
        "file-parent-sync-not-confirmed: {}",
        summary.unconfirmed_file_syncs
    );
    if summary.unconfirmed_file_syncs != 0 {
        eprintln!(
            "warning: one or more imported files returned ParentSyncStatus::NotSynced; encryption commits succeeded, but parent-directory crash durability was not confirmed"
        );
    }
    println!(
        "publish-parent-sync: {}",
        match summary.publish_parent_sync {
            ParentSyncStatus::Synced => "synced",
            ParentSyncStatus::NotSynced => "not-confirmed",
        }
    );
    println!("source-preserved: yes");
    println!("destination: published-new-vault");
    println!("result: staged copy import complete");
    Ok(ExitCode::SUCCESS)
}

fn command_init(vault_path: &Path, input: PasswordInput) -> Result<ExitCode, AppError> {
    let creation_params =
        calibrated_creation_params(KdfPolicy::default()).map_err(VaultError::from)?;
    let password = read_confirmed_password(input, "New vault password: ")?;
    let created_at_ms = unix_time_ms()?;
    let created = Vault::create_with_params(
        vault_path,
        password.as_slice(),
        created_at_ms,
        creation_params,
        KdfPolicy::default(),
    );
    drop(password);
    let created = created?;
    println!("vault created");
    println!("vault-id: {}", created.config().vault_id);
    println!("password-slot: {}", created.unlocked_slot_id());
    print_warnings(created.warnings());
    Ok(ExitCode::SUCCESS)
}

fn command_verify(vault_path: &Path) -> Result<ExitCode, AppError> {
    let report = verify::verify_locked(vault_path)?;
    let pending_git_merge = inex_git::has_pending_recovery(vault_path)?;
    println!("verification-mode: locked-structural");
    println!("mutation-lock: acquired");
    println!(
        "pending-ciphertext-transaction: {}",
        if report.recovered_pending_transaction {
            "recovered"
        } else {
            "none"
        }
    );
    println!("vault-metadata: structurally-valid-untrusted");
    println!("directories: {}", report.directories);
    println!("documents: {}", report.documents);
    println!("weak-kdf-slots: {}", report.weak_kdf_slots);
    println!("authenticated-content: not-performed");
    println!(
        "pending-git-merge-transaction: {}",
        if pending_git_merge {
            "present-authenticated-recovery-required"
        } else {
            "none"
        }
    );
    println!("result: locked structure valid; unlock is required for authenticity");
    Ok(ExitCode::SUCCESS)
}

fn command_password(command: PasswordCommand, input: PasswordInput) -> Result<ExitCode, AppError> {
    match command {
        PasswordCommand::Add { vault, slot } => {
            let current = read_password(input, "Current vault password: ")?;
            let unlocked = Vault::unlock(&vault, current.as_slice(), slot, KdfPolicy::default());
            drop(current);
            let mut vault = unlocked?;
            print_warnings(vault.warnings());
            let rewrap_params = vault.calibrated_password_rewrap_params(KdfPolicy::default())?;
            let new = read_confirmed_password(input, "New password: ")?;
            let created_at_ms = unix_time_ms()?;
            let committed = vault.add_password_slot(
                new.as_slice(),
                created_at_ms,
                rewrap_params,
                KdfPolicy::default(),
            );
            drop(new);
            let committed = committed?;
            print_password_slot_commit("password slot added", committed, "new-slot-parent-sync");
            Ok(ExitCode::SUCCESS)
        }
        PasswordCommand::Remove {
            vault,
            slot_to_remove,
            retained_slot,
        } => {
            let retained = read_password(input, "Retained-slot password: ")?;
            let mut vault = Vault::unlock(
                &vault,
                retained.as_slice(),
                Some(retained_slot),
                KdfPolicy::default(),
            )?;
            print_warnings(vault.warnings());
            let parent_sync = vault.remove_password_slot(
                slot_to_remove,
                retained.as_slice(),
                retained_slot,
                KdfPolicy::default(),
            );
            drop(retained);
            let parent_sync = parent_sync?;
            println!("password slot removed");
            println!("removed-slot: {slot_to_remove}");
            print_parent_sync("slot-removal-parent-sync", parent_sync);
            Ok(ExitCode::SUCCESS)
        }
        PasswordCommand::Change { vault, old_slot } => {
            let current = read_password(input, "Current vault password: ")?;
            let unlocked =
                Vault::unlock(&vault, current.as_slice(), old_slot, KdfPolicy::default());
            drop(current);
            let mut vault = unlocked?;
            print_warnings(vault.warnings());
            let selected_old_slot = vault.unlocked_slot_id();
            let rewrap_params = vault.calibrated_password_rewrap_params(KdfPolicy::default())?;
            let new = read_confirmed_password(input, "New password: ")?;
            let created_at_ms = unix_time_ms()?;
            let committed = vault.change_password(
                new.as_slice(),
                created_at_ms,
                rewrap_params,
                KdfPolicy::default(),
            );
            let committed = match committed {
                Ok(committed) => committed,
                Err(error) => {
                    drop(new);
                    return Err(error.into());
                }
            };
            let retirement = vault.remove_password_slot(
                selected_old_slot,
                new.as_slice(),
                committed.new_slot_id,
                KdfPolicy::default(),
            );
            drop(new);
            let Ok(retirement_parent_sync) = retirement else {
                print_password_slot_commit(
                    "new password slot committed; old slot retained",
                    committed,
                    "new-slot-parent-sync",
                );
                return Err(AppError::PasswordRetirementDeferred {
                    new_slot: committed.new_slot_id,
                });
            };
            print_password_slot_commit("password changed", committed, "new-slot-parent-sync");
            println!("retired-slot: {selected_old_slot}");
            print_parent_sync("old-slot-removal-parent-sync", retirement_parent_sync);
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn command_search(
    vault_path: &Path,
    slot: Option<Uuid>,
    case_sensitive: bool,
    limit: usize,
    password_input: PasswordInput,
    query_input: QueryInput,
) -> Result<ExitCode, AppError> {
    let password = read_password(password_input, "Vault password: ")?;
    let unlocked = Vault::unlock(vault_path, password.as_slice(), slot, KdfPolicy::default());
    drop(password);
    let mut vault = unlocked?;
    print_warnings(vault.warnings());
    let query = read_query(query_input)?;
    vault.rebuild_search_index()?;
    let sensitivity = if case_sensitive {
        CaseSensitivity::Sensitive
    } else {
        CaseSensitivity::UnicodeInsensitive
    };
    let query = SearchQuery::new(query, sensitivity, limit, DEFAULT_SEARCH_SNIPPET_BYTES)?;
    let hits = vault.search(&query)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for hit in hits.iter() {
        write!(
            output,
            "{}:{}:{}\t",
            hit.logical_path(),
            hit.line() + 1,
            hit.utf16_column() + 1,
        )
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
        write_escaped_terminal_text(&mut output, hit.snippet())
            .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
        writeln!(output).map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
    }
    writeln!(output, "matches: {}", hits.len())
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
    Ok(ExitCode::SUCCESS)
}

fn command_serve() -> Result<ExitCode, AppError> {
    let executable = daemon_executable()?;
    let mut command = ProcessCommand::new(executable);
    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let error = command.exec();
        Err(AppError::io(IoOperation::LaunchDaemon, &error))
    }

    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .map_err(|error| AppError::io(IoOperation::LaunchDaemon, &error))?;
        Ok(match status.code() {
            Some(code) => u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from),
            None => ExitCode::FAILURE,
        })
    }
}

fn daemon_executable() -> Result<PathBuf, AppError> {
    if let Some(configured) = configured_daemon_executable(std::env::var_os("INEXD_PATH"))? {
        return Ok(configured);
    }
    let current =
        std::env::current_exe().map_err(|error| AppError::io(IoOperation::LocateDaemon, &error))?;
    sibling_daemon_executable(&current)
}

fn configured_daemon_executable(
    configured: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, AppError> {
    let Some(configured) = configured else {
        return Ok(None);
    };
    if configured.is_empty() {
        return Err(AppError::InvalidDaemonPath);
    }
    Ok(Some(PathBuf::from(configured)))
}

fn sibling_daemon_executable(current: &Path) -> Result<PathBuf, AppError> {
    let sibling = current.with_file_name(if cfg!(windows) { "inexd.exe" } else { "inexd" });
    if sibling.is_file() {
        Ok(sibling)
    } else {
        Err(AppError::DaemonNotFound)
    }
}

fn print_password_slot_commit(
    message: &str,
    committed: PasswordSlotCommit,
    parent_sync_label: &str,
) {
    println!("{message}");
    println!("new-slot: {}", committed.new_slot_id);
    print_parent_sync(parent_sync_label, committed.parent_sync);
}

fn print_parent_sync(label: &str, status: ParentSyncStatus) {
    println!("{label}: {}", parent_sync_name(status));
    if let Some(warning) = parent_sync_warning(status) {
        eprintln!("warning: {label} is {warning}");
    }
}

const fn parent_sync_name(status: ParentSyncStatus) -> &'static str {
    match status {
        ParentSyncStatus::Synced => "ParentSyncStatus::Synced",
        ParentSyncStatus::NotSynced => "ParentSyncStatus::NotSynced",
    }
}

const fn parent_sync_warning(status: ParentSyncStatus) -> Option<&'static str> {
    match status {
        ParentSyncStatus::Synced => None,
        ParentSyncStatus::NotSynced => Some(
            "ParentSyncStatus::NotSynced; the metadata commit succeeded, but parent-directory crash durability was not confirmed",
        ),
    }
}

fn print_warnings(warnings: &[ConfigWarning]) {
    for warning in warnings {
        eprintln!("warning: {}", config_warning_message(warning));
    }
}

fn config_warning_message(warning: &ConfigWarning) -> String {
    match warning {
        ConfigWarning::WeakKdf { slot_id } => format!(
            "password slot {slot_id} uses weak legacy Argon2id parameters below the current creation minimum; unlock was permitted for migration, but this slot should be replaced"
        ),
    }
}

fn write_escaped_terminal_text(output: &mut impl Write, value: &str) -> io::Result<()> {
    for character in value.chars() {
        match character {
            '\\' => output.write_all(b"\\\\")?,
            '\t' => output.write_all(b"\\t")?,
            character if character.is_control() => {
                write!(output, "\\u{{{:04X}}}", u32::from(character))?;
            }
            character => {
                let mut encoded = [0_u8; 4];
                output.write_all(character.encode_utf8(&mut encoded).as_bytes())?;
            }
        }
    }
    Ok(())
}

fn unix_time_ms() -> Result<i64, AppError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Clock)?;
    i64::try_from(duration.as_millis()).map_err(|_| AppError::Clock)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoOperation {
    LocateDaemon,
    LaunchDaemon,
    WriteOutput,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LocateDaemon => "locating inexd",
            Self::LaunchDaemon => "launching inexd",
            Self::WriteOutput => "writing command output",
        })
    }
}

#[derive(Debug)]
enum AppError {
    Arguments(args::ArgumentError),
    Import(import::ImportError),
    Password(password::PasswordError),
    Query(query::QueryError),
    Verification(verify::VerifyError),
    Vault(VaultError),
    Search(inex_core::search::SearchError),
    Git(inex_git::GitError),
    Sodium(inex_core::sodium::SodiumError),
    PasswordRetirementDeferred {
        new_slot: Uuid,
    },
    InvalidDaemonPath,
    DaemonNotFound,
    Clock,
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}

impl AppError {
    fn io(operation: IoOperation, error: &io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }

    fn exit_code(&self) -> ExitCode {
        match self {
            Self::Arguments(_) => ExitCode::from(2),
            Self::Import(_)
            | Self::Password(_)
            | Self::Query(_)
            | Self::Verification(_)
            | Self::Vault(_)
            | Self::Search(_)
            | Self::Git(_)
            | Self::Sodium(_)
            | Self::PasswordRetirementDeferred { .. }
            | Self::InvalidDaemonPath
            | Self::DaemonNotFound
            | Self::Clock
            | Self::Io { .. } => ExitCode::FAILURE,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments(error) => write!(formatter, "{error}\n\n{}", args::USAGE),
            Self::Import(error) => error.fmt(formatter),
            Self::Password(error) => error.fmt(formatter),
            Self::Query(error) => error.fmt(formatter),
            Self::Verification(error) => error.fmt(formatter),
            Self::Vault(error) => error.fmt(formatter),
            Self::Search(error) => error.fmt(formatter),
            Self::Git(error) => error.fmt(formatter),
            Self::Sodium(error) => error.fmt(formatter),
            Self::PasswordRetirementDeferred { new_slot } => write!(
                formatter,
                "new password slot {new_slot} is committed, but old-slot retirement could not be confirmed"
            ),
            Self::InvalidDaemonPath => formatter.write_str("INEXD_PATH is empty"),
            Self::DaemonNotFound => formatter.write_str("sibling inexd executable does not exist"),
            Self::Clock => formatter.write_str("system clock cannot produce a Unix timestamp"),
            Self::Io { operation, kind } => {
                write!(formatter, "I/O failed while {operation}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for AppError {}

impl From<args::ArgumentError> for AppError {
    fn from(error: args::ArgumentError) -> Self {
        Self::Arguments(error)
    }
}

impl From<import::ImportError> for AppError {
    fn from(error: import::ImportError) -> Self {
        Self::Import(error)
    }
}

impl From<password::PasswordError> for AppError {
    fn from(error: password::PasswordError) -> Self {
        Self::Password(error)
    }
}

impl From<query::QueryError> for AppError {
    fn from(error: query::QueryError) -> Self {
        Self::Query(error)
    }
}

impl From<verify::VerifyError> for AppError {
    fn from(error: verify::VerifyError) -> Self {
        Self::Verification(error)
    }
}

impl From<VaultError> for AppError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<inex_core::search::SearchError> for AppError {
    fn from(error: inex_core::search::SearchError) -> Self {
        Self::Search(error)
    }
}

impl From<inex_git::GitError> for AppError {
    fn from(error: inex_git::GitError) -> Self {
        Self::Git(error)
    }
}

impl From<inex_core::sodium::SodiumError> for AppError {
    fn from(error: inex_core::sodium::SodiumError) -> Self {
        Self::Sodium(error)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "inex-cli-daemon-selection-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path)
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

    #[test]
    fn terminal_escaping_blocks_control_sequences() {
        let mut output = Vec::new();
        write_escaped_terminal_text(&mut output, "ok\x1b[31m\t\\")
            .unwrap_or_else(|error| panic!("escape write failed: {error}"));
        assert_eq!(output, b"ok\\u{001B}[31m\\t\\\\");
    }

    #[test]
    fn durability_status_and_warning_are_explicit() {
        assert_eq!(
            parent_sync_name(ParentSyncStatus::Synced),
            "ParentSyncStatus::Synced"
        );
        assert!(parent_sync_warning(ParentSyncStatus::Synced).is_none());
        assert_eq!(
            parent_sync_name(ParentSyncStatus::NotSynced),
            "ParentSyncStatus::NotSynced"
        );
        let warning = parent_sync_warning(ParentSyncStatus::NotSynced)
            .unwrap_or_else(|| panic!("NotSynced must have a warning"));
        assert!(warning.contains("crash durability was not confirmed"));
    }

    #[test]
    fn weak_kdf_warning_identifies_slot_and_migration_action() {
        let slot_id = Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff")
            .unwrap_or_else(|error| panic!("test UUID failed: {error}"));
        let message = config_warning_message(&ConfigWarning::WeakKdf { slot_id });
        assert!(message.contains(&slot_id.to_string()));
        assert!(message.contains("weak legacy Argon2id"));
        assert!(message.contains("should be replaced"));
    }

    #[test]
    fn search_plaintext_in_argv_is_rejected_without_echoing_it() {
        let error = Cli::parse(["search", "/vault", "search-canary-secret"])
            .expect_err("query plaintext in argv must be rejected");
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("search-canary-secret"));
        assert!(!debug.contains("search-canary-secret"));
    }

    #[test]
    fn explicit_daemon_path_remains_authoritative() {
        let configured = PathBuf::from("configured-daemon-that-need-not-exist");
        let selected = configured_daemon_executable(Some(configured.clone().into_os_string()))
            .unwrap_or_else(|error| panic!("selection failed: {error}"));
        assert_eq!(selected, Some(configured));
        assert!(matches!(
            configured_daemon_executable(Some(OsString::new())),
            Err(AppError::InvalidDaemonPath)
        ));
    }

    #[test]
    fn sibling_daemon_selection_fails_closed() {
        let directory = TestDirectory::new();
        let current = directory
            .path()
            .join(if cfg!(windows) { "inex.exe" } else { "inex" });
        assert!(matches!(
            sibling_daemon_executable(&current),
            Err(AppError::DaemonNotFound)
        ));

        let sibling = directory
            .path()
            .join(if cfg!(windows) { "inexd.exe" } else { "inexd" });
        fs::write(&sibling, b"test executable placeholder")
            .unwrap_or_else(|error| panic!("sibling creation failed: {error}"));
        assert_eq!(
            sibling_daemon_executable(&current)
                .unwrap_or_else(|error| panic!("sibling selection failed: {error}")),
            sibling
        );
    }
}
