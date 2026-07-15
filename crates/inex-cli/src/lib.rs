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
mod repository_import;
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
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::args::{Cli, Command, ExportScope, GitCommand, PasswordCommand};
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
        Command::ImportRepository {
            source,
            vault,
            dry_run,
        } => command_import_repository(&source, &vault, dry_run),
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
        Command::Export {
            vault,
            destination,
            scope,
        } => command_export(
            &vault,
            &destination,
            scope,
            PasswordInput::from_environment()?,
        ),
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

fn command_import_repository(
    source: &Path,
    vault_path: &Path,
    dry_run: bool,
) -> Result<ExitCode, AppError> {
    match repository_import::dispatch(source, vault_path)? {
        repository_import::RepositoryImportDispatch::Creation(plan) => {
            print_repository_import_plan(&plan, dry_run);
            if dry_run {
                plan.revalidate_source()?;
                print_repository_import_dry_run_success();
                Ok(ExitCode::SUCCESS)
            } else {
                command_repository_import_create(&plan)
            }
        }
        repository_import::RepositoryImportDispatch::Existing(request) => {
            command_repository_reconcile(&request, dry_run)
        }
    }
}

fn print_repository_import_plan(plan: &repository_import::RepositoryImportPlan, dry_run: bool) {
    println!(
        "import-mode: {}",
        if dry_run {
            "repository-dry-run"
        } else {
            "repository-copy"
        }
    );
    println!("source-policy: clean-head-read-only");
    println!("source-object-format: sha1");
    println!("source-tree-entries: {}", plan.source_tree_entries());
    println!("source-index-entries: {}", plan.source_index_entries());
    println!("source-worktree-files: {}", plan.source_worktree_files());
    println!("source-directories: {}", plan.source_directories());
    println!("markdown-files: {}", plan.markdown_files());
    println!("asset-files: {}", plan.asset_files());
    println!("markdown-bytes: {}", plan.markdown_bytes());
    println!("asset-bytes: {}", plan.asset_bytes());
    println!("largest-asset-bytes: {}", plan.largest_asset_bytes());
    println!("normalized-path-entries: {}", plan.normalized_entries());
    println!("lfs-files: 0");
    println!("filtered-files: 0");
    println!("untracked-entries: 0");
    println!("destination-policy: new-vault-new-git-root-single-atomic-publication");
}

fn print_repository_import_dry_run_success() {
    println!("source-revalidated: yes");
    println!("source-preserved: yes");
    println!("import-writes: none");
    println!("password-prompted: no");
    println!("destination-created: no");
    println!("candidate-root: not-created");
    println!("vault-publication: not-started");
    println!("git-repository: not-created");
    println!("recovery-required: none");
    println!("result: repository import plan valid");
}

fn command_repository_reconcile(
    request: &repository_import::RepositoryReconcileRequest,
    dry_run: bool,
) -> Result<ExitCode, AppError> {
    let report = match repository_import::execute_reconcile(request, dry_run) {
        Ok(report) => report,
        Err(failure) => {
            let output = format_repository_reconcile_terminal(failure.terminal());
            write_repository_reconcile_output(&output)?;
            return Err(failure.into_error().into());
        }
    };
    let output = format_repository_reconcile_success(&report);
    write_repository_reconcile_output(&output)?;
    Ok(ExitCode::SUCCESS)
}

fn format_repository_reconcile_terminal(
    terminal: repository_import::RepositoryReconcileTerminal,
) -> String {
    let [
        marker,
        candidate,
        publication,
        git,
        cleanup,
        recovery,
        result,
    ] = terminal.fields();
    format!(
        "import-mode: repository-reconcile\n\
         terminal-operation: repository-reconcile\n\
         existing-vault: yes\n\
         marker-state: {marker}\n\
         candidate-root: {candidate}\n\
         vault-publication: {publication}\n\
         git-repository: {git}\n\
         marker-cleanup: {cleanup}\n\
         recovery-required: {recovery}\n\
         result: {result}\n"
    )
}

fn format_repository_reconcile_success(
    report: &repository_import::RepositoryReconcileReport,
) -> String {
    let root = report.root_commit_oid();
    format_repository_reconcile_success_values(
        report.outcome(),
        [
            report.worktree_files(),
            report.encrypted_markdown(),
            report.encrypted_assets(),
            report.git_objects(),
        ],
        &root,
    )
}

fn format_repository_reconcile_success_values(
    outcome: repository_import::RepositoryReconcileOutcome,
    counts: [u32; 4],
    root: &str,
) -> String {
    let [
        worktree_files,
        encrypted_markdown,
        encrypted_assets,
        git_objects,
    ] = counts;
    match outcome {
        repository_import::RepositoryReconcileOutcome::Preview => format!(
            "import-mode: repository-reconcile-dry-run\n\
             terminal-operation: repository-reconcile-preview\n\
             existing-vault: yes\n\
             source-policy: path-disjointness-only\n\
             source-git-replanned: no\n\
             password-prompted: no\n\
             kdf-ran: no\n\
             destination-policy: existing-v2-publication-reconcile-only\n\
             publication-marker-version: 2\n\
             candidate-seal-version: repository-candidate-seal-v1\n\
             target-worktree-files: {worktree_files}\n\
             target-encrypted-markdown: {encrypted_markdown}\n\
             target-encrypted-assets: {encrypted_assets}\n\
             target-git-objects: {git_objects}\n\
             target-root-commit: {root}\n\
             target-root-parent-count: 0\n\
             target-plaintext-file-objects: 0\n\
             candidate-physical-audit: passed\n\
             candidate-git-object-audit: passed\n\
             marker-state: v2-exact\n\
             candidate-root: existing-published\n\
             vault-publication: indeterminate\n\
             git-repository: existing-audited\n\
             marker-cleanup: retained\n\
             recovery-required: publication-reconcile\n\
             result: repository reconciliation plan valid\n",
        ),
        repository_import::RepositoryReconcileOutcome::Reconciled => format!(
            "import-mode: repository-reconcile\n\
             terminal-operation: repository-reconcile\n\
             existing-vault: yes\n\
             source-policy: path-disjointness-only\n\
             source-git-replanned: no\n\
             password-prompted: no\n\
             kdf-ran: no\n\
             destination-policy: existing-v2-publication-reconcile-only\n\
             publication-marker-version: 2\n\
             candidate-seal-version: repository-candidate-seal-v1\n\
             target-worktree-files: {worktree_files}\n\
             target-encrypted-markdown: {encrypted_markdown}\n\
             target-encrypted-assets: {encrypted_assets}\n\
             target-git-objects: {git_objects}\n\
             target-root-commit: {root}\n\
             target-root-parent-count: 0\n\
             target-plaintext-file-objects: 0\n\
             candidate-physical-audit: passed\n\
             candidate-git-object-audit: passed\n\
             candidate-root: existing-published\n\
             vault-publication: reconciled\n\
             git-repository: existing-audited\n\
             marker-cleanup: removed\n\
             recovery-required: none\n\
             result: repository publication reconciled\n",
        ),
    }
}

fn write_repository_reconcile_output(output: &str) -> Result<(), AppError> {
    let mut stdout = io::stdout().lock();
    write_repository_reconcile_output_to(&mut stdout, output)
}

fn write_repository_reconcile_output_to(
    writer: &mut impl Write,
    output: &str,
) -> Result<(), AppError> {
    const MAX_RECONCILE_OUTPUT_BYTES: usize = 4 * 1024;
    if output.len() > MAX_RECONCILE_OUTPUT_BYTES {
        return Err(AppError::Io {
            operation: IoOperation::WriteOutput,
            kind: io::ErrorKind::InvalidData,
        });
    }
    writer
        .write_all(output.as_bytes())
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
    writer
        .flush()
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))
}

fn command_repository_import_create(
    plan: &repository_import::RepositoryImportPlan,
) -> Result<ExitCode, AppError> {
    if !inex_git::initial_repository_publication_supported() {
        print_repository_import_terminal(repository_import::RepositoryImportTerminal::NotCreated);
        io::stdout()
            .flush()
            .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
        return Err(repository_import::RepositoryImportError::Publication(
            inex_git::RepositoryCandidatePublicationFailureKind::UnsupportedPlatform,
        )
        .into());
    }
    if let Err(error) = io::stdout().flush() {
        print_repository_import_terminal(repository_import::RepositoryImportTerminal::NotCreated);
        return Err(AppError::io(IoOperation::WriteOutput, &error));
    }
    let creation_params = match calibrated_creation_params(KdfPolicy::default()) {
        Ok(params) => params,
        Err(error) => {
            print_repository_import_terminal(
                repository_import::RepositoryImportTerminal::NotCreated,
            );
            return Err(VaultError::from(error).into());
        }
    };
    let password_input = match PasswordInput::from_environment() {
        Ok(input) => input,
        Err(error) => {
            print_repository_import_terminal(
                repository_import::RepositoryImportTerminal::NotCreated,
            );
            return Err(error.into());
        }
    };
    let password = match read_confirmed_password(password_input, "New vault password: ") {
        Ok(password) => password,
        Err(error) => {
            print_repository_import_terminal(
                repository_import::RepositoryImportTerminal::NotCreated,
            );
            return Err(error.into());
        }
    };
    let created_at_ms = match unix_time_ms() {
        Ok(value) => value,
        Err(error) => {
            drop(password);
            print_repository_import_terminal(
                repository_import::RepositoryImportTerminal::NotCreated,
            );
            return Err(error);
        }
    };
    let report = repository_import::execute(plan, password, created_at_ms, creation_params);
    let report = match report {
        Ok(report) => report,
        Err(failure) => {
            print_repository_import_terminal(failure.terminal());
            if let Err(error) = io::stdout().flush() {
                return Err(AppError::io(IoOperation::WriteOutput, &error));
            }
            return Err(failure.into_error().into());
        }
    };
    print_repository_import_success(&report);
    io::stdout()
        .flush()
        .map_err(|error| AppError::io(IoOperation::WriteOutput, &error))?;
    Ok(ExitCode::SUCCESS)
}

fn print_repository_import_success(report: &repository_import::RepositoryImportReport) {
    print_warnings(&report.warnings);
    println!(
        "committed-encrypted-markdown: {}",
        report.committed_markdown()
    );
    println!("committed-encrypted-assets: {}", report.committed_assets());
    println!("candidate-vault-audit: passed");
    println!("candidate-git-object-audit: passed");
    println!("candidate-plaintext-file-objects: 0");
    println!("source-revalidated: yes");
    println!("source-preserved: yes");
    println!("candidate-root: published");
    println!("vault-publication: published");
    println!("git-repository: initialized");
    println!("git-root-commit: {}", report.git_root_commit());
    println!("git-root-parent-count: 0");
    println!("git-tracked-source-plaintext-files: 0");
    println!("recovery-required: none");
    println!("result: repository import complete");
}

fn print_repository_import_terminal(terminal: repository_import::RepositoryImportTerminal) {
    let [candidate, publication, git, recovery] = terminal.fields();
    println!("candidate-root: {candidate}");
    println!("vault-publication: {publication}");
    println!("git-repository: {git}");
    println!("recovery-required: {recovery}");
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
    println!("assets: {}", report.assets);
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

fn command_export(
    vault_path: &Path,
    destination: &Path,
    scope: ExportScope,
    password_input: PasswordInput,
) -> Result<ExitCode, AppError> {
    let mut daemon = inex_daemon::handler::RpcService::new();
    let mut request_id = 1_i64;
    let _ = daemon_call(
        &mut daemon,
        request_id,
        "system.hello",
        json!({"client":"inex-cli", "clientVersion":env!("CARGO_PKG_VERSION"), "protocolMajor":1}),
    )?;
    request_id += 1;
    let password = read_password(password_input, "Vault password: ")?;
    let password_text = String::from_utf8_lossy(password.as_slice()).into_owned();
    let mut unlocked = daemon_call(
        &mut daemon,
        request_id,
        "vault.unlock",
        json!({"vaultPath": vault_path, "password": password_text}),
    )?;
    drop(password);
    let session = daemon_sensitive_string(&mut unlocked, "session")?;
    inex_daemon::sensitive::scrub_object(&mut unlocked);
    request_id += 1;

    let scope_name = match scope {
        ExportScope::Outer => "outer",
        ExportScope::Umbra => "umbra",
    };
    if matches!(scope, ExportScope::Umbra) {
        let umbra_password = read_password(password_input, "Umbra password: ")?;
        let umbra_password_text = String::from_utf8_lossy(umbra_password.as_slice()).into_owned();
        let mut status = daemon_call(
            &mut daemon,
            request_id,
            "umbra.unlock",
            json!({"session":session.as_str(), "password":umbra_password_text}),
        )?;
        inex_daemon::sensitive::scrub_object(&mut status);
        drop(umbra_password);
        request_id += 1;
    }
    let mut prepared = daemon_call(
        &mut daemon,
        request_id,
        "vault.export.prepare",
        json!({"session":session.as_str(), "destination":destination, "scope":scope_name}),
    )?;
    let confirmation = daemon_sensitive_string(&mut prepared, "confirmation")?;
    let files = prepared
        .get("files")
        .and_then(Value::as_u64)
        .ok_or(AppError::Daemon)?;
    let assets = prepared
        .get("assets")
        .and_then(Value::as_u64)
        .ok_or(AppError::Daemon)?;
    let directories = prepared
        .get("directories")
        .and_then(Value::as_u64)
        .ok_or(AppError::Daemon)?;
    inex_daemon::sensitive::scrub_object(&mut prepared);
    if !confirm_plaintext_export(scope_name, files, assets, directories)? {
        let _ = daemon_call(
            &mut daemon,
            request_id + 1,
            "vault.lock",
            json!({"session":session.as_str()}),
        );
        return Err(AppError::ExportCancelled);
    }
    request_id += 1;
    let mut committed = daemon_call(
        &mut daemon,
        request_id,
        "vault.export.commit",
        json!({"session":session.as_str(), "confirmation":confirmation.as_str()}),
    )?;
    let durability = committed
        .get("durability")
        .and_then(Value::as_str)
        .ok_or(AppError::Daemon)?
        .to_owned();
    inex_daemon::sensitive::scrub_object(&mut committed);
    let _ = daemon_call(
        &mut daemon,
        request_id + 1,
        "vault.lock",
        json!({"session":session.as_str()}),
    );
    println!("plaintext export completed");
    println!("scope: {scope_name}");
    println!("markdown-files: {files}");
    println!("asset-files: {assets}");
    println!("directories: {directories}");
    println!("durability: {durability}");
    Ok(ExitCode::SUCCESS)
}

fn daemon_call(
    daemon: &mut inex_daemon::handler::RpcService,
    id: i64,
    method: &str,
    params: Value,
) -> Result<Map<String, Value>, AppError> {
    let mut object = Map::new();
    object.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
    object.insert("id".to_owned(), Value::from(id));
    object.insert("method".to_owned(), Value::String(method.to_owned()));
    object.insert("params".to_owned(), params);
    let mut response = daemon.handle_object(object).into_json_object();
    let result = response
        .remove("result")
        .and_then(|value| value.as_object().cloned());
    inex_daemon::sensitive::scrub_object(&mut response);
    result.ok_or(AppError::Daemon)
}

fn daemon_sensitive_string(
    result: &mut Map<String, Value>,
    field: &str,
) -> Result<zeroize::Zeroizing<String>, AppError> {
    let value = result.remove(field).ok_or(AppError::Daemon)?;
    let Value::String(value) = value else {
        return Err(AppError::Daemon);
    };
    Ok(zeroize::Zeroizing::new(value))
}

fn confirm_plaintext_export(
    scope: &str,
    files: u64,
    assets: u64,
    directories: u64,
) -> Result<bool, AppError> {
    if std::env::var_os("INEX_EXPORT_TEST_CONFIRM").as_deref() == Some("1".as_ref()) {
        return Ok(true);
    }
    eprintln!("WARNING: this creates a plaintext copy outside the vault.");
    eprintln!("Inex cannot protect its Git, backup, search-index, history, or deletion residue.");
    eprintln!("scope={scope}; markdown={files}; assets={assets}; directories={directories}");
    let typed = rpassword::prompt_password("Type EXPORT PLAINTEXT to continue: ")
        .map_err(|error| AppError::io(IoOperation::ReadConfirmation, &error))?;
    Ok(typed == "EXPORT PLAINTEXT")
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
    ReadConfirmation,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LocateDaemon => "locating inexd",
            Self::LaunchDaemon => "launching inexd",
            Self::WriteOutput => "writing command output",
            Self::ReadConfirmation => "reading plaintext-export confirmation",
        })
    }
}

#[derive(Debug)]
enum AppError {
    Arguments(args::ArgumentError),
    Import(import::ImportError),
    RepositoryImport(repository_import::RepositoryImportError),
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
    Daemon,
    ExportCancelled,
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
            | Self::RepositoryImport(_)
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
            | Self::Daemon
            | Self::ExportCancelled
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
            Self::RepositoryImport(error) => error.fmt(formatter),
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
            Self::Daemon => formatter.write_str("daemon plaintext-export request failed"),
            Self::ExportCancelled => formatter.write_str("plaintext export cancelled"),
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

impl From<repository_import::RepositoryImportError> for AppError {
    fn from(error: repository_import::RepositoryImportError) -> Self {
        Self::RepositoryImport(error)
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

    #[derive(Default)]
    struct OutputWriteSpy {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
    }

    impl Write for OutputWriteSpy {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

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
    #[allow(
        clippy::too_many_lines,
        reason = "goldens freeze both complete reconciliation output protocols"
    )]
    fn reconciliation_output_goldens_and_bounded_acknowledgement_are_exact() {
        let root = "0123456789abcdef0123456789abcdef01234567";
        let preview = format_repository_reconcile_success_values(
            repository_import::RepositoryReconcileOutcome::Preview,
            [12, 7, 5, 19],
            root,
        );
        assert_eq!(
            preview,
            concat!(
                "import-mode: repository-reconcile-dry-run\n",
                "terminal-operation: repository-reconcile-preview\n",
                "existing-vault: yes\n",
                "source-policy: path-disjointness-only\n",
                "source-git-replanned: no\n",
                "password-prompted: no\n",
                "kdf-ran: no\n",
                "destination-policy: existing-v2-publication-reconcile-only\n",
                "publication-marker-version: 2\n",
                "candidate-seal-version: repository-candidate-seal-v1\n",
                "target-worktree-files: 12\n",
                "target-encrypted-markdown: 7\n",
                "target-encrypted-assets: 5\n",
                "target-git-objects: 19\n",
                "target-root-commit: 0123456789abcdef0123456789abcdef01234567\n",
                "target-root-parent-count: 0\n",
                "target-plaintext-file-objects: 0\n",
                "candidate-physical-audit: passed\n",
                "candidate-git-object-audit: passed\n",
                "marker-state: v2-exact\n",
                "candidate-root: existing-published\n",
                "vault-publication: indeterminate\n",
                "git-repository: existing-audited\n",
                "marker-cleanup: retained\n",
                "recovery-required: publication-reconcile\n",
                "result: repository reconciliation plan valid\n",
            )
        );

        let reconciled = format_repository_reconcile_success_values(
            repository_import::RepositoryReconcileOutcome::Reconciled,
            [12, 7, 5, 19],
            root,
        );
        assert_eq!(
            reconciled,
            concat!(
                "import-mode: repository-reconcile\n",
                "terminal-operation: repository-reconcile\n",
                "existing-vault: yes\n",
                "source-policy: path-disjointness-only\n",
                "source-git-replanned: no\n",
                "password-prompted: no\n",
                "kdf-ran: no\n",
                "destination-policy: existing-v2-publication-reconcile-only\n",
                "publication-marker-version: 2\n",
                "candidate-seal-version: repository-candidate-seal-v1\n",
                "target-worktree-files: 12\n",
                "target-encrypted-markdown: 7\n",
                "target-encrypted-assets: 5\n",
                "target-git-objects: 19\n",
                "target-root-commit: 0123456789abcdef0123456789abcdef01234567\n",
                "target-root-parent-count: 0\n",
                "target-plaintext-file-objects: 0\n",
                "candidate-physical-audit: passed\n",
                "candidate-git-object-audit: passed\n",
                "candidate-root: existing-published\n",
                "vault-publication: reconciled\n",
                "git-repository: existing-audited\n",
                "marker-cleanup: removed\n",
                "recovery-required: none\n",
                "result: repository publication reconciled\n",
            )
        );

        let terminal = format_repository_reconcile_terminal(
            repository_import::RepositoryReconcileTerminal::Absent,
        );
        let mut writer = OutputWriteSpy::default();
        write_repository_reconcile_output_to(&mut writer, &terminal)
            .unwrap_or_else(|error| panic!("terminal write failed: {error}"));
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 1);
        assert_eq!(writer.bytes, terminal.as_bytes());

        let mut oversized_writer = OutputWriteSpy::default();
        let error =
            write_repository_reconcile_output_to(&mut oversized_writer, &"x".repeat(4 * 1024 + 1))
                .expect_err("oversized reconciliation output must fail");
        assert!(matches!(
            error,
            AppError::Io {
                operation: IoOperation::WriteOutput,
                kind: io::ErrorKind::InvalidData,
            }
        ));
        assert_eq!(oversized_writer.writes, 0);
        assert_eq!(oversized_writer.flushes, 0);
        assert!(oversized_writer.bytes.is_empty());
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
