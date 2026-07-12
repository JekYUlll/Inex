# Copy import v1

`inex import <plaintext-source> <new-vault> [--dry-run]` is the only import
mode in v1. Destructive in-place conversion and import into an existing vault
are intentionally unsupported.

## Safety contract

- The destination must be absent and its parent must already exist on a
  accepted local filesystem. A user-selected destination name may not use the
  reserved `.inex-import-staging-` prefix.
- The source is opened only for bounded reads. Inex never writes, renames, or
  removes a source entry.
- `--dry-run` performs source/target validation only. It does not prompt for a
  password, create a directory, unlock a vault, or perform KDF work.
- A real import first completes or reuses the process-cached v1 Argon2id
  ops-only calibration, before reading the new password or reserving staging.
  The 250–750 ms target applies to one calibration KDF measurement, not the
  complete import. It then prompts for and confirms a new password and reserves a sibling
  named `.inex-import-staging-<random>` with one create-only directory
  operation; a pre-existing directory is never initialized. Its filesystem
  identity is retained, and the random name is not printed until creation has
  succeeded. Every byte Inex writes there is vault metadata, ciphertext, or
  private non-secret synchronization state.
- The complete staging vault is physically enumerated under the normal vault
  tree limits, every document is authenticated and compared with the planned
  source digest, and the vault is dropped and independently unlocked again.
- The physical staging allowlist is exact: planned directories, planned
  `*.md.enc` files, `vault.json`, `.vault-local`, and
  `.vault-local/mutation.lock`. Missing/wrong-kind entries and every unrelated
  entry—including `.git`, plaintext Markdown, links, and ordinary attachment
  files—abort publication. A single private publication marker is allowed only
  during the final namespace operation. This allowlist is checked after
  population, after independent unlock, before publication, and again at the
  publication critical point with the marker present.
- Import deliberately does not create `.git`, `.gitattributes`, or `.gitignore`
  inside the publication staging tree. After successful publication, initialize
  or clone the Git repository and run `inex git install-driver <vault>`. This
  ordering preserves the exact import allowlist and prevents repository-local
  executable configuration from entering the pre-publication trust boundary.
- After authenticated re-open, SHA-256 seals are captured for `vault.json`,
  every planned ciphertext file, and the mutation-lock file. The complete seal
  is re-read before publication and inside the marker-present critical audit,
  so an in-place ciphertext mutation cannot pass merely by retaining its name
  and inode. Each critical verification hashes all sealed files first and then
  performs the exact physical namespace walk as its final operation, leaving no
  long-running hash pass between the final allowlist and publication.
- Immediately before publication the complete source is scanned again and the
  destination-parent identity is rechecked. Linux opens the absolute parent,
  staging root, and private directory with symlink-rejecting `openat2`, checks
  each descriptor's `fstat` identity against captured `P`, `S`, and `L`, and
  then uses the held parent descriptor for relative
  `renameat2(RENAME_NOREPLACE)`; Windows uses
  `MoveFileExW(MOVEFILE_WRITE_THROUGH)` without
  `MOVEFILE_REPLACE_EXISTING`, with directory FileIds checked before and after.
  There is no replacing-rename fallback.

If work fails before publication, the final path stays absent and a created
staging directory is retained under its explicit prefix. Publication captures
the parent identity `P`, staging-root identity `S`, private-directory identity
`L`, and a synchronized, open, single-link marker handle `M`. The system call's
reported success or failure is never accepted by itself. Its post-state is
classified as follows:

- success requires the staging name to be absent and the final name to resolve
  to exact `S`, containing exact `L` and exact `M`;
- exact `S` at the staging name with an absent final name means not moved;
- exact `S` with an unrelated final entry means destination collision;
- every other combination, including a marker without `S` and `L`, is
  indeterminate.

The cooperative vault mutation lock is held from the marker-present critical
audit through this reconciliation. Marker identity never serves as standalone
proof. After exact publication, success additionally requires removal of the
private marker. If removal fails while exact `P`, `S`, `L`, and `M` still prove
the live final tree, the command exits nonzero with a dedicated
"published, cleanup failed" result: the final vault already exists, the staging
name is absent, and only the private ciphertext-only marker remains. This state
is never reported as an ordinary successful but unsynchronized publication.
An indeterminate result is not retried or overwritten.

## Source validation and limits

Enumeration is streaming and bounded before entries are retained. Exact
lowercase UTF-8 `.md` regular files are imported; other regular files are
counted and skipped. Links, Windows reparse points, special objects, hard-linked
files, mount-boundary traversal, non-portable paths, normalization/case-fold
collisions, and planned physical `*.md.enc`/directory collisions fail closed.
The source and destination parent are also compared by resolved path and
directory identity to reject nested and bind-mount alias overlap.

On Linux, an absolute source root is opened with
`openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`, so symlinks in any root
ancestor are rejected. Source names are then enumerated from held directory
descriptors and each child is opened with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV)`. File reads
and intermediate-directory bindings are checked through those handles. A
kernel without usable `openat2` fails closed. On
Windows, reparse points are rejected and every intermediate directory/file
chain is checked by FileId immediately before and after enumeration/read; the
complete identity-bearing source plan is scanned again before publication.

The v1 limits are:

- 100,000 inspected entries and Markdown files;
- depth 128;
- 32 MiB of observed path storage;
- 16 MiB per Markdown file;
- 256 MiB total Markdown plaintext.

Dry-run computes the complete maximum staging entry/path budget, including
the physical `.enc` suffixes, `vault.json`, private directory, mutation lock,
and temporary publication marker. Path bytes use Rust's platform `OsStr`
encoded-byte representation, matching the core tree budget on both Linux and
Windows. Dry-run still creates nothing.

Each file is allocated once at its exact observed length, read without
reallocation, checked with a zeroized one-byte append probe, validated as
UTF-8, and hashed. The file identity and single-link condition are checked
around the read.

## Recovery

On a reported pre-publication failure, do not rename staging manually. Preserve
the source and `.inex-import-staging-*` directory, verify that the requested
final path is absent, and rerun import to a fresh absent destination after the
underlying fault is resolved. On an indeterminate publication result, first run
`inex verify` against any final path and retain all staging directories until
the namespace state has been audited. Inex will never choose one side by
overwriting an existing destination. On the dedicated publication-marker
cleanup failure, do not rerun import into the same destination: the final vault
has already been published. Preserve it and the private marker, run
`inex verify` against the final path, and remove the marker only after the
namespace state has been independently audited.
