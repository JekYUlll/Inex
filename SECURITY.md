# Security Policy and Threat Model

## Supported security goal

An Inex vault protects Markdown bodies at rest from ordinary local access by a
person who does not know the vault password. Before unlock, filesystem tools,
plain text editors, sync clients, and normal Git tooling see only EDRY
ciphertext. A normal save produces ciphertext before touching the vault.

Directory names and file basenames are intentionally visible in v1. File
length, timestamps, the number of files, Git history shape, and access timing
may also be observable. Users must not put secrets in visible path names.

## Out of scope

Inex does not protect plaintext from:

- an administrator, kernel compromise, debugger, malicious editor extension,
  or malware running with the user's permissions while the vault is unlocked;
- memory forensics, cold-boot attacks, swap/hibernation capture, crash dumps,
  screen capture, clipboard monitoring, or key logging;
- weak/reused passwords or a user exporting/copying plaintext;
- plaintext backups, local history, or session recovery created by an editor
  against Inex's guidance;
- denial of service, deletion, rollback to an older valid Git commit, or
  traffic analysis.

Full-disk encryption, a trusted editor profile, OS updates, and protected
swap/hibernation remain recommended.

## Storage invariants

1. Core and clients never create a temporary plaintext `.md` file.
2. Atomic-write staging files contain complete authenticated ciphertext.
3. Search indexes and decrypted document caches are memory-only in v1.
4. Lock, idle expiry, editor close, EOF, and shutdown invalidate sessions and
   wipe owned secret buffers on a best-effort basis.
5. Passwords, session tokens, keys, and plaintext are never written to logs or
   returned in diagnostic errors.
6. Git diff/merge artifacts remain encrypted, including unresolved conflict
   text.

## Editor caveat

The sidecar can control its own storage, but it cannot prove that another
extension, the OS, or a backup product never persisted a buffer. In particular,
VS Code can back up any modified ordinary working copy independently of the
`files.hotExit` shutdown setting. Inex therefore edits through a custom editor
whose backup implementation writes authenticated ciphertext; it does not expose
the writable journal as an ordinary TextDocument/FileSystemProvider. The client
also audits relevant persistence settings and runs release-time residue tests.
The Sublime client uses scratch buffers and self-managed encrypted drafts,
requires safe application-global persistence settings before writable mode,
and remains experimental until equivalent black-box residue tests pass. Its API
cannot veto every application-exit path, so safety takes precedence over
guaranteeing the final unsent keystrokes survive an abrupt exit.

## Cryptographic design

- Password KDF: Argon2id via libsodium, with parameters stored per password
  slot and a creation-time policy floor.
- Vault secret: random 256-bit master key, wrapped by a password-derived KEK.
- File encryption: random nonce and XChaCha20-Poly1305-IETF per complete file.
- File keys: domain-separated, keyed derivation from the master key and full
  128-bit random file identifier.
- Authentication: the canonical EDRY header, including vault identity and
  normalized logical path, is associated data.

Changing a password rewraps the stable master key and does not rewrite journal
files. Master-key rotation is represented by a key epoch and is a distinct,
explicit migration.

## Reporting vulnerabilities

Do not include real passwords, keys, plaintext journals, session tokens, or
vaults in an issue. Until a private reporting channel is published, create a
minimal report stating that a security issue exists and request a private
contact path.
