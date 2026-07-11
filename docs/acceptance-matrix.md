# Inex Verification and Acceptance Matrix

This matrix is the binding evidence checklist for the pre-alpha release gate.
Test names may change, but no row can be waived without updating the threat
model and product status.

| Area | Required cases | Passing evidence |
|------|----------------|------------------|
| Envelope parsing | Bit flips in magic/version/flags/length/header/body/tag; every truncation boundary; appended bytes | All fail closed and return no plaintext. |
| Deterministic CBOR | Duplicate/out-of-order keys, non-minimal integer/length, indefinite values, unknown fields/features | All rejected before allocation/decryption beyond limits. |
| AAD and path binding | Change nonce, suite, KDF id, file/vault id, epoch, logical path, timestamps, flags, feature list, or draft base etag | Authentication or semantic validation fails; an OS rename is reported as path mismatch. |
| Nonce behavior | Repeated save of identical bytes; rename; encrypted draft | Fresh RNG nonce every time and distinct envelopes. |
| Password slots | Wrong password/slot; changed KDF/wrap data; changed other slot/features/MAC; add/remove/change password | Invalid states fail uniformly; all EDRY hashes remain unchanged for slot-only operations. |
| KDF resources | Below-floor creation, extreme ops/memory input, valid older weak vault | Creation rejected, pre-allocation upper bound enforced, older vault warning is explicit. |
| Secure buffers | Init failure, mlock unavailable, auth failure, panic/error paths, lock/drop | Keys and owned plaintext buffers are wiped; degraded memory-lock state is reported without secrets. |
| Atomic file write | Inject failure at staging create/write/flush/sync, etag recheck, namespace move, post-error state check, and durability barrier | Old or new target remains a complete authenticated envelope; ambiguous namespace state is explicit; no partial plaintext/target. |
| Atomic metadata write | Same fault points during password-slot transaction | At least one unlockable authenticated metadata copy remains; EDRY files unchanged. |
| Concurrency | Two independent sidecars write the same etag; rename/write; delete/write | Exactly one mutation commits; the other receives a stable conflict with current etag. |
| Logical paths | Traversal, absolute/backslash, controls, reserved names/chars/devices, leading/trailing spaces, DOS `~digit` aliases, NFC/case collisions, coexisting aliases, 251-byte filename and 1024-byte path boundaries | Same accept/reject result on Linux and Windows; no vault escape or Git/NTFS alias; Windows native Git round-trip uses `core.longPaths=true`. |
| Filesystem boundary | Network/FUSE root, nested mount/bind mount, symlink, Windows junction/reparse, hardlink and identity swap | Unsupported storage fails before KDF/read/write/recovery; no external path is opened, retired, or deleted. |
| Text byte round trip | Chinese, emoji, combining characters, BOM, LF/CRLF/mixed newline, empty and max-size input | Decrypted bytes exactly equal input; no implicit normalization/newline rewrite. |
| RPC framing | Partial/coalesced frames, invalid length, oversize/deep JSON, batch/notification, stdout noise | Parser stays synchronized or terminates safely; no allocation beyond limits. |
| RPC leakage | Canary password/content/token through success, all errors, malformed input and crash | Canary absent from argv, environment, stderr, diagnostics, backup names, and logs. |
| Session lifecycle | Wrong token, explicit lock, stdin EOF, editor crash, idle expiry, daemon shutdown | Old capabilities fail uniformly; index/cache/key access is gone. |
| Search freshness | External replacement, same-size in-place tamper, preserved timestamps, second sidecar save | Every query verifies current ciphertext etags; changed/corrupt storage invalidates the plaintext index before returning hits. |
| Encrypted drafts | Custom editor dirty backup, restore before unlock, stale base etag, corrupted backup | Backup disk bytes are EDRY draft ciphertext only; restore authenticates and never overwrites stale base silently. |
| VS Code residue | Edit/undo/save/dirty close/crash/restore with Hot Exit and Local History combinations | No plaintext canary in workspace storage, backups, local history, logs, telemetry, or extension state. |
| Sublime residue | Edit/save/close/crash/session restore/recent-files matrix | No plaintext canary on disk before the client leaves experimental status. |
| Locked Git driver | Normal Git merge invokes driver without an unlock broker | `%A` hash unchanged, nonzero status, stages 1/2/3 retained, no plaintext artifact. |
| Unlocked Git resolution | Clean/conflicting diff3, delete/modify, rename/modify, Unicode/space path | Clean result is valid EDRY; unresolved markers are encrypted and conflict flag authenticates. |
| Driver installation | Fresh clone before/after `inex git install-driver` | `.gitattributes` travels with Git; local `.git/config` is installed only by explicit command. |
| Copy import | Symlink/junction, overlap, path collision, source changes, disk fault, existing destination | Source hashes/bytes remain unchanged; destination is absent or a clearly marked ciphertext staging vault. |
| In-place import | Explicit confirmation absent/present and injected failures | Disabled by default; implementation cannot delete a source before verified encrypted replacement and backup. |
| Compatibility | Fixed vault/password/salt/master/slot/file id/nonce/header/body vectors | Linux and Windows produce/consume byte-identical fixtures. |
| Upgrade | Open frozen v1 fixtures in later builds; unknown major/required feature | v1 read does not rewrite; unsupported state fails closed with stable error. |
| Packaging | Offline clean build and platform package smoke test | Bundled libsodium version is reported; binaries/VSIX/Sublime package start on supported targets. |

## Filesystem residue audit roots

Release tests scan the vault, its parent staging area, OS temporary directory,
VS Code user/workspace storage and backup/local-history roots, Sublime session
and cache roots, project logs, and crash-test fixture directories for a unique
plaintext canary. CI reports paths and counts but never uploads the canary body
or a real vault.

## Release decision

- **Core pre-alpha exit:** every non-editor row through “Session lifecycle” and
  the compatibility row pass on Linux and Windows.
- **VS Code MVP:** encrypted draft and VS Code residue rows also pass.
- **Sublime supported:** Sublime residue row passes on each advertised version;
  until then the package remains experimental regardless of functional tests.
- **GA:** Git, import, upgrade, and packaging rows pass with recovery docs and
  a reproducible, offline-capable release build.
