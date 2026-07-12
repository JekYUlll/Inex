# Inex Vault Metadata, Version 1

Status: **frozen for v1 implementation on 2026-07-10**. Compatibility fixtures
are generated in Phase 2; semantic changes require an explicit compatibility
decision.

## JSON representation

`vault.json` is UTF-8 JSON. Member order is irrelevant. Names and numeric units
are fixed; implementations never serialize libsodium's mutable
`ALG_DEFAULT` value.

```json
{
  "format": {"major": 1, "minor": 0},
  "vaultId": "7b9aa4d2-7f30-4d42-b57b-7fd4c155abcd",
  "keyEpoch": 0,
  "createdAt": 1783699200000,
  "requiredFeatures": [],
  "keySlots": [
    {
      "id": "44957ed4-7051-45bd-8e4e-39b17d09a3a1",
      "kind": "password",
      "kdf": {
        "algorithm": "argon2id13",
        "salt": "base64url-no-padding",
        "opsLimit": 3,
        "memLimitBytes": 67108864
      },
      "wrap": {
        "algorithm": "xchacha20-poly1305-ietf",
        "nonce": "base64url-no-padding",
        "ciphertext": "base64url-no-padding"
      },
      "createdAt": 1783699200000
    }
  ],
  "features": {
    "filenameEncryption": false,
    "streamingBlobs": false
  },
  "metadataMac": "base64url-no-padding"
}
```

UUID strings are lowercase and canonical. Binary JSON values are unpadded
base64url with exact decoded lengths: Argon2id salt 16 bytes, wrap nonce 24
bytes, wrapped master key 48 bytes, and metadata MAC 32 bytes. Duplicate slot
IDs, empty slot sets, unknown required features, extra bytes, and non-canonical
encodings fail closed.

## Password slots

Each password slot independently stores all data needed to derive its KEK.
Passwords are exact UTF-8 bytes: implementations do not trim or Unicode
normalize them. v1 accepts 1–1024 bytes.

The KEK is the 32-byte result of libsodium `crypto_pwhash` with the explicit
Argon2id13 algorithm, slot salt, `opsLimit`, and `memLimitBytes`. Production v1
creation fixes memory at 64 MiB and parallelism at one, then process-caches an
ops-only calibration over 3–20 operations using a public dummy password and
salt. It prefers a selected observation in the inclusive 250–750 ms window. The
observation starts before parameter validation and possible libsodium
initialization, includes secure allocation and Argon2id, and ends before the
derived-key allocation is dropped. It is not pure KDF latency. The selected
values are stored in the slot. This window is not the end-to-end duration of
create/import, which also derives from the real password, wraps, commits, and
re-authenticates metadata.

Diagnostic evidence classifies the selector result as exactly one of
`target-window`, `minimum-above-window`, `interior-above-window`,
`maximum-above-window`, or `maximum-below-window`. A fallback classification
means only that the bounded selector returned its documented fallback. Because
timing can be noisy/non-monotonic and the search does not measure every
candidate, it must not be interpreted as proof that all permitted operations
values are incapable of meeting the window.

Under the default production policy, direct and RPC new-vault parameters have
a separate creation cap: 3–20 operations and exactly 64 MiB. Readers remain broader for compatibility
(default ceiling: 1 GiB and operations limit 20) and enforce that ceiling
before KDF allocation. Password add/change takes the componentwise maximum of
the calibrated baseline and the currently authenticated slot; a stronger
reader-safe slot is therefore retained rather than silently downgraded.

The KEK wraps one random 32-byte master key using
XChaCha20-Poly1305-IETF. Wrap AAD is deterministic CBOR over this ordered tuple:

```text
"INEX-WRAP-V1\0", format major/minor, vault UUID, key epoch,
slot UUID, slot kind, KDF algorithm, salt, ops limit, memory bytes,
wrap algorithm
```

The password key-slot identifier never appears in EDRY files. All valid slots
unwrap the same master key for the current epoch.

## Metadata authentication

After a slot unwrap succeeds, the reader authenticates the complete vault
metadata before accepting it. It first derives:

```text
metadata_key = BLAKE2b-256(
  key = vault_master_key,
  data = "INEX-METADATA-KEY-V1\0" || vault_uuid || u32be(key_epoch)
)
```

`metadataMac` is keyed BLAKE2b-256 over deterministic CBOR of every other
semantic field: format, vault id, epoch, creation time, required features,
features, and all complete key slots sorted by raw slot UUID. This detects
modification/removal of slots or feature flags that does not affect the chosen
unwrap operation. It does not claim rollback protection against replacing the
entire vault and Git history with an older valid state.

## Password changes

Changing a password is a key-slot transaction:

1. Unlock and authenticate the current metadata.
2. Create a new random slot id, salt, nonce, and wrapped master key.
3. Recompute `metadataMac` and write a same-directory ciphertext/metadata-only
   staging file with restrictive permissions.
4. Read that staging file and prove the new password unlocks/authenticates it.
5. Under the vault OS lock and expected `vault.json` etag, atomically replace
   the metadata and sync its parent directory where supported.
6. Remove an old slot only when explicitly requested, never before the new
   slot has been committed and verified.

All EDRY file hashes must remain byte-for-byte unchanged. Master-key rotation
is a different explicit migration that increments `keyEpoch` and rewrites every
file under backup/recovery controls.

## Filesystem rules

`vault.json` and its same-directory staging files never contain plaintext keys.
Permissions are restricted to the current user where the platform supports it.
Mutations use the cross-process vault lock, recheck etags inside the lock, sync
the staging file, and commit through the platform namespace backend. Linux uses
same-filesystem rename plus parent-directory sync. Windows uses extended-length
paths and `MoveFileExW(MOVEFILE_WRITE_THROUGH)`; it never enables cross-volume
copy. Ciphertext deletion first retires the logical name to encrypted private
storage on Windows so a crash can leave only an opaque tombstone.

A normal file write may report that durability was unconfirmed while still
returning a complete requested target proven by its etag. If a namespace call
reports failure, the implementation re-inspects the complete target and returns
an explicit indeterminate error unless it proves the exact pre-state or exact
requested ciphertext. A multi-path rename retains its recovery journal and
source unless every checkpoint needed before source retirement passes. Recovery
revalidates all ancestors, mount identity, file identity, and etags before it
touches either path.

Version 1 supports local filesystems only and fails closed when the backing
volume cannot be classified safely. A Linux descendant may not cross mount-id
or device boundaries, including same-device bind mounts. A Windows descendant
may not traverse a reparse point or leave the root volume.
