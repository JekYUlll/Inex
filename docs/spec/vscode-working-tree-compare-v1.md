# VS Code Secure Working-Tree Compare v1

## Purpose

Native VS Code SCM continues to show `*.md.enc` as ciphertext. Inex may offer
`Compare Saved Working Copy with HEAD (Outer)` as a separate, unlocked-vault
command for understanding an already saved encrypted change.

## Boundary

- The left side is the authenticated current on-disk Inex document, never an
  unsaved CustomEditor textarea snapshot.
- The right side is the authenticated `HEAD` blob for the same canonical
  logical Markdown path.
- The daemon owns both worktree reads and Git plumbing. The extension supplies
  only an authenticated session plus a canonical logical path.
- The result is rendered only in an Inex-owned, script-free read-only webview.
  It must not create a plaintext `TextDocument`, native diff URI, temporary
  plaintext file, or Git textconv/filter invocation.
- Outer scope decrypts feature-2 public Drop/Cover/Placeholder projections
  without loading `K_umbra`. Umbra scope is a distinct future command requiring
  a second live Umbra unlock; Outer must never upgrade implicitly.

## Preconditions and failures

The command rejects a dirty active CustomEditor, missing `HEAD`, a missing or
non-regular ciphertext worktree file, unsupported Git control layout, active
merge/rebase/cherry-pick state, linked/external gitdir, and any envelope/path/
vault authentication failure. It is read-only and makes no worktree, index,
ref, configuration, or temporary-file write.

## Required implementation evidence

1. A real encrypted Git fixture changes and saves one working document without
   staging it; the daemon returns working/HEAD projections for that path only.
2. Outer canaries for private body and tag are absent; Umbra remains locked.
3. Extension Host proves the result is an Inex webview and lock/dispose wipes
   owned buffers. Native SCM remains ciphertext-only.
