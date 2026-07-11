# Inex for VS Code

The primary Inex client will live here. It will launch `inexd`, expose an
`inex:` custom Markdown editor and tree, provide controlled navigation and
memory-only search UI, and audit editor settings that can persist plaintext.
The custom editor owns encrypted draft backups; ordinary writable virtual text
documents are deliberately not used because VS Code can persist their backups.

The package manifest is intentionally added only after the current official VS
Code API/engine baseline is frozen in Phase 1.
