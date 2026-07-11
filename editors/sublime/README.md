# Inex for Sublime Text

The lightweight Sublime Text package will live here. It will launch `inexd`,
browse with Quick Panels, and keep Markdown in scratch buffers with plugin-owned
dirty/version state and encrypted draft autosaves. It will not emulate a native
filesystem or rely on non-cancellable `on_pre_save`/`on_pre_close` callbacks.

Writable mode is hard-blocked unless application-global `hot_exit` is
`"disabled"`, `hot_exit_projects` is `false`, and
`update_system_recent_files` is `false`. The package remains experimental until
Safe Mode/isolated-data-directory residue tests pass on every advertised build.

The package skeleton is intentionally added only after the current Sublime API
and persistence limitations are frozen in Phase 1.
