#!/usr/bin/env sh
# Linux-only convenience runner for the real Neovim Outer/Umbra lifecycle.
set -eu

: "${INEX_SIDECAR:?set INEX_SIDECAR to an absolute inexd path}"
case "$INEX_SIDECAR" in /*) ;; *) echo 'INEX_SIDECAR must be absolute' >&2; exit 2;; esac
INEX_CLI=$(dirname "$INEX_SIDECAR")/inex
test -x "$INEX_CLI"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
VAULT=$(mktemp -d "${TMPDIR:-/tmp}/inex-neovim-vault-XXXXXX")
rmdir "$VAULT"
cleanup() { rm -rf "$VAULT"; }
trap cleanup EXIT HUP INT TERM

OUTER_PASSWORD=inex-neovim-test-outer
UMBRA_PASSWORD=inex-neovim-test-umbra
printf '%s\n%s\n' "$OUTER_PASSWORD" "$OUTER_PASSWORD" |
  script -q -e -c "\"$INEX_CLI\" init \"$VAULT\"" /dev/null

INEX_TEST_VAULT="$VAULT" INEX_TEST_PASSWORD="$OUTER_PASSWORD" \
INEX_TEST_UMBRA_PASSWORD="$UMBRA_PASSWORD" \
nvim --headless --clean --cmd "set rtp^=$ROOT/editors/neovim" \
  -l "$ROOT/editors/neovim/tests/outer_lifecycle.lua"
