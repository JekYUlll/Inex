# Sublime Text Build 4200 isolated QA

`run_build4200.py` launches the exact local Build 4200 with a brand-new,
isolated XDG data directory. It starts its own private D-Bus session, Xvfb
server, and metacity instance, and preinstalls the current Inex package, exact
global preferences, and a test-only Python 3.8 helper. It does not use the real
Sublime profile. Build 4200 Safe Mode was not used because it intentionally
clears third-party packages and does not reliably hot-load a package created
after startup.

The initial bounded smoke flow imports one random Markdown document with the
real CLI, unlocks it through the real absolute `zenity` executable, opens
the real `.md.enc`, edits without putting plaintext in command arguments,
saves through Inex, closes the scratch view, terminates Sublime, and scans the
entire isolated root for UTF-8, UTF-16, hex, and base64 forms of both random
canaries and the random password. The password is typed into the masked prompt
from `xdotool` stdin; it is not placed in argv, a helper script, or the report.
`HOME`, all XDG roots, and `TMPDIR`/`TMP`/`TEMP` point into that root.
The report contains only fixed event names, booleans, lengths, and SHA-256
hashes; it never contains managed text.

The pure Python password tests still cover helper resolution, bounded output,
cancel/error behavior, and argv/environment/stderr invariants independently.

Build current binaries, then run:

```sh
cargo build -p inex-cli -p inex-daemon
timeout --signal=TERM --kill-after=5s 90s \
  python3 editors/sublime/test/build4200/run_build4200.py
```

That no-argument form is a developer smoke: it copies the current source
package and uses `target/debug/inex` plus `target/debug/inexd`. It is not
release-artifact evidence.

To bind the same flow to a strict four-file native release set, run from a
clean standalone checkout with exact CPython 3.13.14. The report parent must
already exist outside both the checkout and artifact directory, and each
output path must be absent:

```sh
mkdir -m 700 /absolute/private-evidence
PYTHONDONTWRITEBYTECODE=1 timeout --signal=TERM --kill-after=5s 90s \
  python3.13 editors/sublime/test/build4200/run_build4200.py \
  --artifact-directory /absolute/linux-x64-four-file-artifact \
  --output /absolute/private-evidence/sublime-normal.json

PYTHONDONTWRITEBYTECODE=1 timeout --signal=TERM --kill-after=5s 90s \
  python3.13 editors/sublime/test/build4200/run_build4200.py \
  --artifact-directory /absolute/linux-x64-four-file-artifact \
  --output /absolute/private-evidence/sublime-plugin-host-crash.json \
  --plugin-host-crash
```

Artifact mode snapshots and strictly audits all four files, materializes the
CLI and unpacked Sublime package only from the captured archive bytes, and
forces production's package-owned `Inex/bin/inexd` resolution. It seals the
artifact snapshot, installed package, executable and harness identities across
the run, checks the observed sidecar through Linux `/proc`, removes the
isolated root, and only then creates the external canonical report as mode
0600. The artifact and clean harness commits are recorded separately and need
not be the same commit.

These two single-scenario reports establish an exact-packaged Linux baseline.
They do not close the persistent-profile matrix: same-profile application
restart, keyboard/menu Save variants, export/clipboard/macro surfaces,
matching/stale/corrupt drafts, project/non-project windows, idle/daemon/full
application kills, all CRUD negative paths, other native platforms, and
signing/publication remain explicitly outside this increment.

After the minimal flow passes, probe abrupt Python plugin-host loss with:

```sh
timeout --signal=TERM --kill-after=5s 90s \
  python3 editors/sublime/test/build4200/run_build4200.py \
  --plugin-host-crash --keep
```

That mode follows the same ordinary open/edit/encrypted-save path, then keeps
the managed view open and kills only the isolated profile's
`plugin_host-3.8`. (The default run separately covers close and the final root
scan.) The restarted test helper reports the active view's byte length,
SHA-256 digest, and one fixed boolean marker. It never reports the view text.
An unchanged marked view is a fail-closed blocker and makes the runner exit
nonzero while retaining the isolated root.

Build 4200 does not restart a killed plugin host in the same editor process;
Sublime's documented recovery is to restart Sublime Text. The runner therefore
uses the private Xvfb clipboard for a black-box probe while the old host is
dead. It first tries native Select All/Copy, then a mouse selection through the
X11 PRIMARY channel, compares only byte length and SHA-256 with the pre-kill
values, and records whether a channel could be read. It never writes view text
to the report.

When Build 4200 requires an application restart, the scenario exits zero with
`PASS_WITH_DOCUMENTED_BOUNDARY`, `sublime_restart_required: true`, and the
measured host-dead copy result. This means the harness successfully reproduced
the declared experimental boundary; it does **not** mean crash-time plaintext
scrubbing passed. The runner then terminates the isolated editor and requires a
zero-hit root scan. If a build ever restarts the host automatically, the
existing marker-based orphan scrub remains a mandatory assertion instead.

Use `--keep` to retain an isolated failure root for diagnosis. The runner
tracks every process it starts and terminates Sublime, metacity, Xvfb, and
D-Bus in its `finally` cleanup path, including on SIGTERM. Failure roots are
retained; `--keep` also retains successful roots for inspection.
