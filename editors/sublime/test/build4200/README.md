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

PYTHONDONTWRITEBYTECODE=1 timeout --signal=TERM --kill-after=5s 180s \
  python3.13 editors/sublime/test/build4200/run_build4200.py \
  --artifact-directory /absolute/linux-x64-four-file-artifact \
  --output /absolute/private-evidence/sublime-full-application-restart.json \
  --full-application-kill-restart
```

Artifact mode snapshots and strictly audits all four files, materializes the
CLI and unpacked Sublime package only from the captured archive bytes, and
forces production's package-owned `Inex/bin/inexd` resolution. It seals the
artifact snapshot, installed package, executable and harness identities across
the run, checks the observed sidecar through Linux `/proc`, removes the
isolated root, and only then creates the external canonical report as mode
0600. The artifact and clean harness commits are recorded separately and need
not be the same commit.

The normal and plugin-host-crash reports retain the strict outer schema v2.
The successor full-application-kill-restart scenario uses outer schema v4;
the current validator deliberately rejects the predecessor v3 report as a
successor. It keeps the same isolated profile and installed package for two
launches. After the first
encrypted save, the helper writes only canonical length/SHA-256 fingerprints
to a mode-0600 state file. Before launch, the runner enables and reads back the
Linux child-subreaper setting. It pre-seals and captures the exact main, Python
plugin-host, and packaged-sidecar identities, stabilizes the complete launch
session plus descendant closure, opens pidfds only after PID/start-time/
session/parent identity rechecks, and delivers SIGKILL through those pidfds.
Any descendant which used `setsid` or daemonized is either already in that
closure or is adopted by the confirmed subreaper and drained through a newly
verified pidfd.

The restart child environment also fixes `GTK_USE_PORTAL=0`, and its private
D-Bus daemon uses a generated configuration with no activation service
directories or included host configuration. This prevents GTK or Build 4200
from activating host desktop/document portals against the isolated runtime.

The checkpoint then stops the isolated desktop, X11 socket, and D-Bus session
and performs two stable procfs censuses. A process is root-bound only through
an exact isolated HOME/XDG/TMP environment value or an executable, cwd,
process-root, or open-fd target within the private root; an argv mention alone
is not a binding and is never a reason to signal an unrelated process.
Unreadable procfs state for a verified closure/adopted candidate fails closed.
Any remaining root-bound process also fails the scenario instead of being
blindly killed. The runner then parses bounded `/proc/self/mountinfo` input and
requires zero mountpoints at or below the isolated root. Only after both the
zero-survivor and zero-mount checkpoints does it perform the intermediate
zero-hit residue scan and start the second launch. The same checks are repeated
after the final launch.

A successful run never unmounts anything to manufacture a zero-mount claim.
On a failed run only, after confirming no live root-bound process, cleanup may
use the sealed root-owned `fusermount3` helper for one exact disconnected
`fuse.portal`/`portal` mount at `runtime/doc`. It invokes ordinary `-u` only;
lazy/detach unmounts are forbidden. Any live or unknown mount fails closed and
the root is retained.

Before the runner may answer the second password prompt, the restarted helper
must observe every window and view continuously for two seconds with no Inex
client, session, vault identity/path, unlock operation, registry entry,
plaintext handoff, pending plaintext owner, scrub/ack state, product marker,
known full-content fingerprint, or sliding-window random-token fingerprint.
Zero restored views is valid. The second launch then unlocks the same vault,
reopens `qa.md`, requires its length/SHA-256 to equal the first encrypted-save
checkpoint, and closes it through the normal Inex command. The v4 report binds
both launch identity sets, a reconstructable isolated environment, the exact
profile and package-owned sidecar paths, the unchanged installed tree, and the
canonical state seal. The random-token fingerprint-set digest is independently
cross-bound through the helper event, state binding, and lifecycle record.
Both the checkpoint and final residue scans remain mandatory.

When all three successor runs pass, their single-scenario reports establish an
exact-packaged Linux baseline. They do not close the remaining
persistent-profile matrix:
keyboard/menu Save variants, export/clipboard/macro surfaces,
matching/stale/corrupt drafts, project/non-project windows, idle/daemon/full
application kill variants beyond this one path, all CRUD negative paths,
other native platforms, and signing/publication remain explicitly outside
this increment.

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
