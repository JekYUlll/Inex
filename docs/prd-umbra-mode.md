# Inex Umbra Mode and Private Annotation System

Status: **proposed next implementation milestone; no Umbra storage, RPC, or
editor command is implemented by this document.**

## Product purpose

Umbra Mode lets an unlocked user annotate one or more Markdown ranges as
private content without exposing the annotation kind, private tag IDs, tag
labels, profile names, private Markdown, timestamps, or private link metadata
to Outer Mode or the ciphertext repository.

The primary interaction is comment-like:

```text
select one or more Markdown ranges
  -> invoke a configurable private-annotation command
  -> choose kind, zero-or-more private tags, and an Outer strategy
  -> apply one specification atomically to every selected range
  -> save encrypted private payloads under K_umbra
```

Fresh annotation wraps ordinary Umbra Markdown. A complete existing private
block can be unwrapped only after confirmation; a cursor inside one private
block opens its metadata editor. Mixed plain/private selections and partial
private-block intersections fail atomically.

## Terminology

| Term | Meaning |
|---|---|
| Private annotation | A private marker on selected Markdown content. |
| Annotation kind | `block`, `comment`, or future `inline`. |
| Private tag | User-defined searchable metadata encrypted with K_umbra. |
| Annotation profile | Reusable kind, default tags, Outer strategy, and cover behavior. |
| Interactive annotation | Opens the selector before applying. |
| Quick annotation | Applies the default or last-used profile. |
| Toggle annotation | Wraps plain content, unwraps complete blocks, or edits an enclosing block. |
| Outer strategy | Deliberately public rendering: `drop`, `cover`, or `placeholder`. |

## Commands and editor-local configuration

The editor-neutral command surface is:

```text
inex.togglePrivateAnnotation
inex.choosePrivateAnnotation
inex.applyPrivateAnnotationProfile
inex.editPrivateAnnotation
inex.removePrivateAnnotation
inex.managePrivateTags
inex.managePrivateAnnotationProfiles
```

`togglePrivateAnnotation` requires Umbra Mode. If the current view is Outer
Mode, the client asks for the Umbra password, unlocks it, and then continues.
Its resolution is fixed:

```text
all plain selections             -> obtain a spec and wrap
all complete private blocks      -> confirm and unwrap
cursor inside one private block  -> edit its metadata
mixed or partial intersections   -> reject without mutation
```

`choosePrivateAnnotation` always opens the selector.
`applyPrivateAnnotationProfile` accepts `{ "profileId": "..." }`.
`removePrivateAnnotation` always requires confirmation by default because it
makes the text ordinary Outer content on the next save.

Editor-local settings contain interaction preferences only:

```json
{
  "inex.privateAnnotation.toggleBehavior": "alwaysAsk",
  "inex.privateAnnotation.noSelectionTarget": "paragraph",
  "inex.privateAnnotation.confirmBeforeUnwrap": true,
  "inex.privateAnnotation.rememberLastSelection": true,
  "inex.privateAnnotation.mergeAdjacentSelections": false
}
```

`toggleBehavior` is one of `alwaysAsk` (default), `useLast`,
`useDefaultProfile`, or `askOnFirstUse`. With no explicit selection,
`noSelectionTarget` is one of `line`, `paragraph` (default), `headingSection`,
or `reject`. These settings must not contain tag labels, selected tags,
profiles, or private content.

Default, configurable keybindings are:

```text
Ctrl+Alt+/        inex.togglePrivateAnnotation
Ctrl+Alt+Shift+/  inex.choosePrivateAnnotation
Ctrl+Alt+H        alias for inex.choosePrivateAnnotation
Ctrl+Alt+O        quick redact to Outer Mode
```

Clients contribute ordinary editor keybindings only; they must not handle raw
keyboard events. Profile shortcuts use ordinary command arguments, for example
`{ "profileId": "relationship-comment" }`.

### Current VS Code MVP status

The current VS Code implementation contributes `togglePrivateAnnotation`,
`choosePrivateAnnotation`, `applyPrivateAnnotationProfile`,
`editPrivateAnnotation`, and `removePrivateAnnotation`. `Ctrl+Alt+/` and `Ctrl+Alt+Shift+/` are contributed
through normal keybinding metadata; `Ctrl+Alt+H` is a chooser alias. A profile binding can be added in the user
keybindings file:

```json
{
  "key": "ctrl+alt+2",
  "command": "inex.applyPrivateAnnotationProfile",
  "args": { "profileId": "relationship-comment" },
  "when": "inex.vaultUnlocked"
}
```

The MVP supports one textarea selection. `inex.privateAnnotation.noSelectionTarget`
is a window-local setting with `paragraph` (default), `line`, and `reject`;
the first two resolve an empty selection without retaining content in settings.
`inex.privateAnnotation.confirmBeforeUnwrap` defaults to `true` and governs
both toggle unwrap and explicit removal. Multi-cursor adapters, heading-section
expansion, cursor-inside metadata edit, shortcut `toggleBehavior`, and tag/profile
management commands remain pending. Outer projection editing
and Umbra draft recovery are deliberately fail-closed until their dedicated
authenticated save paths are implemented.

`Inex: Edit Private Annotation` requires the cursor or a non-complete selection
inside exactly one private block. It preselects the block's current kind, tags,
and Outer strategy from the unlocked canonical projection, then sends a
non-empty marker range plus the full RenderMap to the daemon. The daemon
preserves the slot ID and private Markdown while it re-authenticates and
rewrites the encrypted metadata.

## Selection transaction

Before a mutation, the core normalizes selections, resolves empty selections,
sorts, merges overlapping ranges, validates RenderMap boundaries, and rejects
partial private-block intersections. Adjacent selections remain separate unless
the local `mergeAdjacentSelections` setting is enabled. Ranges are applied from
the end of the document toward its beginning. One failure rolls back the entire
operation; no partial set of slots may be committed.

Every selected range receives a separate slot with the same annotation spec.
Nested private blocks and inline fragments are deferred; the MVP supports
`block` and `comment` only.

## Selector requirements

The selector has three groups:

| Group | Cardinality | MVP values |
|---|---:|---|
| Annotation kind | exactly one | Private Block, Private Comment |
| Private tags | zero or more | vault-defined active tags |
| Outer strategy | exactly one | Drop, Cover, Placeholder |

Choosing `Cover` prompts for deliberately public cover text only after the
selector is accepted. The selector also exposes Create Private Tag, Manage
Tags, Save as Profile, Apply, and Cancel actions.

VS Code uses a `QuickPick` with `canSelectMany = true`, while enforcing the
single-choice kind and Outer groups in extension state. Sublime MVP uses a
stateful repeated `show_quick_panel` with checkbox-like labels and Done/Cancel;
it must not claim native multi-selection.

## Encrypted configuration and tags

The shared catalog and profiles live only in this logical encrypted vault
document:

```text
.inex/config.umbra.inex
```

It is encrypted with K_umbra, Git-synchronized, unavailable in Outer Mode, and
loaded only after Umbra unlock. It is not a VS Code setting, Sublime setting, or
plaintext JSON file.

The decrypted v1 schema is:

```json
{
  "format": "inex-umbra-config",
  "version": 1,
  "tagCatalog": [{
    "id": "comment-content",
    "label": "注释内容",
    "description": "General private annotation",
    "aliases": ["comment", "annotation"],
    "sortOrder": 10,
    "defaultSelected": true,
    "archived": false
  }],
  "annotationProfiles": [{
    "id": "relationship-comment",
    "label": "感情私密注释",
    "kind": "comment",
    "tagIds": ["comment-content", "relationship"],
    "outer": { "mode": "drop" },
    "promptForCover": false
  }],
  "defaults": {
    "kind": "comment",
    "tagIds": ["comment-content"],
    "outerStrategy": { "mode": "drop" },
    "defaultProfileId": "relationship-comment"
  }
}
```

Tag IDs match `^[a-z0-9][a-z0-9._-]{0,63}$`, are normalized and deduplicated,
and serialize in catalog `sortOrder`. Labels are free-form Unicode. Renaming a
label never changes its ID; archived tags remain readable in old documents;
missing definitions display as unknown archived tags. Managing tags supports
create, rename label, archive, and reorder. Managing profiles supports create,
edit, and remove. All names, aliases, defaults, and profiles remain encrypted.

## Canonical projected syntax

Umbra's editable projection uses the following canonical block syntax:

```markdown
:::inex-private
id: p_01
kind: comment
tags: [comment-content, relationship, family]
outer: drop
---
真正私密的内容。
:::
```

The parser must have a bounded, unambiguous grammar; compact attribute syntax
is deferred. The projection is an authenticated editor representation, not the
Outer on-disk metadata format.

## Cryptographic data model

The slot's decrypted K_umbra payload v1 is conceptually:

```json
{
  "format": "inex-private-slot",
  "version": 1,
  "kind": "comment",
  "tags": ["comment-content", "relationship", "family"],
  "markdown": "真正私密的内容。\n",
  "createdAt": "RFC3339 timestamp",
  "updatedAt": "RFC3339 timestamp"
}
```

Only slot ID, cipher metadata, and deliberately public Outer strategy/cover
text may be present in the Outer document slot entry. `kind`, tags, private
Markdown, private timestamps, and private link metadata must be inside the
K_umbra ciphertext. Existing slots without kind/tags decode as
`kind = block`, `tags = []` for backwards compatibility.

The core model introduces `PrivateAnnotationKind`, validated `TagId`,
`PrivateAnnotationSpec`, `PrivateSlotPayloadV1`, `PrivateTagDefinition`,
`AnnotationProfile`, `PrivateAnnotationDefaults`, and `UmbraConfigV1`.
Public RPC/API methods include load/save config, apply/toggle/edit/remove
annotation, and create/archive tags. The exact JSON-RPC schema and encrypted
on-disk envelope must be frozen in dedicated v1 specs before implementation.

## Security invariants

1. Tags, tag labels, profile names, kind, selected tags, private Markdown,
   timestamps, and private links never enter the Outer projection, Outer
   search/index, public cover metadata, logs, or exception messages.
2. A tag catalog canary such as `INEX_SECRET_TAG_CANARY` has no disk, Outer
   projection, or Outer index occurrence after save.
3. All annotation mutations are authenticated, etag-aware, and atomic with the
   document update and encrypted config update when both change.
4. Clients never receive K_umbra or a plaintext filesystem path; they only use
   sidecar session capabilities and logical paths.
5. Outer cover text is explicitly public and must be separately confirmed by
   the UI when entered.

## Acceptance criteria

- Rebound normal editor keybindings invoke commands without hard-coded key
  handling.
- One annotation can contain multiple encrypted tags; three normalized ranges
  produce three slots with identical metadata.
- Toggle wrap/confirm-unwarp/edit behavior follows the decision table above.
- Renaming or archiving a tag preserves existing slot IDs and does not rewrite
  their encrypted Markdown merely to change a label.
- A VS Code-created catalog/profile appears in Sublime after Git sync and Umbra
  unlock.
- Tests prove encrypted tag canary absence from disk and Outer state, picker
  constraints, Sublime state transitions, selection rollback, and legacy-slot
  compatibility.

## Implementation sequence

1. Freeze Umbra slot/config storage and cryptographic domain separation.
2. Implement validated core models, atomic encrypted config persistence, and
   backwards-compatible slot decoding.
3. Add daemon session/RPC methods and core selection/render-map transaction.
4. Add VS Code command, QuickPick, profiles, keybinding contributions, and
   tests.
5. Add Sublime stateful picker, commands, keymap examples, and tests.
6. Run cross-editor, canary/residue, mutation/rollback, and Outer-isolation
   acceptance matrices before calling the milestone complete.

Deferred: inline fragments, nesting, tag colors/hierarchies, boolean tag
queries, and a custom Sublime minihtml selector.
