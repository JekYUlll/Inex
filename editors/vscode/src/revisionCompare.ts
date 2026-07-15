/**
 * Render a bounded, no-script revision comparison owned by the Inex webview.
 *
 * The caller already has authenticated HEAD and first-parent bytes.  Keeping
 * the presentation here avoids creating a plaintext VS Code TextDocument or
 * handing plaintext to the normal SCM diff provider. It uses deterministic
 * patience-style anchors plus a linear fallback, rather than an unbounded LCS:
 * large Markdown notes do not turn opening a compare view into quadratic work.
 */
export function revisionCompareHtml(head: Buffer, parent: Buffer): string {
  const headLines = splitLines(head.toString("utf8"));
  const parentLines = splitLines(parent.toString("utf8"));
  const rows: CompareRow[] = [];
  appendAlignedRows(headLines, parentLines, rows);

  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><style>body{font-family:var(--vscode-editor-font-family);padding:1rem;color:var(--vscode-editor-foreground)}p{color:var(--vscode-descriptionForeground)}.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1rem}.column{min-width:0;border:1px solid var(--vscode-panel-border)}h2{margin:.7rem .75rem;font-size:1rem}.row{display:grid;grid-template-columns:3.75rem minmax(0,1fr);min-height:1.35rem}.number{padding:0 .5rem;text-align:right;user-select:none;color:var(--vscode-editorLineNumber-foreground);border-right:1px solid var(--vscode-panel-border)}.line{margin:0;padding:0 .6rem;white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--vscode-editor-font-family)}.head-change{background:color-mix(in srgb,var(--vscode-gitDecoration-addedResourceForeground) 20%,transparent)}.parent-change{background:color-mix(in srgb,var(--vscode-gitDecoration-deletedResourceForeground) 20%,transparent)}.empty{background:var(--vscode-editor-background)}@supports not (background:color-mix(in srgb,red,transparent)){.head-change{background:rgba(0,128,0,.16)}.parent-change{background:rgba(160,0,0,.16)}}</style></head><body><h1>Inex revision comparison</h1><p>HEAD is green; Parent is red. Only changed line ranges are highlighted.</p><div class="grid"><section class="column"><h2>HEAD</h2>${rows.map((row) => row.head).join("")}</section><section class="column"><h2>Parent</h2>${rows.map((row) => row.parent).join("")}</section></div></body></html>`;
}

/** Render an explicit public-only projection in the same no-script boundary. */
export function outerProjectionHtml(content: Buffer): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><style>body{font-family:var(--vscode-editor-font-family);padding:1rem;color:var(--vscode-editor-foreground)}p{color:var(--vscode-descriptionForeground)}pre{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--vscode-panel-border);padding:.75rem}</style></head><body><h1>Inex Outer Projection</h1><p>Read-only public rendering. Private slots are shown only by their public Drop, Cover, or Placeholder strategy.</p><pre>${escapeHtml(content.toString("utf8"))}</pre></body></html>`;
}

interface CompareRow {
  readonly head: string;
  readonly parent: string;
}

type AlignmentTask = EqualTask | SegmentTask | ChangedTask;

interface EqualTask {
  readonly kind: "equal";
  readonly headIndex: number;
  readonly parentIndex: number;
}

interface SegmentTask {
  readonly kind: "segment";
  readonly headStart: number;
  readonly headEnd: number;
  readonly parentStart: number;
  readonly parentEnd: number;
}

interface ChangedTask {
  readonly kind: "changed";
  readonly headStart: number;
  readonly headEnd: number;
  readonly parentStart: number;
  readonly parentEnd: number;
}

function appendAlignedRows(head: readonly string[], parent: readonly string[], rows: CompareRow[]): void {
  const tasks: AlignmentTask[] = [{
    kind: "segment", headStart: 0, headEnd: head.length, parentStart: 0, parentEnd: parent.length,
  }];
  while (tasks.length > 0) {
    const task = tasks.pop()!;
    if (task.kind === "equal") {
      rows.push(compareRow(task.headIndex + 1, head[task.headIndex]!, "same", task.parentIndex + 1, parent[task.parentIndex]!, "same"));
      continue;
    }
    if (task.kind === "changed") {
      appendChangedRows(head, parent, task, rows);
      continue;
    }
    const parts = splitSegment(head, parent, task);
    for (let index = parts.length - 1; index >= 0; index -= 1) tasks.push(parts[index]!);
  }
}

function splitSegment(
  head: readonly string[],
  parent: readonly string[],
  segment: SegmentTask,
): AlignmentTask[] {
  let { headStart, headEnd, parentStart, parentEnd } = segment;
  const parts: AlignmentTask[] = [];
  while (headStart < headEnd && parentStart < parentEnd && head[headStart] === parent[parentStart]) {
    parts.push({ kind: "equal", headIndex: headStart, parentIndex: parentStart });
    headStart += 1;
    parentStart += 1;
  }
  const suffix: EqualTask[] = [];
  while (headStart < headEnd && parentStart < parentEnd && head[headEnd - 1] === parent[parentEnd - 1]) {
    headEnd -= 1;
    parentEnd -= 1;
    suffix.push({ kind: "equal", headIndex: headEnd, parentIndex: parentEnd });
  }

  const anchors = patienceAnchors(head, parent, headStart, headEnd, parentStart, parentEnd);
  if (anchors.length === 0) {
    if (headStart !== headEnd || parentStart !== parentEnd) {
      parts.push({ kind: "changed", headStart, headEnd, parentStart, parentEnd });
    }
  } else {
    let cursorHead = headStart;
    let cursorParent = parentStart;
    for (const anchor of anchors) {
      if (cursorHead !== anchor.headIndex || cursorParent !== anchor.parentIndex) {
        parts.push({
          kind: "segment", headStart: cursorHead, headEnd: anchor.headIndex,
          parentStart: cursorParent, parentEnd: anchor.parentIndex,
        });
      }
      parts.push({ kind: "equal", headIndex: anchor.headIndex, parentIndex: anchor.parentIndex });
      cursorHead = anchor.headIndex + 1;
      cursorParent = anchor.parentIndex + 1;
    }
    if (cursorHead !== headEnd || cursorParent !== parentEnd) {
      parts.push({ kind: "segment", headStart: cursorHead, headEnd, parentStart: cursorParent, parentEnd });
    }
  }
  for (let index = suffix.length - 1; index >= 0; index -= 1) parts.push(suffix[index]!);
  return parts;
}

function patienceAnchors(
  head: readonly string[], parent: readonly string[], headStart: number, headEnd: number, parentStart: number, parentEnd: number,
): readonly EqualTask[] {
  const headUnique = uniqueLinePositions(head, headStart, headEnd);
  const parentUnique = uniqueLinePositions(parent, parentStart, parentEnd);
  const candidates: EqualTask[] = [];
  for (const [line, headIndex] of headUnique) {
    const parentIndex = parentUnique.get(line);
    if (headIndex !== undefined && parentIndex !== undefined) candidates.push({ kind: "equal", headIndex, parentIndex });
  }
  candidates.sort((left, right) => left.headIndex - right.headIndex);
  return longestIncreasingParentSequence(candidates);
}

function uniqueLinePositions(lines: readonly string[], start: number, end: number): Map<string, number | undefined> {
  const positions = new Map<string, number | undefined>();
  for (let index = start; index < end; index += 1) {
    const line = lines[index]!;
    if (!positions.has(line)) positions.set(line, index);
    else positions.set(line, undefined);
  }
  return positions;
}

function longestIncreasingParentSequence(candidates: readonly EqualTask[]): readonly EqualTask[] {
  const tails: number[] = [];
  const previous = new Array<number>(candidates.length).fill(-1);
  for (let index = 0; index < candidates.length; index += 1) {
    const parentIndex = candidates[index]!.parentIndex;
    let low = 0;
    let high = tails.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (candidates[tails[middle]!]!.parentIndex < parentIndex) low = middle + 1;
      else high = middle;
    }
    if (low > 0) previous[index] = tails[low - 1]!;
    tails[low] = index;
  }
  const result: EqualTask[] = [];
  for (let cursor = tails.at(-1) ?? -1; cursor >= 0; cursor = previous[cursor]!) result.push(candidates[cursor]!);
  result.reverse();
  return result;
}

function appendChangedRows(
  head: readonly string[], parent: readonly string[], segment: ChangedTask, rows: CompareRow[],
): void {
  const count = Math.max(segment.headEnd - segment.headStart, segment.parentEnd - segment.parentStart);
  for (let offset = 0; offset < count; offset += 1) {
    const headIndex = segment.headStart + offset;
    const parentIndex = segment.parentStart + offset;
    const hasHead = headIndex < segment.headEnd;
    const hasParent = parentIndex < segment.parentEnd;
    const same = hasHead && hasParent && head[headIndex] === parent[parentIndex];
    rows.push(compareRow(
      hasHead ? headIndex + 1 : undefined, hasHead ? head[headIndex]! : "", same ? "same" : hasHead ? "head-change" : "empty",
      hasParent ? parentIndex + 1 : undefined, hasParent ? parent[parentIndex]! : "", same ? "same" : hasParent ? "parent-change" : "empty",
    ));
  }
}

function splitLines(value: string): string[] {
  if (value.length === 0) return [];
  const lines = value.split("\n");
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

function compareRow(
  headNumber: number | undefined,
  headLine: string,
  headClass: "same" | "head-change" | "empty",
  parentNumber: number | undefined,
  parentLine: string,
  parentClass: "same" | "parent-change" | "empty",
): CompareRow {
  return {
    head: lineHtml(headNumber, headLine, headClass),
    parent: lineHtml(parentNumber, parentLine, parentClass),
  };
}

function lineHtml(number: number | undefined, line: string, className: string): string {
  return `<div class="row ${className}"><span class="number">${number ?? ""}</span><pre class="line">${escapeHtml(line)}</pre></div>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character] ?? character);
}
