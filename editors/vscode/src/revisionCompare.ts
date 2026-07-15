/**
 * Render a bounded, no-script revision comparison owned by the Inex webview.
 *
 * The caller already has authenticated HEAD and first-parent bytes.  Keeping
 * the presentation here avoids creating a plaintext VS Code TextDocument or
 * handing plaintext to the normal SCM diff provider.  This deliberately uses
 * a linear common-prefix/common-suffix alignment rather than an unbounded LCS
 * implementation: a large Markdown note must not turn opening a compare view
 * into quadratic work.
 */
export function revisionCompareHtml(head: Buffer, parent: Buffer): string {
  const headLines = splitLines(head.toString("utf8"));
  const parentLines = splitLines(parent.toString("utf8"));
  let prefix = 0;
  while (
    prefix < headLines.length &&
    prefix < parentLines.length &&
    headLines[prefix] === parentLines[prefix]
  ) {
    prefix += 1;
  }

  let suffix = 0;
  while (
    suffix < headLines.length - prefix &&
    suffix < parentLines.length - prefix &&
    headLines[headLines.length - suffix - 1] === parentLines[parentLines.length - suffix - 1]
  ) {
    suffix += 1;
  }

  const rows: CompareRow[] = [];
  const commonEnd = prefix;
  for (let index = 0; index < commonEnd; index += 1) {
    rows.push(compareRow(index + 1, headLines[index]!, "same", index + 1, parentLines[index]!, "same"));
  }

  const headMiddleEnd = headLines.length - suffix;
  const parentMiddleEnd = parentLines.length - suffix;
  const middleRows = Math.max(headMiddleEnd - prefix, parentMiddleEnd - prefix);
  for (let offset = 0; offset < middleRows; offset += 1) {
    const headIndex = prefix + offset;
    const parentIndex = prefix + offset;
    const hasHead = headIndex < headMiddleEnd;
    const hasParent = parentIndex < parentMiddleEnd;
    rows.push(compareRow(
      hasHead ? headIndex + 1 : undefined,
      hasHead ? headLines[headIndex]! : "",
      hasHead ? "head-change" : "empty",
      hasParent ? parentIndex + 1 : undefined,
      hasParent ? parentLines[parentIndex]! : "",
      hasParent ? "parent-change" : "empty",
    ));
  }

  for (let offset = 0; offset < suffix; offset += 1) {
    const headIndex = headMiddleEnd + offset;
    const parentIndex = parentMiddleEnd + offset;
    rows.push(compareRow(
      headIndex + 1,
      headLines[headIndex]!,
      "same",
      parentIndex + 1,
      parentLines[parentIndex]!,
      "same",
    ));
  }

  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><style>body{font-family:var(--vscode-editor-font-family);padding:1rem;color:var(--vscode-editor-foreground)}p{color:var(--vscode-descriptionForeground)}.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1rem}.column{min-width:0;border:1px solid var(--vscode-panel-border)}h2{margin:.7rem .75rem;font-size:1rem}.row{display:grid;grid-template-columns:3.75rem minmax(0,1fr);min-height:1.35rem}.number{padding:0 .5rem;text-align:right;user-select:none;color:var(--vscode-editorLineNumber-foreground);border-right:1px solid var(--vscode-panel-border)}.line{margin:0;padding:0 .6rem;white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--vscode-editor-font-family)}.head-change{background:color-mix(in srgb,var(--vscode-gitDecoration-addedResourceForeground) 20%,transparent)}.parent-change{background:color-mix(in srgb,var(--vscode-gitDecoration-deletedResourceForeground) 20%,transparent)}.empty{background:var(--vscode-editor-background)}@supports not (background:color-mix(in srgb,red,transparent)){.head-change{background:rgba(0,128,0,.16)}.parent-change{background:rgba(160,0,0,.16)}}</style></head><body><h1>Inex revision comparison</h1><p>HEAD is green; Parent is red. Only changed line ranges are highlighted.</p><div class="grid"><section class="column"><h2>HEAD</h2>${rows.map((row) => row.head).join("")}</section><section class="column"><h2>Parent</h2>${rows.map((row) => row.parent).join("")}</section></div></body></html>`;
}

interface CompareRow {
  readonly head: string;
  readonly parent: string;
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
