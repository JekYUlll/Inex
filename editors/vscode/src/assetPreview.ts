import { assetPathComponents, logicalFileComponents } from "./logicalPath.ts";

const MAX_IMAGE_REFERENCES = 64;

/**
 * Resolve one Markdown image destination into the opaque-asset namespace.
 * External, absolute, query-bearing, encoded-separator, and escaping targets
 * are deliberately inert.
 */
export function resolveAssetImageTarget(
  currentLogicalPath: string,
  rawTarget: string,
): string {
  logicalFileComponents(currentLogicalPath);
  let target = rawTarget.trim();
  if (target.startsWith("<") && target.endsWith(">")) {
    target = target.slice(1, -1);
  }
  if (
    target.length === 0 ||
    target.startsWith("/") ||
    target.startsWith("\\") ||
    target.startsWith("//") ||
    target.includes("?") ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(target)
  ) {
    throw new Error("Markdown image target is not a relative vault asset");
  }

  const hash = target.indexOf("#");
  if (hash >= 0) {
    target = target.slice(0, hash);
  }
  if (target.length === 0) {
    throw new Error("Markdown image target has no asset path");
  }

  const parts = currentLogicalPath.split("/").slice(0, -1);
  for (const encoded of target.split("/")) {
    if (encoded.length === 0) {
      throw new Error("Markdown image target contains an empty component");
    }
    const component = decodePathComponent(encoded);
    if (component === ".") {
      continue;
    }
    if (component === "..") {
      if (parts.length === 0) {
        throw new Error("Markdown image target escapes the vault root");
      }
      parts.pop();
      continue;
    }
    parts.push(component);
  }
  const logicalPath = parts.join("/").normalize("NFC");
  assetPathComponents(logicalPath);
  return logicalPath;
}

/**
 * Extract conservative CommonMark-style inline image destinations. Fenced
 * code, inline code, raw HTML, reference images, and malformed constructs are
 * ignored. Returned paths are canonical, de-duplicated, and bounded.
 */
export function parseMarkdownImageTargets(
  currentLogicalPath: string,
  markdown: string,
): readonly string[] {
  logicalFileComponents(currentLogicalPath);
  const targets: string[] = [];
  const seen = new Set<string>();
  let fence: { readonly marker: "`" | "~"; readonly length: number } | undefined;
  let htmlComment = false;
  let rawHtmlTag: "script" | "style" | "pre" | "textarea" | undefined;

  for (const rawLine of markdown.split(/\n/u)) {
    const completeLine = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (fence !== undefined) {
      const closing = fenceBoundary(completeLine);
      if (
        closing?.marker === fence.marker &&
        closing.length >= fence.length &&
        closing.onlyFence
      ) {
        fence = undefined;
      }
      continue;
    }
    if (rawHtmlTag !== undefined) {
      if (rawHtmlClose(completeLine, rawHtmlTag)) {
        rawHtmlTag = undefined;
      }
      continue;
    }
    const commentFiltered = stripHtmlComments(completeLine, htmlComment);
    htmlComment = commentFiltered.insideComment;
    const line = commentFiltered.text;
    const boundary = fenceBoundary(line);
    if (boundary !== undefined) {
      fence = boundary;
      continue;
    }
    const rawStart = rawHtmlStart(line);
    if (rawStart !== undefined) {
      if (!rawHtmlClose(line, rawStart)) {
        rawHtmlTag = rawStart;
      }
      continue;
    }
    if (/^(?: {4}|\t)/u.test(line)) {
      continue;
    }
    for (const rawTarget of imageDestinationsOutsideInlineCode(line)) {
      let logicalPath: string;
      try {
        logicalPath = resolveAssetImageTarget(currentLogicalPath, rawTarget);
      } catch {
        continue;
      }
      if (!seen.has(logicalPath)) {
        seen.add(logicalPath);
        targets.push(logicalPath);
        if (targets.length >= MAX_IMAGE_REFERENCES) {
          return targets;
        }
      }
    }
  }
  return targets;
}

function decodePathComponent(encoded: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(encoded);
  } catch {
    throw new Error("Markdown image target has invalid percent encoding");
  }
  if (decoded.includes("/") || decoded.includes("\\")) {
    throw new Error("Markdown image target encodes a separator");
  }
  if (decoded.normalize("NFC") !== decoded) {
    decoded = decoded.normalize("NFC");
  }
  return decoded;
}

function fenceBoundary(
  line: string,
): {
  readonly marker: "`" | "~";
  readonly length: number;
  readonly onlyFence: boolean;
} | undefined {
  const match = /^ {0,3}(`{3,}|~{3,})/u.exec(line);
  const run = match?.[1];
  const marker = run?.[0];
  return run !== undefined && (marker === "`" || marker === "~")
    ? {
        marker,
        length: run.length,
        onlyFence: /^[ \t]*$/u.test(line.slice(match?.[0].length ?? 0)),
      }
    : undefined;
}

function rawHtmlStart(
  line: string,
): "script" | "style" | "pre" | "textarea" | undefined {
  const match = /^ {0,3}<(script|style|pre|textarea)(?:[\t >]|$)/iu.exec(line);
  const tag = match?.[1]?.toLowerCase();
  return tag === "script" || tag === "style" || tag === "pre" || tag === "textarea"
    ? tag
    : undefined;
}

function rawHtmlClose(
  line: string,
  tag: "script" | "style" | "pre" | "textarea",
): boolean {
  return new RegExp(`</${tag}[ \\t]*>`, "iu").test(line);
}

function imageDestinationsOutsideInlineCode(line: string): readonly string[] {
  const destinations: string[] = [];
  let cursor = 0;
  let codeRun = 0;
  while (cursor < line.length) {
    if (line[cursor] === "`") {
      const length = runLength(line, cursor, "`");
      if (codeRun === 0) {
        codeRun = length;
      } else if (length === codeRun) {
        codeRun = 0;
      }
      cursor += length;
      continue;
    }
    if (
      codeRun !== 0 ||
      line[cursor] !== "!" ||
      line[cursor + 1] !== "[" ||
      isEscaped(line, cursor)
    ) {
      cursor += 1;
      continue;
    }
    const labelEnd = findUnescaped(line, "]", cursor + 2);
    if (labelEnd < 0 || line[labelEnd + 1] !== "(") {
      cursor += 2;
      continue;
    }
    const parsed = parseInlineDestination(line, labelEnd + 2);
    if (parsed === undefined) {
      cursor = labelEnd + 2;
      continue;
    }
    destinations.push(parsed.destination);
    cursor = parsed.end;
  }
  return destinations;
}

function stripHtmlComments(
  line: string,
  initiallyInside: boolean,
): { readonly text: string; readonly insideComment: boolean } {
  let insideComment = initiallyInside;
  let cursor = 0;
  let result = "";
  while (cursor < line.length) {
    if (insideComment) {
      const close = line.indexOf("-->", cursor);
      if (close < 0) {
        return { text: result, insideComment: true };
      }
      cursor = close + 3;
      insideComment = false;
      continue;
    }
    const open = line.indexOf("<!--", cursor);
    if (open < 0) {
      result += line.slice(cursor);
      break;
    }
    result += line.slice(cursor, open);
    cursor = open + 4;
    insideComment = true;
  }
  return { text: result, insideComment };
}

function isEscaped(line: string, index: number): boolean {
  let slashes = 0;
  for (let cursor = index - 1; cursor >= 0 && line[cursor] === "\\"; cursor -= 1) {
    slashes += 1;
  }
  return slashes % 2 === 1;
}

function parseInlineDestination(
  line: string,
  start: number,
): { readonly destination: string; readonly end: number } | undefined {
  let cursor = start;
  while (line[cursor] === " " || line[cursor] === "\t") {
    cursor += 1;
  }
  if (line[cursor] === "<") {
    const close = findUnescaped(line, ">", cursor + 1);
    if (close < 0) {
      return undefined;
    }
    const end = closingParenthesisAfterOptionalTitle(line, close + 1);
    return end === undefined
      ? undefined
      : { destination: line.slice(cursor, close + 1), end };
  }

  const destinationStart = cursor;
  let depth = 0;
  let escaped = false;
  while (cursor < line.length) {
    const character = line[cursor];
    if (escaped) {
      escaped = false;
      cursor += 1;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      cursor += 1;
      continue;
    }
    if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      if (depth === 0) {
        const destination = line.slice(destinationStart, cursor).trim();
        return destination.length === 0
          ? undefined
          : { destination, end: cursor + 1 };
      }
      depth -= 1;
    } else if ((character === " " || character === "\t") && depth === 0) {
      const destination = line.slice(destinationStart, cursor);
      const end = closingParenthesisAfterOptionalTitle(line, cursor);
      return destination.length === 0 || end === undefined
        ? undefined
        : { destination, end };
    }
    cursor += 1;
  }
  return undefined;
}

function closingParenthesisAfterOptionalTitle(
  line: string,
  start: number,
): number | undefined {
  let remainder = line.slice(start).trimStart();
  const consumed = line.length - line.slice(start).length +
    (line.slice(start).length - remainder.length);
  if (remainder.startsWith(")")) {
    return consumed + 1;
  }
  const quote = remainder[0];
  if (quote !== '"' && quote !== "'") {
    return undefined;
  }
  remainder = remainder.slice(1);
  let index = 0;
  let escaped = false;
  for (; index < remainder.length; index += 1) {
    const character = remainder[index];
    if (escaped) {
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === quote) {
      const tail = remainder.slice(index + 1);
      const whitespace = tail.length - tail.trimStart().length;
      return tail.trimStart().startsWith(")")
        ? consumed + 1 + index + 1 + whitespace + 1
        : undefined;
    }
  }
  return undefined;
}

function findUnescaped(line: string, wanted: string, start: number): number {
  let escaped = false;
  for (let index = start; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === wanted) {
      return index;
    }
  }
  return -1;
}

function runLength(line: string, start: number, character: string): number {
  let end = start;
  while (line[end] === character) {
    end += 1;
  }
  return end - start;
}
