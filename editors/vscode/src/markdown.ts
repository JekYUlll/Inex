import * as path from "node:path";

import { logicalFileComponents } from "./logicalPath.ts";

const MAX_NAVIGATION_ITEMS = 100_000;

export interface MarkdownHeading {
  readonly text: string;
  readonly slug: string;
  readonly level: number;
  readonly line: number;
  readonly startByte: number;
  readonly endByte: number;
}

export interface MarkdownLink {
  readonly target: string;
  readonly label: string;
  readonly line: number;
  readonly startUtf16: number;
  readonly endUtf16: number;
  readonly startByte: number;
  readonly endByte: number;
  readonly wiki: boolean;
}

export interface MarkdownNavigation {
  readonly headings: readonly MarkdownHeading[];
  readonly links: readonly MarkdownLink[];
}

export interface ResolvedMarkdownTarget {
  readonly logicalPath: string;
  readonly fragment: string | undefined;
}

export function parseMarkdownNavigation(text: string): MarkdownNavigation {
  const headings: MarkdownHeading[] = [];
  const links: MarkdownLink[] = [];
  const slugCounts = new Map<string, number>();
  let lineStartUtf16 = 0;
  let lineStartByte = 0;
  let lineNumber = 0;
  let fence: { readonly marker: "`" | "~"; readonly length: number } | undefined;

  while (lineStartUtf16 <= text.length) {
    const newline = text.indexOf("\n", lineStartUtf16);
    const lineEnd = newline < 0 ? text.length : newline;
    const rawLine = text.slice(lineStartUtf16, lineEnd);
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const boundary = fenceBoundary(line);
    if (fence === undefined && boundary !== undefined) {
      fence = boundary;
    } else if (
      fence !== undefined &&
      boundary?.marker === fence.marker &&
      boundary.length >= fence.length
    ) {
      fence = undefined;
    } else if (fence === undefined) {
      parseHeading(line, lineNumber, lineStartByte, headings, slugCounts);
      parseWikiLinks(line, lineNumber, lineStartUtf16, lineStartByte, links);
      parseInlineLinks(line, lineNumber, lineStartUtf16, lineStartByte, links);
    }
    if (headings.length + links.length > MAX_NAVIGATION_ITEMS) {
      throw new Error("Markdown navigation item limit exceeded");
    }
    if (newline < 0) {
      break;
    }
    const consumed = text.slice(lineStartUtf16, newline + 1);
    lineStartByte += Buffer.byteLength(consumed, "utf8");
    lineStartUtf16 = newline + 1;
    lineNumber += 1;
  }
  links.sort((left, right) => left.startUtf16 - right.startUtf16);
  return { headings, links };
}

function fenceBoundary(
  line: string,
): { readonly marker: "`" | "~"; readonly length: number } | undefined {
  const match = /^ {0,3}(`{3,}|~{3,})/u.exec(line);
  const run = match?.[1];
  if (run === undefined) {
    return undefined;
  }
  const marker = run[0];
  if (marker !== "`" && marker !== "~") {
    return undefined;
  }
  return { marker, length: run.length };
}

export function resolveMarkdownTarget(
  currentLogicalPath: string,
  rawTarget: string,
  wiki: boolean,
): ResolvedMarkdownTarget {
  logicalFileComponents(currentLogicalPath);
  const separator = rawTarget.indexOf("#");
  const rawPath = (separator < 0 ? rawTarget : rawTarget.slice(0, separator)).trim();
  const rawFragment = separator < 0 ? undefined : rawTarget.slice(separator + 1).trim();
  const fragment = rawFragment === undefined || rawFragment.length === 0
    ? undefined
    : decodeFragment(rawFragment);
  if (rawPath.length === 0) {
    return { logicalPath: currentLogicalPath, fragment };
  }
  const unwrapped = rawPath.startsWith("<") && rawPath.endsWith(">")
    ? rawPath.slice(1, -1)
    : rawPath;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(unwrapped) || unwrapped.startsWith("//")) {
    throw new Error("External Markdown links are not opened by Inex navigation");
  }

  const absolute = unwrapped.startsWith("/");
  const parts = absolute
    ? []
    : currentLogicalPath.split("/").slice(0, -1);
  for (const encoded of unwrapped.replace(/^\//u, "").split("/")) {
    const component = decodePathComponent(encoded);
    if (component.length === 0 || component === ".") {
      continue;
    }
    if (component === "..") {
      if (parts.length === 0) {
        throw new Error("Markdown link escapes the vault root");
      }
      parts.pop();
      continue;
    }
    parts.push(component);
  }
  if (parts.length === 0) {
    throw new Error("Markdown link has no document target");
  }
  if (wiki && !parts.at(-1)?.endsWith(".md")) {
    parts[parts.length - 1] = `${parts.at(-1)}.md`;
  }
  const logicalPath = parts.join("/").normalize("NFC");
  logicalFileComponents(logicalPath);
  return { logicalPath, fragment };
}

export function headingForFragment(
  navigation: MarkdownNavigation,
  fragment: string,
): MarkdownHeading | undefined {
  const wanted = fragment.replace(/^#/u, "").toLowerCase();
  return navigation.headings.find((heading) => heading.slug.toLowerCase() === wanted);
}

export function linkAtUtf16(
  navigation: MarkdownNavigation,
  offset: number,
): MarkdownLink | undefined {
  return navigation.links.find((link) => offset >= link.startUtf16 && offset <= link.endUtf16);
}

function parseHeading(
  line: string,
  lineNumber: number,
  lineStartByte: number,
  headings: MarkdownHeading[],
  slugCounts: Map<string, number>,
): void {
  const match = /^ {0,3}(#{1,6})[\t ]+(.+?)\s*#*\s*$/u.exec(line);
  if (match === null) {
    return;
  }
  const marks = match[1] ?? "";
  const headingText = (match[2] ?? "").trim();
  if (headingText.length === 0) {
    return;
  }
  const baseSlug = markdownSlug(headingText);
  const duplicate = slugCounts.get(baseSlug) ?? 0;
  slugCounts.set(baseSlug, duplicate + 1);
  const slug = duplicate === 0 ? baseSlug : `${baseSlug}-${duplicate}`;
  headings.push({
    text: headingText,
    slug,
    level: marks.length,
    line: lineNumber,
    startByte: lineStartByte,
    endByte: lineStartByte + Buffer.byteLength(line, "utf8"),
  });
}

function parseWikiLinks(
  line: string,
  lineNumber: number,
  lineStartUtf16: number,
  lineStartByte: number,
  links: MarkdownLink[],
): void {
  let cursor = 0;
  while (cursor < line.length) {
    const start = line.indexOf("[[", cursor);
    if (start < 0) {
      return;
    }
    const close = line.indexOf("]]", start + 2);
    if (close < 0) {
      return;
    }
    const inside = line.slice(start + 2, close);
    const alias = inside.indexOf("|");
    const target = (alias < 0 ? inside : inside.slice(0, alias)).trim();
    const label = (alias < 0 ? target : inside.slice(alias + 1)).trim();
    if (target.length > 0) {
      links.push(makeLink(line, lineNumber, lineStartUtf16, lineStartByte, start, close + 2, target, label, true));
    }
    cursor = close + 2;
  }
}

function parseInlineLinks(
  line: string,
  lineNumber: number,
  lineStartUtf16: number,
  lineStartByte: number,
  links: MarkdownLink[],
): void {
  let cursor = 0;
  while (cursor < line.length) {
    const start = line.indexOf("[", cursor);
    if (start < 0) {
      return;
    }
    if (line[start + 1] === "[" || (start > 0 && line[start - 1] === "!")) {
      cursor = start + 1;
      continue;
    }
    const labelEnd = line.indexOf("](", start + 1);
    if (labelEnd < 0) {
      return;
    }
    const close = line.indexOf(")", labelEnd + 2);
    if (close < 0) {
      return;
    }
    const target = line.slice(labelEnd + 2, close).trim();
    if (target.length > 0) {
      links.push(makeLink(
        line,
        lineNumber,
        lineStartUtf16,
        lineStartByte,
        start,
        close + 1,
        target,
        line.slice(start + 1, labelEnd),
        false,
      ));
    }
    cursor = close + 1;
  }
}

function makeLink(
  line: string,
  lineNumber: number,
  lineStartUtf16: number,
  lineStartByte: number,
  start: number,
  end: number,
  target: string,
  label: string,
  wiki: boolean,
): MarkdownLink {
  return {
    target,
    label,
    line: lineNumber,
    startUtf16: lineStartUtf16 + start,
    endUtf16: lineStartUtf16 + end,
    startByte: lineStartByte + Buffer.byteLength(line.slice(0, start), "utf8"),
    endByte: lineStartByte + Buffer.byteLength(line.slice(0, end), "utf8"),
    wiki,
  };
}

function markdownSlug(text: string): string {
  return text
    .normalize("NFC")
    .toLowerCase()
    .replace(/[^\p{Letter}\p{Number}_ -]/gu, "")
    .trim()
    .replace(/[ ]+/gu, "-");
}

function decodePathComponent(value: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new Error("Markdown link contains invalid percent encoding");
  }
  if (decoded.includes("/") || decoded.includes("\\")) {
    throw new Error("Markdown link contains an encoded path separator");
  }
  return decoded;
}

function decodeFragment(value: string): string {
  try {
    return decodeURIComponent(value).normalize("NFC");
  } catch {
    throw new Error("Markdown heading fragment contains invalid percent encoding");
  }
}

export function logicalStem(logicalPath: string): string {
  const name = path.posix.basename(logicalPath);
  const stem = name.endsWith(".md") ? name.slice(0, -3) : name;
  return stem.length === 0 ? name : stem;
}
