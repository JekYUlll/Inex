"""Small in-memory Markdown navigation helpers for the Sublime strict client."""

from __future__ import annotations

import posixpath
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

try:
    from .inex_core import ModelError, validate_logical_path
except ImportError:
    from inex_core import ModelError, validate_logical_path


_HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
_FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
_INLINE_LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\s]+)\)")
_WIKI_LINK_RE = re.compile(r"\[\[([^\]\n]+)\]\]")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def heading_slug(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value).strip().lower()
    output = []
    previous_dash = False
    for character in normalized:
        category = unicodedata.category(character)
        if character.isspace() or character == "-":
            if output and not previous_dash:
                output.append("-")
                previous_dash = True
            continue
        if category[0] in ("L", "N") or character == "_":
            output.append(character)
            previous_dash = False
    return "".join(output).strip("-")


def markdown_headings(text: str) -> List[Dict[str, object]]:
    headings = []
    counts: Dict[str, int] = {}
    fence: Optional[str] = None
    for line_number, line in enumerate(text.splitlines()):
        marker = _FENCE_RE.match(line)
        if marker is not None:
            candidate = marker.group(1)
            kind = candidate[0]
            if fence is None:
                fence = kind
            elif kind == fence:
                fence = None
            continue
        if fence is not None:
            continue
        match = _HEADING_RE.match(line)
        if match is None:
            continue
        title = re.sub(r"[ \t]+#+[ \t]*$", "", match.group(2)).strip()
        base = heading_slug(title)
        if not base:
            continue
        duplicate = counts.get(base, 0)
        counts[base] = duplicate + 1
        slug = base if duplicate == 0 else "%s-%d" % (base, duplicate)
        headings.append(
            {
                "title": title,
                "slug": slug,
                "level": len(match.group(1)),
                "line": line_number,
                "column": len(match.group(1)) + 1,
            }
        )
    return headings


def resolve_markdown_target(
    current_path: str, raw_target: str, wiki: bool = False
) -> Optional[Tuple[str, Optional[str]]]:
    validate_logical_path(current_path)
    target = raw_target.strip()
    if wiki and "|" in target:
        target = target.split("|", 1)[0].strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if (
        not target
        or _SCHEME_RE.match(target)
        or target.startswith(("/", "//", "\\"))
        or "?" in target
        or "%" in target
        or "\\" in target
    ):
        if target.startswith("#"):
            return current_path, heading_slug(target[1:]) or None
        return None
    path_part, separator, fragment = target.partition("#")
    if not path_part:
        resolved = current_path
    else:
        if wiki and not path_part.endswith(".md"):
            path_part += ".md"
        if not path_part.endswith(".md"):
            return None
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(current_path), path_part)
        )
        try:
            validate_logical_path(resolved)
        except ModelError:
            return None
    anchor = heading_slug(fragment) if separator and fragment else None
    return resolved, anchor or None


def markdown_links(text: str, current_path: str) -> List[Dict[str, object]]:
    validate_logical_path(current_path)
    links = []
    fence: Optional[str] = None
    for line_number, line in enumerate(text.splitlines()):
        marker = _FENCE_RE.match(line)
        if marker is not None:
            kind = marker.group(1)[0]
            if fence is None:
                fence = kind
            elif fence == kind:
                fence = None
            continue
        if fence is not None:
            continue
        for match in _INLINE_LINK_RE.finditer(line):
            resolved = resolve_markdown_target(current_path, match.group(2), False)
            if resolved is not None:
                links.append(
                    {
                        "label": match.group(1),
                        "targetPath": resolved[0],
                        "anchor": resolved[1],
                        "line": line_number,
                    }
                )
        for match in _WIKI_LINK_RE.finditer(line):
            resolved = resolve_markdown_target(current_path, match.group(1), True)
            if resolved is not None:
                label = match.group(1).split("|", 1)[-1].strip()
                links.append(
                    {
                        "label": label,
                        "targetPath": resolved[0],
                        "anchor": resolved[1],
                        "line": line_number,
                    }
                )
    return links
