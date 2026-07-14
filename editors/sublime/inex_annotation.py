"""State-only private annotation picker for the Sublime experimental client.

This module deliberately has no Sublime imports: encrypted catalog labels stay
in the picker instance and can be discarded immediately on cancel or lock.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


class AnnotationPickerError(Exception):
    pass


class AnnotationPickerState:
    """Repeated-panel state with one kind, many tags, and one Outer mode."""

    def __init__(self, config: Dict[str, Any]) -> None:
        if not isinstance(config, dict):
            raise AnnotationPickerError("Umbra catalog is invalid")
        tags = config.get("tags")
        defaults = config.get("defaults")
        if not isinstance(tags, list) or not isinstance(defaults, dict):
            raise AnnotationPickerError("Umbra catalog is invalid")
        self._tags: List[Dict[str, Any]] = []
        self._tag_ids: Set[str] = set()
        for tag in tags:
            if not isinstance(tag, dict):
                raise AnnotationPickerError("Umbra tag is invalid")
            tag_id = tag.get("id")
            label = tag.get("label")
            archived = tag.get("archived")
            if not isinstance(tag_id, str) or not tag_id or not isinstance(label, str) or not isinstance(archived, bool):
                raise AnnotationPickerError("Umbra tag is invalid")
            if tag_id in self._tag_ids:
                raise AnnotationPickerError("Umbra tag is duplicated")
            self._tag_ids.add(tag_id)
            self._tags.append({"id": tag_id, "label": label, "archived": archived})
        kind = defaults.get("kind")
        outer = defaults.get("outer")
        tag_ids = defaults.get("tagIds")
        if kind not in ("block", "comment") or outer not in ("drop", "cover", "placeholder") or not isinstance(tag_ids, list):
            raise AnnotationPickerError("Umbra annotation defaults are invalid")
        if any(not isinstance(tag_id, str) or tag_id not in self._tag_ids for tag_id in tag_ids):
            raise AnnotationPickerError("Umbra default tag is invalid")
        self.kind = kind
        self.outer = outer
        self.tag_ids = set(tag_ids)

    def items(self) -> List[Dict[str, str]]:
        output = [
            {"id": "kind.comment", "label": "[%s] Private Comment" % ("x" if self.kind == "comment" else " ")},
            {"id": "kind.block", "label": "[%s] Private Block" % ("x" if self.kind == "block" else " ")},
        ]
        for tag in self._tags:
            if tag["archived"] and tag["id"] not in self.tag_ids:
                continue
            suffix = " (archived)" if tag["archived"] else ""
            output.append({
                "id": "tag." + tag["id"],
                "label": "[%s] Tag: %s%s" % ("x" if tag["id"] in self.tag_ids else " ", tag["label"], suffix),
            })
        output.extend([
            {"id": "outer.drop", "label": "[%s] Outer: Drop" % ("x" if self.outer == "drop" else " ")},
            {"id": "outer.cover", "label": "[%s] Outer: Cover" % ("x" if self.outer == "cover" else " ")},
            {"id": "outer.placeholder", "label": "[%s] Outer: Placeholder" % ("x" if self.outer == "placeholder" else " ")},
            {"id": "done", "label": "Apply"},
            {"id": "cancel", "label": "Cancel"},
        ])
        return output

    def select(self, item_id: str) -> Optional[str]:
        if item_id == "done" or item_id == "cancel":
            return item_id
        if item_id.startswith("kind.") and item_id[5:] in ("block", "comment"):
            self.kind = item_id[5:]
            return None
        if item_id.startswith("outer.") and item_id[6:] in ("drop", "cover", "placeholder"):
            self.outer = item_id[6:]
            return None
        if item_id.startswith("tag.") and item_id[4:] in self._tag_ids:
            tag_id = item_id[4:]
            if tag_id in self.tag_ids:
                self.tag_ids.remove(tag_id)
            else:
                self.tag_ids.add(tag_id)
            return None
        raise AnnotationPickerError("Umbra picker item is invalid")

    def spec(self, cover_text: Optional[str] = None) -> Dict[str, Any]:
        if self.outer == "cover":
            if not isinstance(cover_text, str) or not cover_text:
                raise AnnotationPickerError("Umbra cover text is required")
        elif cover_text is not None:
            raise AnnotationPickerError("Umbra cover text is not applicable")
        outer: Dict[str, str] = {"mode": self.outer}
        if cover_text is not None:
            outer["coverText"] = cover_text
        return {"kind": self.kind, "tagIds": sorted(self.tag_ids), "outer": outer}

    def apply_profile(self, profile: Dict[str, Any]) -> None:
        """Apply encrypted profile metadata, never an instance cover string."""
        if not isinstance(profile, dict) or set(profile) != {
            "id", "label", "kind", "tagIds", "outer", "promptForCover"
        }:
            raise AnnotationPickerError("Umbra annotation profile is invalid")
        kind = profile.get("kind")
        outer = profile.get("outer")
        tag_ids = profile.get("tagIds")
        prompt_for_cover = profile.get("promptForCover")
        if (
            not isinstance(profile.get("id"), str)
            or not profile.get("id")
            or not isinstance(profile.get("label"), str)
            or kind not in ("block", "comment")
            or outer not in ("drop", "cover", "placeholder")
            or not isinstance(tag_ids, list)
            or not isinstance(prompt_for_cover, bool)
            or (outer == "cover") != prompt_for_cover
            or any(not isinstance(tag_id, str) or tag_id not in self._tag_ids for tag_id in tag_ids)
        ):
            raise AnnotationPickerError("Umbra annotation profile is invalid")
        self.kind = kind
        self.outer = outer
        self.tag_ids = set(tag_ids)

    def clear(self) -> None:
        self.tag_ids.clear()
        for tag in self._tags:
            tag["label"] = ""
        self._tags = []
        self._tag_ids = set()
