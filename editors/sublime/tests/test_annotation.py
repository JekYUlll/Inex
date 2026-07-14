from __future__ import annotations

import unittest

from inex_annotation import (
    AnnotationPickerError,
    AnnotationPickerState,
    parse_visible_private_annotation_spec,
)


def catalog():
    return {
        "tags": [
            {"id": "comment-content", "label": "Comment", "archived": False},
            {"id": "family", "label": "Family", "archived": False},
            {"id": "relationship", "label": "Relationship", "archived": False},
            {"id": "old", "label": "Old", "archived": True},
        ],
        "defaults": {"kind": "comment", "tagIds": ["comment-content"], "outer": "drop"},
    }


class AnnotationPickerTests(unittest.TestCase):
    def test_repeated_picker_enforces_groups_and_canonical_spec(self):
        state = AnnotationPickerState(catalog())
        self.assertNotIn("tag.old", [item["id"] for item in state.items()])
        self.assertIsNone(state.select("kind.block"))
        self.assertIsNone(state.select("outer.cover"))
        self.assertIsNone(state.select("tag.family"))
        self.assertEqual(state.select("done"), "done")
        self.assertEqual(
            state.spec("Public cover"),
            {"kind": "block", "tagIds": ["comment-content", "family"], "outer": {"mode": "cover", "coverText": "Public cover"}},
        )
        with self.assertRaises(AnnotationPickerError):
            state.spec()

    def test_archived_selected_tag_remains_visible_and_clear_discards_labels(self):
        values = catalog()
        values["defaults"]["tagIds"] = ["old"]
        state = AnnotationPickerState(values)
        self.assertIn("tag.old", [item["id"] for item in state.items()])
        state.clear()
        self.assertEqual(state.tag_ids, set())
        self.assertEqual(state.items()[0]["id"], "kind.comment")

    def test_profile_replaces_metadata_but_never_supplies_cover_text(self):
        state = AnnotationPickerState(catalog())
        state.apply_profile({
            "id": "family-comment", "label": "Family", "kind": "block",
            "tagIds": ["family"], "outer": "cover", "promptForCover": True,
        })
        with self.assertRaises(AnnotationPickerError):
            state.spec()
        self.assertEqual(state.spec("Public"), {
            "kind": "block", "tagIds": ["family"],
            "outer": {"mode": "cover", "coverText": "Public"},
        })
        with self.assertRaises(AnnotationPickerError):
            state.apply_profile({
                "id": "bad", "label": "Bad", "kind": "comment",
                "tagIds": [], "outer": "cover", "promptForCover": False,
            })

    def test_canonical_visible_header_prefills_picker_without_cover_text(self):
        spec = parse_visible_private_annotation_spec(bytearray(
            b":::inex-private\nid: p_0123456789abcdef0123456789abcdef\n"
            b"kind: block\ntags: [family, relationship]\nouter: cover\n---\nprivate\n:::\n"
        ))
        self.assertEqual(spec, {
            "kind": "block", "tagIds": ["family", "relationship"], "outer": {"mode": "cover"},
        })
        state = AnnotationPickerState(catalog(), spec)
        self.assertEqual(state.spec("public cover"), {
            "kind": "block", "tagIds": ["family", "relationship"],
            "outer": {"mode": "cover", "coverText": "public cover"},
        })

    def test_visible_header_rejects_noncanonical_tags_and_invalid_metadata(self):
        for content in (
            b":::inex-private\nid: p_0123456789abcdef0123456789abcdef\nkind: inline\ntags: []\nouter: drop\n---\n",
            b":::inex-private\nid: p_0123456789abcdef0123456789abcdef\nkind: block\ntags: [relationship, family]\nouter: drop\n---\n",
        ):
            with self.assertRaises(AnnotationPickerError):
                parse_visible_private_annotation_spec(bytearray(content))
