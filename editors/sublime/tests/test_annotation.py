from __future__ import annotations

import unittest

from inex_annotation import AnnotationPickerError, AnnotationPickerState


def catalog():
    return {
        "tags": [
            {"id": "comment-content", "label": "Comment", "archived": False},
            {"id": "family", "label": "Family", "archived": False},
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
