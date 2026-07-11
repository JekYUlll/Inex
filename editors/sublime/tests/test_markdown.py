from __future__ import annotations

import unittest

from inex_markdown import markdown_headings, markdown_links, resolve_markdown_target


class MarkdownNavigationTests(unittest.TestCase):
    def test_headings_skip_fences_and_disambiguate_slugs(self):
        headings = markdown_headings(
            "# Title\n## Repeat\n## Repeat\n```md\n# Hidden\n```\n"
        )
        self.assertEqual(
            [heading["slug"] for heading in headings],
            ["title", "repeat", "repeat-1"],
        )

    def test_relative_and_wiki_links_stay_inside_logical_vault(self):
        text = (
            "[Next](../next.md#Section)\n"
            "[[topic|Topic alias]]\n"
            "[Web](https://example.com)\n"
            "```\n[[hidden]]\n```\n"
        )
        links = markdown_links(text, "notes/current.md")
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0]["targetPath"], "next.md")
        self.assertEqual(links[0]["anchor"], "section")
        self.assertEqual(links[1]["targetPath"], "notes/topic.md")

    def test_traversal_external_and_encoded_targets_are_rejected(self):
        self.assertIsNone(resolve_markdown_target("a.md", "../../escape.md"))
        self.assertIsNone(resolve_markdown_target("a.md", "file:///tmp/x.md"))
        self.assertIsNone(resolve_markdown_target("a.md", "%2e%2e/x.md"))
        self.assertEqual(
            resolve_markdown_target("notes/a.md", "#Local Heading"),
            ("notes/a.md", "local-heading"),
        )


if __name__ == "__main__":
    unittest.main()
