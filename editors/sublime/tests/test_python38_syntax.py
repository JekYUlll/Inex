from __future__ import annotations

import ast
import os
import types
import unittest


class Python38SyntaxTests(unittest.TestCase):
    def test_package_modules_parse_as_python38(self):
        package = os.path.dirname(os.path.dirname(__file__))
        for name in (
            "Inex.py",
            "inex_core.py",
            "inex_markdown.py",
            "inex_password.py",
            "inex_rpc.py",
        ):
            path = os.path.join(package, name)
            with open(path, "r", encoding="utf-8") as stream:
                source = stream.read()
            with self.subTest(name=name):
                ast.parse(source, filename=path, feature_version=(3, 8))

    def test_plaintext_is_not_a_sublime_command_argument(self):
        package = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(package, "Inex.py"), "r", encoding="utf-8") as stream:
            source = stream.read()
        self.assertNotIn('{"text": text}', source)
        self.assertNotIn('{"content": content}', source)
        self.assertIn('{"token": token}', source)
        self.assertGreaterEqual(source.count('if action == "block_macro"'), 2)
        self.assertGreaterEqual(
            source.count(
                "if _registry.values() and command_name in macro_commands:"
            ),
            2,
        )
        self.assertNotIn("trusted_" + "default_macro_args", source)
        self.assertIn("_detect_active_macro_recording", source)

    def test_macro_guard_is_armed_before_first_plaintext_insert_and_taint_persists(self):
        package = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(package, "Inex.py"), "r", encoding="utf-8") as stream:
            source = stream.read()
        finish_open = source.index("    def finish_open(")
        offer_recovery = source.index("    def offer_recovery(", finish_open)
        body = source[finish_open:offer_recovery]
        self.assertLess(
            body.index("_registry.add(document)"),
            body.index("_start_macro_monitoring()"),
        )
        self.assertLess(
            body.index("_start_macro_monitoring()"),
            body.index("_replace_buffer_from_bytes(view, bytearray(content))"),
        )
        self.assertIn("setattr(builtins, _MACRO_TAINT_ATTRIBUTE, True)", source)
        self.assertGreaterEqual(
            source.count(
                "if _macro_is_tainted() and command_name in macro_commands:"
            ),
            2,
        )
        self.assertIn(
            'issues.append("Sublime macro state captured managed input; '
            'restart Sublime Text")',
            source,
        )
        self.assertNotIn("delattr(builtins, _MACRO_TAINT_ATTRIBUTE", source)

    def test_detected_macro_is_overwritten_by_probed_noop_sequence(self):
        # The exact Build 4200 runtime probe is documented in README. This
        # static boundary prevents later refactors from substituting the known-
        # ineffective empty start/stop sequence or omitting exact [] validation.
        package = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(package, "Inex.py"), "r", encoding="utf-8") as stream:
            source = stream.read()
        detection = source.index("def _detect_active_macro_recording(")
        next_function = source.index("\ndef _all_windows", detection)
        body = source[detection:next_function]
        first_stop = body.index('window.run_command("toggle_record_macro")')
        fresh_start = body.index(
            'window.run_command("toggle_record_macro")', first_stop + 1
        )
        sanitizer = body.index(
            'window.run_command("inex_macro_sanitizer")', fresh_start
        )
        final_stop = body.index(
            'window.run_command("toggle_record_macro")', sanitizer
        )
        verification = body.index("_verify_empty_macro()", final_stop)
        self.assertLess(first_stop, fresh_start)
        self.assertLess(fresh_start, sanitizer)
        self.assertLess(sanitizer, final_stop)
        self.assertLess(final_stop, verification)
        self.assertIn("_macro_sanitize_bypass", body)
        self.assertIn("sanitized = False", body)
        self.assertIn("if sanitized:", body)

    def test_empty_macro_verification_rejects_wrong_types_and_probe_errors(self):
        package = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(package, "Inex.py")
        with open(path, "r", encoding="utf-8") as stream:
            source = stream.read()
        tree = ast.parse(source, filename=path, feature_version=(3, 8))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_verify_empty_macro"
        )

        def verify(get_macro):
            module = ast.Module(body=[function], type_ignores=[])
            ast.fix_missing_locations(module)
            namespace = {
                "sublime": types.SimpleNamespace(get_macro=get_macro),
            }
            exec(compile(module, path, "exec"), namespace)
            return namespace["_verify_empty_macro"]()

        self.assertTrue(verify(lambda: []))
        for value in (None, (), {}, ["not-empty"]):
            with self.subTest(value=value):
                self.assertFalse(verify(lambda value=value: value))

        def failed_probe():
            raise RuntimeError("probe failed")

        self.assertFalse(verify(failed_probe))


if __name__ == "__main__":
    unittest.main()
