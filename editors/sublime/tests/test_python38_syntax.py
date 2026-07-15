from __future__ import annotations

import ast
import json
import os
import types
import unittest


class Python38SyntaxTests(unittest.TestCase):
    def test_package_modules_parse_as_python38(self):
        package = os.path.dirname(os.path.dirname(__file__))
        for name in (
            "Inex.py",
            "inex_core.py",
            "inex_annotation.py",
            "inex_markdown.py",
            "inex_password.py",
            "inex_rpc.py",
            "tests/cross_editor_catalog.py",
            "test/build4200/InexQA.py",
            "test/build4200/run_build4200.py",
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

    def test_host_marker_precedes_plaintext_and_fixed_scrub_clears_it(self):
        package = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(package, "Inex.py")
        with open(path, "r", encoding="utf-8") as stream:
            source = stream.read()
        self.assertIn(
            'VIEW_PLAINTEXT_MARKER = "inex.managed_plaintext"', source
        )

        finish_open = source.index("    def finish_open(")
        offer_recovery = source.index("    def offer_recovery(", finish_open)
        open_body = source[finish_open:offer_recovery]
        marker = open_body.index(
            "view.settings().set(VIEW_PLAINTEXT_MARKER, True)"
        )
        insertion = open_body.index(
            "_replace_buffer_from_bytes(view, bytearray(content))"
        )
        self.assertLess(marker, insertion)
        self.assertLess(open_body.index("_scrubbing_views.add(view.id())"), insertion)
        self.assertLess(
            insertion, open_body.index("_scrubbing_views.discard(view.id())")
        )
        open_failure = open_body.index("        except Exception as error:")
        failure_body = open_body[open_failure:]
        self.assertIn("scrub_then_remove(", failure_body)
        self.assertNotIn("_registry.remove(document.view_id)", failure_body)

        scrub = source.index("def _replace_view_with_fixed_text(")
        replace_plaintext = source.index("def _replace_buffer_from_bytes(", scrub)
        scrub_body = source[scrub:replace_plaintext]
        marker_install = scrub_body.index(
            "view.settings().set(VIEW_PLAINTEXT_MARKER, True)"
        )
        fixed_replace = scrub_body.index("view.run_command(scrub_command)")
        scrub_ack = scrub_body.index("_fixed_scrub_acks.pop(view.id(), None) != scrub_command")
        clear_undo = scrub_body.index('view.run_command("clear_undo_stack")')
        clear_marker = scrub_body.index(
            "view.settings().erase(VIEW_PLAINTEXT_MARKER)"
        )
        self.assertLess(marker_install, fixed_replace)
        self.assertLess(fixed_replace, scrub_ack)
        self.assertLess(scrub_ack, clear_undo)
        self.assertLess(clear_undo, clear_marker)
        self.assertNotIn("_replace_buffer_from_bytes", scrub_body)

        loaded = source.index("def plugin_loaded()")
        unloaded = source.index("def plugin_unloaded()", loaded)
        loaded_body = source[loaded:unloaded]
        self.assertLess(
            loaded_body.index("_scrub_orphaned_marked_views()"),
            loaded_body.index("_plugin_active = True"),
        )

        handoff = source.index("class InexReplaceEntireBufferCommand")
        locked_scrub = source.index("class InexScrubLockedBufferCommand", handoff)
        handoff_body = source[handoff:locked_scrub]
        self.assertIn("not self.view.is_scratch()", handoff_body)
        self.assertIn("self.view.file_name() is not None", handoff_body)
        self.assertIn(
            "self.view.settings().get(VIEW_PLAINTEXT_MARKER) is not True",
            handoff_body,
        )
        blocked_scrub = source.index(
            "class InexScrubBlockedBufferCommand", locked_scrub
        )
        next_class = source.index("class InexShowSecurityStatusCommand", blocked_scrub)
        fixed_commands = source[locked_scrub:next_class]
        self.assertIn("LOCKED_TEXT", fixed_commands)
        self.assertIn("BLOCKED_TEXT", fixed_commands)
        self.assertGreaterEqual(
            fixed_commands.count(
                "self.view.settings().get(VIEW_PLAINTEXT_MARKER) is not True"
            ),
            2,
        )
        self.assertNotIn("token:", fixed_commands)
        self.assertNotIn("_handoffs", fixed_commands)

        qa_path = os.path.join(package, "test", "build4200", "InexQA.py")
        with open(qa_path, "r", encoding="utf-8") as stream:
            qa_source = stream.read()
        self.assertIn('_HOST_MARKER = "inex.managed_plaintext"', qa_source)
        self.assertNotIn("settings().set(_HOST_MARKER", qa_source)
        self.assertIn("initial_clean=not document.dirty", qa_source)
        self.assertIn("orphan_scrubbed", qa_source)
        for command in (
            'window.run_command("inex_new_folder")',
            'window.run_command("inex_new_encrypted_markdown")',
            'window.run_command("inex_rename_active")',
            'window.run_command("inex_delete_active")',
        ):
            self.assertIn(command, qa_source)
        for event in (
            '"crud_folder_created"',
            '"crud_markdown_created"',
            '"crud_markdown_renamed"',
            '"crud_markdown_deleted"',
        ):
            self.assertIn(event, qa_source)

        runner_path = os.path.join(
            package, "test", "build4200", "run_build4200.py"
        )
        with open(runner_path, "r", encoding="utf-8") as stream:
            runner_source = stream.read()
        self.assertIn(
            '"host_dead_plaintext_copyable": plaintext_copyable', runner_source
        )
        self.assertIn('"clipboard_read_ok": clipboard_read_ok', runner_source)
        self.assertIn('[xclip, "-selection", "primary", "-o"]', runner_source)
        self.assertIn('"PASS_WITH_DOCUMENTED_BOUNDARY"', runner_source)
        self.assertIn('"sublime_restart_required"', runner_source)
        self.assertNotIn('"profile_plugins"', runner_source)
        self.assertIn('record.get("orphan_scrubbed") is not True', runner_source)
        self.assertIn('"crud_new_markdown": "qa-crud/new.md"', runner_source)
        self.assertIn('"crud_rename": "qa-crud/renamed.md"', runner_source)
        self.assertIn('raise QaFailure("completion preceded the CRUD assertions")', runner_source)

        lock_start = source.index("def _lock_views_and_drop_models(")
        lock_end = source.index("def _shutdown_client(", lock_start)
        lock_body = source[lock_start:lock_end]
        self.assertIn("for document in documents:", lock_body)
        self.assertIn("except Exception:", lock_body)
        self.assertIn("_orphan_scrub_blocked = True", lock_body)
        per_document = lock_body.index("for document in documents:")
        lookup = lock_body.index("view = _view_by_id(document.view_id)", per_document)
        protected_lookup = lock_body.rfind("        try:", per_document, lookup)
        self.assertGreaterEqual(protected_lookup, per_document)
        self.assertIn(
            "try:\n                    if view.is_valid():\n"
            "                        view.set_read_only(True)",
            lock_body,
        )

        perform_start = source.index("def _perform_lock(")
        perform_end = source.index("def _session_lost(", perform_start)
        perform_body = source[perform_start:perform_end]
        self.assertIn("except Exception:\n        _shutdown_client", perform_body)

    def test_fixed_scrub_commands_never_replace_an_unmarked_view(self):
        package = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(package, "Inex.py")
        with open(path, "r", encoding="utf-8") as stream:
            source = stream.read()
        tree = ast.parse(source, filename=path, feature_version=(3, 8))
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name
            in ("InexScrubLockedBufferCommand", "InexScrubBlockedBufferCommand")
        ]

        class TextCommand:
            pass

        class Edit:
            pass

        namespace = {
            "sublime": types.SimpleNamespace(
                Edit=Edit,
                Region=lambda start, end: (start, end),
            ),
            "sublime_plugin": types.SimpleNamespace(TextCommand=TextCommand),
            "VIEW_PLAINTEXT_MARKER": "inex.managed_plaintext",
            "LOCKED_TEXT": "locked",
            "BLOCKED_TEXT": "blocked",
            "_fixed_scrub_acks": {},
        }
        module = ast.Module(body=classes, type_ignores=[])
        ast.fix_missing_locations(module)
        exec(compile(module, path, "exec"), namespace)

        class Settings:
            def __init__(self, marked):
                self.marked = marked

            def get(self, key):
                return self.marked

        class View:
            def __init__(self, marked):
                self._settings = Settings(marked)
                self.replacements = []

            def settings(self):
                return self._settings

            def id(self):
                return 17

            def size(self):
                return 9

            def replace(self, edit, region, text):
                self.replacements.append(text)

        for class_name in (
            "InexScrubLockedBufferCommand",
            "InexScrubBlockedBufferCommand",
        ):
            with self.subTest(class_name=class_name):
                command = namespace[class_name]()
                unmarked = View(False)
                command.view = unmarked
                with self.assertRaises(RuntimeError):
                    command.run(None)
                self.assertEqual(unmarked.replacements, [])

                marked = View(True)
                command.view = marked
                command.run(None)
                self.assertEqual(len(marked.replacements), 1)

    def test_fixed_scrub_helper_retains_marker_when_command_does_not_acknowledge(self):
        package = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(package, "Inex.py")
        with open(path, "r", encoding="utf-8") as stream:
            source = stream.read()
        tree = ast.parse(source, filename=path, feature_version=(3, 8))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_replace_view_with_fixed_text"
        )
        future = tree.body[0]

        class ModelError(Exception):
            pass

        namespace = {
            "ModelError": ModelError,
            "LOCKED_TEXT": "locked",
            "BLOCKED_TEXT": "blocked",
            "VIEW_PLAINTEXT_MARKER": "inex.managed_plaintext",
            "STATUS_KEY": "inex.document",
            "_fixed_scrub_acks": {},
            "_scrubbing_views": set(),
        }
        module = ast.Module(body=[future, function], type_ignores=[])
        ast.fix_missing_locations(module)
        exec(compile(module, path, "exec"), namespace)
        scrub = namespace["_replace_view_with_fixed_text"]

        class Settings:
            def __init__(self):
                self.values = {}

            def set(self, key, value):
                self.values[key] = value

            def erase(self, key):
                self.values.pop(key, None)

        class View:
            def __init__(self, acknowledge):
                self.acknowledge = acknowledge
                self._settings = Settings()
                self.commands = []
                self.read_only = None

            def is_valid(self):
                return True

            def id(self):
                return 31

            def settings(self):
                return self._settings

            def set_scratch(self, value):
                pass

            def set_read_only(self, value):
                self.read_only = value

            def run_command(self, command):
                self.commands.append(command)
                if self.acknowledge and command.startswith("inex_scrub_"):
                    namespace["_fixed_scrub_acks"][self.id()] = command

            def set_name(self, value):
                pass

            def set_status(self, key, value):
                pass

        silent = View(False)
        with self.assertRaisesRegex(ModelError, "did not acknowledge"):
            scrub(silent, "locked", "status")
        self.assertIs(
            silent.settings().values.get("inex.managed_plaintext"), True
        )
        self.assertTrue(silent.read_only)
        self.assertEqual(silent.commands, ["inex_scrub_locked_buffer"])

        acknowledged = View(True)
        scrub(acknowledged, "locked", "status")
        self.assertNotIn("inex.managed_plaintext", acknowledged.settings().values)
        self.assertTrue(acknowledged.read_only)
        self.assertEqual(
            acknowledged.commands,
            ["inex_scrub_locked_buffer", "clear_undo_stack"],
        )

    def test_crud_ui_keeps_generation_cleanliness_and_scrub_order(self):
        package = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(package, "Inex.py"), "r", encoding="utf-8") as stream:
            source = stream.read()
        for class_name in (
            "InexNewEncryptedMarkdownCommand",
            "InexNewFolderCommand",
            "InexRenameActiveCommand",
            "InexDeleteActiveCommand",
        ):
            self.assertIn("class %s" % class_name, source)
        self.assertGreaterEqual(
            source.count("current_generation == generation"), 8
        )
        self.assertIn("if document.dirty:", source)
        context_start = source.index("def _active_clean_context(")
        context_end = source.index("def _crud_document_current(", context_start)
        context_body = source[context_start:context_end]
        self.assertLess(
            context_body.index("_capture_view(document)"),
            context_body.index("if document.dirty:"),
        )
        self.assertIn("validate_logical_path(destination)", source)
        self.assertIn(
            "validate_logical_path(logical_path, allow_directory=True)", source
        )
        self.assertGreaterEqual(source.count("_warn_if_not_synced("), 5)
        for operation in ("create", "rename", "delete", "save"):
            self.assertIn('"%s": (' % operation, source)

        rename_start = source.index("def _rename_active(")
        delete_start = source.index("def _delete_active(", rename_start)
        rename_operation = source[rename_start:delete_start]
        self.assertIn("document is not expected_document", rename_operation)
        self.assertIn(
            "_rename_active(self.window, destination, document)", source
        )
        self.assertLess(
            rename_operation.index("with document.draft_lock:"),
            rename_operation.index("client.rename_document("),
        )
        self.assertLess(
            rename_operation.index("client.rename_document("),
            rename_operation.index("remove_encrypted_draft("),
        )
        renamed = source.index("    def renamed(")
        rename_failed = source.index("    def failed(error: Exception)", renamed)
        rename_body = source[renamed:rename_failed]
        self.assertIn("document.rename_clean(destination, new_etag)", rename_body)

        delete_operation = source[delete_start:source.index("class InexReplaceEntireBufferCommand")]
        self.assertLess(
            delete_operation.index("with document.draft_lock:"),
            delete_operation.index("client.delete_document("),
        )
        self.assertLess(
            delete_operation.index("client.delete_document("),
            delete_operation.index("remove_encrypted_draft("),
        )
        deleted = source.index("    def deleted(")
        delete_failed = source.index("    def failed(error: Exception)", deleted)
        delete_body = source[deleted:delete_failed]
        self.assertLess(
            delete_body.index("scrub_then_remove("),
            delete_body.index("_close_handle_best_effort"),
        )
        self.assertLess(
            delete_body.index("_replace_view_with_fixed_text("),
            delete_body.index('owner.run_command("close_file")'),
        )

        with open(
            os.path.join(package, "Main.sublime-commands"),
            "r",
            encoding="utf-8",
        ) as stream:
            commands = json.load(stream)
        command_names = {item.get("command") for item in commands}
        self.assertTrue(
            {
                "inex_new_encrypted_markdown",
                "inex_new_folder",
                "inex_rename_active",
                "inex_delete_active",
            }.issubset(command_names)
        )

    def test_not_synced_crud_warning_is_fixed_and_never_contains_a_path(self):
        package = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join(package, "Inex.py")
        with open(path, "r", encoding="utf-8") as stream:
            source = stream.read()
        tree = ast.parse(source, filename=path, feature_version=(3, 8))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_warn_if_not_synced"
        )
        future = tree.body[0]
        module = ast.Module(body=[future, function], type_ignores=[])
        ast.fix_missing_locations(module)
        messages = []
        namespace = {
            "sublime": types.SimpleNamespace(message_dialog=messages.append),
        }
        exec(compile(module, path, "exec"), namespace)
        warn = namespace["_warn_if_not_synced"]
        warn("create", ("synced",))
        self.assertEqual(messages, [])
        warn("rename", ("synced", "notSynced"))
        self.assertEqual(len(messages), 1)
        self.assertNotIn("secret/path.md", messages[0])


if __name__ == "__main__":
    unittest.main()
