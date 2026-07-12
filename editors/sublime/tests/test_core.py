from __future__ import annotations

import os
import tempfile
import threading
import unittest

from inex_core import (
    DocumentRegistry,
    DraftStorageError,
    IdleDeadline,
    ManagedDocument,
    ModelError,
    PendingPlaintextRegistry,
    PlaintextHandoffRegistry,
    atomic_write_ciphertext,
    check_security_preferences,
    classify_text_command,
    classify_window_command,
    draft_filename,
    macro_fingerprint,
    read_encrypted_draft,
    remove_encrypted_draft,
    safe_error_message,
    scrub_then_remove,
    session_epoch_is_current,
    session_owner_is_current,
    validate_logical_path,
)
from inex_rpc import RpcProtocolError


ETAG = "sha256:" + "1" * 64
NEW_ETAG = "sha256:" + "2" * 64


class SecurityGateTests(unittest.TestCase):
    def test_exact_global_values_are_required(self):
        secure = {
            "hot_exit": "disabled",
            "hot_exit_projects": False,
            "remember_open_files": False,
            "update_system_recent_files": False,
        }
        self.assertEqual(check_security_preferences(secure), [])
        for key, unsafe in (
            ("hot_exit", False),
            ("hot_exit_projects", 0),
            ("remember_open_files", 0),
            ("update_system_recent_files", None),
        ):
            values = dict(secure)
            values[key] = unsafe
            self.assertTrue(check_security_preferences(values))

    def test_error_redaction_does_not_echo_arbitrary_exception(self):
        secret = "/private/vault/canary-password"
        self.assertNotIn(secret, safe_error_message(OSError(secret)))
        safe = RpcProtocolError("RPC response envelope is invalid")
        self.assertEqual(safe_error_message(safe), str(safe))


class LogicalPathTests(unittest.TestCase):
    def test_portable_markdown_path(self):
        self.assertEqual(validate_logical_path("notes/today.md"), "notes/today.md")
        for path in (
            "../today.md",
            "/today.md",
            "notes\\today.md",
            "CON.md",
            ".git/today.md",
            "today.MD",
            "bad /today.md",
            "bad\u0085name.md",
        ):
            with self.subTest(path=path):
                with self.assertRaises(ModelError):
                    validate_logical_path(path)


class ModelTests(unittest.TestCase):
    def test_owned_bytearrays_are_wiped_on_replace_and_close(self):
        original = bytearray(b"original secret")
        document = ManagedDocument(10, "notes/today.md", "h" * 43, ETAG, original)
        replacement = bytearray(b"new secret")
        document.replace(replacement)
        self.assertEqual(original, bytearray(len(original)))
        self.assertTrue(document.dirty)
        version, snapshot = document.snapshot()
        document.mark_saved(version, NEW_ETAG)
        self.assertFalse(document.dirty)
        document.close()
        self.assertEqual(replacement, bytearray(len(replacement)))
        self.assertEqual(document.handle, "")
        self.assertEqual(snapshot, bytearray(b"new secret"))

    def test_registry_bypass_is_one_shot(self):
        registry = DocumentRegistry()
        document = ManagedDocument(10, "today.md", "h", ETAG, bytearray())
        registry.add(document)
        self.assertIs(registry.get(10), document)
        registry.grant_bypass(2, "close_file")
        self.assertTrue(registry.consume_bypass(2, "close_file"))
        self.assertFalse(registry.consume_bypass(2, "close_file"))

    def test_surviving_view_is_scrubbed_before_model_drop(self):
        registry = DocumentRegistry()
        document = ManagedDocument(10, "today.md", "secret-handle", ETAG, bytearray(b"secret"))
        registry.add(document)
        events = []

        def scrub():
            self.assertIs(registry.get(10), document)
            self.assertEqual(document.content, bytearray(b"secret"))
            events.append("scrub")

        handle = scrub_then_remove(registry, 10, scrub)
        events.append("removed")
        self.assertEqual(events, ["scrub", "removed"])
        self.assertEqual(handle, "secret-handle")
        self.assertIsNone(registry.get(10))
        self.assertEqual(document.content, bytearray())

    def test_session_epoch_rejects_unload_and_reunlock(self):
        self.assertTrue(session_epoch_is_current(7, 7, True))
        self.assertFalse(session_epoch_is_current(7, 8, True))
        self.assertFalse(session_epoch_is_current(7, 7, False))
        old_client = object()
        new_client = object()
        self.assertFalse(session_owner_is_current(old_client, new_client))
        self.assertTrue(session_owner_is_current(new_client, new_client))

    def test_authenticated_recovery_starts_dirty_and_stale_requires_confirmation(self):
        document = ManagedDocument(
            11,
            "recovered.md",
            "h",
            ETAG,
            bytearray(b"recovered"),
            recovered=True,
            stale_recovery=True,
            recovery_base_etag="sha256:" + "0" * 64,
        )
        self.assertTrue(document.dirty)
        self.assertEqual(document.draft_version, document.version)
        self.assertTrue(document.requires_overwrite_confirmation)
        self.assertEqual(document.draft_base_etag, "sha256:" + "0" * 64)
        document.mark_saved(document.version, NEW_ETAG)
        self.assertFalse(document.dirty)
        self.assertFalse(document.requires_overwrite_confirmation)
        self.assertEqual(document.draft_base_etag, NEW_ETAG)

    def test_only_clean_document_can_update_rename_identity(self):
        document = ManagedDocument(
            12, "before.md", "h", ETAG, bytearray(b"clean")
        )
        source = document.rename_clean("folder/after.md", NEW_ETAG)
        self.assertEqual(source, "before.md")
        self.assertEqual(document.logical_path, "folder/after.md")
        self.assertEqual(document.etag, NEW_ETAG)
        self.assertEqual(document.draft_base_etag, NEW_ETAG)

        document.replace(bytearray(b"dirty"))
        with self.assertRaisesRegex(ModelError, "clean open"):
            document.rename_clean("other.md", ETAG)

    def test_draft_epoch_cancels_waiters_and_crud_lock_waits_for_inflight_draft(self):
        document = ManagedDocument(
            13, "before.md", "h", ETAG, bytearray(b"clean")
        )
        old_epoch = document.draft_epoch
        draft_holds_lock = threading.Event()
        release_draft = threading.Event()
        crud_acquired = threading.Event()

        def inflight_draft():
            with document.draft_lock:
                draft_holds_lock.set()
                release_draft.wait(2.0)

        def crud_worker():
            with document.draft_lock:
                crud_acquired.set()

        draft_thread = threading.Thread(target=inflight_draft)
        draft_thread.start()
        self.assertTrue(draft_holds_lock.wait(1.0))
        new_epoch = document.invalidate_drafts()
        crud_thread = threading.Thread(target=crud_worker)
        crud_thread.start()
        self.assertFalse(crud_acquired.wait(0.05))
        self.assertFalse(document.draft_snapshot_is_current(0, old_epoch))
        self.assertTrue(document.draft_snapshot_is_current(0, new_epoch))
        release_draft.set()
        draft_thread.join(1.0)
        crud_thread.join(1.0)
        self.assertTrue(crud_acquired.is_set())

    def test_idle_deadline_warns_expires_and_renews(self):
        deadline = IdleDeadline(10000, 100.0)
        self.assertEqual(deadline.state(100.0), "active")
        self.assertEqual(deadline.state(deadline.deadline - 1.0), "warning")
        self.assertEqual(deadline.state(deadline.deadline), "expired")
        revision = deadline.renew(200.0)
        self.assertEqual(revision, 2)
        self.assertEqual(deadline.state(200.0), "active")
        # Renewal is anchored to the authenticated worker response, not the
        # later main-thread callback time. A delayed callback must not extend it.
        deadline.renew(300.0)
        delayed_main_thread = deadline.deadline + 5.0
        self.assertEqual(deadline.state(delayed_main_thread), "expired")

    def test_plaintext_handoff_is_one_shot_and_clear_wipes(self):
        registry = PlaintextHandoffRegistry()
        first = bytearray(b"secret-one")
        token = registry.put(first)
        self.assertIs(registry.take(token), first)
        with self.assertRaises(ModelError):
            registry.take(token)
        second = bytearray(b"secret-two")
        registry.put(second)
        registry.clear()
        self.assertEqual(second, bytearray(len(second)))

    def test_pending_plaintext_drain_has_explicit_wipe_owner(self):
        registry = PendingPlaintextRegistry()
        first = bytearray(b"open plaintext")
        second = bytearray(b"recovery plaintext")
        token = registry.add("handle", object(), first)
        self.assertTrue(registry.add_buffer(token, second))
        owners = registry.drain()
        self.assertEqual(len(owners), 1)
        owners[0].wipe()
        self.assertEqual(first, bytearray(len(first)))
        self.assertEqual(second, bytearray(len(second)))
        late = bytearray(b"late")
        self.assertFalse(registry.add_buffer(token, late))
        self.assertEqual(late, bytearray(len(late)))


class DraftStorageTests(unittest.TestCase):
    def test_atomic_draft_contains_only_supplied_edry_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            directory = os.path.join(root, "encrypted-drafts")
            filename = draft_filename("00000000-0000-4000-8000-000000000000", "today.md")
            envelope = bytearray(b"EDRY\x01\x00ciphertext-only")
            destination = atomic_write_ciphertext(directory, filename, envelope)
            with open(destination, "rb") as stream:
                self.assertEqual(stream.read(), bytes(envelope))
            self.assertEqual(
                [name for name in os.listdir(directory) if ".tmp-" in name], []
            )
            self.assertEqual(read_encrypted_draft(directory, filename), envelope)
            self.assertTrue(remove_encrypted_draft(directory, filename))
            self.assertFalse(remove_encrypted_draft(directory, filename))

    def test_atomic_draft_rejects_plaintext_and_symlink_directory(self):
        with tempfile.TemporaryDirectory() as root:
            filename = "0" * 64 + ".edry"
            with self.assertRaises(DraftStorageError):
                atomic_write_ciphertext(root, filename, bytearray(b"plaintext"))
            target = os.path.join(root, "target")
            os.mkdir(target)
            link = os.path.join(root, "link")
            os.symlink(target, link)
            with self.assertRaises(DraftStorageError):
                atomic_write_ciphertext(link, filename, bytearray(b"EDRYcipher"))
            target_draft = os.path.join(target, filename)
            with open(target_draft, "wb") as stream:
                stream.write(b"EDRYcipher")
            with self.assertRaises(DraftStorageError):
                read_encrypted_draft(link, filename)
            with self.assertRaises(DraftStorageError):
                remove_encrypted_draft(link, filename)
            with open(target_draft, "rb") as stream:
                self.assertEqual(stream.read(), b"EDRYcipher")


class CommandInterceptionTests(unittest.TestCase):
    def test_managed_text_commands_are_rewritten(self):
        self.assertEqual(classify_text_command(True, "save"), "save")
        self.assertEqual(classify_text_command(True, "save_as"), "block_save_as")
        self.assertEqual(classify_text_command(True, "clone_file"), "block_plaintext")
        self.assertEqual(classify_text_command(True, "close_file"), "close_active")
        self.assertIsNone(classify_text_command(False, "save"))
        for command in (
            "html_print",
            "print",
            "print_selection",
            "export",
            "copy_as_html",
            "copy",
            "cut",
            "open_context_url",
            "old_open_context_url",
        ):
            self.assertEqual(
                classify_text_command(True, command), "block_disclosure"
            )
        for command in (
            "toggle_record_macro",
            "save_macro",
            "run_macro",
            "run_macro_file",
        ):
            self.assertEqual(classify_text_command(True, command), "block_macro")

    def test_window_save_all_and_close_commands_are_rewritten(self):
        self.assertEqual(
            classify_window_command(True, False, "save_all"), "save_all"
        )
        self.assertEqual(
            classify_window_command(True, True, "prompt_save_as"), "block_save_as"
        )
        self.assertEqual(
            classify_window_command(True, True, "close_file"), "close_active"
        )
        self.assertEqual(
            classify_window_command(True, False, "close_window"), "close_many"
        )
        self.assertEqual(
            classify_window_command(True, False, "close_by_index"), "close_filtered"
        )
        self.assertEqual(
            classify_window_command(True, False, "close_pane"), "close_filtered"
        )
        self.assertEqual(
            classify_window_command(True, True, "html_print"),
            "block_disclosure",
        )
        for command in ("open_context_url", "old_open_context_url"):
            self.assertEqual(
                classify_window_command(True, True, command),
                "block_disclosure",
            )
        for command in ("toggle_record_macro", "save_macro", "run_macro"):
            self.assertEqual(
                classify_window_command(True, True, command), "block_macro"
            )
        self.assertEqual(
            classify_window_command(True, False, "run_macro_file"),
            "block_macro",
        )

    def test_macro_canary_is_only_fingerprinted(self):
        canary = "INEX-MACRO-CANARY-do-not-persist"
        first = macro_fingerprint(
            [{"command": "insert", "args": {"characters": canary}}]
        )
        second = macro_fingerprint(
            [{"command": "insert", "args": {"characters": canary + "-changed"}}]
        )
        self.assertNotIn(canary, first)
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
