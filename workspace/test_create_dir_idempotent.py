# -*- coding: utf-8 -*-
"""Regression tests for create_dir's mkdir -p semantics and policy boundaries."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
import policy  # noqa: E402
import tools  # noqa: E402


class CreateDirIdempotentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gateway-mkdir-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.authorized = self.base / "allowed"
        self.authorized.mkdir()
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.policy = policy.PolicyStore(self.base / "policy.json")
        self.root = self.policy.add_root(str(self.authorized), policy.LEVEL_DELETE)
        # A small fixture can exercise the same large-directory decision as D:\notion.
        self.policy._data["safe_overwrite_max_bytes"] = 1024
        self.policy._data["safe_delete_max_entries"] = 3
        self.patched_policy = patch.object(tools, "POLICY", self.policy)
        self.patched_audit = patch.object(tools.fileops, "audit")
        self.patched_policy.start()
        self.patched_audit.start()
        self.addCleanup(self.patched_audit.stop)
        self.addCleanup(self.patched_policy.stop)

    def large_directory(self) -> Path:
        target = self.authorized / "large"
        target.mkdir()
        (target / "data.bin").write_bytes(b"x" * 2048)
        _, decision = self.policy.evaluate(str(target), policy.OP_WRITE)
        self.assertEqual(decision.code, "LARGE_TARGET_PROTECTED")
        return target

    def test_existing_large_directory_is_a_noop_at_level_three(self) -> None:
        target = self.large_directory()
        with patch.object(tools.fileops, "make_dir") as mkdir:
            result = tools.t_create_dir({"path": str(target)})
            mkdir.assert_not_called()
        self.assertTrue(result["ok"])
        self.assertFalse(result["created"])
        self.assertEqual(result["path"], str(target))
        self.assertEqual((target / "data.bin").read_bytes(), b"x" * 2048)

    def test_existing_directory_can_be_repeated_without_mutation(self) -> None:
        target = self.authorized / "small"
        target.mkdir()
        for _ in range(2):
            result = tools.t_create_dir({"path": str(target)})
            self.assertFalse(result["created"])
        self.assertEqual(list(target.iterdir()), [])

    def test_nonexistent_directory_still_requires_write_permission(self) -> None:
        target = self.authorized / "new" / "child"
        result = tools.t_create_dir({"path": str(target)})
        self.assertTrue(result["created"])
        self.assertTrue(target.is_dir())

    def test_level_one_cannot_bypass_write_permission(self) -> None:
        target = self.large_directory()
        self.policy.update_root(self.root.id, level=policy.LEVEL_READ)
        with self.assertRaises(policy.PolicyError) as ctx:
            tools.t_create_dir({"path": str(target)})
        self.assertEqual(ctx.exception.code, "WRITE_DENIED")

    def test_denied_path_and_global_lock_are_not_bypassed(self) -> None:
        target = self.large_directory()
        self.policy.set_denies([str(target)])
        with self.assertRaises(policy.PolicyError) as ctx:
            tools.t_create_dir({"path": str(target)})
        self.assertEqual(ctx.exception.code, "DENY_LIST")
        self.policy.set_denies([])
        self.policy.set_global_lock(True)
        with self.assertRaises(policy.PolicyError) as ctx:
            tools.t_create_dir({"path": str(target)})
        self.assertEqual(ctx.exception.code, "GLOBAL_LOCK")

    def test_unlisted_directory_is_never_allowed(self) -> None:
        with self.assertRaises(policy.PolicyError) as ctx:
            tools.t_create_dir({"path": str(self.outside)})
        self.assertEqual(ctx.exception.code, "PATH_NOT_ALLOWED")

    def test_protected_directory_keeps_system_write_restrictions(self) -> None:
        target = self.large_directory()
        with patch.object(policy, "looks_protected", return_value=(True, "test protected path")):
            with self.assertRaises(policy.PolicyError) as ctx:
                tools.t_create_dir({"path": str(target)})
        self.assertEqual(ctx.exception.code, "SYSTEM_PATH_PROTECTED")

    def test_normal_write_and_delete_protection_is_unchanged(self) -> None:
        target = self.large_directory()
        self.policy._data["safe_delete_max_bytes"] = 1024
        _, write_decision = self.policy.evaluate(str(target), policy.OP_WRITE)
        _, delete_decision = self.policy.evaluate(str(target), policy.OP_DELETE)
        self.assertEqual(write_decision.code, "LARGE_TARGET_PROTECTED")
        self.assertEqual(delete_decision.code, "LARGE_TARGET_PROTECTED")

    def test_large_directory_level_four_noop_needs_no_approval(self) -> None:
        target = self.large_directory()
        self.policy.update_root(self.root.id, level=policy.LEVEL_FULL)
        with patch.object(tools.APPROVALS, "create") as approval:
            result = tools.t_create_dir({"path": str(target)})
            approval.assert_not_called()
        self.assertFalse(result["created"])


if __name__ == "__main__":
    unittest.main()