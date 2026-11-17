"""Exercise CI selection with real git histories and GitHub event payloads."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "ci_changes", Path(__file__).with_name("ci-changes.py")
)
changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(changes)


class AreaTests(unittest.TestCase):
    def test_area_fanout(self):
        for path, expected in [
            ("wlk/crates/kernel/src/lib.rs", {"integration", "product"}),
            ("wlk/crates/abi/src/generated.rs", {"integration", "product"}),
            ("wlk/crates/syscalls/src/generated.rs", {"integration", "product"}),
            ("lib/wasix/codegen/wit/types.wit", {"integration", "product"}),
            ("lib/wasix/api/src/lib.rs", {"integration", "product"}),
            ("lib/napi/src/lib.rs", {"integration", "product"}),
            ("lib/sdk/native/src/lib.rs", {"integration", "product"}),
            ("lib/c-api/src/lib.rs", {"integration", "product"}),
            ("tests/wasixv2", {"integration", "product"}),
            ("lib/cli/src/lib.rs", {"product"}),
            ("lib/api/src/lib.rs", {"integration", "product"}),
            ("Cargo.lock", {"integration", "product"}),
            (".github/workflows/test.yaml", {"integration", "product"}),
            ("unknown/new-area", {"integration", "product"}),
            ("docs/BUILD.md", set()),
        ]:
            with self.subTest(path=path):
                self.assertEqual(changes.select([path]), expected)

    def test_matrix_selection(self):
        kernel = changes.outputs(changes.select(["wlk/crates/abi/src/lib.rs"]))
        self.assertNotIn("engine", kernel)
        self.assertTrue(kernel["integration"])
        self.assertEqual(
            [item["key"] for item in kernel["build_targets"]],
            ["capi", "capi-v8", "wasmer", "check"],
        )
        self.assertNotIn(
            "check-baremetal", [item["make"] for item in kernel["test_stages"]]
        )
        product = changes.outputs({"product"})
        self.assertEqual([item["key"] for item in product["build_targets"]], ["wasmer", "check"])
        self.assertEqual(changes.outputs(set())["test_stages"], [])
        self.assertNotIn("test-all", [item["make"] for item in kernel["test_stages"]])
        self.assertIn(
            "wasix-integration", [item["make"] for item in product["test_stages"]]
        )


class EventTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, self.previous)
        self.addCleanup(self.directory.cleanup)
        self.git("init", "-q")
        self.git("config", "user.email", "ci-tests@example.invalid")
        self.git("config", "user.name", "CI tests")
        self.base = self.commit("initial", "README.md")

    def git(self, *args):
        return (
            subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )

    def commit(self, message, path):
        file = Path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(message)
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def test_push_rename_and_delete(self):
        self.commit("code", "lib/api/lib.rs")
        Path("docs").mkdir()
        self.git("mv", "lib/api/lib.rs", "docs/moved.md")
        self.git("commit", "-qm", "move")
        with patch.dict(os.environ, GITHUB_SHA=self.git("rev-parse", "HEAD")):
            paths = changes.changed_paths("push", {"before": self.base})
        self.assertEqual(paths, ["docs/moved.md"])
        # Diffing from the preceding commit must include the old engine path.
        with patch.dict(os.environ, GITHUB_SHA=self.git("rev-parse", "HEAD")):
            paths = changes.changed_paths(
                "push", {"before": self.git("rev-parse", "HEAD^")}
            )
        self.assertIn("lib/api/lib.rs", paths)
        self.assertEqual(changes.select(paths), {"integration", "product"})

    def test_pull_request_uses_merge_base(self):
        self.git("checkout", "-qb", "feature")
        head = self.commit("kernel", "wlk/crates/kernel/lib.rs")
        self.git("checkout", "-q", "-")
        base = self.commit("engine", "lib/api/lib.rs")
        with patch.dict(os.environ, GITHUB_SHA=base):
            paths = changes.changed_paths(
                "pull_request",
                {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}},
            )
        self.assertEqual(paths, ["wlk/crates/kernel/lib.rs"])

    def test_merge_group(self):
        head = self.commit("product", "lib/cli/lib.rs")
        with patch.dict(os.environ, GITHUB_SHA=head):
            paths = changes.changed_paths(
                "merge_group",
                {"merge_group": {"base_sha": self.base, "head_sha": head}},
            )
        self.assertEqual(paths, ["lib/cli/lib.rs"])

    def test_full_run_fallback(self):
        event_file = Path("event.json")
        output_file = Path("output")
        for event_name, event in [
            ("push", {"before": "0" * 40}),
            ("push", {"before": "f" * 40}),
            (
                "pull_request",
                {
                    "pull_request": {
                        "base": {"sha": "f" * 40},
                        "head": {"sha": self.base},
                    }
                },
            ),
            (
                "merge_group",
                {"merge_group": {"base_sha": "f" * 40, "head_sha": self.base}},
            ),
            ("workflow_dispatch", {}),
        ]:
            with self.subTest(event=event_name):
                event_file.write_text(json.dumps(event))
                output_file.write_text("")
                with patch.dict(
                    os.environ,
                    GITHUB_EVENT_PATH=str(event_file),
                    GITHUB_OUTPUT=str(output_file),
                    GITHUB_EVENT_NAME=event_name,
                    GITHUB_SHA=self.base,
                ):
                    changes.main()
                output = dict(
                    line.split("=", 1) for line in output_file.read_text().splitlines()
                )
                self.assertEqual(
                    [output[key] for key in ("integration", "product")],
                    ["true"] * 2,
                )


if __name__ == "__main__":
    unittest.main()
