"""Regression coverage for manifest-bound report publication and paging."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from awa_ddd import report_artifacts
from awa_ddd.report_artifacts import (
    handle_for_path,
    managed_artifact_handle_valid,
    read_report_artifact,
)
from awa_ddd.store import EngineError


class ReportArtifactSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="awa-report-artifacts-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = SimpleNamespace(
            base=self.base,
            config={"project_id": "v2"},
        )
        (self.base / "reports").mkdir()

    def _manifest(self, batch, files, *, project_id="v2", embedded=True):
        facts = {
            "format_version": 1,
            "project_id": project_id,
            "files": [
                {
                    "path": name,
                    "sha256": sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
                for name, data in sorted(files.items())
            ],
        }
        if embedded:
            facts["manifest_sha256"] = sha256(
                json.dumps(
                    facts,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
        return facts

    def _write_batch(self, name, files, **manifest_options):
        directory = self.base / "reports" / name
        directory.mkdir()
        for relative, data in files.items():
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        manifest = self._manifest(name, files, **manifest_options)
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return directory, manifest

    def _assert_code(self, expected, function, *args):
        with self.assertRaises(EngineError) as caught:
            function(*args)
        self.assertEqual(expected, caught.exception.code)

    def test_handles_are_portable_and_reject_alternate_or_encoded_paths(self):
        batch = "20261122T010203Z-abcdef123456"
        directory, _ = self._write_batch(
            batch,
            {"report.md": b"safe report\n"},
        )
        report = directory / "report.md"
        handle = "artifact://reports/" + batch + "/report.md"
        self.assertEqual(handle, handle_for_path(self.project, report))
        self.assertTrue(managed_artifact_handle_valid(self.project, handle))

        escaped = (
            "artifact://reports/../" + batch + "/report.md",
            "artifact://reports/" + batch + "\\report.md",
            "artifact://reports/" + batch + "/report%2Emd",
            "artifact://reports/" + batch + "/report.md?download=1",
            "file://reports/" + batch + "/report.md",
        )
        for value in escaped:
            self.assertFalse(managed_artifact_handle_valid(self.project, value))
            self._assert_code(
                "report_material",
                read_report_artifact,
                self.project,
                {"handle": value},
            )

    def test_manifest_binding_rejects_unregistered_tampered_and_foreign_data(self):
        batch = "20261122T010204Z-abcdef123456"
        directory, _ = self._write_batch(
            batch,
            {"report.md": b"first bytes\n", "matrix.json": b"{}\n"},
        )
        handle = "artifact://reports/" + batch + "/report.md"

        (directory / "unregistered.txt").write_bytes(b"not listed\n")
        self._assert_code(
            "report_material",
            read_report_artifact,
            self.project,
            {
                "handle": "artifact://reports/" + batch + "/unregistered.txt",
            },
        )

        (directory / "report.md").write_bytes(b"changed bytes\n")
        self._assert_code(
            "report_material",
            read_report_artifact,
            self.project,
            {"handle": handle},
        )

        foreign = "20261122T010205Z-abcdef123456"
        self._write_batch(
            foreign,
            {"report.md": b"foreign\n"},
            project_id="another-project",
        )
        self._assert_code(
            "report_material",
            read_report_artifact,
            self.project,
            {
                "handle": "artifact://reports/" + foreign + "/report.md",
            },
        )

    def test_manifest_digest_and_file_entries_are_closed(self):
        batch = "20261122T010206Z-abcdef123456"
        directory, manifest = self._write_batch(
            batch,
            {"report.md": b"safe\n"},
        )
        manifest["manifest_sha256"] = "0" * 64
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self._assert_code(
            "report_material",
            read_report_artifact,
            self.project,
            {"handle": "artifact://reports/" + batch + "/manifest.json"},
        )

        unsafe = "20261122T010207Z-abcdef123456"
        directory, _ = self._write_batch(
            unsafe,
            {"report.md": b"safe\n"},
        )
        invalid = self._manifest(
            unsafe,
            {"../escape.md": b"escape\n"},
        )
        (directory / "manifest.json").write_text(
            json.dumps(invalid, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self._assert_code(
            "report_material",
            read_report_artifact,
            self.project,
            {"handle": "artifact://reports/" + unsafe + "/manifest.json"},
        )

    def test_report_pages_preserve_character_offsets_and_digest(self):
        batch = "20261122T010208Z-abcdef123456"
        content = "A测" * 9000
        data = content.encode("utf-8")
        directory, _ = self._write_batch(batch, {"report.md": data})
        handle = "artifact://reports/" + batch + "/report.md"
        pages = []
        offset = 0
        while True:
            page = read_report_artifact(
                self.project,
                {"handle": handle, "offset": offset, "limit": 8000},
            )
            self.assertEqual(offset, page["offset"])
            self.assertEqual(sha256(data).hexdigest(), page["sha256"])
            self.assertEqual(len(data), page["size_bytes"])
            self.assertEqual(
                page["next_offset"],
                None if page["complete"]
                else offset + len(page["content"]),
            )
            pages.append(page)
            if page["complete"]:
                break
            offset = page["next_offset"]
        self.assertEqual(content, "".join(page["content"] for page in pages))
        self.assertEqual([8000, 8000, 2000], [
            len(page["content"]) for page in pages
        ])
        self.assertNotIn(str(self.base), json.dumps(pages))

    def test_report_page_returns_the_same_verified_bytes_if_the_file_changes(self):
        batch = "20261122T010208Z-abcdef123456"
        original = "verified-before-change\n".encode("utf-8")
        directory, _ = self._write_batch(batch, {"report.md": original})
        report = directory / "report.md"
        read_bounded = report_artifacts._read_bounded

        def read_then_change(path, maximum, error_code, message):
            data = read_bounded(path, maximum, error_code, message)
            if path.resolve() == report.resolve():
                report.write_bytes(b"replacement-after-read\n")
            return data

        with patch(
            "awa_ddd.report_artifacts._read_bounded",
            side_effect=read_then_change,
        ):
            page = read_report_artifact(
                self.project,
                {
                    "handle": "artifact://reports/" + batch + "/report.md",
                    "offset": 0,
                    "limit": 8000,
                },
            )

        self.assertEqual(original.decode("utf-8"), page["content"])
        self.assertEqual(sha256(original).hexdigest(), page["sha256"])
        self.assertEqual(len(original), page["size_bytes"])
        self.assertEqual(b"replacement-after-read\n", report.read_bytes())

    def test_link_or_reparse_batch_is_rejected_when_supported(self):
        batch = "20261122T010209Z-abcdef123456"
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "report.md").write_bytes(b"outside\n")
        link = self.base / "reports" / batch
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest("directory symlinks are unavailable: " + type(exc).__name__)
        self._assert_code(
            "path_link",
            read_report_artifact,
            self.project,
            {"handle": "artifact://reports/" + batch + "/report.md"},
        )


if __name__ == "__main__":
    unittest.main()
