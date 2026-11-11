"""路径归一化与清单 schema 的单元测试（不依赖任何外部进程或密钥）。"""

import json
import unittest

from app.manifest import (
    RESERVED_NAMES,
    ManifestError,
    normalize_member_name,
    parse_manifest,
)


def _entry(path: str, size: int = 1, digest: str = "ab" * 32) -> dict:
    return {"path": path, "size": size, "sha256": digest}


def _manifest(files: list[dict], **overrides) -> bytes:
    doc = {
        "issuer": "synthetic-lab",
        "package_id": "stats-monthly",
        "sequence": 1,
        "created": "2026-10-01T00:00:00+00:00",
        "files": files,
    }
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


class NormalizeTests(unittest.TestCase):
    def test_plain_relative_path_passes(self):
        self.assertEqual(
            normalize_member_name("observations/data.json"),
            "observations/data.json",
        )

    def test_nested_path_preserves_segments(self):
        self.assertEqual(normalize_member_name("a/b/c"), "a/b/c")

    def test_rejects_parent_traversal(self):
        for bad in ("../outside.txt", "a/../../b", "..", "a/../b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    normalize_member_name(bad)

    def test_rejects_absolute_and_drive(self):
        for bad in ("/etc/passwd", "C:/Windows", "\\\\server\\share"):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    normalize_member_name(bad)

    def test_rejects_backslash_and_colon(self):
        for bad in ("a\\b", "a:b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    normalize_member_name(bad)

    def test_rejects_dot_segments_and_empty(self):
        for bad in (".", "a/./b", "", "a//b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    normalize_member_name(bad)

    def test_rejects_control_chars_and_nul(self):
        for bad in ("a\tb", "a\x00b", "a\nb"):
            with self.subTest(bad=bad):
                with self.assertRaises(ManifestError):
                    normalize_member_name(bad)

    def test_normalization_collisions_detected_by_parser(self):
        # 两个不同原始写法归一化后同名 -> 清单层面冲突。
        raw = _manifest([_entry("a/b"), _entry("a//b")])
        with self.assertRaises(ManifestError):
            parse_manifest(raw)


class ManifestParseTests(unittest.TestCase):
    def test_valid_manifest(self):
        m = parse_manifest(_manifest([_entry("x.json", 5)]))
        self.assertEqual(m.issuer, "synthetic-lab")
        self.assertEqual(m.package_id, "stats-monthly")
        self.assertEqual(len(m.files), 1)
        self.assertEqual(m.files[0].sha256, bytes.fromhex("ab" * 32))
        self.assertEqual(len(m.fingerprint), 64)

    def test_reserved_names_forbidden(self):
        for name in RESERVED_NAMES:
            with self.subTest(name=name):
                with self.assertRaises(ManifestError):
                    parse_manifest(_manifest([_entry(name)]))

    def test_duplicate_normalized_path_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([_entry("a"), _entry("a")]))

    def test_bad_sequence_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([_entry("a")], sequence=0))
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([_entry("a")], sequence=True))

    def test_bad_size_and_digest_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([_entry("a", size=-1)]))
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([{"path": "a", "size": 1, "sha256": "xyz"}]))

    def test_empty_files_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([]))

    def test_bad_issuer_identifier(self):
        with self.assertRaises(ManifestError):
            parse_manifest(_manifest([_entry("a")], issuer="../escape"))

    def test_invalid_json_and_encoding(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"{not json")
        with self.assertRaises(ManifestError):
            parse_manifest(b"\xff\xfe not utf8")

    def test_fingerprint_stable_over_identical_bytes(self):
        raw = _manifest([_entry("a")])
        self.assertEqual(parse_manifest(raw).fingerprint, parse_manifest(raw).fingerprint)


if __name__ == "__main__":
    unittest.main()
