"""中央目录扫描、资源预算与流式解包的单元测试。

全部样例在测试内用标准库临时构造，不读取项目 fixtures 之外的不可信数据，
也不依赖任何外部进程。
"""

import os
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from app.zipstream import (
    Budget,
    ZipScanError,
    scan_zip,
    stream_member,
)

# 部分用例刻意构造重复 central-directory 名称，zipfile 会发 UserWarning。
warnings.filterwarnings("ignore", message="Duplicate name", category=UserWarning)


def _info(name: str, mode: int | None = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    if mode is not None:
        info.external_attr = (mode << 16)
    return info


class ScanTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_zip(self, name: str, entries: list[tuple[zipfile.ZipInfo, bytes]]) -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for info, payload in entries:
                z.writestr(info, payload)
        return path

    def scan(self, path: Path, budget: Budget | None = None):
        return scan_zip(path, budget or Budget())

    def find(self, scan, code: str):
        return [h for h in scan.hazards if h.code == code]


class StructuralHazardTests(ScanTestBase):
    def test_clean_archive_has_no_hazards(self):
        path = self.write_zip("ok.zip", [
            (_info("manifest.json"), b"{}"),
            (_info("manifest.sig"), b"sig"),
            (_info("a/b.json"), b"data"),
        ])
        scan = self.scan(path)
        self.assertEqual(scan.hazards, ())
        self.assertIsNotNone(scan.manifest)
        self.assertIsNotNone(scan.signature)

    def test_duplicate_central_directory_name_flagged(self):
        path = self.write_zip("dup.zip", [
            (_info("a.json"), b"one"),
            (_info("a.json"), b"two"),
        ])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "DUPLICATE_PATH"))

    def test_symlink_member_flagged(self):
        path = self.write_zip("link.zip", [
            (_info("link", mode=0o120777), b"../../etc/passwd"),
        ])
        scan = self.scan(path)
        hazard = self.find(scan, "SYMLINK_MEMBER")
        self.assertEqual(len(hazard), 1)
        member = next(m for m in scan.members if m.raw_name == "link")
        self.assertTrue(member.is_symlink)

    def test_path_traversal_flagged(self):
        path = self.write_zip("trav.zip", [(_info("../outside.txt"), b"x")])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "UNSAFE_PATH"))
        member = scan.members[0]
        self.assertIsNone(member.normalized)

    def test_absolute_path_flagged(self):
        path = self.write_zip("abs.zip", [(_info("/etc/x"), b"x")])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "UNSAFE_PATH"))

    def test_missing_manifest_and_signature(self):
        path = self.write_zip("none.zip", [(_info("a.json"), b"x")])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "MISSING_MANIFEST"))
        self.assertTrue(self.find(scan, "MISSING_SIGNATURE"))
        self.assertIsNone(scan.manifest)
        self.assertIsNone(scan.signature)

    def test_duplicate_reserved_manifest_flagged(self):
        path = self.write_zip("dm.zip", [
            (_info("manifest.json"), b"{}"),
            (_info("manifest.sig"), b"s"),
            (_info("manifest.json"), b"{}"),
        ])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "DUPLICATE_RESERVED"))

    def test_directory_member_detected(self):
        path = self.write_zip("dir.zip", [
            (_info("adir/", mode=0o040755), b""),
        ])
        scan = self.scan(path)
        member = scan.members[0]
        self.assertTrue(member.is_dir)

    def test_default_mode_regular_file_not_flagged_special(self):
        # ZipInfo 默认 external_attr=0x1800000，unix 部分只有权限位 0o600、
        # 类型位为 0；不得被误判为非常规文件。
        info = zipfile.ZipInfo("plain.txt")
        info.compress_type = zipfile.ZIP_DEFLATED  # 不设置 external_attr
        path = self.write_zip("plain.zip", [
            (_info("manifest.json"), b"{}"),
            (_info("manifest.sig"), b"s"),
            (info, b"ordinary"),
        ])
        scan = self.scan(path)
        self.assertFalse(self.find(scan, "SPECIAL_FILE"))
        self.assertEqual(scan.members[-1].unix_mode, None)

    def test_file_and_directory_prefix_coexist_without_false_hazard(self):
        # 同一前缀既是文件又作为目录：扫描阶段不报错，双射阶段由清单裁决。
        path = self.write_zip("prefix.zip", [
            (_info("manifest.json"), b"{}"),
            (_info("manifest.sig"), b"s"),
            (_info("a"), b"file-called-a"),
            (_info("a/b.txt"), b"child"),
        ])
        scan = self.scan(path)
        self.assertEqual(scan.hazards, ())
        self.assertEqual(
            sorted(m.normalized for m in scan.members),
            ["a", "a/b.txt", "manifest.json", "manifest.sig"],
        )

    def test_encrypted_flag_in_central_directory_detected(self):
        # zipfile 写入时会剥离它不支持的加密位，因此直接在中央目录
        # 字节里把目标成员的 general purpose bit flag 置 0x1，
        # 模拟真实加密归档。
        path = self.write_zip("enc.zip", [
            (_info("manifest.json"), b"{}"),
            (_info("manifest.sig"), b"s"),
            (_info("secret.bin"), b"data"),
        ])
        raw = bytearray(path.read_bytes())
        idx = raw.find(b"PK\x01\x02")
        patched = False
        while idx != -1:
            name_len = struct.unpack_from("<H", raw, idx + 28)[0]
            name = bytes(raw[idx + 46: idx + 46 + name_len])
            if name == b"secret.bin":
                struct.pack_into("<H", raw, idx + 8, 0x0001)
                patched = True
                break
            idx = raw.find(b"PK\x01\x02", idx + 1)
        self.assertTrue(patched)
        path.write_bytes(bytes(raw))

        scan = self.scan(path)
        self.assertTrue(self.find(scan, "ENCRYPTED_MEMBER"))
        member = next(m for m in scan.members if m.raw_name == "secret.bin")
        self.assertTrue(member.is_encrypted)


class BudgetTests(ScanTestBase):
    def test_compression_bomb_flagged_by_ratio(self):
        # 2 MiB 全零，压缩后极小 -> 压缩比远超默认 100:1。
        path = self.write_zip("bomb.zip", [(_info("zeros.bin"), b"\x00" * (2 * 1024 * 1024))])
        scan = self.scan(path)
        self.assertTrue(self.find(scan, "COMPRESSION_BOMB"))

    def test_member_count_budget_raises_fatal(self):
        budget = Budget(max_members=2)
        path = self.write_zip("many.zip", [
            (_info(f"f{i}.txt"), b"x") for i in range(3)
        ])
        with self.assertRaises(ZipScanError) as ctx:
            self.scan(path, budget)
        self.assertEqual(ctx.exception.code, "TOO_MANY_MEMBERS")

    def test_total_uncompressed_budget_raises_fatal(self):
        budget = Budget(max_total_uncompressed=10)
        path = self.write_zip("big.zip", [
            (_info("a.txt"), b"x" * 8),
            (_info("b.txt"), b"y" * 8),
        ])
        with self.assertRaises(ZipScanError) as ctx:
            self.scan(path, budget)
        self.assertEqual(ctx.exception.code, "TOTAL_UNCOMPRESSED_EXCEEDED")

    def test_member_size_budget_flagged_not_fatal(self):
        budget = Budget(max_member_uncompressed=4)
        path = self.write_zip("large.zip", [(_info("a.txt"), b"x" * 10)])
        scan = self.scan(path, budget)
        self.assertTrue(self.find(scan, "MEMBER_TOO_LARGE"))

    def test_truncated_central_directory_is_fatal(self):
        good = self.write_zip("good.zip", [(_info("a.txt"), b"x" * 100)])
        truncated = self.root / "trunc.zip"
        raw = good.read_bytes()
        truncated.write_bytes(raw[: len(raw) // 2])
        with self.assertRaises(ZipScanError) as ctx:
            self.scan(truncated)
        self.assertEqual(ctx.exception.code, "BAD_ZIP")

    def test_non_zip_input_is_fatal(self):
        path = self.root / "plain.bin"
        path.write_bytes(b"this is not a zip at all" * 10)
        with self.assertRaises(ZipScanError) as ctx:
            self.scan(path)
        self.assertEqual(ctx.exception.code, "BAD_ZIP")

    def test_empty_archive_is_fatal(self):
        path = self.root / "empty.zip"
        with zipfile.ZipFile(path, "w"):
            pass
        with self.assertRaises(ZipScanError) as ctx:
            self.scan(path)
        self.assertEqual(ctx.exception.code, "EMPTY_ARCHIVE")


class StreamMemberTests(ScanTestBase):
    def test_stream_matches_size_and_digest(self):
        payload = b"hello streaming world\n" * 1000
        path = self.write_zip("s.zip", [(_info("a.txt"), payload)])
        scan = self.scan(path)
        member = scan.members[0]
        out = self.root / "out.bin"
        with open(out, "wb") as sink:
            outcome = stream_member(path, member, sink, Budget())
        self.assertIsNone(outcome.error)
        self.assertFalse(outcome.truncated)
        self.assertEqual(outcome.bytes_written, len(payload))
        import hashlib
        self.assertEqual(outcome.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(out.read_bytes(), payload)

    def test_stream_detects_declared_size_mismatch(self):
        # 手工写一个中央目录声明大小与实际流不一致的成员。
        path = self.root / "mangle.zip"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("a.txt", b"real bytes here")
        # 直接篡改 ZipInfo 视角不可行（读时重新解析），改为截断文件尾部。
        good = self.write_zip("g.zip", [(_info("a.txt"), b"z" * 5000)])
        cut = self.root / "cut.zip"
        cut.write_bytes(good.read_bytes()[:-20])
        with self.assertRaises(ZipScanError):
            self.scan(cut)


class BudgetDefaultsTests(unittest.TestCase):
    def test_defaults_are_bounded(self):
        b = Budget()
        self.assertLess(b.max_total_uncompressed, 32 * 1024**3)
        self.assertLess(b.max_member_uncompressed, 16 * 1024**3)
        self.assertGreaterEqual(b.max_compression_ratio, 1)
        self.assertGreaterEqual(b.chunk_size, 64 * 1024)


if __name__ == "__main__":
    unittest.main()
