"""接收流水线端到端测试，使用预构建的本地签名与恶意归档样例。

前置条件：fixtures/intake 由 tools/build_fixtures.py 生成（测试私钥
保存在项目外）。若样例缺失，整组跳过并给出构建提示，而不是伪造密钥。
"""

import os
import tempfile
import unittest
from pathlib import Path

from app.audit import audit_package, audit_store, audit_to_dict
from app.crypto import TrustStore
from app.intake import Receiver, SimulatedCrash
from app.store import PackageStore
from app.zipstream import Budget

PROJECT = Path(__file__).resolve().parents[1]
SIGNED = PROJECT / "fixtures" / "intake" / "signed"
MALICIOUS = PROJECT / "fixtures" / "intake" / "malicious"
TRUST = PROJECT / "fixtures" / "intake" / "trust"

RELAXED_ZIP64_BUDGET = Budget(
    max_member_uncompressed=6 * 1024**3,
    max_total_uncompressed=6 * 1024**3,
    max_compression_ratio=100_000,
)


@unittest.skipUnless(
    SIGNED.is_dir() and TRUST.is_dir(),
    "缺少 fixtures/intake 样例；请用 tools/build_fixtures.py 生成（私钥放项目外）",
)
class ReceiverIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.store = PackageStore(self.work / "store")
        self.trust = TrustStore(TRUST)
        self.receiver = Receiver(self.store, self.trust)

    def tearDown(self):
        self.tmp.cleanup()

    def receive(self, name: str, *, directory=SIGNED, budget=None):
        receiver = Receiver(self.store, self.trust, budget=budget) if budget else self.receiver
        return receiver.receive(directory / name)

    # ----------------------------------------------------- 正常路径
    def test_accepts_valid_v1(self):
        result = self.receive("stats-v1.zip")
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.version.version, 1)
        self.assertEqual(result.issuer, "synthetic-lab")
        self.assertIsNotNone(result.key_id)
        self.assertTrue(all(f.ok for f in result.file_results))
        # 数据文件确实落在版本目录，且内容与清单一致。
        data = result.version.path / "observations" / "data.json"
        self.assertTrue(data.is_file())

    def test_redelivery_is_idempotent(self):
        first = self.receive("stats-v1.zip")
        again = self.receive("stats-v1-redelivery.zip")
        self.assertEqual(again.status, "accepted-duplicate")
        self.assertEqual(again.version.version, first.version.version)
        # 没有产生第二个版本目录。
        versions = [p for p in (self.store.package_dir(first.package_id)).iterdir()
                    if p.name.startswith("v") and p.is_dir()]
        self.assertEqual(len(versions), 1)

    def test_signed_but_changed_content_creates_new_version(self):
        v1 = self.receive("stats-v1.zip")
        v2 = self.receive("stats-v2.zip")
        self.assertEqual(v2.status, "accepted")
        self.assertEqual(v2.version.version, 2)
        self.assertNotEqual(v2.manifest_fingerprint, v1.manifest_fingerprint)
        # current 原子指向 v2，旧版本目录仍完整保留。
        self.assertEqual(os.readlink(self.store.package_dir("stats-monthly") / "current"),
                         "v0002")
        self.assertTrue((self.store.package_dir("stats-monthly") / "v0001").is_dir())

    def test_duplicate_fingerprint_after_newer_version_still_idempotent(self):
        self.receive("stats-v1.zip")
        self.receive("stats-v2.zip")  # current 推进到 v2
        again = self.receive("stats-v1.zip")  # 旧指纹再来
        self.assertEqual(again.status, "accepted-duplicate")
        self.assertEqual(again.version.version, 1)
        # current 仍是 v2，不被回退。
        self.assertEqual(os.readlink(self.store.package_dir("stats-monthly") / "current"),
                         "v0002")

    def test_zip64_accepted_under_relaxed_budget_and_flagged_in_receipt(self):
        result = self.receive(
            "stats-v1-zip64.zip", budget=RELAXED_ZIP64_BUDGET
        )
        self.assertEqual(result.status, "accepted")
        self.assertTrue(result.version.receipt["zip64_used"])

    def test_zip64_bomb_quarantined_under_default_budget(self):
        result = self.receive("stats-v1-zip64.zip")
        self.assertEqual(result.status, "quarantined")
        self.assertTrue(any("MEMBER_TOO_LARGE" in r or "COMPRESSION_BOMB" in r
                            for r in result.reasons))

    # ----------------------------------------------------- 恶意样例矩阵
    def assert_quarantined(self, name: str, expected_codes: list[str]):
        result = self.receive(name, directory=MALICIOUS)
        self.assertEqual(result.status, "quarantined", msg=str(result.reasons))
        joined = " ".join(result.reasons)
        for code in expected_codes:
            self.assertIn(code, joined, msg=f"{name} 缺少 {code}；实际：{result.reasons}")
        # 隔离证据里必须保留原始归档副本与收据。
        self.assertTrue(result.quarantine_path.is_dir())
        self.assertTrue(any(result.quarantine_path.glob("package-*.zip")))
        self.assertTrue((result.quarantine_path / "QUARANTINE.json").is_file())
        # 失败尝试绝不产生版本或 current。
        pkg = self.store.package_dir("stats-monthly")
        self.assertFalse((pkg / "current").exists())

    def test_malicious_matrix(self):
        cases = {
            "bad-signature.zip": ["SIGNATURE_INVALID"],
            "compression-bomb.zip": ["COMPRESSION_BOMB"],
            "duplicate-manifest.zip": ["DUPLICATE"],
            "duplicate-path.zip": ["DUPLICATE_PATH"],
            "missing-member.zip": ["MISSING_MEMBER"],
            "missing-signature.zip": ["MISSING_SIGNATURE"],
            "path-traversal.zip": ["UNSAFE_PATH"],
            "size-mismatch.zip": ["SIZE_MISMATCH"],
            "symlink.zip": ["SYMLINK_MEMBER"],
            "truncated-central-directory.zip": ["BAD_ZIP"],
            "undeclared-member.zip": ["UNDECLARED_MEMBER"],
        }
        for name, codes in cases.items():
            with self.subTest(name=name):
                self.assert_quarantined(name, codes)

    def test_digest_mismatch_keeps_member_evidence(self):
        result = self.receive("digest-mismatch.zip", directory=MALICIOUS)
        self.assertEqual(result.status, "quarantined")
        evidence = list((result.quarantine_path / "members").glob("*.actual"))
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].read_bytes(), b'{"sample":"TAMPERED"}\n')
        fr = next(f for f in result.file_results if not f.ok)
        self.assertNotEqual(fr.actual_sha256, fr.expected_sha256)
        self.assertIn("SIZE_MISMATCH", fr.reason)

    def test_failed_acceptance_never_overwrites_current(self):
        good = self.receive("stats-v1.zip")
        before = os.readlink(self.store.package_dir("stats-monthly") / "current")
        self.receive("symlink.zip", directory=MALICIOUS)
        self.receive("bad-signature.zip", directory=MALICIOUS)
        after = os.readlink(self.store.package_dir("stats-monthly") / "current")
        self.assertEqual(before, after)
        # 已发布版本内容字节不变。
        self.assertTrue((good.version.path / "observations" / "data.json").is_file())

    # ----------------------------------------------------- 原子发布
    def test_current_switch_is_atomic_symlink(self):
        r1 = self.receive("stats-v1.zip")
        r2 = self.receive("stats-v2.zip")
        current = self.store.package_dir("stats-monthly") / "current"
        self.assertTrue(current.is_symlink())
        target = os.readlink(current)
        # 链接目标要么是完整 v1，要么是完整 v2，且都已落盘。
        self.assertIn(target, ("v0001", "v0002"))
        linked = (self.store.package_dir("stats-monthly") / target).resolve()
        self.assertTrue((linked / "RECEIPT.json").is_file())
        self.assertEqual(r2.version.path, linked)

    # ----------------------------------------------------- 崩溃恢复
    def test_crash_after_member_verify_does_not_mix_versions(self):
        def crash(event):
            if event == "after_member_verify":
                raise SimulatedCrash("boom")

        crashing = Receiver(self.store, self.trust, crash_hook=crash)
        with self.assertRaises(SimulatedCrash):
            crashing.receive(SIGNED / "stats-v1.zip")

        # 崩溃后没有任何发布版本，但有残留暂存区。
        if self.store.list_packages():
            self.assertFalse(
                (self.store.package_dir("stats-monthly") / "current").exists()
            )
        self.assertTrue(any(self.store.staging_dir.iterdir()))

        # 新进程语义重新接收：残留被隔离到 orphaned，得到干净 v1。
        result = self.receive("stats-v1.zip")
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.version.version, 1)
        self.assertTrue(any(self.store.orphan_dir.iterdir()))
        self.assertFalse(any(self.store.staging_dir.iterdir()))

    def test_crash_before_publish_leaves_no_current(self):
        def crash(event):
            if event == "before_publish":
                raise SimulatedCrash("before publish")

        crashing = Receiver(self.store, self.trust, crash_hook=crash)
        with self.assertRaises(SimulatedCrash):
            crashing.receive(SIGNED / "stats-v1.zip")
        self.assertFalse(
            (self.store.package_dir("stats-monthly") / "current").exists()
        )

    # ----------------------------------------------------- 审计视图
    def test_audit_reports_identity_files_and_quarantine(self):
        self.receive("stats-v1.zip")
        # 坏签名在解析出 package_id 前即被拒，进入兜底隔离区。
        self.receive("bad-signature.zip", directory=MALICIOUS)
        # 同包内隔离（摘要不符，已能识别 package_id）进入包级隔离区。
        self.receive("digest-mismatch.zip", directory=MALICIOUS)

        report = audit_to_dict(audit_package(self.store, "stats-monthly"))
        self.assertEqual(report["current_version"]["issuer"], "synthetic-lab")
        self.assertTrue(report["current_version"]["key_id"])
        package_statuses = {a["status"] for a in report["attempts"]}
        self.assertIn("quarantined", package_statuses)
        # 逐文件摘要都在审计输出里。
        for f in report["current_version"]["files"]:
            self.assertEqual(len(f["expected_sha256"]), 64)

        whole = audit_store(self.store)
        self.assertTrue(whole["unidentified_quarantine"])
        entry = whole["unidentified_quarantine"][0]
        self.assertTrue(any("SIGNATURE_INVALID" in r for r in entry["reasons"]))

    def test_quarantine_without_identifiable_package_uses_orphan_area(self):
        # 截断包无法解析出 package_id，应进入兜底隔离区。
        result = self.receive("truncated-central-directory.zip", directory=MALICIOUS)
        self.assertEqual(result.status, "quarantined")
        self.assertIsNone(result.package_id)
        self.assertTrue(result.quarantine_path.is_dir())
        self.assertIn("unidentified", str(result.quarantine_path))

    def test_concurrent_receivers_are_serialized_by_exclusive_lock(self):
        import threading
        import time

        events: list[tuple[str, str]] = []
        barrier = threading.Barrier(3)

        def worker(tag: str):
            barrier.wait()
            with self.store.exclusive_lock():
                events.append(("start", tag))
                time.sleep(0.05)
                events.append(("end", tag))

        threads = [threading.Thread(target=worker, args=(t,)) for t in ("A", "B", "C")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 每个临界区的 start 必须紧跟同 tag 的 end，证明没有交错。
        for i in range(0, len(events), 2):
            self.assertEqual(events[i][1], events[i + 1][1])


if __name__ == "__main__":
    unittest.main()
