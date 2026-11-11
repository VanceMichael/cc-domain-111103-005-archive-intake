"""接收编排：把签名验证、流式验收、隔离与原子发布串成一条流水线。

阶段顺序固定且不可调换：

0. 全局加锁并恢复上一轮崩溃残留（残留暂存区只进隔离区，绝不复用）；
1. 只读中央目录，按资源预算扫描全部结构风险——此时不展开任何数据；
2. 取出 manifest.json / manifest.sig，**先验证清单签名与签发身份**；
3. 完整校验清单 schema 与路径归一化；
4. 确认清单条目与归档数据成员严格双射（每个条目恰好一个成员）；
5. 逐成员流式解压到全新暂存区，边读边核对长度与 SHA-256；
6. 全部成功后原子发布；任何一步失败，整包隔离且现有版本原封不动。

同一包（package_id + 清单字节指纹）重复接收走幂等分支：重新完整
验收后若发现已发布版本一致，直接返回既有版本，不产生新版本；
签名有效但清单内容不同，则指纹不同，必然形成新版本。
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .crypto import CryptoError, TrustStore
from .manifest import (
    Manifest,
    ManifestError,
    extract_issuer,
    parse_manifest,
)
from .store import (
    CurrentVersion,
    PackageStore,
    new_attempt_id,
    safe_name,
    utc_now,
)
from .zipstream import (
    Budget,
    Hazard,
    MemberInfo,
    ScanResult,
    StreamOutcome,
    ZipScanError,
    read_reserved_member,
    scan_zip,
    stream_member,
)

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
EVIDENCE_SAMPLE_CAP = 1024 * 1024  # 隔离时保留的问题成员样本上限


@dataclass(frozen=True)
class FileResult:
    path: str
    normalized: str
    expected_size: int
    actual_size: int
    expected_sha256: str
    actual_sha256: str
    member_index: int
    ok: bool
    reason: str | None = None


@dataclass(frozen=True)
class IntakeResult:
    status: str                       # accepted | accepted-duplicate | quarantined
    package_id: str | None
    attempt_id: str
    version: CurrentVersion | None
    manifest_fingerprint: str | None
    issuer: str | None
    key_id: str | None
    reasons: tuple[str, ...]
    file_results: tuple[FileResult, ...]
    quarantine_path: Path | None
    receipt_path: Path | None


class SimulatedCrash(RuntimeError):
    """测试用：模拟进程在指定阶段后退出（通过 crash_hook 注入）。"""


def _file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class Receiver:
    def __init__(
        self,
        store: PackageStore,
        trust_store: TrustStore,
        budget: Budget | None = None,
        crash_hook=None,
    ):
        self.store = store
        self.trust = trust_store
        self.budget = budget or Budget()
        # crash_hook(event: str) -> None；抛出 SimulatedCrash 即模拟进程退出。
        self.crash_hook = crash_hook or (lambda event: None)

    # --------------------------------------------------------- 主入口
    def receive(self, archive_path: str | Path) -> IntakeResult:
        archive_path = Path(archive_path)
        if not archive_path.is_file():
            raise FileNotFoundError(f"归档不存在或不是普通文件: {archive_path}")
        attempt_id = new_attempt_id()
        package_id: str | None = None
        issuer: str | None = None
        key_id: str | None = None
        fingerprint: str | None = None
        reasons: list[str] = []
        file_results: list[FileResult] = []
        manifest_doc: Manifest | None = None
        staging: Path | None = None

        with self.store.exclusive_lock():
            # 阶段 0：先收拾上一轮崩溃，保证任何残留字节都不会混入本次验收。
            self.store.recover_staging()

            # 阶段 1：中央目录静态扫描（不读数据内容）。
            try:
                scan = scan_zip(archive_path, self.budget)
            except ZipScanError as exc:
                return self._quarantine(
                    attempt_id, None, None, None, None,
                    [f"{exc.code}: {exc.detail}"], [], None, archive_path,
                )
            reasons.extend(self._format_hazards(scan.hazards))

            # 阶段 2a：先把清单与签名字节取出来（仍在任何解包之前）。
            manifest_bytes = b""
            signature_bytes = b""
            if scan.manifest is None or scan.signature is None:
                # 缺少保留成员的原因已在 hazards 中。
                return self._quarantine(
                    attempt_id, None, None, None, None,
                    reasons or ["missing reserved members"], [], None, archive_path,
                )
            try:
                manifest_bytes = read_reserved_member(
                    archive_path, scan.manifest, MAX_MANIFEST_BYTES
                )
                signature_bytes = read_reserved_member(
                    archive_path, scan.signature, MAX_SIGNATURE_BYTES
                )
            except ZipScanError as exc:
                return self._quarantine(
                    attempt_id, None, None, None, None,
                    reasons + [f"{exc.code}: {exc.detail}"], [], None, archive_path,
                )

            # 阶段 2b：先确认签发身份并验证签名，再做任何内容信任。
            try:
                issuer = extract_issuer(manifest_bytes)
            except ManifestError as exc:
                return self._quarantine(
                    attempt_id, None, None, None, None,
                    reasons + [f"MANIFEST_INVALID: {exc}"], [], None, archive_path,
                    evidence={"manifest.bytes": manifest_bytes},
                )
            try:
                key_info = self.trust.verify(issuer, manifest_bytes, signature_bytes)
                key_id = key_info.key_id
            except CryptoError as exc:
                return self._quarantine(
                    attempt_id, None, issuer, None, None,
                    reasons + [f"SIGNATURE_INVALID: {exc}"], [], None, archive_path,
                    evidence={
                        "manifest.bytes": manifest_bytes,
                        "manifest.sig": signature_bytes,
                    },
                )

            # 阶段 3：签名有效，执行完整清单 schema 与路径校验。
            try:
                manifest_doc = parse_manifest(manifest_bytes)
            except ManifestError as exc:
                return self._quarantine(
                    attempt_id, None, issuer, key_id, None,
                    reasons + [f"MANIFEST_INVALID: {exc}"], [], None, archive_path,
                    evidence={
                        "manifest.bytes": manifest_bytes,
                        "manifest.sig": signature_bytes,
                    },
                )
            package_id = manifest_doc.package_id
            fingerprint = manifest_doc.fingerprint

            # 阶段 4：清单条目与数据成员严格双射；结构类 hazard 一票否决。
            bijection_reasons, data_members = self._check_bijection(scan, manifest_doc)
            reasons.extend(bijection_reasons)
            if reasons:
                return self._quarantine(
                    attempt_id, package_id, issuer, key_id, fingerprint,
                    reasons, [], None, archive_path,
                    evidence={
                        "manifest.bytes": manifest_bytes,
                        "manifest.sig": signature_bytes,
                    },
                )

            # 阶段 5：全新暂存区 + 逐成员流式验收。
            staging = self.store.new_staging(attempt_id)
            all_ok, file_results, member_failures = self._verify_members(
                archive_path, manifest_doc, data_members, staging
            )

            self.crash_hook("after_member_verify")

            if not all_ok:
                failure_details = [
                    f"{fr.normalized}: {fr.reason}" for fr in file_results if not fr.ok
                ]
                return self._quarantine(
                    attempt_id, package_id, issuer, key_id, fingerprint,
                    failure_details, file_results, staging, archive_path,
                    evidence={
                        "manifest.bytes": manifest_bytes,
                        "manifest.sig": signature_bytes,
                    },
                    member_failures=member_failures,
                )

            # 阶段 6a：幂等判断——同 (package_id, 清单指纹) 在任何历史
            # 版本中已发布，就不产生新版本（即使 current 已被后续内容推进）。
            existing = self.store.find_version_by_fingerprint(package_id, fingerprint)
            if existing is not None:
                self.store.discard_staging(staging)
                return IntakeResult(
                    status="accepted-duplicate",
                    package_id=package_id,
                    attempt_id=attempt_id,
                    version=existing,
                    manifest_fingerprint=fingerprint,
                    issuer=issuer,
                    key_id=key_id,
                    reasons=(),
                    file_results=tuple(file_results),
                    quarantine_path=None,
                    receipt_path=existing.path / "RECEIPT.json",
                )

            # 阶段 6b：原子发布新版本。
            version_number = self.store.next_version_number(package_id)
            receipt = self._receipt(
                attempt_id, package_id, issuer, key_id, fingerprint,
                version_number, "accepted", file_results, scan, archive_path,
            )
            self.crash_hook("before_publish")
            published = self.store.publish_version(
                package_id, staging, version_number, receipt
            )
            self.crash_hook("after_publish")
            return IntakeResult(
                status="accepted",
                package_id=package_id,
                attempt_id=attempt_id,
                version=published,
                manifest_fingerprint=fingerprint,
                issuer=issuer,
                key_id=key_id,
                reasons=(),
                file_results=tuple(file_results),
                quarantine_path=None,
                receipt_path=published.path / "RECEIPT.json",
            )

    # --------------------------------------------------------- 双射
    def _check_bijection(
        self, scan: ScanResult, manifest_doc: Manifest
    ) -> tuple[list[str], dict[str, MemberInfo]]:
        reasons: list[str] = []
        data_members: dict[str, MemberInfo] = {}

        for member in scan.members:
            if member.is_reserved:
                continue
            if member.normalized is None:
                # 归一化失败已在扫描阶段记录 UNSAFE_PATH。
                continue
            if member.is_dir:
                reasons.append(f"DIRECTORY_MEMBER: 数据成员不得是目录: {member.raw_name}")
                continue
            if member.normalized in data_members:
                # 扫描阶段已记 DUPLICATE_PATH，这里保留双射视角的说明。
                reasons.append(
                    f"DUPLICATE_PATH: {member.normalized} 对应多个归档成员"
                )
                continue
            data_members[member.normalized] = member

        manifest_paths = manifest_doc.normalized_paths()
        member_paths = frozenset(data_members)

        for extra in sorted(member_paths - manifest_paths):
            reasons.append(f"UNDECLARED_MEMBER: 归档成员未列入清单: {extra}")
        for missing in sorted(manifest_paths - member_paths):
            reasons.append(f"MISSING_MEMBER: 清单条目在归档中没有对应成员: {missing}")
        return reasons, data_members

    # --------------------------------------------------------- 流式验收
    def _verify_members(
        self,
        archive_path: Path,
        manifest_doc: Manifest,
        data_members: dict[str, MemberInfo],
        staging: Path,
    ) -> tuple[bool, list[FileResult], dict[str, Path]]:
        results: list[FileResult] = []
        all_ok = True
        failures: dict[str, Path] = {}

        for entry in manifest_doc.files:
            member = data_members[entry.normalized]
            target = staging.joinpath(*entry.normalized.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            # O_EXCL：暂存区是全新的，任何已存在路径都意味着异常；
            # O_NOFOLLOW：绝不沿预置符号链接写到暂存区之外。
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags, 0o600)
            reason: str | None = None
            try:
                sink = os.fdopen(fd, "wb")
            except BaseException:
                os.close(fd)
                raise
            with sink:
                outcome: StreamOutcome = stream_member(
                    archive_path, member, sink, self.budget
                )

            actual_digest = _file_hash(target)
            expected_digest = entry.sha256.hex()
            if outcome.error:
                reason = outcome.error
            elif outcome.bytes_written != entry.size:
                reason = (
                    f"SIZE_MISMATCH: 清单 {entry.size} 字节，"
                    f"实际 {outcome.bytes_written} 字节"
                )
            elif actual_digest != expected_digest:
                reason = "DIGEST_MISMATCH: SHA-256 与清单不一致"

            ok = reason is None
            all_ok = all_ok and ok
            if not ok:
                failures[entry.normalized] = target
            results.append(
                FileResult(
                    path=entry.path,
                    normalized=entry.normalized,
                    expected_size=entry.size,
                    actual_size=outcome.bytes_written,
                    expected_sha256=expected_digest,
                    actual_sha256=actual_digest,
                    member_index=member.index,
                    ok=ok,
                    reason=reason,
                )
            )
        return all_ok, results, failures

    # --------------------------------------------------------- 隔离
    def _quarantine(
        self,
        attempt_id: str,
        package_id: str | None,
        issuer: str | None,
        key_id: str | None,
        fingerprint: str | None,
        reasons: list[str],
        file_results: list[FileResult],
        staging: Path | None,
        archive_path: Path,
        evidence: dict[str, bytes] | None = None,
        member_failures: dict[str, Path] | None = None,
    ) -> IntakeResult:
        if package_id is None:
            qdir = self.store.quarantine_unidentified(attempt_id)
        else:
            qdir = self.store.quarantine_dir(package_id, attempt_id)

        # 原始归档复制进隔离区，保留第一手证据（不移动用户的交付文件）。
        try:
            shutil.copy2(archive_path, qdir / f"package-{safe_name(archive_path.name)}")
        except OSError as exc:
            reasons = [*reasons, f"EVIDENCE_COPY_FAILED: {exc}"]

        evidence_dir = qdir / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        for name, blob in (evidence or {}).items():
            (evidence_dir / safe_name(name)).write_bytes(blob)

        # 长度/摘要不匹配的成员：把暂存中的实际字节按成员定位保留。
        if staging is not None and member_failures:
            members_dir = qdir / "members"
            members_dir.mkdir(exist_ok=True)
            for normalized, target in member_failures.items():
                destination = members_dir / f"{safe_name(normalized)}.actual"
                self._copy_capped(target, destination)

        if staging is not None:
            self.store.discard_staging(staging)

        receipt = {
            "attempt_id": attempt_id,
            "at": utc_now(),
            "status": "quarantined",
            "package_id": package_id,
            "issuer": issuer,
            "key_id": key_id,
            "manifest_fingerprint": fingerprint,
            "reasons": reasons,
            "source_archive": str(archive_path),
            "files": [self._file_dict(fr) for fr in file_results],
        }
        receipt_path = self.store.write_quarantine_receipt(qdir, attempt_id, receipt)
        return IntakeResult(
            status="quarantined",
            package_id=package_id,
            attempt_id=attempt_id,
            version=None,
            manifest_fingerprint=fingerprint,
            issuer=issuer,
            key_id=key_id,
            reasons=tuple(reasons),
            file_results=tuple(file_results),
            quarantine_path=qdir,
            receipt_path=receipt_path,
        )

    @staticmethod
    def _copy_capped(source: Path, destination: Path) -> None:
        """保留问题成员证据，但单文件封顶，避免炸弹样本撑爆隔离区。"""
        remaining = EVIDENCE_SAMPLE_CAP
        with open(source, "rb") as src, open(destination, "wb") as dst:
            while remaining > 0:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)

    # --------------------------------------------------------- 收据
    def _receipt(
        self,
        attempt_id: str,
        package_id: str,
        issuer: str,
        key_id: str,
        fingerprint: str,
        version: int,
        status: str,
        file_results: list[FileResult],
        scan: ScanResult,
        archive_path: Path,
    ) -> dict:
        return {
            "attempt_id": attempt_id,
            "at": utc_now(),
            "status": status,
            "package_id": package_id,
            "issuer": issuer,
            "key_id": key_id,
            "sequence_version": version,
            "manifest_fingerprint": fingerprint,
            "source_archive": str(archive_path),
            "zip64_used": scan.used_zip64,
            "member_count": len(scan.members),
            "total_uncompressed": scan.total_uncompressed,
            "total_compressed": scan.total_compressed,
            "files": [self._file_dict(fr) for fr in file_results],
        }

    @staticmethod
    def _file_dict(fr: FileResult) -> dict:
        return {
            "path": fr.path,
            "normalized": fr.normalized,
            "member_index": fr.member_index,
            "expected_size": fr.expected_size,
            "actual_size": fr.actual_size,
            "expected_sha256": fr.expected_sha256,
            "actual_sha256": fr.actual_sha256,
            "ok": fr.ok,
            "reason": fr.reason,
        }

    @staticmethod
    def _format_hazards(hazards: tuple[Hazard, ...]) -> list[str]:
        formatted = []
        for hazard in hazards:
            if hazard.member:
                formatted.append(f"{hazard.code}: {hazard.detail} (member={hazard.member})")
            else:
                formatted.append(f"{hazard.code}: {hazard.detail}")
        return formatted