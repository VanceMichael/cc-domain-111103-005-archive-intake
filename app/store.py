"""接收运行时的本地存储：锁、版本、隔离区、收据与原子发布。

目录布局（所有路径都在一个 store root 之下，绝不跨越边界）::

    root/
      .lock                     全包串行接收的 flock 文件
      packages/<package_id>/
        current -> v0003       原子切换的发布符号链接（相对链接）
        v0001/ ... v000N/      不可变已验收版本（包含发布收据）
        receipts/
          <attempt>.accepted.json
        quarantine/
          <attempt>/           失败尝试的完整隔离证据
      staging/<attempt>/       单次接收的暂存区，发布后即清空
      orphaned/                崩溃后无人认领的暂存区 / 版本残骸

关键不变量：

* ``current`` 只在新版本目录 fsync 完成后通过 ``os.replace`` 原子切换，
  读取端要么看到完整旧版，要么看到完整新版；
* 暂存目录按 attempt 新建、绝不复用，恢复时旧暂存区整体移入隔离区，
  因此崩溃恢复不会把新旧包内容拼成一个“已验收”版本；
* 已发布版本目录不可变，发布后不再写入；隔离区只追加、不覆盖。
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_attempt_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:12]}"


def safe_name(name: str) -> str:
    """把成员路径变成可放进证据目录的单层文件名（仍可在收据里追溯原名）。"""
    cleaned = name.replace("/", "__").replace("\x00", "")
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in cleaned)[:180]


@dataclass(frozen=True)
class CurrentVersion:
    version: int
    path: Path
    receipt: dict


class StoreError(RuntimeError):
    pass


class PackageStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.packages_dir = self.root / "packages"
        self.staging_dir = self.root / "staging"
        self.orphan_dir = self.root / "orphaned"
        self._lock_path = self.root / ".lock"
        for directory in (self.root, self.packages_dir, self.staging_dir, self.orphan_dir):
            directory.mkdir(parents=True, exist_ok=True)
        # 收紧运行时目录权限（样例与信任库不在此目录内，不受影响）。
        os.chmod(self.root, 0o700)

    # ------------------------------------------------------------ 全局锁
    @contextlib.contextmanager
    def exclusive_lock(self):
        """串行化所有接收动作，保证幂等判断与版本号分配不出现竞争。"""
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # ------------------------------------------------------------ 包目录
    def package_dir(self, package_id: str) -> Path:
        if not package_id or any(ch in package_id for ch in "/\\\x00.."):
            raise StoreError(f"非法 package_id: {package_id!r}")
        path = (self.packages_dir / package_id).resolve()
        if self.packages_dir not in path.parents:
            raise StoreError("package_id 越界")
        return path

    def ensure_package(self, package_id: str) -> Path:
        path = self.package_dir(package_id)
        (path / "receipts").mkdir(parents=True, exist_ok=True)
        (path / "quarantine").mkdir(parents=True, exist_ok=True)
        return path

    def list_packages(self) -> list[str]:
        if not self.packages_dir.exists():
            return []
        return sorted(p.name for p in self.packages_dir.iterdir() if p.is_dir())

    # ------------------------------------------------------------ 暂存区
    def new_staging(self, attempt_id: str) -> Path:
        if "/" in attempt_id or ".." in attempt_id:
            raise StoreError("非法 attempt_id")
        path = self.staging_dir / attempt_id
        # 每次接收必须使用全新空目录，绝不复用旧暂存内容。
        if path.exists():
            raise StoreError(f"暂存区已存在，拒绝复用: {path}")
        path.mkdir(parents=True)
        os.chmod(path, 0o700)
        return path

    def recover_staging(self) -> list[dict]:
        """启动恢复：把上一轮进程残留的暂存区整体移入隔离残骸区。

        暂存区里的任何字节都不会被继续当作新版本的一部分使用。
        """
        recovered: list[dict] = []
        if not self.staging_dir.exists():
            return recovered
        for child in sorted(self.staging_dir.iterdir()):
            if not child.is_dir():
                continue
            destination = self.orphan_dir / f"staging-{child.name}"
            if destination.exists():
                destination = self.orphan_dir / f"staging-{child.name}-{uuid.uuid4().hex[:6]}"
            shutil.move(str(child), str(destination))
            record = {
                "at": utc_now(),
                "kind": "interrupted_staging",
                "staging": str(child),
                "moved_to": str(destination),
            }
            _atomic_write_json(destination / "recovery.json", record)
            recovered.append(record)
        return recovered

    def discard_staging(self, staging: Path) -> None:
        """已成功发布或确认隔离后，删除本次暂存区（仅允许 staging 下的路径）。"""
        resolved = staging.resolve()
        if self.staging_dir.resolve() not in resolved.parents:
            raise StoreError("只能删除受管暂存区")
        shutil.rmtree(resolved, ignore_errors=True)

    # ------------------------------------------------------------ 隔离区
    def quarantine_dir(self, package_id: str, attempt_id: str) -> Path:
        package = self.ensure_package(package_id)
        path = package / "quarantine" / attempt_id
        if path.exists():
            raise StoreError(f"隔离证据目录已存在: {path}")
        path.mkdir(parents=True)
        os.chmod(path, 0o700)
        return path

    def quarantine_unidentified(self, attempt_id: str) -> Path:
        """连 issuer / package_id 都无法确认时使用的兜底隔离区。"""
        path = self.orphan_dir / f"unidentified-{attempt_id}"
        path.mkdir(parents=True, exist_ok=False)
        os.chmod(path, 0o700)
        return path

    # ------------------------------------------------------------ 发布
    def next_version_number(self, package_id: str) -> int:
        package = self.ensure_package(package_id)
        existing = [
            int(p.name[1:])
            for p in package.iterdir()
            if p.is_dir() and p.name.startswith("v") and p.name[1:].isdigit()
        ]
        return (max(existing) + 1) if existing else 1

    def publish_version(
        self, package_id: str, staging: Path, version: int, receipt: dict
    ) -> CurrentVersion:
        """把暂存区提升为不可变版本并原子切换 current。"""
        package = self.ensure_package(package_id)
        version_name = f"v{version:04d}"
        version_path = package / version_name
        if version_path.exists():
            raise StoreError(f"版本目录已存在，拒绝覆盖: {version_path}")

        staging_resolved = staging.resolve()
        if self.staging_dir.resolve() not in staging_resolved.parents:
            raise StoreError("只能发布受管暂存区")

        # 收据先写入暂存区并随数据一起 fsync，再整体改名进版本位。
        _atomic_write_json(staging_resolved / "RECEIPT.json", receipt)
        _fsync_tree(staging_resolved)
        os.rename(staging_resolved, version_path)
        os.chmod(version_path, 0o755)
        _fsync_tree(version_path)

        self._switch_current(package, version_name)
        # 版本目录从此不可变；再写收据副本到 receipts/ 供审计检索。
        _atomic_write_json(
            package / "receipts" / f"{receipt['attempt_id']}.accepted.json", receipt
        )
        return CurrentVersion(version=version, path=version_path, receipt=receipt)

    def _switch_current(self, package: Path, version_name: str) -> None:
        """os.replace 原子替换符号链接；相对链接保证 store 可整体搬迁。"""
        current = package / "current"
        tmp = package / f"current.tmp-{uuid.uuid4().hex[:8]}"
        os.symlink(version_name, tmp)
        os.replace(tmp, current)
        try:
            dir_fd = os.open(package, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

    def _version_dirs(self, package_id: str) -> list[Path]:
        package = self.package_dir(package_id)
        if not package.is_dir():
            return []
        return sorted(
            p for p in package.iterdir()
            if p.is_dir() and p.name.startswith("v") and p.name[1:].isdigit()
        )

    def find_version_by_fingerprint(
        self, package_id: str, fingerprint: str
    ) -> CurrentVersion | None:
        """在全部历史版本中查找相同清单指纹，支撑跨 current 的幂等。"""
        for version_path in reversed(self._version_dirs(package_id)):
            receipt_path = version_path / "RECEIPT.json"
            if not receipt_path.is_file():
                continue
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if receipt.get("manifest_fingerprint") == fingerprint:
                target = version_path.name
                return CurrentVersion(
                    version=int(target[1:]), path=version_path, receipt=receipt
                )
        return None

    def current_version(self, package_id: str) -> CurrentVersion | None:
        package = self.package_dir(package_id)
        current = package / "current"
        if not current.is_symlink() and not current.exists():
            return None
        if not current.is_symlink():
            raise StoreError(f"{current} 不是受管符号链接，发布状态不可信")
        target = os.readlink(current)
        version_path = (package / target).resolve()
        if not version_path.is_dir() or package.resolve() not in version_path.parents:
            raise StoreError("current 指向的版本目录缺失或越界")
        receipt_path = version_path / "RECEIPT.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        version = int(target[1:]) if target.startswith("v") else -1
        return CurrentVersion(version=version, path=version_path, receipt=receipt)

    def write_quarantine_receipt(
        self, quarantine_path: Path, attempt_id: str, receipt: dict
    ) -> Path:
        target = quarantine_path / "QUARANTINE.json"
        _atomic_write_json(target, receipt)
        return target

    # ------------------------------------------------------------ 审计
    def list_attempts(self, package_id: str) -> list[dict]:
        package = self.package_dir(package_id)
        attempts: list[dict] = []
        receipts_dir = package / "receipts"
        if receipts_dir.is_dir():
            for item in sorted(receipts_dir.glob("*.json")):
                attempts.append(json.loads(item.read_text(encoding="utf-8")))
        quarantine_dir = package / "quarantine"
        if quarantine_dir.is_dir():
            for item in sorted(quarantine_dir.glob("*/QUARANTINE.json")):
                attempts.append(json.loads(item.read_text(encoding="utf-8")))
        attempts.sort(key=lambda r: r.get("attempt_id", ""))
        return attempts

    def list_unidentified_quarantine(self) -> list[dict]:
        """签名/结构阶段就被拒、无法归属到 package 的隔离尝试。"""
        records: list[dict] = []
        if not self.orphan_dir.is_dir():
            return records
        for item in sorted(self.orphan_dir.glob("unidentified-*/QUARANTINE.json")):
            records.append(json.loads(item.read_text(encoding="utf-8")))
        return records


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex[:8]}")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _fsync_tree(root: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                continue
            fd = os.open(full, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        fd = os.open(dirpath, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
