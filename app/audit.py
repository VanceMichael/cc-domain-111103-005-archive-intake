"""验收员审计视图：签名身份、逐文件摘要、隔离原因与当前发布版本。"""

from __future__ import annotations

from dataclasses import dataclass

from .store import PackageStore


@dataclass(frozen=True)
class PackageAudit:
    package_id: str
    current: dict | None
    attempts: tuple[dict, ...]


def audit_package(store: PackageStore, package_id: str) -> PackageAudit:
    current = store.current_version(package_id)
    attempts = tuple(store.list_attempts(package_id))
    return PackageAudit(
        package_id=package_id,
        current=current.receipt if current else None,
        attempts=attempts,
    )


def audit_store(store: PackageStore) -> dict:
    """全店审计：所有已识别包，外加无法归属的兜底隔离尝试。"""
    report = {"packages": [], "unidentified_quarantine": []}
    for package_id in store.list_packages():
        report["packages"].append(audit_to_dict(audit_package(store, package_id)))
    for record in store.list_unidentified_quarantine():
        report["unidentified_quarantine"].append({
            "attempt_id": record.get("attempt_id"),
            "at": record.get("at"),
            "status": record.get("status"),
            "issuer": record.get("issuer"),
            "reasons": record.get("reasons", []),
        })
    return report


def audit_to_dict(audit: PackageAudit) -> dict:
    current_info = None
    if audit.current:
        current_info = {
            "version": audit.current.get("sequence_version"),
            "issuer": audit.current.get("issuer"),
            "key_id": audit.current.get("key_id"),
            "manifest_fingerprint": audit.current.get("manifest_fingerprint"),
            "at": audit.current.get("at"),
            "files": audit.current.get("files", []),
        }

    attempt_views = []
    for attempt in audit.attempts:
        view = {
            "attempt_id": attempt.get("attempt_id"),
            "at": attempt.get("at"),
            "status": attempt.get("status"),
            "issuer": attempt.get("issuer"),
            "key_id": attempt.get("key_id"),
            "manifest_fingerprint": attempt.get("manifest_fingerprint"),
        }
        if attempt.get("status") == "quarantined":
            view["reasons"] = attempt.get("reasons", [])
            view["files"] = attempt.get("files", [])
        else:
            view["files"] = attempt.get("files", [])
        attempt_views.append(view)

    return {
        "package_id": audit.package_id,
        "current_version": current_info,
        "attempts": attempt_views,
    }
