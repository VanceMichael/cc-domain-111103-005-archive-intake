"""命令行入口：receive / inspect / audit。

设计为可通过 ``python -I bin/intake ...`` 运行：``-I`` 隔离模式下
cwd 不进入 ``sys.path``，由 bin/intake 启动器显式注入项目根，
不可信归档目录中的同名模块（如 json.py）无法污染解析过程。
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .audit import audit_package, audit_store, audit_to_dict
from .crypto import TrustStore
from .intake import Receiver
from .store import PackageStore
from .zipstream import Budget, ZipScanError, scan_zip


def _build_budget(args: argparse.Namespace) -> Budget:
    return Budget(
        max_members=args.max_members,
        max_total_uncompressed=args.max_total_uncompressed,
        max_total_compressed=args.max_total_compressed,
        max_member_uncompressed=args.max_member_uncompressed,
        max_compression_ratio=args.max_compression_ratio,
    )


def cmd_receive(args: argparse.Namespace) -> int:
    store = PackageStore(args.store)
    trust = TrustStore(args.trust)
    receiver = Receiver(store, trust, budget=_build_budget(args))
    result = receiver.receive(args.archive)
    payload = {
        "status": result.status,
        "package_id": result.package_id,
        "attempt_id": result.attempt_id,
        "issuer": result.issuer,
        "key_id": result.key_id,
        "manifest_fingerprint": result.manifest_fingerprint,
        "reasons": list(result.reasons),
        "quarantine_path": str(result.quarantine_path) if result.quarantine_path else None,
        "receipt_path": str(result.receipt_path) if result.receipt_path else None,
        "current_version": result.version.version if result.version else None,
        "files": [asdict(fr) for fr in result.file_results],
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result.status in ("accepted", "accepted-duplicate") else 2


def cmd_inspect(args: argparse.Namespace) -> int:
    """只做中央目录静态检查，不落盘，供验收员预判。"""
    try:
        scan = scan_zip(args.archive, _build_budget(args))
    except ZipScanError as exc:
        json.dump(
            {"archive": str(args.archive), "fatal": {"code": exc.code, "detail": exc.detail}},
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        sys.stdout.write("\n")
        return 2
    payload = {
        "archive": str(args.archive),
        "used_zip64": scan.used_zip64,
        "member_count": len(scan.members),
        "total_uncompressed": scan.total_uncompressed,
        "total_compressed": scan.total_compressed,
        "members": [
            {
                "index": m.index,
                "name": m.raw_name,
                "normalized": m.normalized,
                "file_size": m.file_size,
                "compress_size": m.compress_size,
                "is_dir": m.is_dir,
                "is_symlink": m.is_symlink,
                "is_encrypted": m.is_encrypted,
                "zip64": m.zip64,
            }
            for m in scan.members
        ],
        "hazards": [
            {"code": h.code, "detail": h.detail, "member": h.member} for h in scan.hazards
        ],
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    store = PackageStore(args.store)
    if args.package_id:
        report = {
            "packages": [audit_to_dict(audit_package(store, args.package_id))],
            "unidentified_quarantine": [],
        }
    else:
        report = audit_store(store)
    json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intake",
        description="供应商统计资料包的安全解封、验签与原子接收",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_budget(p: argparse.ArgumentParser) -> None:
        p.add_argument("--max-members", type=int, default=Budget.max_members)
        p.add_argument(
            "--max-total-uncompressed", type=int, default=Budget.max_total_uncompressed
        )
        p.add_argument(
            "--max-total-compressed", type=int, default=Budget.max_total_compressed
        )
        p.add_argument(
            "--max-member-uncompressed", type=int, default=Budget.max_member_uncompressed
        )
        p.add_argument(
            "--max-compression-ratio", type=int, default=Budget.max_compression_ratio
        )

    p_recv = sub.add_parser("receive", help="验收并接收一个归档包")
    p_recv.add_argument("--archive", required=True, type=Path)
    p_recv.add_argument("--store", required=True, type=Path)
    p_recv.add_argument("--trust", required=True, type=Path)
    add_budget(p_recv)
    p_recv.set_defaults(func=cmd_receive)

    p_insp = sub.add_parser("inspect", help="只读中央目录做静态检查，不写盘")
    p_insp.add_argument("archive", type=Path)
    add_budget(p_insp)
    p_insp.set_defaults(func=cmd_inspect)

    p_aud = sub.add_parser("audit", help="查看签名身份、逐文件摘要、隔离原因与当前版本")
    p_aud.add_argument("--store", required=True, type=Path)
    p_aud.add_argument("--package-id", default=None)
    p_aud.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # 顶层兜底：异常绝不等于“验收通过”
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
