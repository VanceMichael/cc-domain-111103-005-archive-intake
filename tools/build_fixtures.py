"""本地样例构建工具（仅开发/测试使用，不参与运行时验收）。

用系统 OpenSSL 生成 RSA-2048 测试密钥并构造：

* 两版合法签名包（同 package_id、不同内容，用于版本与幂等测试）；
* 一整套恶意归档样例（符号链接、路径越界、重复路径、重复保留名、
  截断目录、ZIP64、压缩炸弹、摘要/长度不符、错误签名等）。

安全约束：

* 测试私钥只能写入 ``--key-dir`` 指定的目录，且该目录不得位于项目
  根之内；脚本会显式拒绝，私钥因此不可能进入 git；
* 公钥写入项目下的信任库样例（仅含公开材料）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.crypto import key_id_for_pem

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FixtureError(RuntimeError):
    pass


def _run_openssl(args: list[str]) -> bytes:
    try:
        return subprocess.run(
            ["openssl", *args], check=True, capture_output=True
        ).stdout
    except FileNotFoundError as exc:  # pragma: no cover - 环境依赖
        raise FixtureError("未找到 openssl 可执行文件") from exc
    except subprocess.CalledProcessError as exc:
        raise FixtureError(
            f"openssl 调用失败: {exc.stderr.decode('utf-8', 'replace')}"
        ) from exc


def generate_key(key_dir: Path, name: str) -> tuple[Path, Path, str]:
    """在项目外生成 RSA 私钥与 SPKI 公钥，返回 (私钥, 公钥, key_id)。"""
    key_dir = key_dir.resolve()
    try:
        key_dir.relative_to(PROJECT_ROOT.resolve())
        raise FixtureError(
            f"密钥目录 {key_dir} 位于项目根内，测试私钥禁止写入项目"
        )
    except ValueError:
        pass
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = key_dir / f"{name}.key.pem"
    public_key = key_dir / f"{name}.pub.pem"
    _run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                  "-out", str(private_key)])
    _run_openssl(["pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)])
    os.chmod(private_key, 0o600)
    return private_key, public_key, key_id_for_pem(public_key.read_bytes())


def sign_manifest(private_key: Path, manifest_bytes: bytes) -> bytes:
    """对清单原始字节做 RSA/SHA-256 分离签名（PKCS#1 v1.5）。"""
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=manifest_bytes,
        check=True,
        capture_output=True,
    )
    return proc.stdout


# ------------------------------------------------------------- ZIP 构造

def _zip_info(name: str, symlink_target: str | None = None) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    if symlink_target is not None:
        # unix 符号链接：mode 0120777，内容为目标路径。
        info.external_attr = (0o120777 << 16)
        info.compress_type = zipfile.ZIP_STORED
    else:
        info.external_attr = (0o100644 << 16)
        info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _manifest_bytes(issuer: str, package_id: str, sequence: int,
                    created: str, files: list[dict]) -> bytes:
    doc = {
        "issuer": issuer,
        "package_id": package_id,
        "sequence": sequence,
        "created": created,
        "files": files,
    }
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _file_entry(relative: str, payload: bytes) -> dict:
    return {
        "path": relative,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def build_signed_zip(
    destination: Path,
    private_key: Path,
    issuer: str,
    package_id: str,
    sequence: int,
    created: str,
    data: dict[str, bytes],
) -> bytes:
    files = [_file_entry(name, payload) for name, payload in sorted(data.items())]
    manifest = _manifest_bytes(issuer, package_id, sequence, created, files)
    signature = sign_manifest(private_key, manifest)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_zip_info("manifest.json"), manifest)
        archive.writestr(_zip_info("manifest.sig"), signature)
        for name, payload in sorted(data.items()):
            archive.writestr(_zip_info(name), payload)
    return manifest


@dataclass
class FixtureLayout:
    root: Path
    trust_issuer_dir: Path
    public_key: Path


def _write_zip(path: Path, entries: list[tuple]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            if len(entry) == 2:
                info, payload = entry
                force_zip64 = False
            else:
                info, payload, force_zip64 = entry
            if force_zip64:
                with archive.open(info, "w", force_zip64=True) as stream:
                    stream.write(payload)
            else:
                archive.writestr(info, payload)


def _e(info: zipfile.ZipInfo, payload: bytes, force_zip64: bool = False):
    """构造 (info, payload, force_zip64) 三元组。"""
    return (info, payload, force_zip64)


def build_all_fixtures(output_root: Path, key_dir: Path) -> FixtureLayout:
    output_root = output_root.resolve()
    issuer = "synthetic-lab"
    package_id = "stats-monthly"

    private_key, public_key, key_id = generate_key(key_dir, f"{issuer}-test")
    trust_dir = output_root / "trust" / issuer
    trust_dir.mkdir(parents=True, exist_ok=True)
    trusted_pub = trust_dir / f"{key_id}.pub"
    shutil.copy2(public_key, trusted_pub)

    signed_dir = output_root / "signed"
    malicious_dir = output_root / "malicious"
    signed_dir.mkdir(parents=True, exist_ok=True)
    malicious_dir.mkdir(parents=True, exist_ok=True)

    # ---- 合法包 v1 / v2（同 package_id，内容与指纹不同）----
    v1_data = {
        "observations/data.json": b'{"sample":"fictional","value":3}\n',
        "observations/series.csv": b"month,value\n2026-09,3\n",
    }
    build_signed_zip(
        signed_dir / "stats-v1.zip", private_key, issuer, package_id, 1,
        "2026-10-01T00:00:00+00:00", v1_data,
    )
    v2_data = {
        "observations/data.json": b'{"sample":"fictional","value":4}\n',
        "observations/series.csv": b"month,value\n2026-10,4\n",
        "observations/extra.json": b'{"note":"new file"}\n',
    }
    build_signed_zip(
        signed_dir / "stats-v2.zip", private_key, issuer, package_id, 2,
        "2026-11-01T00:00:00+00:00", v2_data,
    )
    # 与 v1 字节完全一致的重复交付包，用于幂等测试。
    shutil.copy2(signed_dir / "stats-v1.zip", signed_dir / "stats-v1-redelivery.zip")

    # ---- 恶意 / 异常样例 ----
    manifest_v1 = _manifest_bytes(
        issuer, package_id, 1, "2026-10-01T00:00:00+00:00",
        [_file_entry(name, payload) for name, payload in sorted(v1_data.items())],
    )
    good_sig = sign_manifest(private_key, manifest_v1)

    # 1. 符号链接成员
    _write_zip(malicious_dir / "symlink.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
        (_zip_info("observations/link", symlink_target="../../etc/passwd"),
         b"../../etc/passwd"),
    ])

    # 2. 路径越界（..）
    evil_manifest = _manifest_bytes(
        issuer, package_id, 9, "2026-10-01T00:00:00+00:00",
        [_file_entry("../outside.txt", b"x")],
    )
    _write_zip(malicious_dir / "path-traversal.zip", [
         _e(_zip_info("manifest.json"), evil_manifest),
         _e(_zip_info("manifest.sig"), sign_manifest(private_key, evil_manifest)),
         _e(_zip_info("../outside.txt"), b"x"),
    ])

    # 3. 重复 central-directory 名称（同名两个成员，磁盘顺序覆盖的根因）
    _write_zip(malicious_dir / "duplicate-path.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("observations/data.json"), b'{"sample":"fictional","value":3}\n'),
         _e(_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
        (_zip_info("observations/data.json"), b'{"sample":"TAMPERED"}\n'),
    ])

    # 4. 重复保留名 manifest.json
    _write_zip(malicious_dir / "duplicate-manifest.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 5. 清单与成员双射破坏：归档多出未声明成员
    _write_zip(malicious_dir / "undeclared-member.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
        (_zip_info("observations/secret.txt"), b"undeclared"),
    ])

    # 6. 清单与成员双射破坏：清单声明的成员缺失
    missing_manifest = _manifest_bytes(
        issuer, package_id, 1, "2026-10-01T00:00:00+00:00",
        [_file_entry("observations/data.json", v1_data["observations/data.json"]),
         _file_entry("observations/series.csv", v1_data["observations/series.csv"]),
         _file_entry("observations/missing.bin", b"abc")],
    )
    _write_zip(malicious_dir / "missing-member.zip", [
         _e(_zip_info("manifest.json"), missing_manifest),
         _e(_zip_info("manifest.sig"), sign_manifest(private_key, missing_manifest)),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 7. 摘要不匹配（清单签名有效但成员内容被换）
    _write_zip(malicious_dir / "digest-mismatch.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("observations/data.json"), b'{"sample":"TAMPERED"}\n'),
         _e(_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 8. 长度不匹配（清单 size 故意写错，签名覆盖该错误清单）
    wrong_size = _manifest_bytes(
        issuer, package_id, 1, "2026-10-01T00:00:00+00:00",
        [{"path": "observations/data.json",
          "size": len(v1_data["observations/data.json"]) + 9,
          "sha256": hashlib.sha256(v1_data["observations/data.json"]).hexdigest()},
         _file_entry("observations/series.csv", v1_data["observations/series.csv"])],
    )
    _write_zip(malicious_dir / "size-mismatch.zip", [
         _e(_zip_info("manifest.json"), wrong_size),
         _e(_zip_info("manifest.sig"), sign_manifest(private_key, wrong_size)),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 9. 签名错误（清单被改但签名未更新）
    tampered_manifest = manifest_v1.replace(b'"sequence":1', b'"sequence":77')
    _write_zip(malicious_dir / "bad-signature.zip", [
         _e(_zip_info("manifest.json"), tampered_manifest),
         _e(_zip_info("manifest.sig"), good_sig),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 10. 缺少签名成员
    _write_zip(malicious_dir / "missing-signature.zip", [
         _e(_zip_info("manifest.json"), manifest_v1),
         _e(_zip_info("observations/data.json"), v1_data["observations/data.json"]),
        (_zip_info("observations/series.csv"), v1_data["observations/series.csv"]),
    ])

    # 11. 截断的中央目录（合法包末尾被截掉一段）
    good_path = signed_dir / "stats-v1.zip"
    raw = good_path.read_bytes()
    (malicious_dir / "truncated-central-directory.zip").write_bytes(raw[: len(raw) // 2])

    # 12. ZIP64 合法包：成员解压尺寸超过 0xFFFFFFFF（4 GiB-1），
    # 中央目录因此必须使用真实 ZIP64 额外字段。零数据高压缩，磁盘占用极小。
    big_size = 0x100000000 + 1024  # 4 GiB + 1 KiB，稳定越过 ZIP64 阈值
    block = b"\x00" * (1024 * 1024)
    big_hasher = hashlib.sha256()
    for _ in range(big_size // len(block)):
        big_hasher.update(block)
    if big_size % len(block):
        big_hasher.update(b"\x00" * (big_size % len(block)))
    big_manifest = _manifest_bytes(
        issuer, package_id, 1, "2026-10-01T00:00:00+00:00",
        [{"path": "observations/zeros.bin", "size": big_size,
          "sha256": big_hasher.hexdigest()}],
    )
    zip64_path = signed_dir / "stats-v1-zip64.zip"
    with zipfile.ZipFile(zip64_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(_zip_info("manifest.json"), big_manifest)
        archive.writestr(_zip_info("manifest.sig"),
                         sign_manifest(private_key, big_manifest))
        info = _zip_info("observations/zeros.bin")
        with archive.open(info, "w", force_zip64=True) as stream:
            for _ in range(big_size // len(block)):
                stream.write(block)
            remainder = big_size % len(block)
            if remainder:
                stream.write(b"\x00" * remainder)

    # 13. 压缩比炸弹（高压缩比零数据，默认预算应拒绝）
    bomb_payload = b"\x00" * (2 * 1024 * 1024)
    bomb_manifest = _manifest_bytes(
        issuer, package_id, 1, "2026-10-01T00:00:00+00:00",
        [_file_entry("observations/bomb.bin", bomb_payload)],
    )
    _write_zip(malicious_dir / "compression-bomb.zip", [
         _e(_zip_info("manifest.json"), bomb_manifest),
         _e(_zip_info("manifest.sig"), sign_manifest(private_key, bomb_manifest)),
         _e(_zip_info("observations/bomb.bin"), bomb_payload),
    ])

    return FixtureLayout(
        root=output_root, trust_issuer_dir=trust_dir, public_key=trusted_pub
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="构造本地签名与恶意归档样例")
    parser.add_argument("--out", required=True, type=Path,
                        help="样例输出目录（可在项目内，仅写入公开材料）")
    parser.add_argument("--key-dir", required=True, type=Path,
                        help="测试私钥目录，必须位于项目根之外")
    args = parser.parse_args(argv)

    if args.out.exists():
        shutil.rmtree(args.out)
    layout = build_all_fixtures(args.out, args.key_dir)
    print(f"fixtures : {layout.root}")
    print(f"trust key: {layout.public_key}")
    print(f"key dir  : {args.key_dir.resolve()} (private key kept outside project)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
