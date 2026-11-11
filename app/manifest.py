"""清单解析与归档成员路径的安全归一化。

所有来自 ZIP 中央目录或清单 JSON 的路径都视为不可信输入。
归一化规则刻意从严：任何需要猜测语义的写法（绝对路径、盘符、
反斜杠、``..`` / ``.`` 段、控制字符、NUL）一律拒绝，而不是
"帮忙修正"，避免不同组件对同一路径产生不同理解。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

# 归档根目录下为清单与分离签名保留的成员名，数据文件不得占用。
RESERVED_NAMES = frozenset({"manifest.json", "manifest.sig"})

_IDENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
_HEX_CHARS = set("0123456789abcdef")
_MAX_IDENT = 128
_MAX_PATH = 4096
_MAX_FILES = 100_000
_MAX_SIZE = 2 * 1024**4  # 单条目声明长度上限 2 TiB，实际还受预算约束


class ManifestError(ValueError):
    """清单结构或路径不满足接收策略。"""


@dataclass(frozen=True)
class FileEntry:
    path: str          # 清单中的原始路径
    normalized: str    # 归一化后的 POSIX 相对路径
    size: int
    sha256: bytes      # 32 字节原始摘要


@dataclass(frozen=True)
class Manifest:
    issuer: str
    package_id: str
    sequence: int
    created: str
    files: tuple[FileEntry, ...]
    raw: bytes
    fingerprint: str  # 对“被签名的原始清单字节”取 SHA-256

    def normalized_paths(self) -> frozenset[str]:
        return frozenset(f.normalized for f in self.files)


def _validate_ident(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_IDENT:
        raise ManifestError(f"{field} 必须是 1..{_MAX_IDENT} 字符的字符串")
    if any(ch not in _IDENT_CHARS for ch in value):
        raise ManifestError(f"{field} 只允许字母、数字、点、下划线与连字符")
    return value


def normalize_member_name(raw: object) -> str:
    """把归档成员名 / 清单路径归一化为安全的相对 POSIX 路径。

    任何越界、歧义或非普通文件语义的写法都抛出 :class:`ManifestError`。
    """
    if not isinstance(raw, str) or not raw:
        raise ManifestError("路径必须是非空字符串")
    if len(raw) > _MAX_PATH:
        raise ManifestError(f"路径长度超过 {_MAX_PATH}")
    if "\x00" in raw:
        raise ManifestError("路径包含 NUL 字节")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise ManifestError("路径包含控制字符")
    if "\\" in raw:
        # 反斜杠在 POSIX 是合法文件名字符、在 Windows 是分隔符，
        # 跨平台语义不一致，直接拒绝。
        raise ManifestError("路径不允许包含反斜杠")
    if ":" in raw:
        # 拒绝 Windows 盘符与备用数据流写法。
        raise ManifestError("路径不允许包含冒号")
    if raw.startswith("/"):
        raise ManifestError("不允许绝对路径")

    # 直接在原始字符串上按 "/" 切分，避免 pathlib 静默折叠
    # 双斜杠与 "." 段（PurePosixPath("a//b").parts 会丢失空段）。
    parts = raw.split("/")
    if not parts:
        raise ManifestError("空路径")
    cleaned: list[str] = []
    for part in parts:
        if part in ("", ".", ".."):
            # 不静默折叠空段 / . 段、不允许任何 .. 段。
            raise ManifestError(f"路径包含非法段: {part!r}")
        cleaned.append(part)
    normalized = "/".join(cleaned)
    if not normalized or normalized.startswith("/") or len(normalized) > _MAX_PATH:
        raise ManifestError("归一化结果非法")
    # 二次确认 pathlib 也视其为无锚点相对路径。
    if PurePosixPath(normalized).is_absolute() or PurePosixPath(normalized).anchor:
        raise ManifestError("不允许绝对路径")
    return normalized


def _coerce_sha256(value: object) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise ManifestError("sha256 必须是 64 位十六进制字符串")
    lowered = value.lower()
    if any(ch not in _HEX_CHARS for ch in lowered):
        raise ManifestError("sha256 含非十六进制字符")
    return bytes.fromhex(lowered)


def parse_manifest(raw: bytes) -> Manifest:
    """解析并完整校验清单字节；签名验证针对同一批原始字节进行。"""
    if not isinstance(raw, (bytes, bytearray)):
        raise ManifestError("清单必须是字节串")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"清单不是合法 UTF-8 JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ManifestError("清单顶层必须是对象")

    issuer = _validate_ident(doc.get("issuer"), "issuer")
    package_id = _validate_ident(doc.get("package_id"), "package_id")

    sequence = doc.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ManifestError("sequence 必须是 >=1 的整数")

    created = doc.get("created")
    if not isinstance(created, str) or not created:
        raise ManifestError("created 必须是非空时间字符串")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestError("created 不是合法 ISO-8601 时间") from exc

    files_raw = doc.get("files")
    if not isinstance(files_raw, list) or not files_raw:
        raise ManifestError("files 必须是非空数组")
    if len(files_raw) > _MAX_FILES:
        raise ManifestError("files 条目数超出上限")

    seen: set[str] = set()
    entries: list[FileEntry] = []
    for index, item in enumerate(files_raw):
        if not isinstance(item, dict):
            raise ManifestError(f"files[{index}] 必须是对象")
        normalized = normalize_member_name(item.get("path"))
        if normalized in RESERVED_NAMES:
            raise ManifestError(f"数据文件不得占用保留名: {normalized}")
        if normalized in seen:
            raise ManifestError(f"清单内归一化路径冲突: {normalized}")
        seen.add(normalized)

        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= _MAX_SIZE:
            raise ManifestError(f"{normalized}: size 必须是 0..{_MAX_SIZE} 的整数")
        digest = _coerce_sha256(item.get("sha256"))
        entries.append(
            FileEntry(path=item["path"], normalized=normalized, size=size, sha256=digest)
        )

    return Manifest(
        issuer=issuer,
        package_id=package_id,
        sequence=sequence,
        created=created,
        files=tuple(entries),
        raw=bytes(raw),
        fingerprint=hashlib.sha256(bytes(raw)).hexdigest(),
    )


def extract_issuer(raw: bytes) -> str:
    """在完整校验前仅取出 issuer，用于选择验签公钥。

    这里容忍 schema 缺陷；验签通过后仍会执行 :func:`parse_manifest`
    的完整校验，因此不会绕过任何接收策略。
    """
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"清单不是合法 UTF-8 JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("issuer"), str):
        raise ManifestError("清单缺少 issuer 字段")
    return doc["issuer"]
