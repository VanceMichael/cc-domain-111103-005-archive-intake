"""不可信 ZIP 的流式检查与解包。

设计原则是 *先看中央目录、再决定是否读数据*：

1. :func:`scan_zip` 只读中央目录（不解压任何数据），在预算内
   枚举成员并标注全部危险特征——重复路径、符号链接、目录条目、
   加密条目、ZIP64、压缩比异常、截断目录；
2. :func:`stream_member` 对通过结构检查的成员逐块解压、逐块计数
   与计算摘要，超预算立即中断，从不把整个成员读进内存，也不先
   完整展开再检查；
3. 调用方负责把数据写入暂存文件，本模块不直接触碰目标目录。
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import RESERVED_NAMES, ManifestError, normalize_member_name

# unix mode（external_attr 高 16 位）中的文件类型位。
_S_IFMT = 0o170000
_S_IFLNK = 0o120000
_S_IFDIR = 0o040000
_S_IFREG = 0o100000

# 常规数据描述符 / UTF-8 名称等标志位之外，任何位被设置都值得警惕。
_KNOWN_FLAG_BITS = 0x0001 | 0x0008 | 0x0800  # encrypted 单独检查


@dataclass(frozen=True)
class Budget:
    max_members: int = 200_000          # 中央目录条目总数上限
    max_total_uncompressed: int = 8 * 1024**3   # 全包解压后总字节
    max_total_compressed: int = 2 * 1024**3     # 全包压缩字节
    max_member_uncompressed: int = 4 * 1024**3  # 单成员解压字节
    max_compression_ratio: int = 100    # 声明 size / 压缩 size 上限
    max_name_length: int = 4096
    chunk_size: int = 1024 * 1024       # 1 MiB 流式块


@dataclass(frozen=True)
class Hazard:
    code: str
    detail: str
    member: str | None = None


@dataclass(frozen=True)
class MemberInfo:
    index: int
    raw_name: str
    normalized: str | None     # 归一化失败时为 None，同时记录 hazard
    file_size: int
    compress_size: int
    is_dir: bool
    is_symlink: bool
    is_encrypted: bool
    zip64: bool
    unix_mode: int | None
    is_reserved: bool


@dataclass(frozen=True)
class ScanResult:
    members: tuple[MemberInfo, ...]
    hazards: tuple[Hazard, ...]
    manifest: MemberInfo | None
    signature: MemberInfo | None
    total_uncompressed: int
    total_compressed: int
    used_zip64: bool


@dataclass
class StreamOutcome:
    bytes_written: int
    sha256: str
    truncated: bool = False
    error: str | None = None


class ZipScanError(Exception):
    """中央目录本身无法解析（截断 / 非 ZIP），无法继续任何验收。"""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _mode_of(info: zipfile.ZipInfo) -> int | None:
    # external_attr 高 16 位是 unix 属性。仅当存在文件类型位
    # （S_IFMT 非零）时才视为携带 unix 语义；像 0o600 这类只有
    # 权限位、类型位为 0 的值不能被当成“非常规文件”。
    unix_attr = (info.external_attr >> 16) & 0xFFFF
    if unix_attr & _S_IFMT:
        return unix_attr
    return None


def _is_zip64(info: zipfile.ZipInfo) -> bool:
    # Python 在解析 ZIP64 额外字段后把哨兵值替换为真实值；
    # 再结合额外字段头 0x0001 双重确认。
    if info.file_size == 0xFFFFFFFF or info.compress_size == 0xFFFFFFFF:
        return True
    extra = info.extra
    i = 0
    while i + 4 <= len(extra):
        header = int.from_bytes(extra[i:i + 2], "little")
        size = int.from_bytes(extra[i + 2:i + 4], "little")
        if header == 0x0001:
            return True
        i += 4 + size
    return False


def scan_zip(path: str | Path, budget: Budget | None = None) -> ScanResult:
    """只读取中央目录并完成全部静态检查，不写入任何数据文件。"""
    budget = budget or Budget()
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ZipScanError("BAD_ZIP", f"不是合法 ZIP 或目录被截断: {exc}") from exc
    except OSError as exc:
        raise ZipScanError("ZIP_IO_ERROR", f"归档不可读: {exc}") from exc

    hazards: list[Hazard] = []
    members: list[MemberInfo] = []
    seen_normalized: dict[str, int] = {}
    total_uncompressed = 0
    total_compressed = 0
    used_zip64 = False
    manifest_member: MemberInfo | None = None
    signature_member: MemberInfo | None = None

    with archive:
        infolist = archive.infolist()
        if not infolist:
            raise ZipScanError("EMPTY_ARCHIVE", "归档没有任何中央目录条目")
        if len(infolist) > budget.max_members:
            raise ZipScanError(
                "TOO_MANY_MEMBERS",
                f"成员数 {len(infolist)} 超过预算 {budget.max_members}",
            )

        for index, info in enumerate(infolist):
            raw_name = info.filename
            unix_mode = _mode_of(info)
            mode_type = (unix_mode & _S_IFMT) if unix_mode is not None else None
            is_symlink = mode_type == _S_IFLNK
            is_dir = info.is_dir() or mode_type == _S_IFDIR
            is_encrypted = bool(info.flag_bits & 0x0001)
            zip64 = _is_zip64(info)
            used_zip64 = used_zip64 or zip64

            normalized: str | None = None
            try:
                normalized = normalize_member_name(raw_name)
            except ManifestError as exc:
                hazards.append(Hazard("UNSAFE_PATH", str(exc), raw_name))

            if len(raw_name) > budget.max_name_length:
                hazards.append(
                    Hazard("NAME_TOO_LONG", f"成员名长度 {len(raw_name)}", raw_name)
                )

            if is_symlink:
                hazards.append(Hazard("SYMLINK_MEMBER", "成员是符号链接", raw_name))
            if is_encrypted:
                hazards.append(Hazard("ENCRYPTED_MEMBER", "成员被加密", raw_name))
            if zip64:
                # ZIP64 是合法编码，本身不构成拒收理由；仅在 ScanResult
                # 层面保留 used_zip64 标记供审计，预算约束另行强制执行。
                pass
            if mode_type is not None and mode_type not in (_S_IFREG, _S_IFDIR, _S_IFLNK):
                hazards.append(
                    Hazard("SPECIAL_FILE", f"非常规文件类型 {oct(mode_type)}", raw_name)
                )
            unknown_flags = info.flag_bits & ~(_KNOWN_FLAG_BITS | 0x0001 | 0x0008 | 0x0800)
            if unknown_flags:
                hazards.append(
                    Hazard("UNKNOWN_FLAGS", f"未知标志位 {hex(unknown_flags)}", raw_name)
                )

            member = MemberInfo(
                index=index,
                raw_name=raw_name,
                normalized=normalized,
                file_size=info.file_size,
                compress_size=info.compress_size,
                is_dir=is_dir,
                is_symlink=is_symlink,
                is_encrypted=is_encrypted,
                zip64=zip64,
                unix_mode=unix_mode,
                is_reserved=normalized in RESERVED_NAMES if normalized else False,
            )
            members.append(member)

            # 预算统计在归一化之外独立进行，坏路径也要计入总量。
            total_uncompressed += info.file_size
            total_compressed += info.compress_size
            if total_uncompressed > budget.max_total_uncompressed:
                raise ZipScanError(
                    "TOTAL_UNCOMPRESSED_EXCEEDED",
                    f"累计解压字节超过预算 {budget.max_total_uncompressed}",
                )
            if total_compressed > budget.max_total_compressed:
                raise ZipScanError(
                    "TOTAL_COMPRESSED_EXCEEDED",
                    f"累计压缩字节超过预算 {budget.max_total_compressed}",
                )
            if info.file_size > budget.max_member_uncompressed:
                hazards.append(
                    Hazard(
                        "MEMBER_TOO_LARGE",
                        f"声明 {info.file_size} 字节，超过单成员预算",
                        raw_name,
                    )
                )

            # 压缩比：压缩尺寸加 1 避免除零；目录与空文件跳过。
            if not is_dir and info.file_size > 0:
                ratio = info.file_size // (info.compress_size + 1)
                if ratio > budget.max_compression_ratio:
                    hazards.append(
                        Hazard(
                            "COMPRESSION_BOMB",
                            f"压缩比约 {ratio}:1，超过预算 {budget.max_compression_ratio}:1",
                            raw_name,
                        )
                    )

            if normalized is not None:
                count = seen_normalized.get(normalized, 0)
                if count:
                    hazards.append(
                        Hazard(
                            "DUPLICATE_PATH",
                            f"归一化路径 {normalized} 在中央目录出现 {count + 1} 次",
                            raw_name,
                        )
                    )
                seen_normalized[normalized] = count + 1

                if normalized == "manifest.json":
                    if is_dir or is_symlink:
                        hazards.append(
                            Hazard("RESERVED_NOT_REGULAR", "manifest.json 不是普通文件", raw_name)
                        )
                    elif manifest_member is not None:
                        hazards.append(
                            Hazard("DUPLICATE_RESERVED", "manifest.json 出现多次", raw_name)
                        )
                    else:
                        manifest_member = member
                elif normalized == "manifest.sig":
                    if is_dir or is_symlink:
                        hazards.append(
                            Hazard("RESERVED_NOT_REGULAR", "manifest.sig 不是普通文件", raw_name)
                        )
                    elif signature_member is not None:
                        hazards.append(
                            Hazard("DUPLICATE_RESERVED", "manifest.sig 出现多次", raw_name)
                        )
                    else:
                        signature_member = member

    if manifest_member is None:
        hazards.append(Hazard("MISSING_MANIFEST", "归档中找不到 manifest.json"))
    if signature_member is None:
        hazards.append(Hazard("MISSING_SIGNATURE", "归档中找不到 manifest.sig"))

    return ScanResult(
        members=tuple(members),
        hazards=tuple(hazards),
        manifest=manifest_member,
        signature=signature_member,
        total_uncompressed=total_uncompressed,
        total_compressed=total_compressed,
        used_zip64=used_zip64,
    )


def read_reserved_member(path: str | Path, member: MemberInfo, max_bytes: int) -> bytes:
    """读取 manifest / 签名这类小的保留成员，带独立字节上限。"""
    if member.file_size > max_bytes:
        raise ZipScanError(
            "RESERVED_TOO_LARGE", f"{member.raw_name} 超过 {max_bytes} 字节"
        )
    with zipfile.ZipFile(path) as archive:
        with archive.open(member.raw_name) as stream:
            data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ZipScanError(
            "RESERVED_TOO_LARGE", f"{member.raw_name} 实际字节超过 {max_bytes}"
        )
    return data


def stream_member(
    path: str | Path,
    member: MemberInfo,
    sink,
    budget: Budget | None = None,
) -> StreamOutcome:
    """逐块解压一个成员，边读边写 sink（文件对象）并计算 SHA-256。

    实际解压字节若超过单成员预算、与中央目录声明不符，或数据流被
    截断，都会在 :class:`StreamOutcome` 中如实标注，由调用方决定隔离。
    """
    budget = budget or Budget()
    hasher = hashlib.sha256()
    written = 0
    truncated = False
    error: str | None = None
    try:
        with zipfile.ZipFile(path) as archive:
            with archive.open(member.raw_name) as stream:
                while True:
                    chunk = stream.read(budget.chunk_size)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > budget.max_member_uncompressed:
                        raise ZipScanError(
                            "MEMBER_UNCOMPRESSED_EXCEEDED",
                            f"{member.raw_name} 解压超过单成员预算",
                        )
                    if written > member.file_size:
                        raise ZipScanError(
                            "SIZE_MISMATCH",
                            f"{member.raw_name} 实际字节超过中央目录声明 "
                            f"{member.file_size}",
                        )
                    hasher.update(chunk)
                    sink.write(chunk)
    except (zipfile.BadZipFile, EOFError, OSError, ZipScanError) as exc:
        code = getattr(exc, "code", "TRUNCATED_STREAM")
        truncated = code in ("TRUNCATED_STREAM", "BAD_ZIP")
        error = f"{code}: {exc}"

    if error is None and written != member.file_size:
        truncated = True
        error = (
            f"TRUNCATED_STREAM: {member.raw_name} 声明 {member.file_size} 字节，"
            f"实际仅解压 {written} 字节"
        )

    return StreamOutcome(
        bytes_written=written,
        sha256=hasher.hexdigest(),
        truncated=truncated,
        error=error,
    )
