"""分离签名验证（仅依赖标准库）。

运行环境没有第三方加密库，而接收流程必须在解包之前验证清单签名。
这里实现 RFC 8017 的 RSASSA-PKCS1-v1_5 验签（SHA-256）：

* 公钥运算 :func:`pow` 是纯模幂，不涉及私钥材料；
* 仅支持 SPKI（``BEGIN PUBLIC KEY``）与 PKCS#1（``BEGIN RSA PUBLIC KEY``）
  两种公钥封装，内置最小 DER 读取器；
* 私钥永远不会出现在本模块与项目目录中，测试私钥由外部 OpenSSL 生成。

信任库布局::

    <trust_root>/<issuer>/<key_id>.pub

其中 key_id 是 SPKI DER 的 SHA-256 前 16 个十六进制字符。
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

# rsaEncryption: 1.2.840.113549.1.1.1
_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")
# SHA-256 DigestInfo 前缀（RFC 8017 9.2 note 1），后接 32 字节摘要
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_MIN_MODULUS_BITS = 2048
_PEM_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END [A-Z0-9 ]+-----", re.DOTALL
)


class CryptoError(ValueError):
    """签名或公钥不可信 / 格式不支持。"""


# ---------------------------------------------------------------- DER 读取

class _DER:
    def __init__(self, data: bytes, offset: int = 0, end: int | None = None):
        self.data = data
        self.pos = offset
        self.end = len(data) if end is None else end

    def read_tlv(self) -> tuple[int, bytes]:
        if self.pos >= self.end:
            raise CryptoError("DER 意外结束")
        tag = self.data[self.pos]
        self.pos += 1
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4:
                raise CryptoError("DER 长度编码非法")
            length = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n
        start = self.pos
        end = start + length
        if end > self.end:
            raise CryptoError("DER 长度越界")
        self.pos = end
        return tag, self.data[start:end]

    def expect(self, tag: int) -> bytes:
        actual, content = self.read_tlv()
        if actual != tag:
            raise CryptoError(f"DER 期望标签 {tag:#x}，实际 {actual:#x}")
        return content

    def at_end(self) -> bool:
        return self.pos == self.end


def _decode_oid(content: bytes) -> bytes:
    """返回 OID 的内容字节，直接与已知算法 OID 比较，无需转点分字符串。"""
    if not content:
        raise CryptoError("OID 为空")
    return bytes(content)


def _read_rsa_public_key(der: bytes) -> tuple[int, int]:
    outer = _DER(der)
    seq = outer.expect(0x30)
    if not outer.at_end():
        raise CryptoError("公钥结构存在多余尾部字节")
    body = _DER(seq)
    n_bytes = body.expect(0x02)
    e_bytes = body.expect(0x02)
    if not body.at_end():
        raise CryptoError("RSAPublicKey 存在多余字段")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    if n <= 0 or e <= 0:
        raise CryptoError("RSA 参数非正")
    return n, e


def _read_spki(der: bytes) -> tuple[int, int, bytes]:
    outer = _DER(der)
    spki = outer.expect(0x30)
    if not outer.at_end():
        raise CryptoError("SPKI 存在多余尾部字节")
    root = _DER(spki)
    alg = root.expect(0x30)
    alg_reader = _DER(alg)
    oid_content = alg_reader.expect(0x06)
    if _decode_oid(oid_content) != _RSA_ENCRYPTION_OID:
        raise CryptoError("仅支持 rsaEncryption 公钥")
    # 算法参数应为 NULL（可显式出现），其他标签直接拒绝。
    while not alg_reader.at_end():
        tag, _ = alg_reader.read_tlv()
        if tag != 0x05:
            raise CryptoError("rsaEncryption 参数必须为 NULL")
    bit_string = root.expect(0x03)
    if not bit_string or bit_string[0] != 0x00:
        raise CryptoError("SPKI BIT STRING 编码非法")
    inner = bit_string[1:]
    n, e = _read_rsa_public_key(inner)
    return n, e, inner


def _read_public_key(der: bytes) -> tuple[int, int, bytes]:
    """返回 (n, e, spki_der)；PKCS#1 输入会被包装成 SPKI 以便计算 key id。"""
    try:
        return _read_spki(der)
    except CryptoError:
        n, e = _read_rsa_public_key(der)
        spki = _wrap_pkcs1_spki(der)
        return n, e, spki


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(content)) + content


def _wrap_pkcs1_spki(pkcs1_der: bytes) -> bytes:
    alg_id = _der_tlv(
        0x30,
        _der_tlv(0x06, _RSA_ENCRYPTION_OID) + _der_tlv(0x05, b""),
    )
    bit_string = _der_tlv(0x03, b"\x00" + pkcs1_der)
    return _der_tlv(0x30, alg_id + bit_string)


def _unarmor(pem: bytes) -> bytes:
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    match = _PEM_RE.search(pem.decode("ascii", errors="strict"))
    if not match:
        raise CryptoError("未找到 PEM 公钥块")
    label, body = match.groups()
    if label not in ("PUBLIC KEY", "RSA PUBLIC KEY"):
        raise CryptoError(f"不支持的 PEM 类型: {label}")
    try:
        return base64.b64decode("".join(body.split()), validate=True)
    except Exception as exc:  # base64 异常类型较散，统一转换
        raise CryptoError("PEM Base64 解码失败") from exc


# ---------------------------------------------------------------- 验签

def _pkcs1_v15_verify(n: int, e: int, message: bytes, signature: bytes) -> None:
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < _MIN_MODULUS_BITS:
        raise CryptoError(f"RSA 模数短于 {_MIN_MODULUS_BITS} 位，拒绝")
    if len(signature) != k:
        raise CryptoError("签名长度与模数不一致")
    s = int.from_bytes(signature, "big")
    if s >= n:
        raise CryptoError("签名整数越界")
    em = pow(s, e, n).to_bytes(k, "big")

    digest = hashlib.sha256(message).digest()
    expected_t = _SHA256_DIGEST_INFO + digest
    # EM = 0x00 || 0x01 || PS(0xFF, >=8) || 0x00 || T
    if len(em) < len(expected_t) + 11:
        raise CryptoError("EM 长度不足")
    if em[0] != 0x00 or em[1] != 0x01:
        raise CryptoError("EM 头部不是 0x00 0x01")
    sep = 2
    while sep < len(em) and em[sep] == 0xFF:
        sep += 1
    if sep < 10 or sep >= len(em):
        raise CryptoError("填充串长度不足或内容非法")
    if em[sep] != 0x00:
        raise CryptoError("填充分隔符缺失")
    if em[sep + 1:] != expected_t:
        raise CryptoError("签名摘要不匹配（PKCS#1 v1.5 / SHA-256 校验失败）")


@dataclass(frozen=True)
class KeyInfo:
    issuer: str
    key_id: str
    spki_der: bytes


def key_id_for_pem(pem: bytes) -> str:
    der = _unarmor(pem)
    _, _, spki = _read_public_key(der)
    return hashlib.sha256(spki).hexdigest()[:16]


def verify_pem_signature(pem: bytes, message: bytes, signature: bytes) -> None:
    """用单把 PEM 公钥验证分离签名，失败抛 :class:`CryptoError`。"""
    der = _unarmor(pem)
    n, e, _ = _read_public_key(der)
    _pkcs1_v15_verify(n, e, message, signature)


class TrustStore:
    """按 issuer 组织的公钥目录；构造时即完成全部公钥解析。"""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._keys: dict[str, list[KeyInfo]] = {}
        if not self.root.is_dir():
            raise CryptoError(f"信任库目录不存在: {self.root}")
        for issuer_dir in sorted(p for p in self.root.iterdir() if p.is_dir()):
            infos: list[KeyInfo] = []
            for pem_path in sorted(issuer_dir.glob("*.pub")):
                pem = pem_path.read_bytes()
                der = _unarmor(pem)
                _, _, spki = _read_public_key(der)
                infos.append(
                    KeyInfo(
                        issuer=issuer_dir.name,
                        key_id=hashlib.sha256(spki).hexdigest()[:16],
                        spki_der=spki,
                    )
                )
            if infos:
                self._keys[issuer_dir.name] = infos

    def issuers(self) -> list[str]:
        return sorted(self._keys)

    def verify(self, issuer: str, message: bytes, signature: bytes) -> KeyInfo:
        candidates = self._keys.get(issuer)
        if not candidates:
            raise CryptoError(f"信任库中没有 issuer={issuer} 的公钥")
        last_error: Exception | None = None
        for info in candidates:
            n, e, _ = _read_public_key(info.spki_der)
            try:
                _pkcs1_v15_verify(n, e, message, signature)
                return info
            except CryptoError as exc:
                last_error = exc
        raise CryptoError(f"issuer={issuer} 的所有公钥均验签失败: {last_error}")
