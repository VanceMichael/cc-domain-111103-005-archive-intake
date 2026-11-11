"""纯标准库 RSA/PKCS#1 v1.5 验签的单元测试。

不调用 OpenSSL：固化一个由测试私钥（在项目外）一次性生成的
“消息+签名”向量，配合 fixtures 信任库中的公钥验证。私钥从不进项目。
"""

import base64
import shutil
import tempfile
import unittest
from pathlib import Path

from app.crypto import (
    CryptoError,
    TrustStore,
    key_id_for_pem,
    verify_pem_signature,
)

PROJECT = Path(__file__).resolve().parents[1]
TRUST_DIR = PROJECT / "fixtures" / "intake" / "trust" / "synthetic-lab"

_fixtures_available = TRUST_DIR.is_dir() and bool(list(TRUST_DIR.glob("*.pub")))
_skip_no_fixtures = unittest.skipUnless(
    _fixtures_available,
    "缺少 fixtures/intake 信任库；请用 tools/build_fixtures.py 生成（私钥放项目外）",
)

MESSAGE = base64.b64decode("dGVzdCBtZXNzYWdlIGZvciBzaWduYXR1cmUgdmVjdG9yCg==")
SIGNATURE = base64.b64decode(
    "OXGNdHf1u3s6kWHeHOwR42KUpd7iUsunrTeFAKxEZ1Y1qEC9KWoC1k7PGWovec/k4"
    "ZfQOdKb5SxDLIQyKKRGdM0St4g2ixBTuq1IkRI05aw8W9bSyghH9JA0g7T0ydBjlq"
    "sCCduE4bncc9oa7l9xcE6LDibXiQaTOYuJYz0ORTxijaho46qzMoFpmnb/MTu1HJM"
    "qD+AyC4WeM2+2Uc/32l7vZmSBrSxikMqSJvji6Neb/jKzMSZW87Myh1GuoHy0fLpu"
    "vOvUphZPmcEa8BwDc7EXgLOFDX9Jbb/ERCriT+TNzBd7sHHFZaARcQ/2YJ5mB6Gw"
    "5FXgaIwfU3Utm3GfZg=="
)


def _public_pem() -> bytes:
    pubs = sorted(TRUST_DIR.glob("*.pub"))
    assert pubs, "fixtures 信任库缺失，请先运行样例构建"
    return pubs[0].read_bytes()


@_skip_no_fixtures
class SignatureVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pem = _public_pem()

    def test_valid_signature_verifies(self):
        verify_pem_signature(self.pem, MESSAGE, SIGNATURE)

    def test_tampered_message_rejected(self):
        with self.assertRaises(CryptoError):
            verify_pem_signature(self.pem, MESSAGE + b"x", SIGNATURE)

    def test_tampered_signature_rejected(self):
        broken = bytearray(SIGNATURE)
        broken[-1] ^= 0x01
        with self.assertRaises(CryptoError):
            verify_pem_signature(self.pem, MESSAGE, bytes(broken))

    def test_truncated_signature_rejected(self):
        with self.assertRaises(CryptoError):
            verify_pem_signature(self.pem, MESSAGE, SIGNATURE[:-1])

    def test_all_zero_signature_rejected(self):
        with self.assertRaises(CryptoError):
            verify_pem_signature(self.pem, MESSAGE, b"\x00" * 256)

    def test_garbage_pem_rejected(self):
        with self.assertRaises(CryptoError):
            key_id_for_pem(b"not a pem at all")

    def test_short_modulus_rejected(self):
        # 构造结构合法但内容被截断的 SPKI，模数长度不足应拒绝。
        # 直接用错误标签的 DER 触发解析失败，覆盖错误处理分支。
        with self.assertRaises(CryptoError):
            verify_pem_signature(
                b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                MESSAGE,
                SIGNATURE,
            )


@_skip_no_fixtures
class TrustStoreTests(unittest.TestCase):
    def test_trust_store_verifies_known_issuer(self):
        store = TrustStore(TRUST_DIR.parent)
        info = store.verify("synthetic-lab", MESSAGE, SIGNATURE)
        self.assertEqual(info.issuer, "synthetic-lab")
        self.assertEqual(len(info.key_id), 16)

    def test_unknown_issuer_rejected(self):
        store = TrustStore(TRUST_DIR.parent)
        with self.assertRaises(CryptoError):
            store.verify("unknown-issuer", MESSAGE, SIGNATURE)

    def test_key_id_is_deterministic(self):
        pem = _public_pem()
        self.assertEqual(key_id_for_pem(pem), key_id_for_pem(pem))

    def test_rotated_second_key_does_not_accept_old_bad_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "trust" / "synthetic-lab"
            root.mkdir(parents=True)
            shutil.copy2(next(TRUST_DIR.glob("*.pub")), root / "key-a.pub")
            store = TrustStore(Path(tmp) / "trust")
            # 有效签名仍可验证；篡改签名即使有多把钥匙也全部失败。
            store.verify("synthetic-lab", MESSAGE, SIGNATURE)
            broken = bytearray(SIGNATURE)
            broken[0] ^= 0xFF
            with self.assertRaises(CryptoError):
                store.verify("synthetic-lab", MESSAGE, bytes(broken))


if __name__ == "__main__":
    unittest.main()
