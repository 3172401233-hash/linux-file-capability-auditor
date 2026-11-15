"""人工构造的版本化 capability 二进制解析测试（不依赖真实 xattr）。"""

import struct
import unittest

from capaudit.capabilities import CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN
from capaudit.xattr import (
    CapXattrError,
    build_cap_xattr,
    parse_cap_xattr,
)


class ParseVersionedBlobsTest(unittest.TestCase):
    def test_v1_roundtrip_low_caps(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        blob = build_cap_xattr(permitted=mask, inheritable=mask, version=1)
        self.assertEqual(len(blob), 4 + 12)
        parsed = parse_cap_xattr(blob)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual(parsed["permitted"], mask)
        self.assertEqual(parsed["inheritable"], mask)
        self.assertFalse(parsed["effective"])
        self.assertEqual(parsed["rootid"], 0)

    def test_v2_roundtrip_high_caps(self):
        # CAP_SYS_ADMIN(21) 与 CAP_BPF(39) 跨 lo/hi 两个 u32
        mask = (1 << CAP_SYS_ADMIN) | (1 << 39)
        blob = build_cap_xattr(permitted=mask, effective=True, version=2)
        self.assertEqual(len(blob), 4 + 24)
        parsed = parse_cap_xattr(blob)
        self.assertEqual(parsed["version"], 2)
        self.assertEqual(parsed["permitted"], mask)
        self.assertTrue(parsed["effective"])

    def test_v3_roundtrip_with_rootid(self):
        blob = build_cap_xattr(
            permitted=1 << CAP_NET_BIND_SERVICE,
            effective=True,
            version=3,
            rootid=100000,
        )
        self.assertEqual(len(blob), 4 + 24 + 4)
        parsed = parse_cap_xattr(blob)
        self.assertEqual(parsed["version"], 3)
        self.assertEqual(parsed["rootid"], 100000)
        self.assertTrue(parsed["effective"])

    def test_handcrafted_bytes_match_kernel_layout(self):
        # 手工按 vfs_ns_cap_data 布局拼字节，验证解析器不依赖构造器
        magic = 0x03000000 | 0x000001  # v3 + effective
        blob = struct.pack(
            "<IIIIIIII",
            magic,
            0,
            0x00000400,  # lo permitted = CAP_NET_BIND_SERVICE
            0,
            0,
            0x00000004,  # hi permitted bit2 = CAP_SYSLOG(34)
            0,
            0,  # rootid = 0
        )
        parsed = parse_cap_xattr(blob)
        self.assertEqual(parsed["permitted"], (1 << CAP_NET_BIND_SERVICE) | (1 << 34))
        self.assertTrue(parsed["effective"])

    def test_rejects_unknown_version(self):
        blob = struct.pack("<I", 0x07000000) + b"\x00" * 24
        with self.assertRaises(CapXattrError):
            parse_cap_xattr(blob)

    def test_rejects_truncated_blob(self):
        blob = build_cap_xattr(version=3)[:-2]
        with self.assertRaises(CapXattrError):
            parse_cap_xattr(blob)

    def test_rejects_empty_blob(self):
        with self.assertRaises(CapXattrError):
            parse_cap_xattr(b"")


if __name__ == "__main__":
    unittest.main()
