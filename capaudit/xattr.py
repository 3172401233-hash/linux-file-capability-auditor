"""security.capability xattr 二进制结构（vfs_cap_data）的解析与构造。

本模块只操作字节串，不读取真实文件系统的扩展属性，
因此可以在任何平台（包括 Windows）上解析人工构造的样本。

内核结构（include/uapi/linux/capability.h）::

    struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
    };

    struct vfs_cap_data {          // v1: 1 组 data，v2/v3: 2 组（lo/hi）
        __le32 magic_etc;
        struct __user_cap_data_struct data[...];
    };

    struct vfs_ns_cap_data {       // v3 在末尾追加 rootid
        struct vfs_cap_data data;
        kuid_t rootid;             // __le32
    };

magic_etc 低 8 位为版本号（1/2/3），bit 0 之后的 VFS_CAP_FLAGS_EFFECTIVE
(0x000001) 表示文件 effective 位。
"""

import struct

VFS_CAP_REVISION_1 = 0x01000000
VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_REVISION_3 = 0x03000000
VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_FLAGS_EFFECTIVE = 0x000001
VFS_CAP_FLAGS_MASK = 0x0000FFFF

_U32 = 4


class CapXattrError(ValueError):
    """capability xattr 数据非法时抛出。"""


def parse_cap_xattr(blob):
    """解析 vfs_cap_data / vfs_ns_cap_data 二进制。

    返回 dict，包含:
      - ``version``: 1、2 或 3
      - ``effective``: bool，文件 effective 位
      - ``permitted`` / ``inheritable``: int 位掩码（合并 lo/hi 两个 u32）
      - ``rootid``: v3 的 rootid，其余版本为 0
    """
    if len(blob) < _U32:
        raise CapXattrError("数据太短，缺少 magic_etc 字段")
    (magic_etc,) = struct.unpack_from("<I", blob, 0)
    revision = magic_etc & VFS_CAP_REVISION_MASK
    effective = bool(magic_etc & VFS_CAP_FLAGS_EFFECTIVE)

    if revision == VFS_CAP_REVISION_1:
        blocks = 1
        has_rootid = False
    elif revision == VFS_CAP_REVISION_2:
        blocks = 2
        has_rootid = False
    elif revision == VFS_CAP_REVISION_3:
        blocks = 2
        has_rootid = True
    else:
        raise CapXattrError(
            "未知的 capability xattr 版本: 0x%08x" % (magic_etc & VFS_CAP_REVISION_MASK)
        )

    expected = _U32 + blocks * 3 * _U32 + (_U32 if has_rootid else 0)
    if len(blob) != expected:
        raise CapXattrError(
            "v%d 数据长度应为 %d 字节，实际 %d 字节"
            % (revision >> 24, expected, len(blob))
        )

    offset = _U32
    permitted = 0
    inheritable = 0
    for index in range(blocks):
        _eff, perm, inh = struct.unpack_from("<III", blob, offset)
        shift = 32 * index
        permitted |= perm << shift
        inheritable |= inh << shift
        offset += 3 * _U32

    rootid = 0
    if has_rootid:
        (rootid,) = struct.unpack_from("<I", blob, offset)

    return {
        "version": revision >> 24,
        "effective": effective,
        "permitted": permitted,
        "inheritable": inheritable,
        "rootid": rootid,
    }


def build_cap_xattr(permitted=0, inheritable=0, effective=False, version=3, rootid=0):
    """构造 vfs_cap_data / vfs_ns_cap_data 二进制，供测试与工具生成样本。"""
    if version == 1:
        magic = VFS_CAP_REVISION_1
        blocks = 1
    elif version == 2:
        magic = VFS_CAP_REVISION_2
        blocks = 2
    elif version == 3:
        magic = VFS_CAP_REVISION_3
        blocks = 2
    else:
        raise CapXattrError("不支持的版本: %r" % (version,))
    if effective:
        magic |= VFS_CAP_FLAGS_EFFECTIVE

    parts = [struct.pack("<I", magic)]
    for index in range(blocks):
        shift = 32 * index
        parts.append(
            struct.pack(
                "<III",
                0,  # data[].effective 在磁盘格式中恒为 0，effective 在 magic_etc 里
                (permitted >> shift) & 0xFFFFFFFF,
                (inheritable >> shift) & 0xFFFFFFFF,
            )
        )
    if version == 3:
        parts.append(struct.pack("<I", rootid))
    return b"".join(parts)
