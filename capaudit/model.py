"""审计输入的数据模型。"""

import os
from dataclasses import dataclass, field

from .capabilities import ALL_CAPS


@dataclass(frozen=True)
class FileCaps:
    """文件 capability（security.capability xattr 解析结果）。

    ``present=False`` 表示文件没有 capability xattr。
    ``rootid`` 仅 v3 有意义，是文件所属用户命名空间内 kuid 为 0
    的 uid 在初始命名空间中的映射值。
    """

    permitted: int = 0
    inheritable: int = 0
    effective: bool = False
    rootid: int = 0
    version: int = 0
    present: bool = False

    @classmethod
    def from_xattr(cls, blob):
        """从 xattr 二进制构造；blob 为 None 表示文件无 capability。"""
        if blob is None:
            return cls()
        from .xattr import parse_cap_xattr

        parsed = parse_cap_xattr(blob)
        return cls(
            permitted=parsed["permitted"],
            inheritable=parsed["inheritable"],
            effective=parsed["effective"],
            rootid=parsed["rootid"],
            version=parsed["version"],
            present=True,
        )


@dataclass(frozen=True)
class FileContext:
    """被执行文件的静态属性。"""

    uid: int = 0
    gid: int = 0
    mode: int = 0o755  # 仅权限位（含 setuid/setgid/sticky）
    caps: FileCaps = field(default_factory=FileCaps)

    @property
    def setuid(self):
        return bool(self.mode & 0o4000)

    @property
    def setgid(self):
        return bool(self.mode & 0o2000)

    def writable_by(self, user):
        """按普通文件权限位判断 user 是否可写该文件。"""
        if user.uid == 0:
            return True
        if user.uid == self.uid:
            return bool(self.mode & 0o200)
        if user.gid == self.gid or self.gid in user.groups:
            return bool(self.mode & 0o020)
        return bool(self.mode & 0o002)


@dataclass(frozen=True)
class UserContext:
    """发起 exec 的用户身份。

    ``ns_rootid`` 是用户所在用户命名空间中 kuid==0 映射到初始命名空间
    的 uid；初始命名空间下为 0。用于校验 v3 capability 的 rootid。
    """

    uid: int = 0
    euid: int = 0
    gid: int = 0
    groups: tuple = ()
    ns_rootid: int = 0

    @property
    def is_root(self):
        return self.uid == 0 or self.euid == 0


@dataclass(frozen=True)
class ProcessCaps:
    """exec 前进程的 capability 集合与 bounding set。"""

    permitted: int = 0
    effective: int = 0
    inheritable: int = 0
    ambient: int = 0
    bounding: int = ALL_CAPS


@dataclass(frozen=True)
class ExecInput:
    """一次 execve 审计的全部输入。"""

    file: FileContext
    user: UserContext
    process: ProcessCaps = field(default_factory=ProcessCaps)
    no_new_privs: bool = False


@dataclass(frozen=True)
class ExecResult:
    """exec 之后进程（近似）拥有的 capability 集合。"""

    permitted: int
    effective: int
    inheritable: int
    ambient: int
    gained: int  # 相对 exec 前 permitted 新增的位
    file_caps_ignored: bool  # rootid 不匹配等原因导致文件 capability 被忽略

    def gained_names(self):
        from .capabilities import mask_to_names

        return mask_to_names(self.gained)


def file_context_from_stat(st, caps=None):
    """由 os.stat_result 构造 FileContext（便于 Linux 上实测，可选使用）。"""
    return FileContext(
        uid=st.st_uid,
        gid=st.st_gid,
        mode=st.st_mode & 0o7777,
        caps=caps if caps is not None else FileCaps(),
    )


def current_user_context():
    """采集当前进程的用户身份（Linux 实测辅助，可选使用）。"""
    return UserContext(
        uid=os.getuid(),
        euid=os.geteuid(),
        gid=os.getgid(),
        groups=tuple(os.getgroups()),
        ns_rootid=0,
    )
