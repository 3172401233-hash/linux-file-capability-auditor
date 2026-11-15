"""Linux 文件 capability 安全审计库。

输入文件 capability mask、rootid、文件权限、执行用户、进程已有集合、
bounding set 与 no_new_privs，计算 exec 后进程可能获得的 capability，
并给出安全审计发现。纯计算实现，不依赖真实 xattr，可跨平台运行。
"""

from .audit import AuditReport, Finding, RuleId, Severity, audit
from .capabilities import ALL_CAPS, cap_name, mask_to_names, names_to_mask
from .model import (
    ExecInput,
    ExecResult,
    FileCaps,
    FileContext,
    ProcessCaps,
    UserContext,
)
from .transform import compute_post_exec
from .xattr import CapXattrError, build_cap_xattr, parse_cap_xattr

__version__ = "0.1.0"

__all__ = [
    "ALL_CAPS",
    "AuditReport",
    "CapXattrError",
    "ExecInput",
    "ExecResult",
    "FileCaps",
    "FileContext",
    "Finding",
    "ProcessCaps",
    "RuleId",
    "Severity",
    "UserContext",
    "audit",
    "build_cap_xattr",
    "cap_name",
    "compute_post_exec",
    "mask_to_names",
    "names_to_mask",
    "parse_cap_xattr",
]
