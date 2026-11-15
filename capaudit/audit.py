"""基于 exec 转换结果的安全审计规则。"""

from dataclasses import dataclass
from enum import Enum

from .capabilities import (
    CAP_BPF,
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_DAC_READ_SEARCH,
    CAP_NET_ADMIN,
    CAP_NET_RAW,
    CAP_SETGID,
    CAP_SETPCAP,
    CAP_SETUID,
    CAP_SYS_ADMIN,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_RAWIO,
    mask_to_names,
)
from .transform import compute_post_exec


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleId(Enum):
    NON_ROOT_EXECUTION = "NON_ROOT_EXECUTION"
    FILE_WRITABLE = "FILE_WRITABLE"
    ROOTID_MISMATCH = "ROOTID_MISMATCH"
    EFFECTIVE_NOT_CLEARED = "EFFECTIVE_NOT_CLEARED"
    DANGEROUS_COMBINATION = "DANGEROUS_COMBINATION"
    EXCESSIVE_CAPABILITIES = "EXCESSIVE_CAPABILITIES"


@dataclass(frozen=True)
class Finding:
    rule: RuleId
    severity: Severity
    message: str
    capabilities: tuple = ()  # 涉及的 capability 名称


@dataclass(frozen=True)
class AuditReport:
    findings: tuple
    result: object  # ExecResult

    @property
    def ok(self):
        return not self.findings

    def by_rule(self, rule):
        return [f for f in self.findings if f.rule is rule]


#: 单个即等价于（或极易提升为）root 的 capability。
_ROOT_EQUIVALENT = {
    CAP_SYS_ADMIN: "CAP_SYS_ADMIN 可挂载/卸载文件系统、操作命名空间，实际等价于 root",
    CAP_SYS_MODULE: "CAP_SYS_MODULE 可加载内核模块，直接等价于 root",
    CAP_SYS_RAWIO: "CAP_SYS_RAWIO 可访问 /dev/mem 与原始 IO，可直接改写内核内存",
    CAP_BPF: "CAP_BPF 可加载 eBPF 程序，历史上多次成为提权原语",
}

#: 组合后显著放大风险的 capability 组（子集匹配）。
_DANGEROUS_COMBOS = [
    (
        {CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH},
        "CAP_DAC_OVERRIDE + CAP_DAC_READ_SEARCH 可任意读写文件系统，可改写 /etc/shadow 等",
    ),
    (
        {CAP_SETUID, CAP_SETPCAP},
        "CAP_SETUID + CAP_SETPCAP 可切换到任意 uid 并重新赋予 capability",
    ),
    (
        {CAP_SETUID, CAP_DAC_OVERRIDE},
        "CAP_SETUID + CAP_DAC_OVERRIDE 可写任意文件后切到 root 执行",
    ),
    (
        {CAP_SETGID, CAP_DAC_OVERRIDE},
        "CAP_SETGID + CAP_DAC_OVERRIDE 可借高权限组写敏感文件",
    ),
    (
        {CAP_SYS_PTRACE, CAP_SYS_ADMIN},
        "CAP_SYS_PTRACE + CAP_SYS_ADMIN 可注入任意进程并完全控制系统",
    ),
    (
        {CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH},
        "CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH 可读取并注入任意进程内存",
    ),
    (
        {CAP_NET_ADMIN, CAP_NET_RAW},
        "CAP_NET_ADMIN + CAP_NET_RAW 可劫持/伪造网络流量",
    ),
    (
        {CAP_CHOWN, CAP_DAC_OVERRIDE},
        "CAP_CHOWN + CAP_DAC_OVERRIDE 可夺取任意文件所有权并改写内容",
    ),
]


def audit(exec_input, needed_caps=0):
    """对一次 exec 做完整审计，返回 AuditReport。

    ``needed_caps`` 可选：程序实际需要的 capability 掩码（例如仅需
    CAP_NET_BIND_SERVICE 绑定低端口），用于发现过度授权。
    """
    result = compute_post_exec(exec_input)
    findings = []
    file_ctx = exec_input.file
    user = exec_input.user
    caps = file_ctx.caps

    gained_names = tuple(result.gained_names())

    # 1. 非根用户执行后获得 capability
    if not user.is_root and result.gained:
        findings.append(
            Finding(
                RuleId.NON_ROOT_EXECUTION,
                Severity.HIGH,
                "非根用户 (uid=%d) 执行后新增 capability: %s"
                % (user.uid, ", ".join(gained_names)),
                gained_names,
            )
        )

    # 2. 文件对执行者（或任意人）可写
    if caps.present and file_ctx.writable_by(user):
        if file_ctx.mode & 0o002:
            detail = "文件对其他用户可写 (mode=%04o)" % (file_ctx.mode & 0o7777)
            severity = Severity.CRITICAL
        else:
            detail = "文件对执行者可写 (mode=%04o)" % (file_ctx.mode & 0o7777)
            severity = Severity.HIGH
        findings.append(
            Finding(
                RuleId.FILE_WRITABLE,
                severity,
                "带 capability 的文件%s，二进制可被替换后借 capability 提权" % detail,
                tuple(mask_to_names(caps.permitted)),
            )
        )

    # 3. rootid 不匹配
    if caps.present and caps.version >= 3 and caps.rootid != user.ns_rootid:
        findings.append(
            Finding(
                RuleId.ROOTID_MISMATCH,
                Severity.MEDIUM,
                "v3 capability 的 rootid=%d 与执行者命名空间 ns_rootid=%d 不匹配，"
                "文件 capability 将被内核忽略（可能来自其他用户命名空间的镜像）"
                % (caps.rootid, user.ns_rootid),
                (),
            )
        )

    # 4. effective 位长期开启
    if caps.present and caps.effective and caps.permitted:
        findings.append(
            Finding(
                RuleId.EFFECTIVE_NOT_CLEARED,
                Severity.MEDIUM,
                "文件 effective 位开启：exec 后 %d 个 capability 立即生效，"
                "进程无法按需启停，违背最小权限的延迟生效惯例"
                % len(mask_to_names(caps.permitted)),
                tuple(mask_to_names(caps.permitted)),
            )
        )

    # 5. 危险 capability 组合（按 exec 后实际获得的 permitted 判定）
    granted = result.permitted
    for cap, reason in _ROOT_EQUIVALENT.items():
        if granted & (1 << cap):
            findings.append(
                Finding(
                    RuleId.DANGEROUS_COMBINATION,
                    Severity.CRITICAL,
                    reason,
                    (mask_to_names(1 << cap)[0],),
                )
            )
    for combo, reason in _DANGEROUS_COMBOS:
        combo_mask = 0
        for cap in combo:
            combo_mask |= 1 << cap
        if granted & combo_mask == combo_mask:
            findings.append(
                Finding(
                    RuleId.DANGEROUS_COMBINATION,
                    Severity.HIGH,
                    reason,
                    tuple(mask_to_names(combo_mask)),
                )
            )

    # 6. 过度授权：实际获得远超声明需要（例如只需绑定低端口却拿到整套）
    if needed_caps and granted & ~needed_caps:
        excess = granted & ~needed_caps
        findings.append(
            Finding(
                RuleId.EXCESSIVE_CAPABILITIES,
                Severity.HIGH,
                "exec 后获得的 capability 超出实际需要: %s"
                % ", ".join(mask_to_names(excess)),
                tuple(mask_to_names(excess)),
            )
        )

    return AuditReport(findings=tuple(findings), result=result)
