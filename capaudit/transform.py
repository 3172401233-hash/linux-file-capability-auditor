"""execve 时 capability 集合的转换规则（内核算法的可审计近似）。

参考 capabilities(7) 与 security/commoncap.c 的 cap_bprm_creds_from_file()。

内核公式（本模块实现的语义）:

* root（uid/euid 为 0，或 setuid-root 文件）执行时，文件的
  permitted/inheritable 集合按"全 1"处理；
* 非 root 时:
      pP' = (F(P) & bounding) | (pI & F(I)) | pA'
      pE' = pP' & F(E)            （文件带 capability 时）
      pE' = pA'                   （文件不带 capability 时）
* root 时:
      pP' = bounding | (pI & 全1) | pA'  = bounding | pI | pA'
      pE' = pP' & F(E)            （文件带 capability 时）
      pE' = pP'                   （文件不带 capability 时）
* ambient 仅在 pA ⊆ (pI ∩ pP') 时保留；文件带 capability 或提权执行时
  内核直接清空 ambient；
* no_new_privs 时 ambient 清空，且 pP' 不得超出 exec 前的 pP；
* v3 文件 capability 的 rootid 与执行者命名空间的 ns_rootid 不一致时，
  文件 capability 整体被忽略。

与真实内核的差异见 README.md。
"""

from .capabilities import ALL_CAPS
from .model import ExecResult


def compute_post_exec(exec_input):
    """计算 exec 后的 capability 集合。

    参数为 model.ExecInput，返回 model.ExecResult。
    """
    file_ctx = exec_input.file
    user = exec_input.user
    proc = exec_input.process
    caps = file_ctx.caps

    # rootid 校验：v3 capability 只在创建它的用户命名空间（及其子命名
    # 空间）内有效；不匹配时内核静默忽略文件 capability。
    file_caps_ignored = False
    if caps.present and caps.rootid != user.ns_rootid:
        file_caps_ignored = True

    effective_caps = caps if (caps.present and not file_caps_ignored) else None

    # 提权执行：root 身份，或 setuid-root 文件（rootid 匹配时）。
    privileged = user.is_root or (file_ctx.setuid and file_ctx.uid == 0)

    if privileged:
        file_permitted = ALL_CAPS
        file_inheritable = ALL_CAPS
    elif effective_caps is not None:
        file_permitted = effective_caps.permitted
        file_inheritable = effective_caps.inheritable
    else:
        file_permitted = 0
        file_inheritable = 0

    new_permitted = (file_permitted & proc.bounding) | (
        proc.inheritable & file_inheritable
    )

    # ambient：文件带 capability 或提权执行时被内核清空；
    # 否则保留 pA ∩ pI（与 commoncap.c 中无提权 exec 的路径一致）。
    if exec_input.no_new_privs or effective_caps is not None or privileged:
        new_ambient = 0
    else:
        new_ambient = proc.ambient & proc.inheritable
    new_permitted |= new_ambient

    if exec_input.no_new_privs:
        # no_new_privs：exec 不得赋予进程此前没有的 permitted 位。
        new_permitted &= proc.permitted

    # effective 集合
    if effective_caps is not None:
        new_effective = new_permitted if effective_caps.effective else 0
    elif privileged:
        new_effective = new_permitted
    else:
        new_effective = new_ambient

    gained = new_permitted & ~proc.permitted

    return ExecResult(
        permitted=new_permitted,
        effective=new_effective,
        inheritable=proc.inheritable,
        ambient=new_ambient,
        gained=gained,
        file_caps_ignored=file_caps_ignored,
    )
