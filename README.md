# linux-file-capability-auditor

Python Linux 文件 capability 安全审计库。输入文件 capability mask、rootid、
文件权限、执行用户、进程已有集合、bounding set 与 `no_new_privs`，计算
`execve` 之后进程可能获得的 capability，并标出常见提权路径——例如一个
只需 `CAP_NET_BIND_SERVICE` 绑定低端口的工具被配置成整套 permitted 且
effective 位长期开启：普通文件权限检查（`ls -l`）完全看不出这条路径。

纯计算实现：只解析人工构造（或从 Linux 上导出）的 `security.capability`
xattr 字节串，**不依赖真实 xattr 系统调用**，因此可在 Windows/macOS 上
开发与测试。

## 快速开始

```python
from capaudit import (
    ExecInput, FileCaps, FileContext, ProcessCaps, UserContext,
    audit, build_cap_xattr, ALL_CAPS,
)

# 人工构造一个 v3 capability：整套 permitted + effective 常开
blob = build_cap_xattr(permitted=ALL_CAPS, effective=True, version=3, rootid=0)

report = audit(
    ExecInput(
        file=FileContext(uid=0, gid=0, mode=0o755,
                         caps=FileCaps.from_xattr(blob)),
        user=UserContext(uid=1000, euid=1000, gid=1000),
        process=ProcessCaps(),          # 默认空集合 + 完整 bounding set
        no_new_privs=False,
    ),
    needed_caps=1 << 10,                # 程序实际只需 CAP_NET_BIND_SERVICE
)

for finding in report.findings:
    print(finding.rule.value, finding.severity.value, finding.message)
```

## 审计规则

| 规则 | 触发条件 |
| --- | --- |
| `NON_ROOT_EXECUTION` | 非根用户 exec 后 permitted 集合新增 capability |
| `FILE_WRITABLE` | 带 capability 的文件对执行者/组/其他人可写（可替换二进制借 capability 提权） |
| `ROOTID_MISMATCH` | v3 capability 的 rootid 与执行者命名空间 `ns_rootid` 不一致（capability 被内核忽略） |
| `EFFECTIVE_NOT_CLEARED` | 文件 effective 位开启且 permitted 非空（exec 后立即全部生效） |
| `DANGEROUS_COMBINATION` | exec 后实际获得 root 等价单项（`CAP_SYS_ADMIN`/`CAP_SYS_MODULE`/`CAP_SYS_RAWIO`/`CAP_BPF`）或危险组合（如 `DAC_OVERRIDE+DAC_READ_SEARCH`、`SETUID+SETPCAP` 等） |
| `EXCESSIVE_CAPABILITIES` | 实际获得超出 `needed_caps` 声明的需要（过度授权） |

危险组合按 **exec 后实际获得的 permitted** 判定：bounding set 裁掉组合中
任一项、或 `no_new_privs` 阻断增益后，组合告警即不再触发。

## exec 转换模型

`capaudit.transform.compute_post_exec` 实现 capabilities(7) 描述的转换：

- root（uid/euid 为 0）或 setuid-root 文件：文件 permitted/inheritable
  按全 1 处理，`pP' = bounding | pI | pA'`；
- 非 root：`pP' = (F(P) & bounding) | (pI & F(I)) | pA'`；
- 文件带 capability 时 `pE' = pP' & F(E)`；root 无文件 capability 时
  `pE' = pP'`；否则 `pE' = pA'`；
- ambient：文件带 capability、提权执行或 `no_new_privs` 时清空，否则
  保留 `pA ∩ pI`；
- `no_new_privs`：`pP'` 不得超出 exec 前的 `pP`，ambient 清空；
- v3 rootid 与执行者 `ns_rootid` 不匹配时文件 capability 整体忽略。

## 与真实内核策略的差异

本库是**静态审计近似**，并非内核模拟器，有意简化如下：

1. **securebits 未建模**：真实内核的 `SECBIT_KEEP_CAPS`、
   `SECBIT_NO_SETUID_FIXUP`、`SECBIT_NOROOT` 等会改变 root 执行的默认
   授予行为；本库按默认 securebits（全 0）处理。
2. **setuid/setgid 简化**：仅把 setuid-root 视为提权执行；非 root 属主的
   setuid/setgid、以及 `PR_SET_KEEPCAPS` 跨 setuid 保留 permitted 的
   语义未建模。
3. **rootid 判定简化**：真实内核判断 v3 rootid 是否等于**当前用户命名
   空间**的 kuid 映射根（并对后代命名空间有效）；本库用调用方提供的
   `ns_rootid` 做单值比较，不建模命名空间层级。
4. **ambient 语义**：真实内核在"无提权 exec"时保留 `pA ∩ pI`，本库一致；
   但 `PR_CAP_AMBIENT_RAISE` 的运行时约束（须同时在 pP 与 pI 中）属于
   进程行为，不在静态审计范围内。
5. **LSM 未建模**：SELinux/AppArmor/smack 的 hook 可能进一步收缩或拒绝
   capability 授予；本库结果是最坏情况上界。
6. **capability 版本上限**：常量表截至 `CAP_CHECKPOINT_RESTORE`(40)；
   更新内核新增的 capability 需要扩展 `capaudit/capabilities.py`。
7. **文件可写判定**：按 uid/gid/mode 位静态判断，不考虑 ACL、只读挂载、
   `immutable` 属性；内核在写文件时会清掉 capability xattr，但可写仍
   意味着可被"先改写再赋权"的部署流程利用。

结论：本库用于发现**配置层面**的过度授权与提权路径，输出应作为人工
复核的起点，而非内核行为的精确预言。

## 测试

```sh
python -m unittest discover -s tests
```

测试全部使用 `capaudit.xattr.build_cap_xattr` 或手工 `struct.pack` 构造的
v1/v2/v3 capability 二进制，覆盖根用户、非根用户、bounding set 限制、
`no_new_privs`、ambient 保留与跨 UID（rootid 匹配/不匹配、setuid）场景，
不访问真实文件系统 xattr。
