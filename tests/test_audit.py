"""审计规则测试：五类必报发现 + 过度授权场景。"""

import unittest

from capaudit.audit import RuleId, Severity, audit
from capaudit.capabilities import (
    ALL_CAPS,
    CAP_DAC_OVERRIDE,
    CAP_DAC_READ_SEARCH,
    CAP_NET_BIND_SERVICE,
    CAP_SYS_ADMIN,
    names_to_mask,
)
from capaudit.model import ExecInput, FileCaps, FileContext, ProcessCaps, UserContext
from capaudit.xattr import build_cap_xattr


def make_input(
    uid=1000,
    caps=None,
    file_uid=0,
    file_mode=0o755,
    ns_rootid=0,
    process=None,
    no_new_privs=False,
):
    file_ctx = FileContext(
        uid=file_uid,
        gid=0,
        mode=file_mode,
        caps=caps if caps is not None else FileCaps(),
    )
    user = UserContext(uid=uid, euid=uid, gid=uid, ns_rootid=ns_rootid)
    return ExecInput(
        file=file_ctx,
        user=user,
        process=process if process is not None else ProcessCaps(),
        no_new_privs=no_new_privs,
    )


def caps_from(permitted=0, inheritable=0, effective=False, rootid=0, version=3):
    return FileCaps.from_xattr(
        build_cap_xattr(
            permitted=permitted,
            inheritable=inheritable,
            effective=effective,
            version=version,
            rootid=rootid,
        )
    )


class ScenarioTest(unittest.TestCase):
    def test_low_port_tool_with_full_caps_and_effective(self):
        """题述场景：只需低端口绑定，却配置整套 permitted + effective 常开。"""
        caps = caps_from(permitted=ALL_CAPS, effective=True)
        report = audit(
            make_input(uid=1000, caps=caps),
            needed_caps=1 << CAP_NET_BIND_SERVICE,
        )
        rules = {f.rule for f in report.findings}
        self.assertIn(RuleId.NON_ROOT_EXECUTION, rules)
        self.assertIn(RuleId.EFFECTIVE_NOT_CLEARED, rules)
        self.assertIn(RuleId.DANGEROUS_COMBINATION, rules)
        self.assertIn(RuleId.EXCESSIVE_CAPABILITIES, rules)
        # 非 root 用户 exec 后实际拿到整套 capability
        self.assertEqual(report.result.permitted, ALL_CAPS)
        self.assertEqual(report.result.effective, ALL_CAPS)

    def test_minimal_config_is_clean(self):
        """只授予所需 capability、effective 关闭、文件不可写时不应告警。"""
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE, effective=False)
        report = audit(
            make_input(uid=1000, caps=caps),
            needed_caps=1 << CAP_NET_BIND_SERVICE,
        )
        rules = {f.rule for f in report.findings}
        self.assertNotIn(RuleId.EFFECTIVE_NOT_CLEARED, rules)
        self.assertNotIn(RuleId.DANGEROUS_COMBINATION, rules)
        self.assertNotIn(RuleId.EXCESSIVE_CAPABILITIES, rules)
        self.assertNotIn(RuleId.FILE_WRITABLE, rules)
        # 非 root 获得 capability 属于预期，仍会提示
        self.assertIn(RuleId.NON_ROOT_EXECUTION, rules)


class FileWritableTest(unittest.TestCase):
    def test_world_writable_is_critical(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE)
        report = audit(make_input(uid=1000, caps=caps, file_mode=0o777))
        findings = report.by_rule(RuleId.FILE_WRITABLE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_owner_writable_by_non_owner_exec(self):
        # 文件属主可写，执行者不是属主：对执行者不可写，不告警
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE)
        report = audit(make_input(uid=1000, caps=caps, file_uid=0, file_mode=0o755))
        self.assertEqual(report.by_rule(RuleId.FILE_WRITABLE), [])

    def test_group_writable_matching_group(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE)
        exec_input = make_input(uid=1000, caps=caps, file_mode=0o775)
        user = UserContext(uid=1000, euid=1000, gid=1000, groups=(0,))
        exec_input = ExecInput(
            file=exec_input.file, user=user, process=exec_input.process
        )
        report = audit(exec_input)
        self.assertEqual(len(report.by_rule(RuleId.FILE_WRITABLE)), 1)


class RootIdTest(unittest.TestCase):
    def test_rootid_mismatch_flagged(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE, rootid=100000)
        report = audit(make_input(uid=1000, caps=caps, ns_rootid=0))
        findings = report.by_rule(RuleId.ROOTID_MISMATCH)
        self.assertEqual(len(findings), 1)
        self.assertTrue(report.result.file_caps_ignored)

    def test_rootid_match_not_flagged(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE, rootid=100000)
        report = audit(make_input(uid=1000, caps=caps, ns_rootid=100000))
        self.assertEqual(report.by_rule(RuleId.ROOTID_MISMATCH), [])

    def test_v2_caps_have_no_rootid_finding(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE, version=2)
        report = audit(make_input(uid=1000, caps=caps))
        self.assertEqual(report.by_rule(RuleId.ROOTID_MISMATCH), [])


class DangerousComboTest(unittest.TestCase):
    def test_sys_admin_alone_is_critical(self):
        caps = caps_from(permitted=1 << CAP_SYS_ADMIN, effective=True)
        report = audit(make_input(uid=1000, caps=caps))
        findings = report.by_rule(RuleId.DANGEROUS_COMBINATION)
        self.assertTrue(any(f.severity is Severity.CRITICAL for f in findings))

    def test_dac_combo_flagged(self):
        mask = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH)
        caps = caps_from(permitted=mask, effective=True)
        report = audit(make_input(uid=1000, caps=caps))
        findings = report.by_rule(RuleId.DANGEROUS_COMBINATION)
        self.assertEqual(len(findings), 1)
        self.assertIn("CAP_DAC_OVERRIDE", findings[0].capabilities)

    def test_combo_blocked_by_bounding_set_not_flagged(self):
        # bounding set 砍掉 DAC_READ_SEARCH 后组合不成立
        mask = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH)
        caps = caps_from(permitted=mask, effective=True)
        proc = ProcessCaps(bounding=1 << CAP_DAC_OVERRIDE)
        report = audit(make_input(uid=1000, caps=caps, process=proc))
        self.assertEqual(report.by_rule(RuleId.DANGEROUS_COMBINATION), [])

    def test_no_new_privs_neutralizes_gain(self):
        caps = caps_from(permitted=ALL_CAPS, effective=True)
        report = audit(make_input(uid=1000, caps=caps, no_new_privs=True))
        self.assertEqual(report.result.permitted, 0)
        self.assertEqual(report.by_rule(RuleId.NON_ROOT_EXECUTION), [])
        self.assertEqual(report.by_rule(RuleId.DANGEROUS_COMBINATION), [])


class RootUserTest(unittest.TestCase):
    def test_root_exec_not_flagged_as_non_root(self):
        caps = caps_from(permitted=1 << CAP_NET_BIND_SERVICE)
        report = audit(make_input(uid=0, caps=caps))
        self.assertEqual(report.by_rule(RuleId.NON_ROOT_EXECUTION), [])


if __name__ == "__main__":
    unittest.main()
