"""exec 转换规则测试：root、非 root、bounding、no_new_privs、跨 UID。"""

import unittest

from capaudit.capabilities import (
    ALL_CAPS,
    CAP_NET_BIND_SERVICE,
    CAP_SYS_ADMIN,
    names_to_mask,
)
from capaudit.model import ExecInput, FileCaps, FileContext, ProcessCaps, UserContext
from capaudit.transform import compute_post_exec
from capaudit.xattr import build_cap_xattr


def make_input(
    uid=1000,
    euid=None,
    caps=None,
    file_uid=0,
    file_mode=0o755,
    ns_rootid=0,
    process=None,
    no_new_privs=False,
):
    if euid is None:
        euid = uid
    file_ctx = FileContext(
        uid=file_uid,
        gid=0,
        mode=file_mode,
        caps=caps if caps is not None else FileCaps(),
    )
    user = UserContext(uid=uid, euid=euid, gid=uid, ns_rootid=ns_rootid)
    return ExecInput(
        file=file_ctx,
        user=user,
        process=process if process is not None else ProcessCaps(),
        no_new_privs=no_new_privs,
    )


class RootExecutionTest(unittest.TestCase):
    def test_root_exec_no_file_caps_gets_full_bounding_set(self):
        result = compute_post_exec(make_input(uid=0))
        self.assertEqual(result.permitted, ALL_CAPS)
        self.assertEqual(result.effective, ALL_CAPS)

    def test_root_exec_respects_bounding_set(self):
        bounding = ALL_CAPS & ~(1 << CAP_SYS_ADMIN)
        proc = ProcessCaps(bounding=bounding)
        result = compute_post_exec(make_input(uid=0, process=proc))
        self.assertEqual(result.permitted, bounding)
        self.assertFalse(result.permitted & (1 << CAP_SYS_ADMIN))

    def test_root_exec_file_caps_with_effective_bit(self):
        caps = FileCaps.from_xattr(
            build_cap_xattr(permitted=1 << CAP_NET_BIND_SERVICE, effective=True)
        )
        result = compute_post_exec(make_input(uid=0, caps=caps))
        # root 执行时文件 permitted 按全 1 处理，effective 位仍然生效
        self.assertEqual(result.permitted, ALL_CAPS)
        self.assertEqual(result.effective, ALL_CAPS)

    def test_root_exec_file_caps_without_effective_bit(self):
        caps = FileCaps.from_xattr(
            build_cap_xattr(permitted=1 << CAP_NET_BIND_SERVICE, effective=False)
        )
        result = compute_post_exec(make_input(uid=0, caps=caps))
        self.assertEqual(result.permitted, ALL_CAPS)
        self.assertEqual(result.effective, 0)


class NonRootExecutionTest(unittest.TestCase):
    def test_non_root_gains_file_permitted_caps(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask, effective=True))
        result = compute_post_exec(make_input(uid=1000, caps=caps))
        self.assertEqual(result.permitted, mask)
        self.assertEqual(result.effective, mask)
        self.assertEqual(result.gained, mask)

    def test_non_root_effective_cleared_when_bit_off(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask, effective=False))
        result = compute_post_exec(make_input(uid=1000, caps=caps))
        self.assertEqual(result.permitted, mask)
        self.assertEqual(result.effective, 0)

    def test_non_root_no_file_caps_gains_nothing(self):
        result = compute_post_exec(make_input(uid=1000))
        self.assertEqual(result.permitted, 0)
        self.assertEqual(result.gained, 0)

    def test_inheritable_intersection(self):
        # 进程 inheritable 与文件 inheritable 的交集进入 permitted
        file_inh = names_to_mask(["CAP_NET_BIND_SERVICE", "CAP_SETUID"])
        caps = FileCaps.from_xattr(build_cap_xattr(inheritable=file_inh))
        proc = ProcessCaps(inheritable=1 << CAP_NET_BIND_SERVICE)
        result = compute_post_exec(make_input(uid=1000, caps=caps, process=proc))
        self.assertEqual(result.permitted, 1 << CAP_NET_BIND_SERVICE)

    def test_file_permitted_limited_by_bounding(self):
        mask = names_to_mask(["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"])
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask, effective=True))
        proc = ProcessCaps(bounding=1 << CAP_NET_BIND_SERVICE)
        result = compute_post_exec(make_input(uid=1000, caps=caps, process=proc))
        self.assertEqual(result.permitted, 1 << CAP_NET_BIND_SERVICE)
        self.assertEqual(result.effective, result.permitted)


class NoNewPrivsTest(unittest.TestCase):
    def test_no_new_privs_blocks_file_cap_gain(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask, effective=True))
        result = compute_post_exec(make_input(uid=1000, caps=caps, no_new_privs=True))
        self.assertEqual(result.permitted, 0)
        self.assertEqual(result.gained, 0)

    def test_no_new_privs_keeps_already_permitted(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask, effective=True))
        proc = ProcessCaps(permitted=mask)
        result = compute_post_exec(
            make_input(uid=1000, caps=caps, process=proc, no_new_privs=True)
        )
        self.assertEqual(result.permitted, mask)

    def test_no_new_privs_clears_ambient(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        proc = ProcessCaps(permitted=mask, inheritable=mask, ambient=mask)
        result = compute_post_exec(
            make_input(uid=1000, process=proc, no_new_privs=True)
        )
        self.assertEqual(result.ambient, 0)


class AmbientTest(unittest.TestCase):
    def test_ambient_survives_plain_exec(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        proc = ProcessCaps(permitted=mask, inheritable=mask, ambient=mask)
        result = compute_post_exec(make_input(uid=1000, process=proc))
        self.assertEqual(result.ambient, mask)
        self.assertEqual(result.permitted, mask)

    def test_ambient_cleared_by_file_caps(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(build_cap_xattr(permitted=mask))
        proc = ProcessCaps(permitted=mask, inheritable=mask, ambient=mask)
        result = compute_post_exec(make_input(uid=1000, caps=caps, process=proc))
        self.assertEqual(result.ambient, 0)


class CrossUidTest(unittest.TestCase):
    def test_rootid_mismatch_ignores_file_caps(self):
        # 容器镜像里的 v3 capability，rootid=100000，在初始命名空间执行
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(
            build_cap_xattr(permitted=mask, effective=True, rootid=100000)
        )
        result = compute_post_exec(make_input(uid=1000, caps=caps, ns_rootid=0))
        self.assertTrue(result.file_caps_ignored)
        self.assertEqual(result.permitted, 0)
        self.assertEqual(result.gained, 0)

    def test_rootid_match_inside_user_namespace(self):
        mask = 1 << CAP_NET_BIND_SERVICE
        caps = FileCaps.from_xattr(
            build_cap_xattr(permitted=mask, effective=True, rootid=100000)
        )
        result = compute_post_exec(make_input(uid=1000, caps=caps, ns_rootid=100000))
        self.assertFalse(result.file_caps_ignored)
        self.assertEqual(result.permitted, mask)

    def test_setuid_root_file_grants_full_caps(self):
        # 非 root 用户执行 setuid-root 文件（无文件 capability）
        result = compute_post_exec(make_input(uid=1000, file_uid=0, file_mode=0o4755))
        self.assertEqual(result.permitted, ALL_CAPS)

    def test_setuid_non_root_file_grants_nothing(self):
        result = compute_post_exec(
            make_input(uid=1000, file_uid=2000, file_mode=0o4755)
        )
        self.assertEqual(result.permitted, 0)


if __name__ == "__main__":
    unittest.main()
