#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §8 姓名校验 / 拼音转换 / 多音姓氏补丁 单元测试。

契约来源：campus-signup/SPEC.md §8.1、§8.2、§8.3（姓名部分）。
只依赖 stdlib unittest，Python 3.9 兼容。
"""

import os
import re
import sys
import unittest

# 避免在仓库里生成 __pycache__（SPEC §14）。
sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VENDOR = os.path.join(PROJECT_ROOT, "vendor", "site-packages")
for _path in (_VENDOR, PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

_MODULE_PATH = os.path.join(PROJECT_ROOT, "app", "pinyin_util.py")
if not os.path.isfile(_MODULE_PATH):
    raise unittest.SkipTest("app/pinyin_util.py 尚未实现（等待 backend 完成）")

from app.pinyin_util import (  # noqa: E402  (必须在 sys.path 调整之后导入)
    COMPOUND_SURNAME_OVERRIDES,
    SINGLE_SURNAME_OVERRIDES,
    name_to_pinyin,
    normalize_real_name,
)

CJK_RE = re.compile(r"[\u4e00-\u9fff]")
LOWER_RE = re.compile(r"^[a-z]+$")

# SPEC §8.2「必须通过的单元用例」——逐条断言。
SPEC_PINYIN_CASES = [
    ("张三", "zhangsan"),
    ("李四", "lisi"),
    ("王小明", "wangxiaoming"),
    ("欧阳锋", "ouyangfeng"),
    ("吕小布", "lvxiaobu"),
    ("曾小贤", "zengxiaoxian"),
    ("单伟", "shanwei"),
    ("解雨臣", "xieyuchen"),
    ("仇英", "qiuying"),
    ("区志强", "ouzhiqiang"),
    ("查良镛", "zhaliangyong"),
    ("朴树", "piaoshu"),
    ("缪斯", "miaosi"),
    ("尉健行", "yujianxing"),
    ("盖聂", "genie"),
    ("折可存", "shekecun"),
    ("尉迟恭", "yuchigong"),
    ("万俟明", "moqiming"),
    ("澹台灭明", "tantaimieming"),
    ("长孙无忌", "zhangsunwuji"),
    ("阿依古丽·买买提", "ayigulimaimaiti"),
    ("张 三", "zhangsan"),  # 中间空格应被去掉
]

# SPEC §8.2 非法用例 + §8.1 其它非法输入。
SPEC_INVALID_NAMES = [
    "吕",                    # 单字姓名：汉字数 < 2
    "张",                    # 单字
    "张三; rm -rf /",        # 标点 + 空格
    "张3",                   # 数字
    "张·",                   # 间隔号在结尾
    "·张三",                 # 间隔号在开头
    "张··三",                # 间隔号连续
    "张三a",                 # 字母
    "Zhang三",               # 字母
    "张三，",                # 中文标点
    "张三\x01",              # 控制字符
    "",                      # 空
    "   ",                   # 纯空格
    "张三李四王五赵六钱七八",  # 11 个汉字（> 10）
]


def _has_cjk(text):
    return bool(CJK_RE.search(text or ""))


class NormalizeRealNameTest(unittest.TestCase):
    """SPEC §8.1 姓名规范化与校验。"""

    def test_returns_cleaned_name_for_valid_input(self):
        cases = [
            ("张三", "张三"),
            (" 张三 ", "张三"),
            ("张 三", "张三"),
            ("张  三", "张三"),
            ("\u3000张\u3000三\u3000", "张三"),  # 全角空格
            ("阿依古丽·买买提", "阿依古丽·买买提"),
            ("张·三", "张·三"),
            ("张·三·四", "张·三·四"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                name, error = normalize_real_name(raw)
                self.assertEqual(error, "", "合法姓名不应返回错误信息: %r" % (raw,))
                self.assertEqual(name, expected)

    def test_returns_none_and_chinese_message_for_invalid_input(self):
        for raw in SPEC_INVALID_NAMES:
            with self.subTest(raw=raw):
                name, error = normalize_real_name(raw)
                self.assertIsNone(name, "非法姓名应返回 None: %r" % (raw,))
                self.assertIsInstance(error, str)
                self.assertTrue(error.strip(), "非法姓名必须返回具体中文提示: %r" % (raw,))
                self.assertTrue(_has_cjk(error), "提示应为中文: %r -> %r" % (raw, error))

    def test_han_count_boundary(self):
        # 2–10 汉字边界：10 个汉字合法，11 个非法。
        ten = "王五王五王五王五王五"
        self.assertEqual(len(ten), 10)
        name, error = normalize_real_name(ten)
        self.assertEqual(error, "")
        self.assertEqual(name, ten)

        eleven = ten + "王"
        name, error = normalize_real_name(eleven)
        self.assertIsNone(name)
        self.assertTrue(error)

    def test_interval_dot_rules(self):
        # 间隔号只能在中间、不能连续；剩余汉字仍须 2–10 个。
        self.assertEqual(normalize_real_name("张·三")[0], "张·三")
        for raw in ("·张三", "张·", "张··三", "·张·三·"):
            with self.subTest(raw=raw):
                self.assertIsNone(normalize_real_name(raw)[0])
        # 去掉间隔号后只剩 1 个汉字 → 非法。
        self.assertIsNone(normalize_real_name("张·")[0])

    def test_rejects_ascii_digits_and_letters(self):
        for raw in ("abc", "张a三", "123", "张三1", "A张三"):
            with self.subTest(raw=raw):
                self.assertIsNone(normalize_real_name(raw)[0])


class NameToPinyinTest(unittest.TestCase):
    """SPEC §8.2 拼音转换与多音姓氏补丁。"""

    def test_spec_table_pinyin(self):
        for name, expected in SPEC_PINYIN_CASES:
            with self.subTest(name=name):
                pinyin, error = name_to_pinyin(name)
                self.assertEqual(error, "", "合法姓名应返回空错误信息: %r" % (name,))
                self.assertEqual(pinyin, expected)

    def test_pinyin_result_shape(self):
        for name, _expected in SPEC_PINYIN_CASES:
            with self.subTest(name=name):
                pinyin, error = name_to_pinyin(name)
                self.assertEqual(error, "")
                self.assertIsInstance(pinyin, str)
                self.assertTrue(LOWER_RE.match(pinyin), "拼音只能是小写字母: %r" % (pinyin,))
                self.assertGreaterEqual(len(pinyin), 2)
                self.assertLessEqual(len(pinyin), 28)

    def test_invalid_names_return_error(self):
        for raw in SPEC_INVALID_NAMES:
            with self.subTest(raw=raw):
                pinyin, error = name_to_pinyin(raw)
                self.assertIsNone(pinyin, "非法姓名应返回 None: %r" % (raw,))
                self.assertIsInstance(error, str)
                self.assertTrue(error.strip())
                self.assertTrue(_has_cjk(error))

    def test_invalid_name_error_matches_normalize(self):
        # SPEC §8.2 第 1 步：非法直接返回 normalize_real_name 的错误。
        for raw in ("张3", "张", "张三; rm -rf /"):
            with self.subTest(raw=raw):
                _, normalize_error = normalize_real_name(raw)
                pinyin, pinyin_error = name_to_pinyin(raw)
                self.assertIsNone(pinyin)
                self.assertEqual(pinyin_error, normalize_error)

    def test_whitespace_inside_name_ignored(self):
        for raw in ("张 三", " 张 三 ", "张\u3000三"):
            with self.subTest(raw=raw):
                self.assertEqual(name_to_pinyin(raw), ("zhangsan", ""))

    def test_compound_and_single_surname_overrides(self):
        self.assertIsInstance(SINGLE_SURNAME_OVERRIDES, dict)
        self.assertIsInstance(COMPOUND_SURNAME_OVERRIDES, dict)
        # SPEC §8 显式给出的两项。
        self.assertEqual(SINGLE_SURNAME_OVERRIDES.get("单"), "shan")
        self.assertEqual(COMPOUND_SURNAME_OVERRIDES.get("尉迟"), "yuchi")
        # 补丁值必须是小写拼音。
        for mapping in (SINGLE_SURNAME_OVERRIDES, COMPOUND_SURNAME_OVERRIDES):
            for key, value in mapping.items():
                with self.subTest(key=key, value=value):
                    self.assertIsInstance(key, str)
                    self.assertIsInstance(value, str)
                    self.assertTrue(value)
                    self.assertEqual(value, value.lower())
                    self.assertTrue(LOWER_RE.match(value))

    def test_compound_surname_uses_override_only_for_surname(self):
        # 尉迟恭 → yuchigong；长孙无忌 → zhangsunwuji（其余音节用 pypinyin 默认）。
        self.assertEqual(name_to_pinyin("尉迟恭"), ("yuchigong", ""))
        self.assertEqual(name_to_pinyin("长孙无忌"), ("zhangsunwuji", ""))

    def test_pinyin_too_long_returns_error(self):
        # 10 个「张」= zhang * 10 = 50 字母 > 28 → SPEC 要求返回「姓名拼音过长」错误。
        name = "张" * 10
        pinyin, error = name_to_pinyin(name)
        self.assertIsNone(pinyin)
        self.assertIn("过长", error)

    def test_multi_codepoint_name(self):
        # 「阿依古丽·买买提」：· 不计入音节，8 个汉字 → ayigulimaimaiti。
        pinyin, error = name_to_pinyin("阿依古丽·买买提")
        self.assertEqual((pinyin, error), ("ayigulimaimaiti", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
