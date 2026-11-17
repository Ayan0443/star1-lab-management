#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §9 密码策略单元测试。

覆盖：长度、四类字符、符号白名单、用户名包含、弱密码、连续重复、
生成器 500 次全部通过校验、estimate_strength 单调性。
只依赖 stdlib unittest，Python 3.9 兼容。
"""

import os
import re
import sys
import unittest

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

_MODULE_PATH = os.path.join(PROJECT_ROOT, "app", "security.py")
if not os.path.isfile(_MODULE_PATH):
    raise unittest.SkipTest("app/security.py 尚未实现（等待 backend 完成）")

from app.security import (  # noqa: E402
    estimate_strength,
    generate_password,
    validate_password,
)

# SPEC §9.1 符号白名单
ALLOWED_SYMBOLS = "!@#$%^&*()-_=+[]{};,.?/|~"
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "abcdefghijklmnopqrstuvwxyz".upper()
DIGITS = "0123456789"
AMBIGUOUS = "0O1lI"

BASE_VALID = "K7#mQ2$vX9!pR4@t"  # SPEC §7.3 示例：16 位、四类齐全
CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _classes(password):
    return (
        any(ch in LOWER for ch in password),
        any(ch in UPPER for ch in password),
        any(ch in DIGITS for ch in password),
        any(ch in ALLOWED_SYMBOLS for ch in password),
    )


def _max_repeat(password):
    best, run = 0, 1
    for i, ch in enumerate(password):
        if i and ch == password[i - 1]:
            run += 1
        else:
            run = 1
        best = max(best, run)
    return best


class ValidatePasswordTest(unittest.TestCase):
    """SPEC §9.1 validate_password 契约。"""

    def assert_rejected(self, password, username, keywords=None):
        ok, message = validate_password(password, username)
        self.assertFalse(ok, "该密码应被拒绝: %r (username=%r)" % (password, username))
        self.assertIsInstance(message, str)
        self.assertTrue(message.strip(), "拒绝时必须给出具体中文提示")
        self.assertTrue(CJK_RE.search(message), "提示应为中文: %r" % (message,))
        if keywords:
            self.assertTrue(
                any(word in message for word in keywords),
                "提示未指出具体原因（期望包含 %r 之一）: %r" % (keywords, message),
            )
        return message

    def assert_accepted(self, password, username=""):
        ok, message = validate_password(password, username)
        self.assertTrue(ok, "该密码应通过校验: %r，实际提示: %r" % (password, message))
        self.assertFalse(message, "通过校验时错误信息应为空: %r" % (message,))

    def test_valid_passwords(self):
        cases = [
            (BASE_VALID, ""),
            (BASE_VALID, "zhangsan"),
            ("K7#mQ2$vX9!p", ""),          # 恰好 12 位
            ("Aa1!" + "bcd" * 20, "lisi"),  # 恰好 64 位
            ("K7&mQ2vX9pR4tW8", ""),        # 使用 & 符号
            ("K7~mQ2|vX9pR4tW8", ""),       # 使用 ~ | 等符号
        ]
        for password, username in cases:
            with self.subTest(password=password, username=username):
                self.assert_accepted(password, username)

    def test_length_bounds(self):
        # 12–64 位，边界外拒绝，并提示长度原因。
        self.assert_rejected("K7#mQ2$vX9!", "", ("长度", "12"))
        self.assert_rejected("Aa1!" + "bcd" * 20 + "e", "", ("长度", "64"))
        self.assert_rejected("", "", None)
        self.assert_rejected("Ab1!", "", None)

    def test_requires_four_character_classes(self):
        # 每个用例只缺一类字符，其余均满足。
        self.assert_rejected("K7#MQ2$VX9!PR4@T", "", ("小写",))
        self.assert_rejected("k7#mq2$vx9!pr4@t", "", ("大写",))
        self.assert_rejected("Kq#mQw$vXp!rT@z", "", ("数字",))
        self.assert_rejected("K7mQ2vX9pR4tW8", "", ("符号",))

    def test_symbol_whitelist_accepts_each_allowed_symbol(self):
        # SPEC §9.1 允许集合中的每个符号都应被接受。
        for symbol in ALLOWED_SYMBOLS:
            with self.subTest(symbol=symbol):
                password = BASE_VALID[:6] + symbol + BASE_VALID[7:]
                self.assert_accepted(password)

    def test_rejects_chars_outside_whitelist(self):
        # 空格、引号、反斜杠、冒号、中文、控制字符 → 拒绝。
        for bad_char in (" ", '"', "'", "\\", ":", "\t", "\r", "\n", "中", "`"):
            with self.subTest(bad_char=repr(bad_char)):
                password = BASE_VALID[:6] + bad_char + BASE_VALID[7:]
                self.assert_rejected(password, "", ("字符", "允许"))

    def test_rejects_username_containment_case_insensitive(self):
        # 密码包含用户名（不区分大小写）→ 拒绝。
        self.assert_rejected("K7#Zhangsan!2$", "zhangsan", ("用户名",))
        self.assert_rejected("K7#ZHANGSANx!2$", "zhangsan", ("用户名",))
        # 用户名不包含时通过。
        self.assert_accepted(BASE_VALID, "zhangsan2")
        # 空用户名/None 时跳过包含关系检查（SPEC §9.2）。
        self.assert_accepted(BASE_VALID, "")
        self.assert_accepted(BASE_VALID, None)

    def test_rejects_weak_passwords(self):
        # SPEC §9.1 明确要求内置的弱密码条目，全部必须拒绝。
        weak_passwords = [
            "123456789012",
            "password1234",
            "qwertyuiop12",
            "administrator1",
            "P@ssw0rd1234",
            "Aa123456789!",
        ]
        for password in weak_passwords:
            with self.subTest(password=password):
                self.assert_rejected(password, "", None)
        # 其中结构上满足四类字符的条目必须由「弱密码」规则拦下。
        self.assert_rejected("P@ssw0rd1234", "", ("常见", "弱"))
        self.assert_rejected("Aa123456789!", "", ("常见", "弱"))

    def test_rejects_consecutive_repeats(self):
        # 4 个及以上连续相同字符 → 拒绝。
        self.assert_rejected("Aaaaa#mQ2$vX9!pR", "", ("连续", "重复"))
        self.assert_rejected("K7#mQ2$vX9!ppppR", "", ("连续", "重复"))
        # 3 个连续相同字符是允许的（边界）。
        self.assert_accepted("Kaaa#mQ2$vX9!pR")

    def test_username_containment_uses_full_username(self):
        # username 只是拼音 base；包含 base 即视为包含用户名。
        ok, message = validate_password("K7#lisi!mQ2$vX9p", "lisi")
        self.assertFalse(ok)
        self.assertIn("用户名", message)

    def test_returns_tuple(self):
        result = validate_password(BASE_VALID, "zhangsan")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], bool)
        self.assertIsInstance(result[1], str)


class GeneratePasswordTest(unittest.TestCase):
    """SPEC §9.2 generate_password 契约。"""

    def test_500_generated_passwords_all_valid(self):
        passwords = set()
        for _ in range(500):
            password = generate_password()
            ok, message = validate_password(password, "")
            self.assertTrue(ok, "生成的密码未通过校验: %r，提示: %r" % (password, message))
            passwords.add(password)
        self.assertEqual(len(passwords), 500, "500 次生成的密码不应重复")

    def test_default_length_is_16(self):
        password = generate_password()
        self.assertEqual(len(password), 16)

    def test_length_parameter_respected(self):
        for length in (12, 16, 20, 32):
            with self.subTest(length=length):
                password = generate_password(length)
                self.assertEqual(len(password), length)
                self.assertTrue(validate_password(password, "")[0])

    def test_charset_excludes_ambiguous_and_colon(self):
        for _ in range(200):
            password = generate_password()
            with self.subTest(password=password):
                for ch in password:
                    self.assertNotIn(ch, AMBIGUOUS, "不应出现易混淆字符: %r" % (password,))
                    self.assertNotEqual(ch, ":", "不应出现冒号: %r" % (password,))
                    self.assertTrue(
                        ch in LOWER or ch in UPPER or ch in DIGITS or ch in ALLOWED_SYMBOLS,
                        "字符不在允许集合内: %r" % (password,),
                    )

    def test_has_all_four_classes(self):
        for _ in range(100):
            lower, upper, digit, symbol = _classes(generate_password())
            self.assertTrue(lower and upper and digit and symbol)


class EstimateStrengthTest(unittest.TestCase):
    """SPEC §9.3 estimate_strength 契约（0–4 分、中文标签、percent、单调）。"""

    LABELS = {"很弱", "弱", "中等", "强", "很强"}

    def assert_strength_shape(self, strength):
        self.assertIsInstance(strength, dict)
        self.assertIn("score", strength)
        self.assertIn("label", strength)
        self.assertIn("percent", strength)
        self.assertIsInstance(strength["score"], int)
        self.assertTrue(0 <= strength["score"] <= 4)
        self.assertIsInstance(strength["label"], str)
        self.assertIn(strength["label"], self.LABELS)
        self.assertIsInstance(strength["percent"], int)
        self.assertTrue(0 <= strength["percent"] <= 100)

    def test_shape_and_label_set(self):
        for password in ("", "a", "abcdefgh", "Abcd1234", BASE_VALID, "中" * 3):
            with self.subTest(password=password):
                self.assert_strength_shape(estimate_strength(password))

    def test_monotonic_with_strength(self):
        samples = [
            "a",
            "abcdefgh",
            "Abcd1234",
            "Abcd1234efgh",
            BASE_VALID,
            BASE_VALID + BASE_VALID,
        ]
        strengths = [estimate_strength(p) for p in samples]
        for i in range(1, len(strengths)):
            with self.subTest(weaker=samples[i - 1], stronger=samples[i]):
                self.assertLessEqual(
                    strengths[i - 1]["score"],
                    strengths[i]["score"],
                    "更强的密码得分不应更低: %r -> %r" % (samples[i - 1], samples[i]),
                )
                self.assertLessEqual(
                    strengths[i - 1]["percent"],
                    strengths[i]["percent"],
                    "更强的密码 percent 不应更低: %r -> %r" % (samples[i - 1], samples[i]),
                )

    def test_longer_password_not_weaker(self):
        short = estimate_strength("Ab1!Ab1!")
        longer = estimate_strength("Ab1!Ab1!Ab1!Ab1!")
        self.assertGreaterEqual(longer["score"], short["score"])
        self.assertGreaterEqual(longer["percent"], short["percent"])

    def test_very_strong_password_scores_high(self):
        strength = estimate_strength(BASE_VALID)
        self.assertGreaterEqual(strength["score"], 3)
        self.assertIn(strength["label"], ("强", "很强"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
