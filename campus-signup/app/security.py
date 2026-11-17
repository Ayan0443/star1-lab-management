#!/usr/bin/env python3
"""密码策略：生成 / 校验 / 强度估计（SPEC §9）。

公开接口：
    generate_password(length=16)           -> str
    validate_password(password, username)  -> (ok, error_message)
    estimate_strength(password)            -> {"score": 0-4, "label": str, "percent": int}
"""

import secrets

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
# SPEC §9.1 限定的符号集合
SYMBOLS = "!@#$%^&*()-_=+[]{};,.?/|~"

MIN_LENGTH = 12
MAX_LENGTH = 64

# 易混淆字符（生成时排除）
AMBIGUOUS = frozenset("0O1lI")

# 常见弱密码（小写比较），覆盖 SPEC 明确要求的内置条目
WEAK_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "1234567890ab",
        "111111111111",
        "000000000000",
        "password1234",
        "password12345",
        "password123!",
        "qwertyuiop12",
        "qwertyuiopas",
        "qwerty123456",
        "administrator1",
        "admin1234567",
        "admin123456!",
        "p@ssw0rd1234",
        "p@ssw0rd!2345",
        "aa123456789!",
        "aa1234567890!",
        "abc123456789",
        "aa123456789",
        "iloveyou1234",
        "letmein123456",
        "welcome12345",
        "changeme1234",
        "passw0rd1234",
        "root12345678",
        "test12345678",
        "1qaz2wsx3edc",
        "zaq12wsxcde3",
        "1q2w3e4r5t6y",
        "qwerty!@#$%^",
        "abcdefghijkl",
        "1234567890!@#",
        "qwertyuiop!@#",
        "a123456789012",
    }
)

STRENGTH_LABELS = ("很弱", "弱", "中等", "强", "很强")
STRENGTH_PERCENTS = (5, 25, 55, 80, 100)


def _has_lower(password):
    return any("a" <= ch <= "z" for ch in password)


def _has_upper(password):
    return any("A" <= ch <= "Z" for ch in password)


def _has_digit(password):
    return any("0" <= ch <= "9" for ch in password)


def _has_symbol(password):
    return any(ch in SYMBOLS for ch in password)


def _has_forbidden_char(password):
    allowed = set(LOWERCASE + UPPERCASE + DIGITS + SYMBOLS)
    return any(ch not in allowed for ch in password)


def _max_repeat_run(password):
    if not password:
        return 0
    best = 1
    run = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            run += 1
            if run > best:
                best = run
        else:
            run = 1
    return best


def validate_password(password, username):
    """校验密码是否满足 SPEC §9.1。

    返回 ``(True, "")`` 或 ``(False, 具体中文提示)``。
    ``username`` 为空/None 时跳过「不得包含用户名」检查。
    """
    if not isinstance(password, str):
        return False, "密码格式不正确"
    if len(password) < MIN_LENGTH:
        return False, "密码长度至少 12 位"
    if len(password) > MAX_LENGTH:
        return False, "密码长度不能超过 64 位"
    if password.lower() in WEAK_PASSWORDS:
        return False, "密码过于常见，请更换"
    if _has_forbidden_char(password):
        return False, "密码包含不允许的字符（仅支持字母、数字和 !@#$%^&*()-_=+[]{};,.?/|~）"
    if not _has_lower(password):
        return False, "需包含小写字母"
    if not _has_upper(password):
        return False, "需包含大写字母"
    if not _has_digit(password):
        return False, "需包含数字"
    if not _has_symbol(password):
        return False, "需包含符号（!@#$%^&*()-_=+[]{};,.?/|~）"
    if _max_repeat_run(password) >= 4:
        return False, "密码不能包含 4 个及以上连续相同字符"
    if isinstance(username, str) and username:
        needle = username.strip().lower()
        if len(needle) >= 2 and needle in password.lower():
            return False, "密码不能包含用户名"
    return True, ""


def _generate_once(length):
    rng = secrets.SystemRandom()
    lower_pool = "".join(ch for ch in LOWERCASE if ch not in AMBIGUOUS)
    upper_pool = "".join(ch for ch in UPPERCASE if ch not in AMBIGUOUS)
    digit_pool = "".join(ch for ch in DIGITS if ch not in AMBIGUOUS)
    symbol_pool = "".join(ch for ch in SYMBOLS if ch not in AMBIGUOUS)
    all_pool = lower_pool + upper_pool + digit_pool + symbol_pool
    chars = [
        rng.choice(lower_pool),
        rng.choice(upper_pool),
        rng.choice(digit_pool),
        rng.choice(symbol_pool),
    ]
    chars.extend(rng.choice(all_pool) for _ in range(length - len(chars)))
    rng.shuffle(chars)
    return "".join(chars)


def generate_password(length=16):
    """生成满足 SPEC §9 的强密码（secrets，排除易混淆字符）。"""
    try:
        length = int(length)
    except (TypeError, ValueError):
        raise ValueError("密码长度必须是整数")
    if length < 4:
        raise ValueError("密码长度至少 4 位")
    if length > MAX_LENGTH:
        raise ValueError("密码长度不能超过 64 位")
    for _ in range(200):
        password = _generate_once(length)
        ok, _err = validate_password(password, "")
        if ok:
            return password
    raise RuntimeError("密码生成失败，请重试")  # pragma: no cover


def estimate_strength(password):
    """估计密码强度，仅用于 UI 展示（0-4 分，单调合理）。"""
    if not isinstance(password, str) or not password:
        return {"score": 0, "label": STRENGTH_LABELS[0], "percent": 0}

    length = len(password)
    classes = 0
    if _has_lower(password):
        classes += 1
    if _has_upper(password):
        classes += 1
    if _has_digit(password):
        classes += 1
    if _has_symbol(password) or _has_forbidden_char(password):
        classes += 1

    points = 0
    if length >= 8:
        points += 1
    if length >= 12:
        points += 1
    if length >= 16:
        points += 1
    if classes >= 2:
        points += 1
    if classes >= 3:
        points += 1
    if classes >= 4:
        points += 1

    if _max_repeat_run(password) >= 4:
        points -= 1
    if len(set(password)) <= max(1, length // 3):
        points -= 1

    score = points - 2
    if score < 0:
        score = 0
    if score > 4:
        score = 4
    return {
        "score": score,
        "label": STRENGTH_LABELS[score],
        "percent": STRENGTH_PERCENTS[score],
    }
