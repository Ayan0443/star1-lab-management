#!/usr/bin/env python3
"""姓名校验与拼音转换工具（SPEC §8）。

公开接口：
    normalize_real_name(raw)      -> (normalized_name, error_message)
    name_to_pinyin(name)          -> (pinyin, error_message)
    SINGLE_SURNAME_OVERRIDES      -> dict  单字多音姓氏补丁
    COMPOUND_SURNAME_OVERRIDES    -> dict  复姓补丁

依赖项目内置的 pypinyin（vendor/site-packages），不使用任何第三方在线服务。
"""

import os
import re
import sys

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_APP_DIR)
_VENDOR_DIR = os.path.join(_PROJECT_ROOT, "vendor", "site-packages")
if os.path.isdir(_VENDOR_DIR) and _VENDOR_DIR not in sys.path:
    sys.path.insert(0, _VENDOR_DIR)

try:  # pragma: no cover - 导入失败属于部署问题
    from pypinyin import Style, lazy_pinyin
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "未找到 pypinyin，请确认 %s 存在" % _VENDOR_DIR
    ) from exc


MIDDLE_DOT = "\u00b7"  # 间隔号 U+00B7
MIN_HANZI = 2
MAX_HANZI = 10
MAX_TOTAL_CHARS = 24
MIN_PINYIN_LEN = 2
MAX_PINYIN_LEN = 28

_HANZI_START = 0x4E00
_HANZI_END = 0x9FFF

# 单字多音姓氏补丁：pypinyin 默认读音在作姓氏时不正确者。
SINGLE_SURNAME_OVERRIDES = {
    "曾": "zeng",
    "单": "shan",
    "解": "xie",
    "仇": "qiu",
    "区": "ou",
    "查": "zha",
    "朴": "piao",
    "缪": "miao",
    "尉": "yu",
    "盖": "ge",
    "折": "she",
    "乐": "yue",
    "覃": "qin",
    "秘": "bi",
    "员": "yun",
    "长": "chang",
    "重": "chong",
    "角": "jue",
    "阚": "kan",
    "句": "gou",
    "藏": "zang",
    "种": "chong",
    "祭": "zhai",
    "繁": "po",
    "圈": "juan",
    "番": "pan",
    "召": "shao",
    "射": "ye",
    "洗": "xian",
}

# 复姓补丁：值为前两个音节的读法（连写）。
COMPOUND_SURNAME_OVERRIDES = {
    "欧阳": "ouyang",
    "尉迟": "yuchi",
    "万俟": "moqi",
    "澹台": "tantai",
    "长孙": "zhangsun",
    "皇甫": "huangfu",
    "令狐": "linghu",
    "上官": "shangguan",
    "司马": "sima",
    "诸葛": "zhuge",
    "东方": "dongfang",
    "独孤": "dugu",
    "慕容": "murong",
    "宇文": "yuwen",
    "司徒": "situ",
    "司空": "sikong",
    "公孙": "gongsun",
    "端木": "duanmu",
    "夏侯": "xiahou",
    "南宫": "nangong",
    "西门": "ximen",
    "呼延": "huyan",
    "赫连": "helian",
    "钟离": "zhongli",
    "拓跋": "tuoba",
    "申屠": "shentu",
    "太史": "taishi",
    "仲孙": "zhongsun",
    "闻人": "wenren",
    "公冶": "gongye",
    "宗政": "zongzheng",
    "濮阳": "puyang",
    "淳于": "chunyu",
    "单于": "chanyu",
    "太叔": "taishu",
    "完颜": "wanyan",
    "公羊": "gongyang",
    "轩辕": "xuanyuan",
    "段干": "duangan",
    "百里": "baili",
    "东郭": "dongguo",
    "南门": "nanmen",
    "羊舌": "yangshe",
    "微生": "weisheng",
    "梁丘": "liangqiu",
    "左丘": "zuoqiu",
    "东里": "dongli",
    "第五": "diwu",
    "即墨": "jimo",
    "达奚": "daxi",
    "褚师": "chushi",
    "闾丘": "lvqiu",
    "亓官": "qiguan",
    "司寇": "sikou",
    "巫马": "wuma",
    "公西": "gongxi",
    "颛孙": "zhuansun",
    "壤驷": "rangsi",
    "公良": "gongliang",
    "漆雕": "qidiao",
    "乐正": "yuezheng",
    "宰父": "zaifu",
    "谷梁": "guliang",
    "夹谷": "jiagu",
    "鲜于": "xianyu",
}

_NON_PINYIN_RE = re.compile(r"[^a-z]")


def _is_hanzi(ch):
    return _HANZI_START <= ord(ch) <= _HANZI_END


def normalize_real_name(raw):
    """校验并规范化中文真实姓名。

    返回 ``(normalized_name, "")`` 或 ``(None, 中文错误提示)``。
    """
    if raw is None:
        return None, "请输入真实姓名"
    if not isinstance(raw, str):
        return None, "姓名格式不正确"
    # 去掉首尾与姓名中间的空白（含全角空格 U+3000，str.isspace() 覆盖）
    cleaned = "".join(ch for ch in raw if not ch.isspace())
    if not cleaned:
        return None, "请输入真实姓名"
    if len(cleaned) > MAX_TOTAL_CHARS:
        return None, "姓名过长（最多 24 个字符）"

    for ch in cleaned:
        if ch == MIDDLE_DOT:
            continue
        if not _is_hanzi(ch):
            return None, "姓名只能包含中文汉字（少数民族姓名可使用间隔号·）"

    if cleaned.startswith(MIDDLE_DOT) or cleaned.endswith(MIDDLE_DOT):
        return None, "间隔号·不能位于姓名开头或结尾"
    if MIDDLE_DOT * 2 in cleaned:
        return None, "间隔号·不能连续出现"

    hanzi_count = len(cleaned) - cleaned.count(MIDDLE_DOT)
    if hanzi_count < MIN_HANZI or hanzi_count > MAX_HANZI:
        return None, "姓名需为 2–10 个汉字"

    return cleaned, ""


def _split_per_hanzi(chars):
    """按汉字逐个转换，保证音节与汉字一一对应。"""
    syllables = lazy_pinyin(chars, style=Style.NORMAL, errors="default")
    if len(syllables) == len(chars):
        return [str(s or "") for s in syllables]
    # 极少数情况下 lazy_pinyin 的音节数与汉字数不一致，退化为逐字转换。
    result = []
    for ch in chars:
        parts = lazy_pinyin(ch, style=Style.NORMAL, errors="default")
        result.append(str(parts[0]) if parts else "")
    return result


def name_to_pinyin(name):
    """中文姓名 -> 无声调小写全拼（SPEC §8.2）。

    返回 ``(pinyin, "")`` 或 ``(None, 中文错误提示)``。
    """
    normalized, err = normalize_real_name(name)
    if err or normalized is None:
        return None, err or "姓名格式不正确"

    chars = normalized.replace(MIDDLE_DOT, "")
    try:
        syllables = _split_per_hanzi(chars)
    except Exception:  # pragma: no cover - pypinyin 异常视为名称无法转换
        return None, "姓名解析失败，请联系管理员"

    # 多音姓氏补丁：只影响姓氏读音，其余音节使用 pypinyin 默认读音。
    if len(chars) >= 3 and chars[:2] in COMPOUND_SURNAME_OVERRIDES:
        syllables = [COMPOUND_SURNAME_OVERRIDES[chars[:2]]] + syllables[2:]
    elif chars and chars[0] in SINGLE_SURNAME_OVERRIDES:
        syllables = [SINGLE_SURNAME_OVERRIDES[chars[0]]] + syllables[1:]

    pinyin = _NON_PINYIN_RE.sub("", "".join(syllables).lower())
    if len(pinyin) > MAX_PINYIN_LEN:
        return None, "姓名拼音过长，请联系管理员"
    if len(pinyin) < MIN_PINYIN_LEN:
        return None, "无法生成有效的姓名拼音，请联系管理员"
    return pinyin, ""
