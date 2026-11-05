"""VS_VERSIONINFO 리소스 생성기.  사용법: python3 make_versioninfo.py ko|ja 출력파일"""
import struct
import sys

VERSION = (2, 5, 4, 0)

INFO = {
    "ko": (0x0412, {
        "CompanyName": "NIKKE community (open source)",
        "FileDescription": "니케 런처 해킹 점검·복구 도구",
        "ProductName": "NIKKE Hack Checker",
        "Comments": "2026년 11월 니케 PC 런처 해킹(insightjs/k2f) 점검 도구. 검사는 읽기 전용, 해결은 사용자가 확인한 항목만 실행.",
    }),
    "ja": (0x0411, {
        "CompanyName": "NIKKE community (open source)",
        "FileDescription": "NIKKEランチャー ハッキング チェック・復旧ツール",
        "ProductName": "NIKKE Hack Checker",
        "Comments": "2026年11月のNIKKE PCランチャー改ざん(insightjs/k2f)のチェックツール。チェックは読み取りのみ、対処はユーザーが確認した項目だけを実行。",
    }),
}


def wstr(s):
    return (s + "\0").encode("utf-16-le")


def pad4(b):
    return b + b"\0" * ((4 - len(b) % 4) % 4)


def node(key, value=b"", wtype=1, vlen=0, children=b""):
    body = pad4(struct.pack("<HHH", 0, vlen, wtype) + wstr(key))
    if value:
        body = pad4(body + value)
    body += children
    return struct.pack("<H", len(body)) + body[2:]


def build(lang):
    langid, strings = INFO[lang]
    v = ".".join(map(str, VERSION))
    strings = dict(strings, FileVersion=v, ProductVersion=v, InternalName="nikke_check",
                   OriginalFilename="nikke_check_%s.exe" % lang,
                   LegalCopyright="Open source - source code distributed with this file")
    ms = (VERSION[0] << 16) | VERSION[1]
    ls = (VERSION[2] << 16) | VERSION[3]
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    table = b"".join(pad4(node(k, wstr(s), 1, len(s) + 1)) for k, s in strings.items())
    st = pad4(node("%04X04B0" % langid, children=table))
    sfi = pad4(node("StringFileInfo", children=st))
    var = pad4(node("Translation", struct.pack("<HH", langid, 0x04B0), 0, 4))
    vfi = pad4(node("VarFileInfo", children=var))
    return node("VS_VERSION_INFO", fixed, 0, len(fixed), children=sfi + vfi)


if __name__ == "__main__":
    open(sys.argv[2], "wb").write(build(sys.argv[1]))
