"""i18n.go 생성기. 소스의 모든 T("...") 문장에 일본어 번역이 있는지 확인하고, 없으면 멈춥니다.
사용법: python3 res/gen_i18n.py   (nikke-check 폴더에서)"""
import re
import sys

sys.path.insert(0, "res")
from ja_strings import JA  # noqa: E402
from ja_strings2 import JA2, GUIDE_JA2  # noqa: E402

GO_FILES = ["main.go", "scan.go", "fix.go", "win.go", "procs.go", "wipe.go", "optimize.go"]

table = dict(JA)
table.update(JA2)

quoted, raws = set(), []
for fn in GO_FILES:
    src = open(fn, encoding="utf-8").read()
    quoted.update(m.group(1) for m in re.finditer(r'T\("((?:[^"\\\n]|\\.)*)"\)', src))
    raws += [m.group(1) for m in re.finditer(r"T\(`([^`]*)`\)", src)]

missing = sorted(q for q in quoted if q not in table)
if missing:
    print("번역 없음:")
    for m in missing:
        print("  " + repr(m))
    sys.exit(1)
if len(raws) != 1:
    sys.exit("안내문(raw 문자열)이 1개가 아닙니다: %d" % len(raws))

used = {k: table[k] for k in sorted(quoted)}
for k, v in used.items():
    if '"' in k.replace('\\"', "") or '"' in v.replace('\\"', ""):
        sys.exit("따옴표 문제: " + k)
    if k.count("%") != v.count("%"):
        sys.exit("서식 문자(%) 개수가 다름: " + k)

out = [
    "//go:build windows",
    "",
    "// 번역 (자동 생성: res/gen_i18n.py). 한국어 원문을 키로 씁니다.",
    '// 일본어판 빌드: go build -ldflags "-X main.lang=ja" ...',
    "package main",
    "",
    '// 빌드할 때 -ldflags "-X main.lang=ja" 로 바꿉니다.',
    'var lang = "ko"',
    "",
    "// T 는 현재 언어에 맞는 문자열을 돌려줍니다. 번역이 없으면 원문을 그대로 씁니다.",
    "func T(s string) string {",
    '\tif lang == "ja" {',
    "\t\tif v, ok := jaStrings[s]; ok {",
    "\t\t\treturn v",
    "\t\t}",
    "\t}",
    "\treturn s",
    "}",
    "",
    "func uiFontName() string {",
    '\tif lang == "ja" {',
    '\t\treturn "Yu Gothic UI"',
    "\t}",
    '\treturn "Malgun Gothic"',
    "}",
    "",
    "var jaStrings = map[string]string{",
]
for k, v in used.items():
    out.append('\t"%s": "%s",' % (k, v))
out.append("\t`" + raws[0] + "`: `" + GUIDE_JA2 + "`,")
out.append("}")
open("i18n.go", "w", encoding="utf-8").write("\n".join(out) + "\n")
print("i18n.go: %d개 문장 + 안내문 1개" % len(used))
