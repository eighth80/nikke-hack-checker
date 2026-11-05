//go:build windows

// 감염 흔적 검사 (읽기 전용)
//
// 기준 자료:
//   - MotherSphere 분석 gist (gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5, 2026-11-04 02:00 GMT 판)
//   - nikke-checker v1.2.1 의 점검 규칙 (github.com/nikke-checker/nikke-checker): HSTS 해시 키, 에이전트 빌드 ETag,
//     구버전 지속성 파일, 로드된 DLL, 전체 드라이브 이름 검사, 설치 경로 찾기
//   - 니케 마이너 갤러리 "해킹사태 총정리함"
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	maliciousCLSID = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}"
	persistDir     = "PlatformExperienceHelper"
	dllName        = "platform_experience_helper.dll"
	oldPersistDir  = `Google\Chrome\Application\PlatformExperienceHelper`
	fwRuleName     = "Block NIKKE k2f attacker"
	knownAgentSize = 205135
	maxRead        = 64 * 1024 * 1024
)

var (
	agentIDLineRe = regexp.MustCompile(`(?i)(adopted|resuming) [0-9a-f]{8}-[0-9a-f]{4}-`)
	runLineRe     = regexp.MustCompile(`(?i)k2f_chan registered|adopted \S+|resuming \S+|agent started as|lua downloaded to`)
	agentNameRe   = regexp.MustCompile(`agent started as ([^"\s]+)`)
	agentIDRe     = regexp.MustCompile(`"agent_id"\s*:\s*"([0-9a-fA-F-]{36})"`)
	hex64Re       = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	hexDLLPathRe  = regexp.MustCompile(`(?i)\\PlatformExperienceHelper\\[0-9a-f]{64}\\platform_experience_helper\.dll`)
	loadedDLLRe   = regexp.MustCompile(`(?i)\\PlatformExperienceHelper\\([0-9a-f]{64}\\)?platform_experience_helper\.dll$`)
	etagRe        = regexp.MustCompile(`(?i)ETag:\s*"([0-9a-f]+)-([0-9a-f]+)"`)
	stsObservedRe = regexp.MustCompile(`"sts_observed"\s*:\s*([0-9.]+)`)
	jsonObjRe     = regexp.MustCompile(`\{[^{}]*\}`)
	launcherExeRe = regexp.MustCompile(`(?i)([A-Z]:\\[^"\r\n]*?)\\Launcher\\nikke_launcher(_google)?\.exe`)
	cloudLabelRe  = regexp.MustCompile(`(?i)Google Drive|OneDrive|Dropbox|pCloud|iCloud|MEGA|MYBOX|\bBox\b`)
	envVarRe      = regexp.MustCompile(`%([^%]+)%`)
	exeInCmd      = regexp.MustCompile(`^\s*"?([^"]+?\.exe)`)

	// 로더 스크립트가 남기는 V8 코드 캐시 파일 이름 (모든 PC에서 같음)
	loaderCacheNames = map[string]string{
		"dd65fa4d61079e7e_0": "aegis",
		"ce2fd3f1007a9fe9_0": "images",
		"1416c638b3830103_0": "feedlist",
		"fd520c7c0f65c2d7_0": "vue",
	}

	// TransportSecurity(HSTS)에는 도메인 문자열이 아니라 base64(SHA-256(DNS 형식 호스트 이름))가 남습니다.
	hstsKeys = []struct{ domain, key string }{
		{"insightjs.com", "JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg="},
		{"analytics.insightjs.com", "wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw="},
		{"insightjs.org", "+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk="},
	}

	// insight.bundle 빌드 ETag ("<mtime hex>-3214f")
	knownBuildEtags = map[string]bool{"6ae78037": true, "6ae8ccff": true, "6ae90538": true, "6ae9d408": true, "6ae9f628": true}

	oldPersistFiles = []string{"platform_experience_helper.dll", "platform_experience_helper.dll.old", "old-clsid.txt"}

	blockDomains = []string{"insightjs.com", "analytics.insightjs.com", "insightjs.org"}
	blockIPs     = "89.127.233.127,89.126.250.172"

	launcherProcNames = []string{"nikke_launcher.exe", "nikke_launcher_google.exe", "nikke_launcher_hmt.exe", "tbs_browser.exe", "intl_service.exe"}
)

type browserDef struct{ name, userData, exe, hint string }

// 크로미움 계열 브라우저: 이름, User Data 경로, 프로세스 이름, 실행 파일 경로 힌트
func chromiumBrowsers() []browserDef {
	l := expand("%LOCALAPPDATA%")
	a := expand("%APPDATA%")
	list := []browserDef{
		{"Chrome", l + `\Google\Chrome\User Data`, "chrome.exe", ""},
		{"Chrome Beta", l + `\Google\Chrome Beta\User Data`, "chrome.exe", ""},
		{"Chrome Dev", l + `\Google\Chrome Dev\User Data`, "chrome.exe", ""},
		{"Chrome Canary", l + `\Google\Chrome SxS\User Data`, "chrome.exe", ""},
		{"Chromium", l + `\Chromium\User Data`, "chrome.exe", `\Chromium\`},
		{"Edge", l + `\Microsoft\Edge\User Data`, "msedge.exe", ""},
		{"Edge Beta", l + `\Microsoft\Edge Beta\User Data`, "msedge.exe", ""},
		{"Edge Dev", l + `\Microsoft\Edge Dev\User Data`, "msedge.exe", ""},
		{"Edge Canary", l + `\Microsoft\Edge SxS\User Data`, "msedge.exe", ""},
		{"Brave", l + `\BraveSoftware\Brave-Browser\User Data`, "brave.exe", ""},
		{"Brave Beta", l + `\BraveSoftware\Brave-Browser-Beta\User Data`, "brave.exe", ""},
		{"Brave Nightly", l + `\BraveSoftware\Brave-Browser-Nightly\User Data`, "brave.exe", ""},
		{"Vivaldi", l + `\Vivaldi\User Data`, "vivaldi.exe", ""},
		{"네이버 웨일", l + `\Naver\Naver Whale\User Data`, "whale.exe", ""},
		{"Opera", a + `\Opera Software\Opera Stable`, "opera.exe", ""},
		{"Opera GX", a + `\Opera Software\Opera GX Stable`, "opera.exe", ""},
		{"Yandex", l + `\Yandex\YandexBrowser\User Data`, "browser.exe", `\Yandex\`},
		{"Cốc Cốc", l + `\CocCoc\Browser\User Data`, "browser.exe", `\CocCoc\`},
		{"Comodo Dragon", l + `\Comodo\Dragon\User Data`, "dragon.exe", ""},
		{"Thorium", l + `\Thorium\User Data`, "thorium.exe", ""},
		{"Epic", l + `\Epic Privacy Browser\User Data`, "epic.exe", ""},
	}
	// Arc 는 MSIX 패키지 폴더 아래에 User Data 가 있음
	if ms, _ := filepath.Glob(l + `\Packages\TheBrowserCompany.Arc_*`); len(ms) > 0 {
		for _, m := range ms {
			list = append(list, browserDef{"Arc", m + `\LocalCache\Local\Arc\User Data`, "arc.exe", ""})
		}
	}
	return list
}

type severity int

const (
	sevInfo severity = iota
	sevOpt           // 선택 사항 (쿠키·데이터 삭제). 기본으로 체크하지 않음
	sevTune          // PC 최적화 항목 (기본 체크)
	sevFix           // 감염 흔적은 아니지만 예방 조치가 가능한 항목
	sevWarn
	sevCrit
)

func (s severity) label() string {
	return map[severity]string{sevInfo: T("정상"), sevOpt: T("선택 사항"), sevTune: T("최적화"), sevFix: T("예방 조치"), sevWarn: T("주의"), sevCrit: T("감염 흔적")}[s]
}

type fixKind int

const (
	fixNone         fixKind = iota
	fixRegKey               // HKCU 레지스트리 키 삭제 (백업 후)
	fixFile                 // 악성 파일 삭제
	fixHashDir              // 브라우저의 64자리 해시 폴더 삭제
	fixCache                // 런처 캐시(tbs_cache) 삭제
	fixBlock                // hosts·방화벽 차단 (관리자 권한)
	fixKill                 // 프로세스 종료
	fixOldElev              // Program Files 의 구버전 지속성 파일 삭제 (관리자 권한)
	fixWipeLauncher         // 런처 데이터 폴더 전체 삭제 (선택)
	fixWipeCookies          // 브라우저 쿠키 삭제 (선택)
	fixWipeSiteData         // 브라우저 사이트 데이터 삭제 (선택)
)

func (k fixKind) label() string {
	if l, ok := optLabel(k); ok {
		return l
	}
	return map[fixKind]string{
		fixNone: "-", fixRegKey: T("레지스트리 키 삭제(백업)"), fixFile: T("파일 삭제"),
		fixHashDir: T("악성 폴더 삭제"), fixCache: T("런처 캐시 삭제"), fixBlock: T("공격자 서버 차단(관리자)"),
		fixKill: T("프로세스 종료"), fixOldElev: T("파일 삭제(관리자)"),
		fixWipeLauncher: T("런처 데이터 전체 삭제"), fixWipeCookies: T("쿠키 삭제"), fixWipeSiteData: T("사이트 데이터 삭제"),
	}[k]
}

type finding struct {
	sev        severity
	title      string
	where      string
	detail     string
	fix        fixKind
	target     string   // 조치 대상 (파일/폴더 경로, 레지스트리 경로)
	pid        uint32   // fixKill 대상
	browserExe string   // 지우려면 닫아야 하는 브라우저 (예: chrome.exe)
	browserHnt string   // browser.exe 처럼 흔한 이름일 때 경로 힌트
	fromDisk   bool     // 전체 드라이브 검사에서 나온 항목 (중복 제거용)
	targets    []string // 여러 경로를 지우는 항목 (쿠키·사이트 데이터)
}

type scanResult struct {
	findings      []finding
	roots         []string
	crit          int
	warn          int
	unreadable    []string
	hkcuDLL       string
	fullScan      bool
	noInstallMode bool // 이미 니케를 지운 사람용 점검
	optimizeMode  bool // PC 간단 최적화 결과
}

type scanner struct {
	r        *scanResult
	progress func(string)
}

func (s *scanner) add(f finding) { s.r.findings = append(s.r.findings, f) }

// ---------------------------------------------------------------------------
// 파일/레지스트리 유틸
// ---------------------------------------------------------------------------

func expand(p string) string {
	return envVarRe.ReplaceAllStringFunc(p, func(m string) string {
		if v, ok := os.LookupEnv(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }
func isDir(p string) bool  { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
func isFile(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

func modTime(p string) string {
	if fi, err := os.Stat(p); err == nil {
		return fi.ModTime().Format("2006-01-02 15:04:05")
	}
	return "?"
}

func fileSize(p string) int64 {
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return -1
}

// 런처가 열어 둔 파일도 읽을 수 있게 공유 모드로 엽니다(읽기 전용).
func openShared(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func readHead(path string, max int64) []byte {
	f, err := openShared(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil && len(b) == 0 {
		return nil
	}
	if b == nil {
		b = []byte{}
	}
	return b
}

// ASCII 소문자로 바꾼 사본 (바이너리 안전)
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		out[i] = c
	}
	return out
}

// 소문자로 바꾼 데이터에서 ASCII 또는 UTF-16LE 로 needle 을 찾습니다.
func hasCI(lower []byte, needle string) bool {
	n := strings.ToLower(needle)
	if bytes.Contains(lower, []byte(n)) {
		return true
	}
	u := make([]byte, 0, len(n)*2)
	for i := 0; i < len(n); i++ {
		u = append(u, n[i], 0)
	}
	return bytes.Contains(lower, u)
}

func isLuaJITBytes(h []byte) bool { return len(h) >= 3 && h[0] == 0x1B && h[1] == 0x4C && h[2] == 0x4A }
func isLuaJIT(p string) bool      { return isLuaJITBytes(readHead(p, 3)) }

// 에이전트가 만드는 이름 형식(k2f-, k2f_, k2f.)만. 대소문자 구분 — K2F3A.tmp 같은 임의 이름 오탐 방지.
func isK2fName(n string) bool {
	return strings.HasPrefix(n, "k2f-") || strings.HasPrefix(n, "k2f_") || strings.HasPrefix(n, "k2f.")
}

// 에이전트 상태에 저장된 비밀값은 출력하지 않음
func redactLine(s string) string {
	if i := strings.Index(strings.ToLower(s), "agent_pass"); i >= 0 {
		s = s[:i] + "…"
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func isUnderUserProfile(p string) bool {
	up := strings.TrimRight(os.Getenv("USERPROFILE"), `\`)
	return up != "" && strings.HasPrefix(strings.ToLower(p), strings.ToLower(up)+`\`)
}

func hiddenCmd(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 /*CREATE_NO_WINDOW*/}
	return c
}

func regOpen(root syscall.Handle, path string) (syscall.Handle, bool) {
	var h syscall.Handle
	if syscall.RegOpenKeyEx(root, u16(path), 0, syscall.KEY_READ, &h) != nil {
		return 0, false
	}
	return h, true
}

func regKeyExists(root syscall.Handle, path string) bool {
	h, ok := regOpen(root, path)
	if ok {
		syscall.RegCloseKey(h)
	}
	return ok
}

func regString(root syscall.Handle, path, name string) string {
	h, ok := regOpen(root, path)
	if !ok {
		return ""
	}
	defer syscall.RegCloseKey(h)
	var typ, n uint32
	np := u16(name)
	if syscall.RegQueryValueEx(h, np, nil, &typ, nil, &n) != nil || n == 0 {
		return ""
	}
	buf := make([]uint16, n/2+1)
	if syscall.RegQueryValueEx(h, np, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n) != nil {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func regSubkeys(root syscall.Handle, path string) []string {
	h, ok := regOpen(root, path)
	if !ok {
		return nil
	}
	defer syscall.RegCloseKey(h)
	var names []string
	for i := uint32(0); ; i++ {
		buf := make([]uint16, 512)
		n := uint32(len(buf))
		if syscall.RegEnumKeyEx(h, i, &buf[0], &n, nil, nil, nil, nil) != nil {
			break
		}
		names = append(names, syscall.UTF16ToString(buf[:n]))
	}
	return names
}

// 정션·심볼릭 링크 폴더인지 (따라 들어가지 않기 위해)
func isReparseDir(d os.DirEntry) bool {
	return d.Type()&(os.ModeSymlink|os.ModeIrregular) != 0
}

// ---------------------------------------------------------------------------
// 니케 설치 경로 찾기
// ---------------------------------------------------------------------------

func isInstall(root string) bool {
	return root != "" && (isFile(filepath.Join(root, `Launcher\nikke_launcher.exe`)) ||
		isFile(filepath.Join(root, `Launcher\intl_service\debug.log`)) ||
		isFile(filepath.Join(root, `Launcher\nikke_launcher_google.exe`)) ||
		isDir(filepath.Join(root, `Launcher\intl_service`)) ||
		isDir(filepath.Join(root, `Launcher\log`)))
}

// 니케 최상위 폴더, Launcher 폴더, 런처 exe, 그 상위 폴더(예: D:\Games) 중 무엇을 줘도
// "Launcher"가 들어 있는 니케 루트 폴더를 돌려줍니다.
func resolveRoot(c string) string { return resolveRootDepth(c, 0) }

func resolveRootDepth(c string, depth int) string {
	c = strings.TrimSpace(strings.Trim(strings.TrimSpace(c), `"'`))
	if c == "" {
		return ""
	}
	c = expand(c)
	if isFile(c) {
		c = filepath.Dir(c)
	}
	if !isDir(c) {
		return ""
	}
	c, _ = filepath.Abs(c)
	c = strings.TrimRight(c, `\`)
	if isInstall(c) {
		return c
	}
	low := strings.ToLower(filepath.Base(c))
	switch low {
	case "launcher":
		if isInstall(filepath.Dir(c)) {
			return filepath.Dir(c)
		}
	case "intl_service", "log":
		return resolveRootDepth(filepath.Dir(filepath.Dir(c)), depth)
	case "tinyget":
		return resolveRootDepth(filepath.Dir(filepath.Dir(filepath.Dir(c))), depth)
	}
	// 하위에 NIKKE 폴더가 있는 경우 (최대 2단계)
	if depth < 2 {
		if entries, err := os.ReadDir(c); err == nil {
			for _, e := range entries {
				if e.IsDir() && strings.Contains(strings.ToUpper(e.Name()), "NIKKE") {
					if r := resolveRootDepth(filepath.Join(c, e.Name()), depth+1); r != "" {
						return r
					}
				}
			}
		}
	}
	return ""
}

// 런처 실행 파일 경로가 들어 있는 문자열에서 설치 루트를 뽑습니다.
func rootFromValue(v string) string {
	if m := launcherExeRe.FindStringSubmatch(strings.ReplaceAll(v, `\\`, `\`)); m != nil {
		return m[1]
	}
	return ""
}

func autoFindRoots(walkDrivesIfNone bool, progress func(string)) []string {
	var c []string
	for d := 'C'; d <= 'Z'; d++ {
		root := string(d) + `:\`
		if exists(root) {
			c = append(c, root+"NIKKE", root+`Games\NIKKE`, root+`Program Files\NIKKE`, root+`Program Files (x86)\NIKKE`,
				root+`Program Files\Level Infinite\NIKKE`)
		}
	}
	// 설치 프로그램 목록: 키 이름에 nikke 가 들어가거나 표시 이름이 NIKKE 인 모든 키
	for _, u := range []struct {
		root syscall.Handle
		path string
	}{
		{syscall.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	} {
		for _, k := range regSubkeys(u.root, u.path) {
			kp := u.path + `\` + k
			if !strings.Contains(strings.ToUpper(k), "NIKKE") && !strings.Contains(strings.ToUpper(regString(u.root, kp, "DisplayName")), "NIKKE") {
				continue
			}
			for _, v := range []string{"GameInstallPath", "InstallLocation"} {
				if loc := regString(u.root, kp, v); loc != "" {
					c = append(c, loc)
				}
			}
			for _, v := range []string{"UninstallString", "DisplayIcon"} {
				val := regString(u.root, kp, v)
				if r := rootFromValue(val); r != "" {
					c = append(c, r)
				}
				if m := exeInCmd.FindStringSubmatch(val); m != nil {
					c = append(c, m[1])
				}
			}
		}
	}
	// nikkelauncher:// 링크 처리기
	for _, k := range []string{`Software\Classes\nikkelauncher\DefaultIcon`, `Software\Classes\nikkelauncher\Shell\Open\Command`} {
		v := regString(syscall.HKEY_CURRENT_USER, k, "")
		if r := rootFromValue(v); r != "" {
			c = append(c, r)
		}
		if m := exeInCmd.FindStringSubmatch(v); m != nil {
			c = append(c, m[1])
		}
	}
	// 런처가 남긴 url_protocol.reg
	for _, name := range []string{"nikke_launcher", "nikke_launcher_hmt"} {
		b := readHead(filepath.Join(os.Getenv("APPDATA"), name, "url_protocol.reg"), 1024*1024)
		if b == nil {
			continue
		}
		text := string(b)
		if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
			u := make([]uint16, 0, len(b)/2)
			for i := 2; i+1 < len(b); i += 2 {
				u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
			}
			text = syscall.UTF16ToString(append(u, 0))
		}
		for _, m := range launcherExeRe.FindAllStringSubmatch(strings.ReplaceAll(text, `\\`, `\`), -1) {
			c = append(c, m[1])
		}
	}
	// 스팀 라이브러리
	steamRoots := []string{expand(`%ProgramFiles(x86)%\Steam`), expand(`%ProgramFiles%\Steam`)}
	if sp := regString(syscall.HKEY_CURRENT_USER, `Software\Valve\Steam`, "SteamPath"); sp != "" {
		steamRoots = append(steamRoots, strings.ReplaceAll(sp, "/", `\`))
	}
	libRe := regexp.MustCompile(`"path"\s+"([^"]+)"`)
	for _, sr := range steamRoots {
		libs := []string{sr}
		if b, err := os.ReadFile(filepath.Join(sr, `steamapps\libraryfolders.vdf`)); err == nil {
			for _, m := range libRe.FindAllStringSubmatch(string(b), -1) {
				libs = append(libs, strings.ReplaceAll(m[1], `\\`, `\`))
			}
		}
		for _, lib := range libs {
			common := filepath.Join(lib, `steamapps\common`)
			if es, err := os.ReadDir(common); err == nil {
				for _, e := range es {
					if e.IsDir() && strings.Contains(strings.ToUpper(e.Name()), "NIKKE") {
						c = append(c, filepath.Join(common, e.Name()))
					}
				}
			}
		}
	}
	roots := dedupeRoots(c)
	if len(roots) == 0 && walkDrivesIfNone {
		// 기록된 설치 경로가 없으면 드라이브를 탐색 (7단계까지, \Windows 등 제외, 정션 미추적)
		for _, drive := range scanDrives() {
			if progress != nil {
				progress(fmt.Sprintf(T("설치 기록이 없어 %s 드라이브에서 니케 폴더를 찾는 중..."), drive))
			}
			c = append(c, walkForInstalls(drive)...)
		}
		roots = dedupeRoots(c)
	}
	return roots
}

func dedupeRoots(c []string) []string {
	seen := map[string]bool{}
	var roots []string
	for _, cand := range c {
		if r := resolveRoot(cand); r != "" && !seen[strings.ToLower(r)] {
			seen[strings.ToLower(r)] = true
			roots = append(roots, r)
		}
	}
	sort.Strings(roots)
	return roots
}

var skipRootDirs = map[string]bool{"windows": true, "$recycle.bin": true, "system volume information": true, "$winreagent": true, "recovery": true}

func walkForInstalls(drive string) []string {
	var found []string
	base := strings.TrimRight(drive, `\`)
	filepath.WalkDir(drive, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if p == drive {
			return nil
		}
		if isReparseDir(d) {
			return filepath.SkipDir
		}
		rel := strings.TrimPrefix(p, base+`\`)
		depth := strings.Count(rel, `\`) + 1
		if depth == 1 && skipRootDirs[strings.ToLower(d.Name())] {
			return filepath.SkipDir
		}
		if strings.EqualFold(d.Name(), "Launcher") && isInstall(filepath.Dir(p)) {
			found = append(found, filepath.Dir(p))
			return filepath.SkipDir
		}
		if depth >= 7 {
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

// ---------------------------------------------------------------------------
// 검사
// ---------------------------------------------------------------------------

func runScan(roots []string, fullScan, noInstall bool, progress func(string)) *scanResult {
	r := &scanResult{fullScan: fullScan, noInstallMode: noInstall}
	s := &scanner{r: r, progress: progress}
	step := func(t string) {
		if progress != nil {
			progress(t)
		}
	}

	step(T("레지스트리 확인 중..."))
	s.checkComHijack()
	step(T("브라우저 지속성 DLL 확인 중..."))
	s.checkBrowserPersistence()
	step(T("실행 중인 프로세스 확인 중..."))
	s.checkProcesses()
	step(T("런처 저장소 확인 중..."))
	s.checkLauncherProfile()
	step(T("임시 폴더 확인 중..."))
	s.checkTemp()
	var diskLaunchers []string
	if fullScan {
		diskLaunchers = s.checkFullScan()
	}
	// 전체 드라이브 검사에서 찾은 런처도 설치 폴더로 추가
	roots = dedupeRoots(append(append([]string{}, roots...), diskLaunchers...))
	r.roots = roots
	if len(roots) == 0 && noInstall {
		s.add(finding{sev: sevInfo, title: T("니케를 지운 상태로 점검: 설치 폴더 안의 런처 로그는 확인하지 않음"),
			detail: T("런처 로그(debug.log)는 니케를 지울 때 함께 사라집니다.\r\n") +
				T("대신 지운 뒤에도 남는 흔적 — 브라우저 악성 DLL, 레지스트리 키, %APPDATA%\\nikke_launcher 의 에이전트 상태·접속 기록, 임시 파일 — 을 확인했습니다.\r\n") +
				T("그래도 감염 여부를 확실히 알 수 없으니, 9/27 이후 PC 런처를 켠 적이 있다면 [털렸을 때 할 일]을 따르는 걸 권장합니다.")})
	} else if len(roots) == 0 {
		s.add(finding{sev: sevInfo, title: T("니케 설치 폴더를 찾지 못해 런처 로그 검사는 건너뜀"),
			detail: T("니케를 삭제했어도 아래 브라우저·레지스트리·런처 저장소 검사는 그대로 의미가 있습니다.\r\n") +
				T("런처를 이미 지웠다면 지난 실행 기록도 함께 지워져, 그동안 감염됐었는지는 이 항목으로 알 수 없습니다.\r\n") +
				T("설치 폴더가 남아 있다면 위에서 폴더를 추가하고 다시 검사하세요.")})
	}
	for _, root := range roots {
		step(T("니케 설치 폴더 로그 확인 중: ") + root)
		s.checkInstall(root)
	}
	step(T("DNS 캐시·차단 상태 확인 중..."))
	s.checkDNSCache()
	s.checkBlocking()
	s.dedupeDiskFindings()
	if len(roots) == 0 || s.hasCrit() {
		s.addWipeOptions(len(roots) == 0)
	}

	for _, f := range r.findings {
		switch f.sev {
		case sevCrit:
			r.crit++
		case sevWarn:
			r.warn++
		}
	}
	if len(r.unreadable) > 0 {
		shown := r.unreadable
		if len(shown) > 30 {
			shown = shown[:30]
		}
		s.add(finding{sev: sevInfo, title: fmt.Sprintf(T("읽지 못해 검사가 불완전한 파일 %d개"), len(r.unreadable)),
			detail: T("다른 프로그램이 잠갔거나 권한이 없는 파일입니다. 런처를 끄고 다시 검사하면 읽힐 수 있습니다.\r\n\r\n") + strings.Join(shown, "\r\n")})
	}
	sort.SliceStable(r.findings, func(i, j int) bool { return r.findings[i].sev > r.findings[j].sev })
	return r
}

// 1) 레지스트리 COM 하이재킹 (HKCU만 악성. HKLM의 같은 키는 윈도우 정상 항목 wpc.dll)
func (s *scanner) checkComHijack() {
	found := false
	for _, view := range []string{`Software\Classes\CLSID\`, `Software\Classes\WOW6432Node\CLSID\`} {
		key := view + maliciousCLSID
		if !regKeyExists(syscall.HKEY_CURRENT_USER, key) {
			continue
		}
		found = true
		srv := regString(syscall.HKEY_CURRENT_USER, key+`\InprocServer32`, "")
		if strings.TrimSpace(srv) == "" {
			s.add(finding{sev: sevCrit, title: T("레지스트리에 악성 지속성 잔여 키 (기본값 비어 있음)"), where: `HKEY_CURRENT_USER\` + key,
				fix: fixRegKey, target: key,
				detail: T("에이전트의 정리 명령(chrome_uninstall)은 값만 지우고 키를 남깁니다. 악성 DLL 이 디스크에 남아 있을 수 있습니다.\r\n") +
					T("삭제 전에 .reg 백업을 만듭니다.")})
			continue
		}
		dll := expand(strings.Trim(strings.TrimSpace(srv), `"`))
		if s.r.hkcuDLL == "" {
			s.r.hkcuDLL = dll
		}
		s.add(finding{sev: sevCrit, title: T("레지스트리에 악성 COM 하이재킹 키 발견"), where: `HKEY_CURRENT_USER\` + key,
			fix: fixRegKey, target: key,
			detail: T("윈도우 '자녀 보호' 기능 이름을 도용해 악성 DLL을 자동으로 로드시키는 키입니다.\r\n") +
				"InprocServer32 = " + srv + T("\r\n\r\nHKEY_LOCAL_MACHINE 쪽 같은 이름의 키는 윈도우 정상 항목이라 건드리지 않습니다.\r\n") +
				T("삭제 전에 .reg 백업을 만듭니다.")})
		// 키가 가리키는 파일이 정확히 그 DLL 이름일 때만 삭제 대상 (다른 파일을 지우게 유도당하지 않도록)
		leaf := strings.ToLower(filepath.Base(dll))
		if (leaf == dllName || leaf == dllName+".old") && isFile(dll) {
			f := finding{sev: sevCrit, title: T("레지스트리가 가리키는 악성 DLL 파일"), where: dll, target: dll, browserExe: "chrome.exe",
				detail: fmt.Sprintf(T("크기 %d바이트, 수정 %s"), fileSize(dll), modTime(dll))}
			if isUnderUserProfile(dll) {
				f.fix = fixFile
			} else {
				f.detail += T("\r\n사용자 폴더 밖이라 자동 삭제하지 않습니다. 직접 확인하세요.")
			}
			s.add(f)
		}
	}
	// 변종: 다른 CLSID 라도 64자리 폴더의 platform_experience_helper.dll 을 가리키면 악성
	for _, view := range []string{`Software\Classes\CLSID`, `Software\Classes\WOW6432Node\CLSID`} {
		for _, k := range regSubkeys(syscall.HKEY_CURRENT_USER, view) {
			if strings.EqualFold(k, maliciousCLSID) {
				continue
			}
			for _, sub := range []string{"InprocServer32", "LocalServer32"} {
				v := regString(syscall.HKEY_CURRENT_USER, view+`\`+k+`\`+sub, "")
				if !strings.Contains(strings.ToLower(v), dllName) {
					continue
				}
				key := view + `\` + k
				if hexDLLPathRe.MatchString(expand(v)) {
					s.add(finding{sev: sevCrit, title: T("변종 COM 하이재킹: 다른 레지스트리 키도 악성 DLL을 가리킴"), where: `HKEY_CURRENT_USER\` + key,
						fix: fixRegKey, target: key, detail: sub + " = " + v})
				} else {
					s.add(finding{sev: sevWarn, title: T("확인 필요한 레지스트리 키 (자동 삭제 안 함)"), where: `HKEY_CURRENT_USER\` + key,
						detail: sub + " = " + v + T("\r\n악성 DLL 이름을 쓰지만 알려진 위치가 아닙니다. 직접 확인하세요.")})
				}
				found = true
				break
			}
		}
	}
	if !found {
		s.add(finding{sev: sevInfo, title: T("레지스트리에 악성 COM 키 없음"), where: `HKEY_CURRENT_USER\Software\Classes\CLSID\` + maliciousCLSID})
	}
}

// 2) 브라우저 지속성 DLL: User Data\PlatformExperienceHelper\<64자리 해시>\platform_experience_helper.dll
//
//	PlatformExperienceHelper 폴더 자체, LoadFeatures, platform_experience_helper.exe 는 크롬 정상 파일.
//	+ 구버전 지속성: Chrome\Application\PlatformExperienceHelper 의 DLL / .dll.old / old-clsid.txt
func (s *scanner) checkBrowserPersistence() {
	var checked []string
	bad := false
	for _, b := range chromiumBrowsers() {
		if !isDir(b.userData) {
			continue
		}
		checked = append(checked, b.name)
		peh := filepath.Join(b.userData, persistDir)
		entries, err := os.ReadDir(peh)
		if err != nil {
			continue
		}
		var hexDirs []string
		for _, e := range entries {
			if e.IsDir() && hex64Re.MatchString(e.Name()) {
				p := filepath.Join(peh, e.Name())
				hexDirs = append(hexDirs, p)
				var inside []string
				filepath.WalkDir(p, func(q string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						inside = append(inside, fmt.Sprintf(T("%s (%d바이트, 수정 %s)"), q, fileSize(q), modTime(q)))
					}
					return nil
				})
				if len(inside) == 0 {
					inside = append(inside, T("DLL 은 없지만 64자리 폴더가 남아 있습니다 (DLL 이 이미 지워졌을 수 있음)"))
				}
				s.add(finding{sev: sevCrit, title: b.name + T(" 에 심어진 악성 DLL 폴더 발견"), where: p, fix: fixHashDir, target: p,
					browserExe: b.exe, browserHnt: b.hint,
					detail: T("브라우저(또는 윈도우 기능)가 켜질 때마다 로드되는 해킹 지속성 장치입니다.\r\n") +
						T("레지스트리 키를 먼저 지우고 이 폴더를 지웁니다. 파일이 잠겨 있으면 재부팅 후 마저 지웁니다.\r\n\r\n폴더 안 파일:\r\n") +
						strings.Join(inside, "\r\n")})
				bad = true
			}
		}
		// 64자리 폴더 밖의 DLL
		filepath.WalkDir(peh, func(q string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(q), ".dll") {
				return nil
			}
			for _, h := range hexDirs {
				if strings.HasPrefix(strings.ToLower(q), strings.ToLower(h)+`\`) {
					return nil
				}
			}
			if strings.EqualFold(d.Name(), dllName) {
				s.add(finding{sev: sevCrit, title: b.name + T(" 에서 악성 지속성 DLL 발견"), where: q, fix: fixFile, target: q,
					browserExe: b.exe, browserHnt: b.hint})
			} else {
				s.add(finding{sev: sevWarn, title: b.name + T(" 의 ") + persistDir + T(" 안에 수상한 DLL (자동 삭제 안 함)"), where: q,
					detail: T("브라우저는 이 폴더에 DLL을 두지 않습니다. 이름이 알려진 악성 DLL과 달라 직접 확인이 필요합니다.")})
			}
			bad = true
			return nil
		})
	}
	// 구버전 지속성 파일
	type base struct {
		dir   string
		elev  bool
		label string
	}
	bases := []base{}
	seen := map[string]bool{}
	for _, v := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		if p := os.Getenv(v); p != "" {
			bases = append(bases, base{filepath.Join(p, oldPersistDir), true, ""})
		}
	}
	bases = append(bases, base{filepath.Join(os.Getenv("LOCALAPPDATA"), oldPersistDir), false, ""})
	for _, b := range bases {
		if seen[strings.ToLower(b.dir)] {
			continue
		}
		seen[strings.ToLower(b.dir)] = true
		for _, name := range oldPersistFiles {
			f := filepath.Join(b.dir, name)
			if !isFile(f) {
				continue
			}
			fk := fixFile
			if b.elev {
				fk = fixOldElev
			}
			s.add(finding{sev: sevCrit, title: T("구버전 크롬 지속성 파일 발견"), where: f, fix: fk, target: f, browserExe: "chrome.exe",
				detail: T("에이전트의 예전 버전이 크롬 설치 폴더에 남긴 파일입니다.")})
			bad = true
		}
	}
	if !bad {
		if len(checked) == 0 {
			s.add(finding{sev: sevInfo, title: T("확인할 크로미움 계열 브라우저가 없음")})
		} else {
			s.add(finding{sev: sevInfo, title: T("브라우저에 악성 DLL 없음 (") + strings.Join(checked, ", ") + ")"})
		}
	}
}

// 3) 실행 중인 런처, 악성 DLL 이 로드된 프로세스
func (s *scanner) checkProcesses() {
	procs := listProcesses()
	for _, p := range procs {
		if strings.HasPrefix(strings.ToLower(p.name), "nikke_launcher") {
			s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("니케 런처가 실행 중: %s (PID %d) — 즉시 종료해야 합니다"), p.name, p.pid),
				fix: fixKill, pid: p.pid, target: p.name,
				detail: T("에이전트는 런처가 켜져 있는 동안 공격자의 명령을 받습니다. 알림 영역(트레이)에 숨어 있을 수 있습니다.")})
		}
	}
	hk := strings.ToLower(s.r.hkcuDLL)
	for _, p := range procs {
		if p.pid <= 4 {
			continue
		}
		for _, m := range listModules(p.pid) {
			lm := strings.ToLower(m)
			// 크롬은 원래 platform_experience_helper.exe 라는 정상 프로그램을 실행하므로(모듈 목록 첫 줄에 자기 자신이 나옴)
			// .exe 는 제외하고, 악성 DLL(.dll / .dll.old) 만 봅니다.
			base := strings.ToLower(filepath.Base(m))
			isBadDLL := strings.HasPrefix(base, "platform_experience_helper") && (strings.HasSuffix(base, ".dll") || strings.HasSuffix(base, ".dll.old"))
			if !(loadedDLLRe.MatchString(m) || isBadDLL || (hk != "" && lm == hk && !strings.HasSuffix(lm, ".exe"))) {
				continue
			}
			if strings.EqualFold(p.name, "explorer.exe") {
				s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("악성 DLL 이 현재 로드됨: %s (PID %d)"), p.name, p.pid), where: m,
					detail: T("explorer.exe 는 종료하지 않습니다. 레지스트리 키를 지운 뒤 재부팅하면 풀립니다.")})
			} else {
				s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("악성 DLL 이 현재 로드됨: %s (PID %d)"), p.name, p.pid), where: m,
					fix: fixKill, pid: p.pid, target: p.name,
					detail: T("프로세스를 종료하거나 재부팅해야 DLL 을 지울 수 있습니다.")})
			}
			break
		}
	}
}

// 4) 런처 내장 브라우저 저장소 (%APPDATA%\nikke_launcher, nikke_launcher_hmt)
func (s *scanner) checkLauncherProfile() {
	anyProf := false
	for _, name := range []string{"nikke_launcher", "nikke_launcher_hmt"} {
		prof := filepath.Join(os.Getenv("APPDATA"), name)
		if !isDir(prof) {
			continue
		}
		anyProf = true
		cache := filepath.Join(prof, "tbs_cache")
		var agentFiles, cacheHits, otherHits []string
		agentID := ""
		before := len(s.r.findings)
		filepath.WalkDir(prof, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != prof && isReparseDir(d) {
					return filepath.SkipDir
				}
				return nil
			}
			data := readHead(p, maxRead)
			if data == nil {
				s.r.unreadable = append(s.r.unreadable, p)
				return nil
			}
			low := asciiLower(data)
			rel := strings.TrimPrefix(p, prof+`\`)
			base := d.Name()

			if hasCI(low, "k2f_chan") || hasCI(low, "k2f.agent") {
				agentFiles = append(agentFiles, rel)
				if agentID == "" {
					if m := agentIDRe.FindSubmatch(data); m != nil {
						agentID = string(m[1])
					}
				}
			}
			switch base {
			case "TransportSecurity":
				s.checkHSTS(rel, data, cache)
				return nil
			case "Network Persistent State":
				if hasCI(low, "analytics.insightjs.com") {
					s.add(finding{sev: sevCrit, title: T("런처가 에이전트 배포 서버(analytics.insightjs.com)에 접속한 기록"), where: p})
				} else if hasCI(low, "insightjs") {
					s.add(finding{sev: sevWarn, title: T("런처가 공격자 서버(insightjs)에 접속한 기록"), where: p})
				}
				return nil
			case "Reporting and NEL":
				if hasCI(low, "insightjs") {
					s.add(finding{sev: sevWarn, title: T("런처가 공격자 서버(insightjs)에 접속한 기록 (Reporting and NEL)"), where: p})
				}
				return nil
			}
			parent := strings.ToLower(filepath.Base(filepath.Dir(p)))
			grand := strings.ToLower(filepath.Base(filepath.Dir(filepath.Dir(p))))
			if parent == "js" && grand == "code cache" {
				if what, ok := loaderCacheNames[strings.ToLower(base)]; ok {
					cacheHits = append(cacheHits, fmt.Sprintf(T("l.js?f=%s 로더 캐시: %s (%s)"), what, rel, modTime(p)))
					return nil
				}
			}
			if !hasCI(low, "insightjs") {
				return nil
			}
			lowRel := strings.ToLower(rel)
			if strings.Contains(lowRel, `\cache\`) || strings.Contains(lowRel, `\code cache\`) || strings.HasPrefix(lowRel, `cache\`) {
				cacheHits = append(cacheHits, fmt.Sprintf("%s (%s)", rel, modTime(p)))
			} else {
				otherHits = append(otherHits, rel)
			}
			return nil
		})
		if len(agentFiles) > 0 {
			detail := T("공격자 에이전트가 자기 상태(k2f.agent.state)를 저장해 둔 흔적입니다.\r\n니케 폴더를 지워도 남는 기록이라 가장 확실한 증거 중 하나입니다.")
			if agentID != "" {
				detail += T("\r\n에이전트 ID: ") + agentID + T("\r\n(비밀키 값은 표시하지 않습니다.)")
			}
			detail += "\r\n\r\n" + strings.Join(limit(agentFiles, 10), "\r\n")
			s.add(finding{sev: sevCrit, title: T("런처 저장소에서 해킹 에이전트 상태값(k2f.agent) 발견"), where: prof, detail: detail})
		}
		if len(cacheHits) > 0 {
			s.add(finding{sev: sevWarn, title: fmt.Sprintf(T("런처가 공격자 로더 스크립트(insightjs)를 불러온 캐시 %d개"), len(cacheHits)), where: cache,
				detail: T("9/27부터 변조된 공식 파일이 공격자 서버(insightjs.com)의 스크립트를 불러왔습니다.\r\n") +
					T("이것만으로 에이전트가 실행됐다고 단정할 수는 없지만, 감염 가능성으로 대응하세요.\r\n\r\n") + strings.Join(limit(cacheHits, 15), "\r\n")})
		}
		if len(otherHits) > 0 {
			s.add(finding{sev: sevWarn, title: fmt.Sprintf(T("insightjs 를 언급하는 런처 파일 %d개"), len(otherHits)), where: prof,
				detail: strings.Join(limit(otherHits, 15), "\r\n")})
		}
		infected := len(s.r.findings) > before
		if isDir(cache) {
			sev := sevFix
			title := T("런처 캐시(tbs_cache) — 다시 켜기 전 삭제 권장")
			if infected {
				sev = sevWarn
				title = T("감염된 런처 캐시(tbs_cache) — 삭제 필요")
			}
			s.add(finding{sev: sev, title: title, where: cache, fix: fixCache, target: cache,
				detail: T("변조된 파일이 캐시에 남아 있으면 런처를 다시 켤 때 또 실행될 수 있습니다.\r\n") +
					T("런처가 다시 만들어 주며, 다시 로그인해야 할 수 있습니다.\r\n") +
					T("(해결을 누르면 삭제 전에 보고서가 자동으로 저장됩니다.)")})
		}
		if !infected {
			s.add(finding{sev: sevInfo, title: T("런처 저장소에 에이전트·로더 흔적 없음"), where: prof})
		}
	}
	if !anyProf {
		s.add(finding{sev: sevInfo, title: T("런처 저장소(%APPDATA%\\nikke_launcher) 없음"), where: filepath.Join(os.Getenv("APPDATA"), "nikke_launcher")})
	}
}

func limit(l []string, n int) []string {
	if len(l) <= n {
		return l
	}
	return append(append([]string{}, l[:n]...), fmt.Sprintf(T("… 외 %d개"), len(l)-n))
}

// HSTS: 런처가 HTTPS 로 접속한 도메인이 해시 키로 남습니다.
func (s *scanner) checkHSTS(rel string, data []byte, cache string) {
	text := string(data)
	var lines []string
	analytics := false
	for _, obj := range jsonObjRe.FindAllString(text, -1) {
		for _, k := range hstsKeys {
			if !strings.Contains(obj, `"`+k.key+`"`) {
				continue
			}
			when := T("알 수 없음")
			if m := stsObservedRe.FindStringSubmatch(obj); m != nil {
				if sec, err := strconv.ParseFloat(m[1], 64); err == nil {
					when = time.Unix(int64(sec), 0).Format("2006-01-02 15:04:05")
				}
			}
			lines = append(lines, fmt.Sprintf(T("%s HSTS 기록 (마지막 접속 %s)"), k.domain, when))
			if k.domain == "analytics.insightjs.com" {
				analytics = true
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	detail := rel + "\r\n" + strings.Join(lines, "\r\n") +
		T("\r\n\r\nHSTS 기록에는 도메인 이름이 아니라 해시값이 저장되어, 글자 검색으로는 찾을 수 없는 흔적입니다.")
	if analytics {
		s.add(finding{sev: sevCrit, title: T("런처가 에이전트 배포 서버(analytics.insightjs.com)에 접속한 기록 (HSTS)"), where: cache, detail: detail})
	} else {
		s.add(finding{sev: sevWarn, title: T("런처가 공격자 서버(insightjs)에 접속한 기록 (HSTS)"), where: cache, detail: detail})
	}
}

// 5) %TEMP% 의 k2f-bcreds-* (브라우저 비번 덤프), k2f_screen_* (스크린샷) 등
func (s *scanner) checkTemp() {
	dirs := map[string]bool{}
	for _, d := range []string{os.TempDir(), filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp")} {
		dirs[strings.ToLower(strings.TrimRight(d, `\`))] = true
	}
	found := false
	for d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !isK2fName(e.Name()) {
				continue
			}
			p := filepath.Join(d, e.Name())
			kind := T("에이전트 임시 파일")
			switch {
			case strings.HasPrefix(e.Name(), "k2f-bcreds"):
				kind = T("에이전트가 만든 브라우저 비밀번호 덤프 파일")
			case strings.HasPrefix(e.Name(), "k2f_screen"):
				kind = T("에이전트가 찍은 화면 캡처 파일")
			}
			s.add(finding{sev: sevCrit, title: kind, where: p, fix: fixFile, target: p,
				detail: fmt.Sprintf(T("크기 %d바이트, 수정 %s"), fileSize(p), modTime(p)) + "\r\n" +
					T("비밀번호가 읽을 수 있는 형태로 들어 있을 수 있어 삭제를 강력히 권장합니다.")})
			found = true
		}
	}
	if !found {
		s.add(finding{sev: sevInfo, title: T("임시 폴더에 에이전트 파일 없음"), where: os.TempDir(),
			detail: T("에이전트는 이 파일들을 보낸 직후 지우기 때문에, 없다고 해서 안 털렸다는 뜻은 아닙니다.")})
	}
}

// 6) (선택) 전체 드라이브 파일 이름 검사 — 정해진 위치 밖에 남은 에이전트·지속성 파일. 찾은 런처 위치를 돌려줌.
func isDiskScanName(n string) bool {
	if isK2fName(n) {
		return true
	}
	s := strings.ToLower(n)
	return strings.HasPrefix(s, "tinyget") || s == "nikke_launcher.exe" || strings.HasPrefix(s, dllName) || s == "old-clsid.txt" || s == "insight.bundle"
}

func (s *scanner) checkFullScan() []string {
	var hits, launchers []string
	for _, drive := range scanDrives() {
		base := strings.TrimRight(drive, `\`)
		winDir := strings.ToLower(base + `\Windows`)
		n := 0
		last := time.Now()
		filepath.WalkDir(drive, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != drive && (isReparseDir(d) || strings.ToLower(p) == winDir) {
					return filepath.SkipDir
				}
				return nil
			}
			n++
			if time.Since(last) > 700*time.Millisecond && s.progress != nil {
				last = time.Now()
				s.progress(fmt.Sprintf(T("전체 드라이브 검사 중... %s 파일 %d개 확인"), drive, n))
			}
			if isDiskScanName(d.Name()) {
				hits = append(hits, p)
			}
			return nil
		})
	}
	for _, h := range hits {
		leaf := filepath.Base(h)
		lower := strings.ToLower(leaf)
		switch {
		case lower == "nikke_launcher.exe":
			launchers = append(launchers, filepath.Dir(filepath.Dir(h)))
		case strings.HasPrefix(lower, dllName) || (lower == "old-clsid.txt" && strings.Contains(strings.ToLower(h), `\platformexperiencehelper\`)):
			f := finding{sev: sevCrit, title: T("악성 지속성 DLL 파일 (다른 위치)"), where: h, target: h, fromDisk: true}
			if isUnderUserProfile(h) {
				f.fix = fixFile
			} else {
				f.detail = T("사용자 폴더 밖이라 자동 삭제하지 않습니다. 직접 확인하세요.")
			}
			s.add(f)
		case lower == "insight.bundle" || leaf == "k2f.lua" || strings.HasPrefix(lower, "tinyget"):
			head := readHead(h, 3)
			if head == nil {
				s.r.unreadable = append(s.r.unreadable, h)
				continue
			}
			if isLuaJITBytes(head) {
				s.add(finding{sev: sevCrit, title: T("내려받은 에이전트 파일 (LuaJIT 바이트코드, 다른 위치)"), where: h, fix: fixFile, target: h, fromDisk: true})
			} else if !strings.HasPrefix(lower, "tinyget") {
				s.add(finding{sev: sevInfo, title: T("이름만 일치하는 파일 (내용은 에이전트가 아님, 직접 확인)"), where: h, fromDisk: true})
			}
		case strings.HasPrefix(leaf, "k2f-bcreds") || strings.HasPrefix(leaf, "k2f_screen") || strings.HasPrefix(leaf, "k2f.agent"):
			// 임시 폴더 안의 것은 5번 항목이 처리. 그 밖(연구용 샘플 폴더 등)은 보고만 함.
			s.add(finding{sev: sevCrit, title: T("에이전트 관련 파일 (임시 폴더 밖, 자동 삭제 안 함 — 직접 확인)"), where: h, target: h, fromDisk: true})
		}
	}
	return launchers
}

// 다른 항목이 이미 잡은 경로(또는 그 아래)는 전체 드라이브 검사 결과에서 뺍니다.
func (s *scanner) dedupeDiskFindings() {
	var others []string
	for _, f := range s.r.findings {
		if !f.fromDisk && f.target != "" && f.fix != fixRegKey && f.fix != fixKill {
			others = append(others, strings.ToLower(strings.TrimRight(f.target, `\`)))
		}
	}
	out := s.r.findings[:0]
	for _, f := range s.r.findings {
		if f.fromDisk && f.where != "" {
			lw := strings.ToLower(f.where)
			dup := false
			for _, o := range others {
				if lw == o || strings.HasPrefix(lw, o+`\`) {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
		}
		out = append(out, f)
	}
	s.r.findings = out
}

// 7) 니케 설치 폴더: debug.log, Launcher\log\** (tinyget, LuaJIT 에이전트, ETag)
func (s *scanner) checkInstall(root string) {
	log := filepath.Join(root, `Launcher\intl_service\debug.log`)
	info := T("debug.log 없음 (니케를 재설치했거나 폴더를 지운 경우 로그가 남아 있지 않습니다)")
	if isFile(log) {
		info = T("debug.log 마지막 기록 ") + modTime(log)
	}
	s.add(finding{sev: sevInfo, title: T("검사한 니케 설치 폴더: ") + root, where: root, detail: info})
	if isFile(log) {
		s.checkDebugLog(log)
	}
	if logDir := filepath.Join(root, `Launcher\log`); isDir(logDir) {
		s.checkLauncherLogs(logDir)
	}
}

func (s *scanner) checkDebugLog(log string) {
	f, err := openShared(log)
	if err != nil {
		s.r.unreadable = append(s.r.unreadable, log)
		s.add(finding{sev: sevWarn, title: T("debug.log 를 읽을 수 없습니다 (에이전트 실행 여부 확인 불가)"), where: log,
			detail: T("런처를 완전히 끈 뒤 다시 검사하세요.")})
		return
	}
	defer f.Close()
	k2f, server, loader := false, false, false
	var runs []string
	no := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		no++
		line := sc.Text()
		low := strings.ToLower(line)
		if strings.Contains(low, "k2f_chan") || strings.Contains(low, "agent started as") || strings.Contains(low, "lua downloaded to") || agentIDLineRe.MatchString(line) {
			k2f = true
		}
		if strings.Contains(low, "analytics.insightjs.com") || strings.Contains(low, "insight.bundle") {
			server = true
		} else if strings.Contains(low, "insightjs") {
			loader = true
		}
		if runLineRe.MatchString(line) {
			runs = append(runs, fmt.Sprintf(T("[%d행] %s"), no, redactLine(line)))
		}
	}
	if k2f {
		detail := T("에이전트(원격 조종 프로그램)가 이 PC에서 실행된 기록입니다.\r\n시간 형식: [월일/시분초], 이 PC 현지 시각\r\n\r\n") +
			strings.Join(limit(runs, 50), "\r\n")
		host, _ := os.Hostname()
		for _, h := range runs {
			if m := agentNameRe.FindStringSubmatch(h); m != nil {
				if strings.EqualFold(m[1], host) {
					detail = fmt.Sprintf(T("→ 이 PC 이름(%s)으로 공격자 서버에 등록됐습니다.\r\n\r\n"), m[1]) + detail
				} else {
					detail = fmt.Sprintf(T("→ '%s' 이름으로 등록됨 (현재 PC 이름: %s)\r\n\r\n"), m[1], host) + detail
				}
				break
			}
		}
		s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("런처 로그에서 해킹 에이전트 실행 기록 발견 (%d줄)"), len(runs)), where: log, detail: detail})
	}
	if server {
		s.add(finding{sev: sevCrit, title: T("런처 로그: 에이전트 배포 서버에 요청한 기록 (analytics.insightjs.com / insight.bundle)"), where: log})
	}
	if loader && !server && !k2f {
		s.add(finding{sev: sevWarn, title: T("런처 로그: 공격자 로더(insightjs)만 실행된 기록"), where: log})
	}
	if !k2f && !server && !loader {
		s.add(finding{sev: sevInfo, title: T("런처 로그(debug.log)에 해킹 에이전트 기록 없음"), where: log})
	}
}

func (s *scanner) checkLauncherLogs(logDir string) {
	var downloads, builds []string
	found := false
	filepath.WalkDir(logDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && p != logDir && isReparseDir(d) {
				return filepath.SkipDir
			}
			return nil
		}
		data := readHead(p, maxRead)
		if data == nil {
			s.r.unreadable = append(s.r.unreadable, p)
			return nil
		}
		rel := strings.TrimPrefix(p, logDir+`\`)
		if isLuaJITBytes(data) || isK2fName(d.Name()) {
			kind := T("k2f 파일")
			if isLuaJITBytes(data) {
				kind = T("LuaJIT 바이트코드")
			}
			extra := ""
			if len(data) == knownAgentSize {
				extra = T(" (알려진 에이전트와 같은 크기)")
			}
			s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("내려받은 악성 에이전트 파일이 남아 있음 (%s)"), kind), where: p, fix: fixFile, target: p,
				detail: fmt.Sprintf(T("크기 %d바이트, 수정 %s"), len(data), modTime(p)) + extra})
			found = true
			return nil
		}
		low := asciiLower(data)
		switch {
		case hasCI(low, "insight.bundle"):
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(strings.ToLower(line), "insight.bundle") {
					downloads = append(downloads, rel+": "+redactLine(strings.Trim(line, "\r\x00")))
					break
				}
			}
			if strings.EqualFold(d.Name(), "tinyget.mem.log") {
				for _, m := range etagRe.FindAllStringSubmatch(string(data), -1) {
					mt, _ := strconv.ParseInt(m[1], 16, 64)
					sz, _ := strconv.ParseInt(m[2], 16, 64)
					k := T(" (알려지지 않은 빌드)")
					if knownBuildEtags[strings.ToLower(m[1])] {
						k = T(" (알려진 빌드)")
					}
					b := fmt.Sprintf(T("ETag %s-%s → 업로드 %s UTC, %d바이트%s"), m[1], m[2], time.Unix(mt, 0).UTC().Format("2006-01-02 15:04:05"), sz, k)
					dup := false
					for _, x := range builds {
						if x == b {
							dup = true
						}
					}
					if !dup {
						builds = append(builds, b)
					}
				}
			}
		case hasCI(low, "analytics.insightjs.com"):
			s.add(finding{sev: sevCrit, title: T("런처 로그: 에이전트 배포 서버 접속 기록"), where: p})
			found = true
		case hasCI(low, "insightjs"):
			s.add(finding{sev: sevWarn, title: T("런처 로그: 공격자 서버(insightjs) 기록"), where: p})
			found = true
		}
		return nil
	})
	if len(downloads) > 0 {
		detail := strings.Join(limit(downloads, 20), "\r\n")
		if len(builds) > 0 {
			detail += T("\r\n\r\n내려받은 에이전트 빌드 (tinyget.mem.log):\r\n") + strings.Join(builds, "\r\n")
		}
		s.add(finding{sev: sevCrit, title: fmt.Sprintf(T("에이전트(insight.bundle) 다운로드 기록 %d건"), len(downloads)), where: logDir, detail: detail})
		found = true
	}
	if !found {
		s.add(finding{sev: sevInfo, title: T("런처 다운로드 로그에 공격자 서버 기록 없음"), where: logDir})
	}
}

// 8) DNS 캐시 (재부팅하면 비워짐)
func (s *scanner) checkDNSCache() {
	b, err := hiddenCmd("ipconfig", "/displaydns").Output()
	if err != nil {
		return
	}
	// hosts 파일에 적힌 주소도 DNS 캐시에 올라가므로, hosts 로 막아 둔 도메인과 차단 주소(0.0.0.0 등)로 나온 기록은 제외.
	// (출력 문구는 윈도우 언어마다 다르므로 도메인 이름과 IP 형식만 봄)
	hostsBlocked := map[string]bool{}
	missing := map[string]bool{}
	for _, d := range hostsMissing() {
		missing[d] = true
	}
	for _, d := range blockDomains {
		if !missing[d] {
			hostsBlocked[d] = true
		}
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n")
	realLookup := func(domain string) (bool, []string) {
		if hostsBlocked[domain] {
			return false, nil
		}
		found := false
		var ips []string
		for i, line := range lines {
			fs := strings.Fields(line)
			if len(fs) == 0 || !strings.EqualFold(fs[len(fs)-1], domain) {
				continue
			}
			found = true
			for j := i + 1; j < len(lines) && j <= i+8; j++ {
				f := strings.Fields(lines[j])
				if len(f) == 0 {
					continue
				}
				last := f[len(f)-1]
				if ipLikeRe.MatchString(last) {
					dup := false
					for _, x := range ips {
						dup = dup || x == last
					}
					if !dup {
						ips = append(ips, last)
					}
				}
				if strings.Contains(strings.ToLower(last), "insightjs.") && !strings.EqualFold(last, domain) {
					break // 다른 도메인 기록이 시작됨
				}
			}
		}
		if !found {
			return false, nil
		}
		real := len(ips) == 0 // 응답 없는(존재하지 않음) 기록도 조회는 한 것
		for _, ip := range ips {
			if !hostsBlockAddrs[ip] {
				real = true
			}
		}
		return real, ips
	}
	why := T("이 기록만으로는 감염이라고 볼 수 없습니다. 이 사태를 확인하려고 주소를 직접 열어 봤거나, 다른 점검 도구가 조회해도 남습니다.\r\n") +
		T("런처 저장소·브라우저 DLL·레지스트리 등 다른 항목이 깨끗하면 크게 걱정하지 않아도 됩니다. 재부팅하면 지워지는 기록입니다.")
	if ok, ips := realLookup("analytics.insightjs.com"); ok {
		s.add(finding{sev: sevWarn, title: T("최근 이 PC에서 analytics.insightjs.com 주소를 조회한 기록 (DNS 캐시)"), where: T("DNS 캐시 (ipconfig /displaydns)"),
			detail: why + T("\r\n\r\n응답 주소: ") + strings.Join(ips, ", ")})
		return
	}
	for _, d := range []string{"insightjs.com", "insightjs.org"} {
		if ok, ips := realLookup(d); ok {
			s.add(finding{sev: sevInfo, title: T("최근 이 PC에서 ") + d + T(" 주소를 조회한 기록 (DNS 캐시, 참고용)"), where: T("DNS 캐시 (ipconfig /displaydns)"),
				detail: why + T("\r\n\r\n응답 주소: ") + strings.Join(ips, ", ")})
			return
		}
	}
	s.add(finding{sev: sevInfo, title: T("DNS 캐시에 공격자 서버 조회 기록 없음"),
		detail: T("hosts 파일로 차단해 둔 주소는 DNS 캐시에 나타나도 조회 기록으로 보지 않습니다. 재부팅하면 비워지는 기록이라 참고용입니다.")})
}

var ipLikeRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]+$`)

// 9) hosts·방화벽 차단 여부
var hostsBlockAddrs = map[string]bool{"0.0.0.0": true, "127.0.0.1": true, "::1": true, "::": true}

func hostsMissing() []string {
	hp := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	b, _ := os.ReadFile(hp)
	var missing []string
	for _, h := range blockDomains {
		blocked := false
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			fs := strings.Fields(line)
			if len(fs) < 2 || !hostsBlockAddrs[fs[0]] {
				continue
			}
			for _, f := range fs[1:] {
				if strings.EqualFold(f, h) {
					blocked = true
				}
			}
		}
		if !blocked {
			missing = append(missing, h)
		}
	}
	return missing
}

// 다른 점검 도구(nikke-checker 등)가 만든 규칙도 인정합니다.
var knownFwRuleNames = []string{fwRuleName, "Block_Nikke_Malware_C2", "Block_Nikke_Malware_C2_89.127.233.127"}

// 이름만 보지 않고 규칙 안에 두 IP 가 들어 있는지 확인 (netsh 출력은 언어별로 달라 IP 로만 판단).
// 규칙이 IP 마다 따로 있어도 합쳐서 판단. 반환: IP별 차단 여부, 찾은 규칙 이름
func firewallStatus() (map[string]bool, []string) {
	blocked := map[string]bool{}
	var rules []string
	for _, name := range knownFwRuleNames {
		out, err := hiddenCmd("netsh", "advfirewall", "firewall", "show", "rule", "name="+name, "verbose").Output()
		if err != nil {
			continue
		}
		hit := false
		for _, ip := range strings.Split(blockIPs, ",") {
			if bytes.Contains(out, []byte(ip)) {
				blocked[ip] = true
				hit = true
			}
		}
		if hit {
			rules = append(rules, name)
		}
	}
	return blocked, rules
}

func firewallRuleValid() bool {
	b, _ := firewallStatus()
	for _, ip := range strings.Split(blockIPs, ",") {
		if !b[ip] {
			return false
		}
	}
	return true
}

func (s *scanner) checkBlocking() {
	missing := hostsMissing()
	miss := map[string]bool{}
	for _, d := range missing {
		miss[d] = true
	}
	fwb, rules := firewallStatus()
	var lines []string
	for _, d := range blockDomains {
		st := T("차단됨")
		if miss[d] {
			st = T("차단 안 됨")
		}
		lines = append(lines, "hosts "+d+": "+st)
	}
	fwAll := true
	for _, ip := range strings.Split(blockIPs, ",") {
		st := T("차단됨")
		if !fwb[ip] {
			st = T("차단 안 됨")
			fwAll = false
		}
		lines = append(lines, T("방화벽 ")+ip+": "+st)
	}
	if len(rules) > 0 {
		lines = append(lines, T("(찾은 방화벽 규칙: ")+strings.Join(rules, ", ")+")")
	}
	status := strings.Join(lines, "\r\n")
	if len(missing) == 0 && fwAll {
		s.add(finding{sev: sevInfo, title: T("공격자 서버가 hosts·방화벽에서 이미 차단되어 있음"), detail: status})
		return
	}
	s.add(finding{sev: sevFix, title: T("공격자 서버 차단 안 됨 — 예방 차단 권장"), fix: fixBlock,
		detail: status + T("\r\n\r\n해결을 누르면 관리자 권한 확인 창이 뜨고, 차단 안 된 것만 hosts 파일과 윈도우 방화벽에 추가합니다.\r\n") +
			T("(공격자가 새 도메인을 쓰면 막지 못하니, 공식 발표 전까지 PC 런처는 켜지 마세요.)")})
}
