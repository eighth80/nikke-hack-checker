//go:build windows

// 해결(복구) 작업. 사용자가 체크한 항목만, 안전 검증을 통과한 경로만 지웁니다.
//
// 안전장치 (nikke-checker v1.2.1 의 규칙 반영):
//   - 해결 전에 보고서를 먼저 저장하고, 저장하지 못하면 아무것도 지우지 않음
//   - 경로 중간에 정션·심볼릭 링크가 있으면 삭제하지 않음
//   - 관리자 권한 프로세스는 정해진 구버전 지속성 파일·hosts·방화벽 외에는 손대지 않음
//   - explorer.exe 는 종료하지 않음
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 백업·보고서 폴더 (OneDrive 동기화 피하려고 바탕화면이 아닌 사용자 폴더)
var sessionDir = filepath.Join(os.Getenv("USERPROFILE"), T("NIKKE_점검_")+time.Now().Format("20060102_150405"))

func ensureSessionDir() (string, error) {
	return sessionDir, os.MkdirAll(sessionDir, 0755)
}

// 지워도 되는 경로인지 다시 확인합니다. (스캔 결과가 이상해도 엉뚱한 걸 지우지 않게)
func safeToDelete(f finding) bool {
	p := filepath.Clean(f.target)
	low := strings.ToLower(p)
	base := strings.ToLower(filepath.Base(p))
	if f.fix == fixRegKey {
		return strings.HasPrefix(low, `software\classes\`) && strings.Contains(low, `clsid\`)
	}
	if hasReparseInPath(p) {
		return false
	}
	switch f.fix {
	case fixHashDir:
		return hex64Re.MatchString(filepath.Base(p)) && strings.EqualFold(filepath.Base(filepath.Dir(p)), persistDir)
	case fixCache:
		parent := strings.ToLower(filepath.Base(filepath.Dir(p)))
		return base == "tbs_cache" && (parent == "nikke_launcher" || parent == "nikke_launcher_hmt")
	case fixFile:
		switch {
		case strings.HasPrefix(base, dllName) && isUnderUserProfile(p):
			return true // 레지스트리가 가리킨 DLL, 브라우저 폴더·다른 위치의 DLL (사용자 폴더 안만)
		case base == "old-clsid.txt" && strings.Contains(low, `\platformexperiencehelper\`) && isUnderUserProfile(p):
			return true
		case strings.Contains(low, `\launcher\log\`):
			return isK2fName(filepath.Base(p)) || isLuaJIT(p)
		case isK2fName(filepath.Base(p)):
			dir := strings.ToLower(strings.TrimRight(filepath.Dir(p), `\`))
			return dir == strings.ToLower(strings.TrimRight(os.TempDir(), `\`)) ||
				dir == strings.ToLower(filepath.Join(os.Getenv("LOCALAPPDATA"), "Temp"))
		case base == "insight.bundle" || base == "k2f.lua" || strings.HasPrefix(base, "tinyget"):
			return isLuaJIT(p) // 이름만으로는 지우지 않고, 내용이 LuaJIT 바이트코드일 때만
		}
	}
	return false
}

type fixOutcome struct {
	log          []string
	needReboot   bool
	failed       int
	done         int
	doBlock      bool
	doOldPersist bool
	reportPath   string
	aborted      bool
	optimize     bool // PC 간단 최적화 결과
}

// UI 스레드 밖에서 실행됩니다. report: 삭제 전에 저장할 보고서 내용
func applyFixes(items []finding, closeBrowsers bool, report func() (string, error)) fixOutcome {
	var o fixOutcome
	logf := func(format string, a ...any) { o.log = append(o.log, fmt.Sprintf(format, a...)) }

	// 0) 보고서를 먼저 저장. 실패하면 아무것도 하지 않음 (증거가 사라지지 않게)
	rp, err := report()
	if err != nil {
		logf(T("× 보고서를 저장하지 못해 아무것도 지우지 않았습니다: %v"), err)
		o.failed++
		o.aborted = true
		return o
	}
	o.reportPath = rp
	logf(T("• 해결 전 보고서 저장: %s"), rp)
	dir := filepath.Dir(rp)

	// 1) 런처 종료 (에이전트는 런처 안에서 돌아감)
	needLauncherClosed := false
	for _, f := range items {
		if f.fix == fixCache || f.fix == fixFile || f.fix == fixKill || f.fix == fixWipeLauncher {
			needLauncherClosed = true
		}
	}
	if needLauncherClosed {
		n := 0
		for _, name := range launcherProcNames {
			n += killByName(name, "")
		}
		if n > 0 {
			logf(T("• 니케 런처 관련 프로세스 %d개를 종료했습니다."), n)
			time.Sleep(1500 * time.Millisecond)
		}
	}

	// 2) 레지스트리 먼저: 브라우저가 DLL 을 다시 로드하지 않게
	for _, f := range items {
		if f.fix != fixRegKey {
			continue
		}
		if !safeToDelete(f) {
			logf(T("× 안전 확인 실패로 건너뜀: HKCU\\%s"), f.target)
			o.failed++
			continue
		}
		full := `HKCU\` + f.target
		backup := filepath.Join(dir, T("레지스트리백업_")+sanitize(f.target)+".reg")
		hiddenCmd("reg", "export", full, backup, "/y").Run()
		if err := hiddenCmd("reg", "delete", full, "/f").Run(); err != nil {
			logf(T("× 레지스트리 키 삭제 실패: %s (%v)"), full, err)
			o.failed++
		} else {
			logf(T("○ 레지스트리 키 삭제: %s\r\n    백업: %s"), full, backup)
			o.done++
		}
	}

	// 3) 악성 DLL 을 로드한 프로세스, (동의 시) 해당 브라우저 종료
	for _, f := range items {
		if f.fix != fixKill || f.pid == 0 || strings.EqualFold(f.target, "explorer.exe") {
			continue
		}
		if killPID(f.pid) {
			logf(T("○ 프로세스 종료: %s (PID %d)"), f.target, f.pid)
			o.done++
		} else {
			logf(T("△ 프로세스 종료 안 됨 (이미 꺼졌거나 권한 없음): %s (PID %d)"), f.target, f.pid)
		}
	}
	if closeBrowsers {
		type bk struct{ exe, hint string }
		done := map[bk]bool{}
		for _, f := range items {
			if f.browserExe == "" {
				continue
			}
			k := bk{f.browserExe, f.browserHnt}
			if done[k] {
				continue
			}
			done[k] = true
			if n := killByName(k.exe, k.hint); n > 0 {
				logf(T("• 브라우저 종료: %s (%d개)"), k.exe, n)
			}
		}
		time.Sleep(2 * time.Second)
	}

	// 4) 파일·폴더
	for _, f := range items {
		switch f.fix {
		case fixFile, fixHashDir, fixCache:
		default:
			continue
		}
		if !exists(f.target) {
			logf(T("• 이미 없음: %s"), f.target)
			continue
		}
		if !safeToDelete(f) {
			if hasReparseInPath(f.target) {
				logf(T("× 경로에 정션·바로가기 폴더가 있어 삭제하지 않음 (직접 확인하세요): %s"), f.target)
			} else {
				logf(T("× 안전 확인 실패로 건너뜀: %s"), f.target)
			}
			o.failed++
			continue
		}
		var err error
		if f.fix == fixFile {
			err = os.Remove(f.target)
		} else {
			err = os.RemoveAll(f.target)
		}
		if err != nil {
			if f.fix == fixHashDir || f.browserExe != "" {
				o.needReboot = true
				logf(T("△ 사용 중이라 지금은 못 지움 (재부팅 후 다시 실행하면 지워집니다): %s"), f.target)
			} else {
				logf(T("× 삭제 실패: %s (%v)"), f.target, err)
			}
			o.failed++
		} else {
			logf(T("○ 삭제: %s"), f.target)
			o.done++
		}
	}

	// 5) 선택 사항: 런처 데이터·쿠키·사이트 데이터 (여러 경로)
	for _, f := range items {
		switch f.fix {
		case fixWipeLauncher, fixWipeCookies, fixWipeSiteData:
		default:
			continue
		}
		ok, fail, skipped := 0, 0, 0
		for _, p := range f.targets {
			if !exists(p) {
				continue
			}
			if !safeWipePath(f.fix, p) {
				skipped++
				logf(T("× 안전 확인 실패로 건너뜀: %s"), p)
				continue
			}
			if err := os.RemoveAll(p); err != nil {
				fail++
				logf(T("× 삭제 실패 (프로그램이 사용 중일 수 있음): %s"), p)
			} else {
				ok++
			}
		}
		switch {
		case fail == 0 && skipped == 0:
			logf(T("○ %s: %d개 삭제"), f.title, ok)
			o.done++
		default:
			logf(T("△ %s: %d개 삭제, %d개 실패 — 브라우저/런처를 완전히 닫고 다시 해결을 누르세요"), f.title, ok, fail+skipped)
			o.failed++
		}
	}

	for _, f := range items {
		switch f.fix {
		case fixBlock:
			o.doBlock = true
		case fixOldElev:
			o.doOldPersist = true
		}
	}
	return o
}

func sanitize(s string) string {
	r := strings.NewReplacer(`\`, "_", "/", "_", ":", "_", "{", "", "}", "")
	return r.Replace(s)
}

// ---------------------------------------------------------------------------
// 관리자 권한으로 다시 실행된 경우: --elevated [block] [oldpersist]
// 넘겨받은 경로가 아니라 고정된 위치만 다룹니다.
// 종료 코드 비트: 1=hosts 실패, 2=방화벽 실패, 4=구버전 파일 삭제 실패
// ---------------------------------------------------------------------------

func runElevatedTasks(args []string) int {
	code := 0
	for _, a := range args {
		switch a {
		case "block":
			code |= applyBlock()
		case "oldpersist":
			code |= deleteOldPersistElevated()
		}
	}
	return code
}

func deleteOldPersistElevated() int {
	code := 0
	for _, v := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
		pf := os.Getenv(v)
		if pf == "" {
			continue
		}
		dir := filepath.Join(pf, oldPersistDir)
		for _, name := range oldPersistFiles {
			f := filepath.Join(dir, name)
			if !isFile(f) || hasReparseInPath(f) {
				continue
			}
			if os.Remove(f) != nil {
				code |= 4
			}
		}
	}
	return code
}

func applyBlock() int {
	hp := filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
	code := 0
	if missing := hostsMissing(); len(missing) > 0 {
		orig, _ := os.ReadFile(hp)
		os.WriteFile(hp+".nikke_backup", orig, 0644)
		var b strings.Builder
		if len(orig) > 0 && !strings.HasSuffix(string(orig), "\n") {
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n# NIKKE launcher compromise (insightjs) - attacker servers blocked " + time.Now().Format("2006-01-02") + "\r\n")
		for _, d := range missing {
			b.WriteString("0.0.0.0 " + d + "\r\n")
		}
		f, err := os.OpenFile(hp, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			code |= 1
		} else {
			if _, err := f.WriteString(b.String()); err != nil {
				code |= 1
			}
			f.Close()
		}
		hiddenCmd("ipconfig", "/flushdns").Run()
	}
	if !firewallRuleValid() {
		// 이름이 같은데 내용이 다른 규칙은 지우고 다시 만듦
		hiddenCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRuleName).Run()
		if hiddenCmd("netsh", "advfirewall", "firewall", "add", "rule", "name="+fwRuleName,
			"dir=out", "action=block", "enable=yes", "profile=any", "remoteip="+blockIPs).Run() != nil || !firewallRuleValid() {
			code |= 2
		}
	}
	return code
}

// 재부팅 후 한 번 자동 실행 (HKCU RunOnce)
func registerRunOnce() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return hiddenCmd("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		"/v", "NikkeHackCheckResume", "/t", "REG_SZ", "/d", `"`+exe+`" --after-reboot`, "/f").Run()
}

var guideText = T(`털렸을 때 이 프로그램 밖에서 꼭 해야 할 것
※ 비밀번호 변경은 반드시 다른 깨끗한 기기(스마트폰 등)로 하세요.

1. 레벨인피니트가 공식으로 안전하다고 발표하기 전까지 PC 니케 런처를 켜지 마세요.
2. 니케/레벨인피니트 비밀번호부터 바꾸고, 이메일·디스코드·은행·브라우저에 저장해 둔 모든 비밀번호를 바꾸세요. 2단계 인증을 켜세요.
3. 구글·디스코드·스팀·깃허브 등 모든 사이트에서 "모든 기기 로그아웃"을 하고, 브라우저 설정에서 쿠키를 삭제하세요. (훔친 쿠키는 비밀번호 없이도 로그인됩니다)
4. API 토큰, SSH 키, Claude/Codex/GitHub/npm/AWS 등 개발용·클라우드 CLI 자격 증명은 폐기하고 새로 발급하세요.
5. 암호화폐 지갑은 새 시드로 만든 새 지갑으로 자산을 옮기세요.
6. 이 PC를 다른 윈도우 사용자 계정도 쓴다면, 그 계정으로 로그인해서 이 프로그램을 한 번 더 실행하세요. (레지스트리·AppData 는 계정마다 따로 있습니다)
7. 가장 확실한 방법은 파일을 백업하고 윈도우를 다시 설치(포맷)하는 것입니다.
   공격자는 감염 기간 동안 아무 명령이나 실행할 수 있었기 때문에, 이 도구로 알려진 흔적을 지워도 다른 게 남지 않았다고 보장할 수 없습니다.
   백신 검사 결과가 깨끗해도 믿지 마세요(Defender가 이 DLL을 못 잡은 사례가 있습니다).`)
