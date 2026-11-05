//go:build windows

// 선택 사항: 쿠키·사이트 데이터·런처 데이터 삭제
//
// 니케 폴더를 못 찾아 감염 여부를 로그로 확인할 수 없거나, 감염 흔적이 나온 경우에 보여 줍니다. 기본은 체크 해제.
// 에이전트의 browserscan 은 브라우저 쿠키를 가져갈 수 있었으므로, 쿠키를 지우면 모든 사이트에서 로그아웃되어
// 훔친 쿠키(세션)가 쓸모없어집니다. (서버 쪽 세션까지 끊으려면 각 사이트에서 '모든 기기 로그아웃'도 해야 합니다)
//
// 지우지 않는 것: 비밀번호(Login Data), 북마크, 방문 기록, 확장 프로그램, 확장 프로그램 저장소
// (지갑 확장 프로그램 데이터를 지우면 시드가 없을 때 자산을 잃을 수 있으므로 chrome-extension_ / moz-extension 은 제외)
package main

import (
	"os"
	"path/filepath"
	"strings"
)

var (
	chromiumCookieNames = []string{`Network\Cookies`, `Network\Cookies-journal`, "Cookies", "Cookies-journal",
		"Extension Cookies", "Extension Cookies-journal"}
	chromiumSiteDataNames = []string{"Local Storage", "Session Storage", "Service Worker", "WebStorage", "databases", "File System"}
	firefoxCookieNames    = []string{"cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm"}
	firefoxSiteDataNames  = []string{"webappsstore.sqlite", "webappsstore.sqlite-wal", "webappsstore.sqlite-shm"}

	// 삭제를 허용하는 이름 (safeToDelete 에서 다시 확인)
	wipeAllowedNames = map[string]bool{}
)

func init() {
	for _, l := range [][]string{chromiumCookieNames, chromiumSiteDataNames, firefoxCookieNames, firefoxSiteDataNames} {
		for _, n := range l {
			wipeAllowedNames[strings.ToLower(filepath.Base(n))] = true
		}
	}
}

func (s *scanner) hasCrit() bool {
	for _, f := range s.r.findings {
		if f.sev == sevCrit {
			return true
		}
	}
	return false
}

// 크로미움 User Data 아래의 프로필 폴더 (Default, Profile 1, ...). Opera 처럼 User Data 자체가 프로필인 경우도 포함.
func browserProfiles(userData string) []string {
	if isFile(filepath.Join(userData, "Preferences")) {
		return []string{userData}
	}
	var out []string
	entries, _ := os.ReadDir(userData)
	for _, e := range entries {
		p := filepath.Join(userData, e.Name())
		if e.IsDir() && isFile(filepath.Join(p, "Preferences")) {
			out = append(out, p)
		}
	}
	return out
}

func existing(paths []string) []string {
	var out []string
	for _, p := range paths {
		if exists(p) {
			out = append(out, p)
		}
	}
	return out
}

// IndexedDB·storage\default 아래에서 확장 프로그램 것은 빼고 웹사이트 것만
func siteSubdirs(dir, skipPrefix string) []string {
	var out []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(strings.ToLower(e.Name()), skipPrefix) {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

func (s *scanner) addWipeOptions(noInstall bool) {
	why := T("감염 흔적이 나와서, 에이전트가 가져갔을 수 있는 쿠키(로그인 세션)를 무효로 만드는 선택 항목입니다.")
	if noInstall {
		why = T("니케 설치 폴더를 찾지 못해 런처 로그로 감염 여부를 확인할 수 없어서, 만약을 위해 지울 수 있는 선택 항목입니다.")
	}
	why += T("\r\n기본으로 체크되어 있지 않습니다. 필요한 것만 직접 체크하세요.")

	// 1) 런처 데이터 전체
	var launcherDirs []string
	for _, name := range []string{"nikke_launcher", "nikke_launcher_hmt"} {
		if d := filepath.Join(os.Getenv("APPDATA"), name); isDir(d) {
			launcherDirs = append(launcherDirs, d)
		}
	}
	if len(launcherDirs) > 0 {
		s.add(finding{sev: sevOpt, title: T("니케 런처 데이터 전체 삭제 (저장된 로그인·캐시·에이전트 상태)"), where: strings.Join(launcherDirs, ", "),
			fix: fixWipeLauncher, targets: launcherDirs,
			detail: why + T("\r\n\r\n런처가 저장해 둔 로그인 정보(psd.dat, last_user.dat), 캐시, 에이전트가 남긴 상태값까지 모두 지웁니다.\r\n") +
				T("런처를 다시 켜면 새로 만들어지며, 다시 로그인해야 합니다. 게임 설치 파일은 지우지 않습니다.\r\n") +
				T("(지우면 감염 증거도 사라지므로, 해결을 누르면 삭제 전에 보고서가 자동으로 저장됩니다.)")})
	}

	// 2) 크로미움 계열 브라우저
	for _, b := range chromiumBrowsers() {
		if !isDir(b.userData) {
			continue
		}
		profiles := browserProfiles(b.userData)
		var cookies, site []string
		for _, p := range profiles {
			for _, n := range chromiumCookieNames {
				cookies = append(cookies, filepath.Join(p, n))
			}
			for _, n := range chromiumSiteDataNames {
				site = append(site, filepath.Join(p, n))
			}
			site = append(site, siteSubdirs(filepath.Join(p, "IndexedDB"), "chrome-extension_")...)
		}
		s.addBrowserWipe(b.name, b.userData, b.exe, b.hint, len(profiles), existing(cookies), existing(site), why)
	}

	// 3) Firefox (에이전트가 key4.db·logins.json·쿠키를 통째로 가져갈 수 있었음)
	if ffs, _ := filepath.Glob(filepath.Join(os.Getenv("APPDATA"), `Mozilla\Firefox\Profiles\*`)); len(ffs) > 0 {
		var cookies, site []string
		n := 0
		for _, p := range ffs {
			if !isDir(p) {
				continue
			}
			n++
			for _, f := range firefoxCookieNames {
				cookies = append(cookies, filepath.Join(p, f))
			}
			for _, f := range firefoxSiteDataNames {
				site = append(site, filepath.Join(p, f))
			}
			site = append(site, siteSubdirs(filepath.Join(p, `storage\default`), "moz-extension")...)
		}
		s.addBrowserWipe("Firefox", filepath.Join(os.Getenv("APPDATA"), `Mozilla\Firefox\Profiles`), "firefox.exe", "", n, existing(cookies), existing(site), why)
	}
}

func (s *scanner) addBrowserWipe(name, where, exe, hint string, profiles int, cookies, site []string, why string) {
	if len(cookies) > 0 {
		s.add(finding{sev: sevOpt, title: name + T(" 쿠키 삭제 (모든 사이트에서 로그아웃)"), where: where,
			fix: fixWipeCookies, targets: cookies, browserExe: exe, browserHnt: hint,
			detail: why + "\r\n\r\n" +
				T("이 브라우저의 모든 프로필에서 쿠키를 지웁니다. 모든 사이트에서 로그아웃되어, 훔쳐 간 쿠키로는 더 이상 로그인할 수 없게 됩니다.\r\n") +
				T("저장된 비밀번호·북마크·방문 기록·확장 프로그램은 지우지 않습니다.\r\n") +
				T("지울 때 이 브라우저를 닫아야 합니다.\r\n\r\n") +
				T("프로필 수: ") + itoa(profiles) + "\r\n" + strings.Join(limit(cookies, 12), "\r\n")})
	}
	if len(site) > 0 {
		s.add(finding{sev: sevOpt, title: name + T(" 사이트 데이터 삭제 (Local Storage·IndexedDB 등)"), where: where,
			fix: fixWipeSiteData, targets: site, browserExe: exe, browserHnt: hint,
			detail: why + "\r\n\r\n" +
				T("웹사이트가 저장한 데이터(일부 사이트는 로그인 토큰을 여기에 둡니다)를 지웁니다. 사이트 설정이 초기화될 수 있습니다.\r\n") +
				T("확장 프로그램의 저장소는 빼고 지웁니다 (지갑 확장 프로그램 데이터를 지키기 위해).\r\n") +
				T("※ 그래도 웹 지갑·확장 프로그램을 쓴다면, 시드 구문을 따로 보관했는지 먼저 확인하세요.\r\n") +
				T("지울 때 이 브라우저를 닫아야 합니다.\r\n\r\n") + strings.Join(limit(site, 12), "\r\n")})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// 쿠키·사이트 데이터 경로가 허용된 이름·위치인지 다시 확인
func safeWipePath(kind fixKind, p string) bool {
	p = filepath.Clean(p)
	low := strings.ToLower(p)
	local := strings.ToLower(strings.TrimRight(os.Getenv("LOCALAPPDATA"), `\`)) + `\`
	roam := strings.ToLower(strings.TrimRight(os.Getenv("APPDATA"), `\`)) + `\`
	if !(strings.HasPrefix(low, local) || strings.HasPrefix(low, roam)) || hasReparseInPath(p) {
		return false
	}
	base := strings.ToLower(filepath.Base(p))
	parent := strings.ToLower(filepath.Base(filepath.Dir(p)))
	switch kind {
	case fixWipeLauncher:
		return filepath.Dir(low) == strings.TrimRight(roam, `\`) && (base == "nikke_launcher" || base == "nikke_launcher_hmt")
	case fixWipeCookies:
		return strings.HasPrefix(base, "cookies") || strings.HasPrefix(base, "extension cookies")
	case fixWipeSiteData:
		if parent == "indexeddb" {
			return !strings.HasPrefix(base, "chrome-extension_")
		}
		if parent == "default" && strings.HasSuffix(strings.ToLower(filepath.Dir(p)), `\storage\default`) {
			return !strings.HasPrefix(base, "moz-extension")
		}
		return wipeAllowedNames[base] && !strings.HasPrefix(base, "cookies")
	}
	return false
}
