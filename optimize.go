//go:build windows

// PC 간단 최적화: 임시 파일·브라우저 캐시·DNS 캐시·휴지통 정리, 시작 프로그램·여유 공간 보기.
// 분석은 용량만 계산하고, 정리는 사용자가 체크한 항목만 합니다. 사용 중인 파일은 건너뜁니다.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	fixOptTemp = fixKind(100 + iota)
	fixOptBrowserCache
	fixOptDNS
	fixOptRecycle
)

var (
	pSHQueryRecycleBinW  = shell32.NewProc("SHQueryRecycleBinW")
	pSHEmptyRecycleBinW  = shell32.NewProc("SHEmptyRecycleBinW")
	pGetDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
	pRegEnumValueW       = syscall.NewLazyDLL("advapi32.dll").NewProc("RegEnumValueW")

	chromiumCacheNames = []string{"Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache"}
	userDataCacheNames = []string{"ShaderCache", "GrShaderCache", "GraphiteDawnCache"}
)

func optLabel(k fixKind) (string, bool) {
	switch k {
	case fixOptTemp:
		return T("임시 파일 삭제"), true
	case fixOptBrowserCache:
		return T("캐시 삭제"), true
	case fixOptDNS:
		return T("DNS 캐시 비우기"), true
	case fixOptRecycle:
		return T("휴지통 비우기"), true
	}
	return "", false
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// 폴더 안 파일 크기 합계 (정션은 따라가지 않음). olderThan 이 0 이 아니면 그보다 오래된 파일만.
func dirSize(dir string, olderThan time.Duration) (int64, int) {
	var total int64
	n := 0
	cut := time.Now().Add(-olderThan)
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && isReparseDir(d) {
				return filepath.SkipDir
			}
			return nil
		}
		if fi, err := d.Info(); err == nil {
			if olderThan == 0 || fi.ModTime().Before(cut) {
				total += fi.Size()
				n++
			}
		}
		return nil
	})
	return total, n
}

// 브라우저 캐시 폴더 목록 (쿠키·비밀번호·사이트 데이터는 포함하지 않음)
func browserCacheDirs() []string {
	var out []string
	for _, b := range chromiumBrowsers() {
		if !isDir(b.userData) {
			continue
		}
		for _, n := range userDataCacheNames {
			out = append(out, filepath.Join(b.userData, n))
		}
		for _, p := range browserProfiles(b.userData) {
			for _, n := range chromiumCacheNames {
				out = append(out, filepath.Join(p, n))
			}
		}
	}
	// Firefox 캐시는 LOCALAPPDATA 쪽 프로필에 있음
	if ffs, _ := filepath.Glob(filepath.Join(os.Getenv("LOCALAPPDATA"), `Mozilla\Firefox\Profiles\*\cache2`)); len(ffs) > 0 {
		out = append(out, ffs...)
	}
	return existing(out)
}

type shQueryRBInfo struct {
	cbSize      uint32
	i64Size     int64
	i64NumItems int64
}

func recycleBinInfo() (int64, int64) {
	info := shQueryRBInfo{}
	info.cbSize = uint32(unsafe.Sizeof(info))
	r, _, _ := pSHQueryRecycleBinW.Call(0, uintptr(unsafe.Pointer(&info)))
	if r != 0 {
		return -1, -1
	}
	return info.i64Size, info.i64NumItems
}

func regValues(root syscall.Handle, path string) []string {
	h, ok := regOpen(root, path)
	if !ok {
		return nil
	}
	defer syscall.RegCloseKey(h)
	var out []string
	for i := uint32(0); ; i++ {
		name := make([]uint16, 512)
		nlen := uint32(len(name))
		data := make([]uint16, 2048)
		dlen := uint32(len(data) * 2)
		var typ uint32
		r, _, _ := pRegEnumValueW.Call(uintptr(h), uintptr(i), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nlen)),
			0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dlen)))
		if r != 0 {
			break
		}
		v := ""
		if typ == syscall.REG_SZ || typ == syscall.REG_EXPAND_SZ {
			v = syscall.UTF16ToString(data)
		}
		out = append(out, syscall.UTF16ToString(name[:nlen])+"  →  "+v)
	}
	return out
}

func startupPrograms() []string {
	var out []string
	add := func(where string, items []string) {
		for _, it := range items {
			out = append(out, "["+where+"] "+it)
		}
	}
	add(T("현재 사용자"), regValues(syscall.HKEY_CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`))
	add(T("모든 사용자"), regValues(syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`))
	add(T("모든 사용자 32비트"), regValues(syscall.HKEY_LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`))
	for _, d := range []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`),
	} {
		es, _ := os.ReadDir(d)
		var names []string
		for _, e := range es {
			if !strings.EqualFold(e.Name(), "desktop.ini") {
				names = append(names, e.Name())
			}
		}
		add(T("시작 폴더"), names)
	}
	return out
}

// 분석: 용량만 계산하고 아무것도 지우지 않음
func analyzeOptimize(progress func(string)) *scanResult {
	r := &scanResult{optimizeMode: true}
	add := func(f finding) { r.findings = append(r.findings, f) }

	progress(T("임시 파일 크기 계산 중..."))
	tmp := os.TempDir()
	sz, n := dirSize(tmp, 24*time.Hour)
	add(finding{sev: sevTune, title: fmt.Sprintf(T("임시 파일 정리 — %s (%d개)"), humanSize(sz), n), where: tmp,
		fix: fixOptTemp, targets: []string{tmp},
		detail: T("프로그램들이 쓰고 남긴 임시 파일입니다. 하루 이상 지난 것만 지우고, 지금 쓰고 있는 파일은 건너뜁니다.")})

	progress(T("브라우저 캐시 크기 계산 중..."))
	caches := browserCacheDirs()
	var csz int64
	for _, c := range caches {
		s, _ := dirSize(c, 0)
		csz += s
	}
	if len(caches) > 0 {
		add(finding{sev: sevTune, title: fmt.Sprintf(T("브라우저 캐시 정리 — %s"), humanSize(csz)), where: T("크롬·엣지·웨일·파이어폭스 등"),
			fix: fixOptBrowserCache, targets: caches,
			detail: T("웹페이지를 빨리 열려고 저장해 둔 사본(캐시)입니다. 지워도 로그인·비밀번호·북마크는 그대로이고, 처음 여는 사이트가 잠깐 느릴 수 있습니다.\r\n") +
				T("브라우저가 켜져 있으면 사용 중인 파일은 건너뜁니다. 브라우저를 닫고 하면 더 많이 정리됩니다.\r\n\r\n") +
				strings.Join(limit(caches, 15), "\r\n")})
	}

	add(finding{sev: sevTune, title: T("DNS 캐시 비우기"), fix: fixOptDNS,
		detail: T("인터넷 주소 기억을 초기화합니다. 일부 사이트가 안 열리거나 느릴 때 도움이 됩니다.")})

	if rsz, rn := recycleBinInfo(); rsz > 0 {
		add(finding{sev: sevOpt, title: fmt.Sprintf(T("휴지통 비우기 — %s (%d개)"), humanSize(rsz), rn), fix: fixOptRecycle,
			detail: T("휴지통의 파일을 완전히 지웁니다. 되돌릴 수 없으니 필요한 파일이 없는지 먼저 확인하세요. (기본으로 체크하지 않음)")})
	}

	progress(T("시작 프로그램·디스크 확인 중..."))
	if sp := startupPrograms(); len(sp) > 0 {
		add(finding{sev: sevInfo, title: fmt.Sprintf(T("윈도우 시작 시 자동 실행되는 프로그램 %d개 (보기만 함)"), len(sp)),
			detail: T("필요 없는 프로그램은 작업 관리자(Ctrl+Shift+Esc) → [시작 앱]에서 '사용 안 함'으로 바꾸면 부팅이 빨라집니다.\r\n") +
				T("모르는 이름이 있으면 검색해 보세요.\r\n\r\n") + strings.Join(sp, "\r\n")})
	}
	var disks []string
	for d := 'C'; d <= 'Z'; d++ {
		root := string(d) + `:\`
		var free, total, totalFree uint64
		r1, _, _ := pGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(u16(root))), uintptr(unsafe.Pointer(&free)),
			uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
		if r1 != 0 && total > 0 {
			pct := float64(free) / float64(total) * 100
			warn := ""
			if pct < 10 {
				warn = T("  ← 공간 부족 (10% 미만이면 느려질 수 있음)")
			}
			disks = append(disks, fmt.Sprintf(T("%s 여유 %s / 전체 %s (%.0f%%)%s"), root, humanSize(int64(free)), humanSize(int64(total)), pct, warn))
		}
	}
	if len(disks) > 0 {
		add(finding{sev: sevInfo, title: T("드라이브 여유 공간 (보기만 함)"), detail: strings.Join(disks, "\r\n")})
	}
	sort.SliceStable(r.findings, func(i, j int) bool { return r.findings[i].sev > r.findings[j].sev })
	return r
}

// 정리 실행 (UI 스레드 밖)
func applyOptimize(items []finding, owner uintptr) fixOutcome {
	var o fixOutcome
	logf := func(format string, a ...any) { o.log = append(o.log, fmt.Sprintf(format, a...)) }
	for _, f := range items {
		switch f.fix {
		case fixOptTemp:
			freed, skipped := cleanDir(os.TempDir(), 24*time.Hour, true)
			logf(T("○ 임시 파일 정리: %s 확보 (사용 중이라 건너뜀 %d개)"), humanSize(freed), skipped)
			o.done++
		case fixOptBrowserCache:
			var freed int64
			skipped := 0
			for _, d := range f.targets {
				if !safeCachePath(d) {
					continue
				}
				fr, sk := cleanDir(d, 0, false)
				freed += fr
				skipped += sk
			}
			logf(T("○ 브라우저 캐시 정리: %s 확보 (사용 중이라 건너뜀 %d개)"), humanSize(freed), skipped)
			o.done++
		case fixOptDNS:
			if hiddenCmd("ipconfig", "/flushdns").Run() == nil {
				logf(T("○ DNS 캐시를 비웠습니다."))
				o.done++
			} else {
				logf(T("× DNS 캐시 비우기 실패"))
				o.failed++
			}
		case fixOptRecycle:
			r, _, _ := pSHEmptyRecycleBinW.Call(owner, 0, 0x1|0x2|0x4) // NOCONFIRMATION|NOPROGRESSUI|NOSOUND
			if r == 0 {
				logf(T("○ 휴지통을 비웠습니다."))
				o.done++
			} else {
				logf(T("× 휴지통 비우기 실패"))
				o.failed++
			}
		}
	}
	return o
}

// 브라우저 캐시 폴더인지 다시 확인 (이름이 정해진 캐시 폴더만)
func safeCachePath(p string) bool {
	base := strings.ToLower(filepath.Base(p))
	ok := base == "cache2"
	for _, n := range append(append([]string{}, chromiumCacheNames...), userDataCacheNames...) {
		if base == strings.ToLower(n) {
			ok = true
		}
	}
	low := strings.ToLower(p)
	return ok && strings.HasPrefix(low, strings.ToLower(strings.TrimRight(os.Getenv("LOCALAPPDATA"), `\`))+`\`) && !hasReparseInPath(p)
}

// 폴더 "안의 내용"만 지움 (폴더 자체는 남김). 사용 중인 파일은 건너뜀.
func cleanDir(dir string, olderThan time.Duration, keepRecentDirs bool) (int64, int) {
	var freed int64
	skipped := 0
	cut := time.Now().Add(-olderThan)
	entries, err := os.ReadDir(dir)
	if err != nil || hasReparseInPath(dir) {
		return 0, 0
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if e.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue // 정션·링크는 따라가지도 지우지도 않음
		}
		if olderThan > 0 && info.ModTime().After(cut) && (!e.IsDir() || keepRecentDirs) {
			continue
		}
		if e.IsDir() {
			fr, sk := cleanDir(p, olderThan, keepRecentDirs)
			freed += fr
			skipped += sk
			os.Remove(p) // 비었으면 지워짐
			continue
		}
		if os.Remove(p) == nil {
			freed += info.Size()
		} else {
			skipped++
		}
	}
	return freed, skipped
}
