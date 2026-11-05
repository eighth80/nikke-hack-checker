//go:build windows

// 프로세스·모듈 목록 (Toolhelp32), 프로세스 종료
package main

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	pModule32FirstW             = kernel32.NewProc("Module32FirstW")
	pModule32NextW              = kernel32.NewProc("Module32NextW")
	pQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	pGetDriveTypeW              = kernel32.NewProc("GetDriveTypeW")
	pGetVolumeInformationW      = kernel32.NewProc("GetVolumeInformationW")
)

type MODULEENTRY32W struct {
	dwSize        uint32
	th32ModuleID  uint32
	th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	modBaseAddr   uintptr
	modBaseSize   uint32
	hModule       uintptr
	szModule      [256]uint16
	szExePath     [260]uint16
}

type procInfo struct {
	pid  uint32
	name string // 실행 파일 이름 (예: chrome.exe)
}

func listProcesses() []procInfo {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var out []procInfo
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = syscall.Process32First(snap, &pe); err == nil; err = syscall.Process32Next(snap, &pe) {
		out = append(out, procInfo{pe.ProcessID, syscall.UTF16ToString(pe.ExeFile[:])})
	}
	return out
}

// 프로세스에 로드된 모듈(DLL) 경로 목록. 권한이 없으면 nil.
func listModules(pid uint32) []string {
	const TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32 = 0x8, 0x10
	snap, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var me MODULEENTRY32W
	me.dwSize = uint32(unsafe.Sizeof(me))
	var out []string
	r, _, _ := pModule32FirstW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	for r != 0 {
		out = append(out, syscall.UTF16ToString(me.szExePath[:]))
		r, _, _ = pModule32NextW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	}
	return out
}

func processImagePath(pid uint32) string {
	h, err := syscall.OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, _ := pQueryFullProcessImageNameW.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

func killPID(pid uint32) bool {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	return syscall.TerminateProcess(h, 1) == nil
}

// 이름이 같은 프로세스를 모두 종료. hint 가 있으면 실행 파일 경로에 hint 가 들어 있는 것만
// (Yandex·Cốc Cốc 처럼 browser.exe 라는 흔한 이름을 쓰는 브라우저 대비). explorer.exe 는 절대 종료하지 않음.
func killByName(exe, hint string) int {
	n := 0
	for _, p := range listProcesses() {
		if !strings.EqualFold(p.name, exe) || strings.EqualFold(p.name, "explorer.exe") {
			continue
		}
		if hint != "" && !strings.Contains(strings.ToLower(processImagePath(p.pid)), strings.ToLower(hint)) {
			continue
		}
		if killPID(p.pid) {
			n++
		}
	}
	return n
}

// 경로나 그 상위 폴더 중에 정션·심볼릭 링크가 있으면 true (엉뚱한 곳을 지우지 않기 위해)
func hasReparseInPath(p string) bool {
	const FILE_ATTRIBUTE_REPARSE_POINT = 0x400
	for cur := p; ; {
		a, err := syscall.GetFileAttributes(u16(cur))
		if err == nil && a&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
		parent := parentDir(cur)
		if parent == cur || parent == "" {
			return false
		}
		cur = parent
	}
}

func parentDir(p string) string {
	p = strings.TrimRight(p, `\`)
	i := strings.LastIndex(p, `\`)
	if i <= 2 { // "C:" 까지
		if len(p) >= 2 && p[1] == ':' {
			return p[:2] + `\`
		}
		return p
	}
	return p[:i]
}

// 고정·이동식 드라이브 목록 (클라우드 드라이브 이름이 붙은 것은 제외)
func scanDrives() []string {
	var out []string
	for d := 'C'; d <= 'Z'; d++ {
		root := string(d) + `:\`
		t, _, _ := pGetDriveTypeW.Call(uintptr(unsafe.Pointer(u16(root))))
		if t != 2 && t != 3 { // DRIVE_REMOVABLE, DRIVE_FIXED
			continue
		}
		label := make([]uint16, 261)
		r, _, _ := pGetVolumeInformationW.Call(uintptr(unsafe.Pointer(u16(root))), uintptr(unsafe.Pointer(&label[0])), 261, 0, 0, 0, 0, 0)
		if r == 0 {
			continue // 준비 안 된 드라이브
		}
		if cloudLabelRe.MatchString(syscall.UTF16ToString(label)) {
			continue
		}
		out = append(out, root)
	}
	return out
}
