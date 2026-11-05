//go:build windows

// 니케 PC 런처 해킹(2026년 11월, insightjs / k2f 에이전트) 점검·복구 도구 - 창(GUI)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const appVersion = "2026-11-04 v6"

var appTitle = T("니케 런처 해킹 점검·복구 도구")

func init() { runtime.LockOSThread() } // Win32 창은 한 스레드에서만 다뤄야 함

const (
	idAdd = 101 + iota
	idAuto
	idRemove
	idScan
	idFix
	idGuide
	idSave
	idList
	idLV
	idCheckAll
	idFull
	idDeleted
	idOptim
)

const (
	wmAutoFindDone = WM_APP + 1
	wmScanDone     = WM_APP + 2
	wmFixDone      = WM_APP + 3
	wmBlockDone    = WM_APP + 4
	wmStatus       = WM_APP + 5
)

var (
	pCoInitializeEx              = ole32.NewProc("CoInitializeEx")
	pChangeWindowMessageFilterEx = user32.NewProc("ChangeWindowMessageFilterEx")
)

var (
	dpi                                        = 96
	hwnd, hTitle, hDesc, hPathLabel, hPathList uintptr
	hAdd, hAuto, hRemove, hHint, hScan         uintptr
	hVerdict, hVerdictSub, hResLabel, hLV      uintptr
	hDetail, hFix, hGuide, hSave, hCheckAll    uintptr
	fontNormal, fontBold, fontTitle, fontBig   uintptr
	whiteBrush                                 uintptr
	hFull, hDeleted, hOptim                    uintptr

	roots       []string
	result      *scanResult
	displayed   []finding
	populating  bool
	busy        bool
	verdictClr  = rgb(60, 60, 60)
	afterReboot bool

	mu           sync.Mutex
	pendingRoots []string
	pendingScan  *scanResult
	pendingFix   fixOutcome
	pendingBlock struct {
		code uint32
		ok   bool
	}
	lastFixLog    []string
	pendingStatus string
	hadCrit       bool
)

func sc(v int) int32 { return int32(v * dpi / 96) }

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--elevated" { // 관리자 권한 작업만 하고 종료
		os.Exit(runElevatedTasks(args[1:]))
	}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "--apply-block": // 이전 버전 호환
			os.Exit(runElevatedTasks([]string{"block"}))
		case "--after-reboot":
			afterReboot = true
		default:
			if r := resolveRoot(a); r != "" { // exe 위에 폴더를 끌어다 놓은 경우
				roots = appendUnique(roots, r)
			}
		}
	}

	// 비주얼 스타일·DPI 설정은 exe 안에 넣은 매니페스트 리소스가 처리합니다.
	pSetProcessDPIAware.Call()
	pOleInitialize.Call(0)
	icc := struct{ size, icc uint32 }{8, 0x1 | 0x4000 /*LISTVIEW|STANDARD*/}
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	hdc, _, _ := pGetDC.Call(0)
	if d, _, _ := pGetDeviceCaps.Call(hdc, 88 /*LOGPIXELSX*/); d > 0 {
		dpi = int(d)
	}
	pReleaseDC.Call(0, hdc)

	mkFont := func(pt, weight int) uintptr {
		h, _, _ := pCreateFontW.Call(uintptr(-int32(pt*dpi/72)), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0,
			uintptr(unsafe.Pointer(u16(uiFontName()))))
		return h
	}
	fontNormal = mkFont(10, 400)
	fontBold = mkFont(10, 700)
	fontTitle = mkFont(16, 700)
	fontBig = mkFont(14, 700)
	whiteBrush, _, _ = pGetStockObject.Call(0)

	hInst, _, _ := pGetModuleHandleW.Call(0)
	cursor, _, _ := pLoadCursorW.Call(0, 32512)
	icon, _, _ := pLoadIconW.Call(0, 32518) // IDI_SHIELD
	className := u16("NikkeHackCheckWnd")
	wc := WNDCLASSEXW{
		lpfnWndProc: syscall.NewCallback(wndProc), hInstance: hInst, hCursor: cursor, hIcon: icon, hIconSm: icon,
		hbrBackground: 6 /*COLOR_WINDOW+1*/, lpszClassName: className, style: 0x3,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	sw, _, _ := pGetSystemMetrics.Call(0)
	sh, _, _ := pGetSystemMetrics.Call(1)
	w, h := int32(sc(1000)), int32(sc(800))
	if w > int32(sw)-20 {
		w = int32(sw) - 20
	}
	if h > int32(sh)-60 {
		h = int32(sh) - 60
	}
	hwnd, _, _ = pCreateWindowExW.Call(WS_EX_ACCEPTFILES, uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16(appTitle+"  ("+appVersion+")"))), WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		uintptr((int32(sw)-w)/2), uintptr((int32(sh)-h)/2), uintptr(w), uintptr(h), 0, 0, hInst, 0)

	createControls(hInst)
	// 관리자 권한으로 실행해도 탐색기에서 끌어다 놓기가 되도록
	for _, m := range []uintptr{WM_DROPFILES, 0x004A, 0x0049} {
		pChangeWindowMessageFilterEx.Call(hwnd, m, 1, 0)
	}
	pDragAcceptFiles.Call(hwnd, 1)

	pShowWindow.Call(hwnd, SW_SHOW)
	pUpdateWindow.Call(hwnd)
	layout()

	// 시작할 때는 아무것도 자동으로 하지 않음 (이미 니케를 지운 사람도 있으므로).
	// 재부팅 후 자동 실행된 경우에만 남은 항목을 바로 다시 검사.
	refreshPathList()
	if afterReboot {
		startScan(false)
	} else {
		showWelcome()
	}

	var msg MSG
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			break
		}
		if d, _, _ := pIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&msg))); d != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func child(class, text string, style, exStyle uintptr, id int, font uintptr, hInst uintptr) uintptr {
	h, _, _ := pCreateWindowExW.Call(exStyle, uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
		WS_CHILD|WS_VISIBLE|style, 0, 0, 10, 10, hwnd, uintptr(id), hInst, 0)
	sendMsg(h, WM_SETFONT, font, 1)
	ctlText[h] = text
	ctlFont[h] = font
	return h
}

var ctlFont = map[uintptr]uintptr{}

func createControls(hInst uintptr) {
	hTitle = child("STATIC", T("니케 PC 런처 해킹 점검·복구 도구"), SS_NOPREFIX, 0, 0, fontTitle, hInst)
	hPathLabel = child("STATIC", T("① 니케 설치 폴더 (자동으로 찾은 곳 + 직접 추가한 곳 전부 검사)"), SS_NOPREFIX, 0, 0, fontBold, hInst)
	hPathList = child("LISTBOX", "", WS_TABSTOP|WS_VSCROLL|LBS_NOTIFY|LBS_NOINTEGRAL, WS_EX_CLIENTEDGE, idList, fontNormal, hInst)
	hAdd = child("BUTTON", T("폴더 선택해서 추가..."), WS_TABSTOP, 0, idAdd, fontNormal, hInst)
	hAuto = child("BUTTON", T("자동으로 찾기"), WS_TABSTOP, 0, idAuto, fontNormal, hInst)
	hRemove = child("BUTTON", T("선택한 경로 빼기"), WS_TABSTOP, 0, idRemove, fontNormal, hInst)
	hHint = child("STATIC", T("※ 탐색기에서 니케 폴더(또는 런처 바로가기·exe)를 이 창에 끌어다 놓아도 추가됩니다. 구글 플레이 게임즈/공식 런처/스팀 모두 추가하세요."),
		SS_NOPREFIX, 0, 0, fontNormal, hInst)
	hFull = child("BUTTON", T("전체 드라이브 정밀 검사 — 다른 위치에 남은 악성 파일과 니케 설치 폴더까지 찾습니다 (몇 분 걸림)"), WS_TABSTOP|0x3 /*BS_AUTOCHECKBOX*/ |0x2000 /*BS_MULTILINE*/, 0, idFull, fontNormal, hInst)
	hScan = child("BUTTON", T("② 검사 시작"), WS_TABSTOP|BS_DEFPUSHBUTTON, 0, idScan, fontBig, hInst)
	hDeleted = child("BUTTON", T("이미 니케를 지웠어요\n→ 바로 점검·조치"), WS_TABSTOP|0x2000 /*BS_MULTILINE*/, 0, idDeleted, fontBold, hInst)
	hVerdict = child("STATIC", T("준비 중..."), SS_NOPREFIX, 0, 0, fontBig, hInst)
	hVerdictSub = child("STATIC", "", SS_NOPREFIX, 0, 0, fontNormal, hInst)
	hResLabel = child("STATIC", resLabelScan(), SS_NOPREFIX, 0, 0, fontBold, hInst)

	hLV = child("SysListView32", "", WS_TABSTOP|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS, WS_EX_CLIENTEDGE, idLV, fontNormal, hInst)
	sendMsg(hLV, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_CHECKBOXES|LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER)
	for i, name := range []string{T("결과"), T("내용"), T("위치"), T("해결 방법")} {
		col := LVCOLUMNW{mask: LVCF_TEXT | LVCF_WIDTH, cx: sc(100), pszText: u16(name)}
		sendMsgP(hLV, LVM_INSERTCOLUMNW, uintptr(i), unsafe.Pointer(&col))
	}

	hDetail = child("EDIT", "", WS_TABSTOP|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL, WS_EX_CLIENTEDGE, 0, fontNormal, hInst)
	sendMsg(hDetail, 0x00C5 /*EM_SETLIMITTEXT*/, 4*1024*1024, 0)
	hFix = child("BUTTON", fixButtonScan(), WS_TABSTOP, 0, idFix, fontBold, hInst)
	hCheckAll = child("BUTTON", T("권장 항목 전체 체크"), WS_TABSTOP, 0, idCheckAll, fontNormal, hInst)
	hOptim = child("BUTTON", T("PC 간단 최적화"), WS_TABSTOP, 0, idOptim, fontNormal, hInst)
	hGuide = child("BUTTON", T("털렸을 때 할 일"), WS_TABSTOP, 0, idGuide, fontNormal, hInst)
	hSave = child("BUTTON", T("보고서 저장"), WS_TABSTOP, 0, idSave, fontNormal, hInst)
	enable(hFix, false)
	enable(hCheckAll, false)
}

func resLabelScan() string {
	return T("검사 결과 — 항목을 클릭하면 아래에 자세한 내용이 나옵니다. 체크된 항목이 ③ 해결 대상입니다.")
}
func fixButtonScan() string { return T("③ 체크한 항목 해결") }

func move(h uintptr, x, y, w, ht int32) {
	if h != 0 {
		pMoveWindow.Call(h, uintptr(x), uintptr(y), uintptr(max32(w, 1)), uintptr(max32(ht, 1)), 1)
	}
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

// 글자가 잘리지 않도록 너비에 맞춰 필요한 높이를 계산
func textH(h uintptr, width int32) int32 {
	if ctlText[h] == "" {
		return sc(2)
	}
	// 실제 줄바꿈이 계산과 조금 달라도 잘리지 않게, 조금 좁은 폭으로 재고 여유를 둠
	_, ht := measureText(ctlText[h], ctlFont[h], width-sc(10), true, h)
	return ht + sc(6)
}

// 버튼 글자에 맞는 폭
func btnW(h uintptr) int32 {
	w, _ := measureText(ctlText[h], ctlFont[h], 0, false, h)
	return w + sc(32)
}

var inLayout bool

func layout() {
	if hLV == 0 || inLayout {
		return
	}
	inLayout = true
	defer func() { inLayout = false }()
	var rc RECT
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	W, H := rc.right, rc.bottom
	m := sc(16)
	gap := sc(8)
	full := W - 2*m
	y := m

	h := textH(hTitle, full)
	move(hTitle, m, y, full, h)
	y += h + gap

	h = textH(hPathLabel, full)
	move(hPathLabel, m, y, full, h)
	y += h + sc(4)
	bw := max32(max32(btnW(hAdd), btnW(hAuto)), max32(btnW(hRemove), sc(170)))
	bh := sc(30)
	move(hPathList, m, y, full-bw-sc(10), bh*3+sc(4))
	bx := W - m - bw
	move(hAdd, bx, y, bw, bh)
	move(hAuto, bx, y+bh+sc(2), bw, bh)
	move(hRemove, bx, y+2*(bh+sc(2)), bw, bh)
	y += bh*3 + sc(4) + gap

	h = textH(hHint, full)
	move(hHint, m, y, full, h)
	y += h + sc(4)
	h = max32(textH(hFull, full-sc(24)), sc(22))
	move(hFull, m, y, full, h)
	y += h + gap

	// 검사 버튼 두 개 + 오른쪽에 판정 문구 (문구 길이에 맞춰 높이 계산)
	sw := max32(btnW(hScan), sc(150))
	dw := sc(190)
	move(hScan, m, y, sw, sc(54))
	move(hDeleted, m+sw+gap, y, dw, sc(54))
	vx := m + sw + gap + dw + sc(14)
	vw := W - m - vx
	vh := textH(hVerdict, vw)
	vsh := textH(hVerdictSub, vw)
	move(hVerdict, vx, y, vw, vh)
	move(hVerdictSub, vx, y+vh+sc(2), vw, vsh)
	y += max32(sc(54), vh+vsh+sc(2)) + gap

	h = textH(hResLabel, full)
	move(hResLabel, m, y, full, h)
	y += h + sc(4)

	// 아래 버튼: 글자 길이에 맞춘 폭. 한 줄에 다 안 들어가면 두 줄로.
	bh = sc(36)
	left := []uintptr{hFix, hCheckAll}
	right := []uintptr{hOptim, hGuide, hSave}
	total := int32(0)
	for _, b := range append(append([]uintptr{}, left...), right...) {
		total += btnW(b) + gap
	}
	rows := int32(1)
	if total > full {
		rows = 2
	}
	by := H - m - bh
	x := m
	if rows == 2 {
		for _, b := range left {
			move(b, x, by-bh-gap, btnW(b), bh)
			x += btnW(b) + gap
		}
		x = m
		for _, b := range right {
			move(b, x, by, btnW(b), bh)
			x += btnW(b) + gap
		}
	} else {
		for _, b := range left {
			move(b, x, by, btnW(b), bh)
			x += btnW(b) + gap
		}
		x = W - m
		for i := len(right) - 1; i >= 0; i-- {
			x -= btnW(right[i])
			move(right[i], x, by, btnW(right[i]), bh)
			x -= gap
		}
	}
	barTop := by - (rows-1)*(bh+gap)

	detailH := sc(140)
	dy := barTop - gap - detailH
	lvH := dy - gap - y
	if lvH < sc(120) { // 창이 작으면 상세창을 줄여서 목록을 확보
		detailH = max32(sc(70), detailH-(sc(120)-lvH))
		dy = barTop - gap - detailH
		lvH = dy - gap - y
	}
	move(hDetail, m, dy, full, detailH)
	move(hLV, m, y, full, lvH)

	avail := full - sc(24)
	c0, c3 := sc(95), sc(190)
	c1 := (avail - c0 - c3) * 55 / 100
	c2 := avail - c0 - c3 - c1
	for i, w := range []int32{c0, c1, c2, c3} {
		sendMsg(hLV, LVM_SETCOLUMNWIDTH, uintptr(i), uintptr(w))
	}
}

func appendUnique(list []string, r string) []string {
	for _, x := range list {
		if strings.EqualFold(x, r) {
			return list
		}
	}
	return append(list, r)
}

func refreshPathList() {
	sendMsg(hPathList, LB_RESETCONTENT, 0, 0)
	if len(roots) == 0 {
		sendMsgP(hPathList, LB_ADDSTRING, 0, unsafe.Pointer(u16(T("(자동으로 찾지 않습니다 — 니케가 설치되어 있으면 오른쪽 버튼으로 찾거나 폴더를 끌어다 놓으세요)"))))
		return
	}
	for _, r := range roots {
		sendMsgP(hPathList, LB_ADDSTRING, 0, unsafe.Pointer(u16(r)))
	}
}

func setBusy(b bool, status string) {
	busy = b
	for _, h := range []uintptr{hScan, hAdd, hAuto, hRemove, hFix, hCheckAll, hFull, hDeleted, hOptim} {
		enable(h, !b)
	}
	if !b && (result == nil || !hasFixable()) {
		enable(hFix, false)
		enable(hCheckAll, false)
	}
	if status != "" {
		verdictClr = rgb(60, 60, 60)
		setText(hVerdict, status)
		setText(hVerdictSub, "")
	}
}

func hasFixable() bool {
	for _, f := range displayed {
		if f.fix != fixNone {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 백그라운드 작업 시작
// ---------------------------------------------------------------------------

func startAutoFind(thenScan bool) {
	setBusy(true, T("니케 설치 폴더를 찾는 중..."))
	go func() {
		found := autoFindRoots(true, postStatus)
		mu.Lock()
		pendingRoots = found
		mu.Unlock()
		ts := uintptr(0)
		if thenScan {
			ts = 1
		}
		pPostMessageW.Call(hwnd, wmAutoFindDone, ts, 0)
	}()
}

// noInstall: 이미 니케를 지운 사람용. 설치 폴더 없이 점검 (목록의 폴더도 쓰지 않음)
func startScan(noInstall bool) {
	if busy {
		return
	}
	full := sendMsg(hFull, 0x00F0 /*BM_GETCHECK*/, 0, 0) == 1
	if full {
		setBusy(true, T("전체 드라이브 정밀 검사 중... (몇 분 걸립니다)"))
	} else {
		setBusy(true, T("검사 중... (보통 수십 초 걸립니다)"))
	}
	setText(hDetail, "")
	rs := append([]string(nil), roots...)
	if noInstall {
		rs = nil
		setBusy(true, T("니케를 지운 상태로 점검 중... (설치 폴더 없이 확인하는 항목만)"))
	}
	go func() {
		r := runScan(rs, full, noInstall, postStatus)
		mu.Lock()
		pendingScan = r
		mu.Unlock()
		pPostMessageW.Call(hwnd, wmScanDone, 0, 0)
	}()
}

// PC 간단 최적화: 분석 시작
func startOptimize() {
	if busy {
		return
	}
	setBusy(true, T("PC 상태 확인 중... (정리할 수 있는 용량 계산)"))
	setText(hDetail, "")
	go func() {
		r := analyzeOptimize(postStatus)
		mu.Lock()
		pendingScan = r
		mu.Unlock()
		pPostMessageW.Call(hwnd, wmScanDone, 0, 0)
	}()
}

func showOptimizeSummary(r *scanResult) {
	verdictClr = rgb(20, 120, 90)
	setText(hVerdict, T("PC 간단 최적화"))
	setText(hVerdictSub, T("체크된 항목을 확인하고 [③ 체크한 항목 정리]를 누르세요. 개인 파일·비밀번호·로그인은 건드리지 않습니다. 해킹 점검으로 돌아가려면 [② 검사 시작]을 누르세요."))
	pInvalidateRect.Call(hVerdict, 0, 1)
	var sb strings.Builder
	sb.WriteString(T("PC 상태 확인 완료: ") + time.Now().Format("2006-01-02 15:04:05") + "\r\n\r\n")
	for _, f := range r.findings {
		sb.WriteString("· " + f.title + "\r\n")
	}
	if len(lastFixLog) > 0 {
		sb.WriteString(T("\r\n── 직전 작업 기록 ──\r\n") + strings.Join(lastFixLog, "\r\n"))
	}
	setText(hDetail, sb.String())
}

// 처음 켰을 때 안내
func showWelcome() {
	verdictClr = rgb(40, 70, 130)
	setText(hVerdict, T("니케가 설치되어 있나요?"))
	setText(hVerdictSub, T("설치되어 있으면 위에서 [자동으로 찾기]나 [폴더 선택해서 추가] 후 [② 검사 시작]. ")+
		T("이미 지웠다면 [이미 니케를 지웠어요]를 누르세요 — 지운 뒤에도 남는 흔적(브라우저 DLL·레지스트리·런처 데이터)을 점검하고 정리합니다."))
	pInvalidateRect.Call(hVerdict, 0, 1)
}

// 폴더 찾기·추가 후 안내 (검사는 사용자가 직접 시작)
func showFoundMessage() {
	verdictClr = rgb(40, 70, 130)
	if len(roots) > 0 {
		setText(hVerdict, fmt.Sprintf(T("니케 설치 폴더 %d개를 찾았습니다 — [② 검사 시작]을 누르세요"), len(roots)))
		setText(hVerdictSub, T("빠진 설치 폴더(구글 플레이 게임즈·스팀 등)가 있으면 위에서 추가한 뒤 검사하세요."))
	} else {
		setText(hVerdict, T("니케 설치 폴더를 찾지 못했습니다"))
		setText(hVerdictSub, T("설치되어 있다면 [폴더 선택해서 추가]로 직접 넣어 주세요. 이미 니케를 지웠다면 [이미 니케를 지웠어요]를 누르세요."))
	}
	pInvalidateRect.Call(hVerdict, 0, 1)
}

// 백그라운드 작업이 진행 상황을 화면에 알립니다.
func postStatus(s string) {
	mu.Lock()
	pendingStatus = s
	mu.Unlock()
	pPostMessageW.Call(hwnd, wmStatus, 0, 0)
}

func addPath(p string, quiet bool) bool {
	r := resolveRoot(p)
	if r == "" {
		if !quiet {
			msgBox(hwnd, T("이 위치에서 니케를 찾지 못했습니다:\n")+p+T("\n\n'Launcher' 폴더가 들어 있는 니케 최상위 폴더를 골라 주세요.\n(예: C:\\NIKKE, D:\\Games\\NIKKE)"), appTitle, MB_ICONWARNING)
		}
		return false
	}
	roots = appendUnique(roots, r)
	refreshPathList()
	return true
}

// ---------------------------------------------------------------------------
// 결과 표시
// ---------------------------------------------------------------------------

func lvSetText(row, col int, s string) {
	it := LVITEMW{mask: LVIF_TEXT, iItem: int32(row), iSubItem: int32(col), pszText: u16(s)}
	if col == 0 {
		sendMsgP(hLV, LVM_INSERTITEMW, 0, unsafe.Pointer(&it))
	} else {
		sendMsgP(hLV, LVM_SETITEMTEXTW, uintptr(row), unsafe.Pointer(&it))
	}
}

func lvSetCheck(row int, state uint32) { // 0=체크박스 없음, 1=해제, 2=체크
	it := LVITEMW{stateMask: LVIS_STATEIMAGEMASK, state: state << 12}
	sendMsgP(hLV, LVM_SETITEMSTATE, uintptr(row), unsafe.Pointer(&it))
}

func lvChecked(row int) bool {
	return (sendMsg(hLV, LVM_GETITEMSTATE, uintptr(row), LVIS_STATEIMAGEMASK)>>12)&0xF == 2
}

func showResult(r *scanResult) {
	result = r
	displayed = r.findings
	if r.optimizeMode {
		setText(hFix, T("③ 체크한 항목 정리"))
		setText(hResLabel, T("PC 간단 최적화 — 항목을 클릭하면 아래에 자세한 내용이 나옵니다. 체크된 항목만 정리합니다."))
	} else {
		setText(hFix, fixButtonScan())
		setText(hResLabel, resLabelScan())
	}
	populating = true
	sendMsg(hLV, LVM_DELETEALLITEMS, 0, 0)
	for i, f := range displayed {
		lvSetText(i, 0, f.sev.label())
		lvSetText(i, 1, f.title)
		lvSetText(i, 2, f.where)
		lvSetText(i, 3, f.fix.label())
		switch {
		case f.fix == fixNone:
			lvSetCheck(i, 0)
		case f.sev == sevOpt:
			lvSetCheck(i, 1) // 선택 사항은 체크하지 않은 상태로
		default:
			lvSetCheck(i, 2)
		}
	}
	populating = false

	if r.optimizeMode {
		showOptimizeSummary(r)
		return
	}
	hadCrit = r.crit > 0
	note := ""
	if r.noInstallMode {
		note = T(" (니케를 지운 상태로 점검)")
	} else if len(r.roots) == 0 {
		note = T(" (니케 폴더 없이 검사함)")
	}
	switch {
	case r.crit > 0:
		verdictClr = rgb(200, 30, 30)
		setText(hVerdict, fmt.Sprintf(T("■ 털렸습니다 — 감염 흔적 %d건"), r.crit))
		setText(hVerdictSub, T("항목을 클릭해 내용을 확인하고, ③ 해결로 정리한 뒤 [털렸을 때 할 일]대로 비밀번호를 바꾸세요.")+note)
	case r.warn > 0:
		verdictClr = rgb(215, 110, 0)
		setText(hVerdict, fmt.Sprintf(T("▲ 위험 노출 — 주의 %d건"), r.warn))
		setText(hVerdictSub, T("런처가 공격자 코드를 불러온 흔적이 있습니다. 감염됐을 수 있다고 보고 대응하세요.")+note)
	default:
		verdictClr = rgb(20, 140, 60)
		setText(hVerdict, T("● 알려진 감염 흔적 없음"))
		setText(hVerdictSub, T("니케를 지웠거나 재설치했다면 로그가 없어 확실하지 않습니다. 체크된 예방 조치는 해 두세요.")+note)
	}
	pInvalidateRect.Call(hVerdict, 0, 1)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(T("검사 완료: %s\r\n감염 흔적 %d건, 주의 %d건\r\n검사한 니케 폴더: "), time.Now().Format("2006-01-02 15:04:05"), r.crit, r.warn))
	if len(r.roots) == 0 {
		sb.WriteString(T("없음"))
	} else {
		sb.WriteString(strings.Join(r.roots, ", "))
	}
	// 무엇 때문에 그런 판정이 나왔는지 바로 보이도록, 감염·주의 항목의 내용을 먼저 보여 줌
	if r.crit+r.warn > 0 {
		sb.WriteString(T("\r\n\r\n━━ 이렇게 판단한 이유 ━━"))
		for _, f := range r.findings {
			if f.sev != sevCrit && f.sev != sevWarn {
				continue
			}
			sb.WriteString("\r\n\r\n[" + f.sev.label() + "] " + f.title)
			if f.where != "" {
				sb.WriteString(T("\r\n위치: ") + f.where)
			}
			if f.detail != "" {
				lines := strings.Split(f.detail, "\r\n")
				if len(lines) > 12 {
					lines = append(lines[:12], T("… (목록에서 이 항목을 클릭하면 전체 내용)"))
				}
				sb.WriteString("\r\n" + strings.Join(lines, "\r\n"))
			}
		}
	}
	sb.WriteString(T("\r\n\r\n위 목록에서 항목을 클릭하면 자세한 내용을 볼 수 있습니다."))
	if len(lastFixLog) > 0 {
		sb.WriteString(T("\r\n\r\n── 직전 해결 작업 기록 ──\r\n") + strings.Join(lastFixLog, "\r\n"))
	}
	setText(hDetail, sb.String())
}

func showDetail(i int) {
	if i < 0 || i >= len(displayed) {
		return
	}
	f := displayed[i]
	var sb strings.Builder
	sb.WriteString("[" + f.sev.label() + "] " + f.title + "\r\n")
	if f.where != "" {
		sb.WriteString(T("위치: ") + f.where + "\r\n")
	}
	if f.fix != fixNone {
		sb.WriteString(T("해결 방법: ") + f.fix.label() + "\r\n")
	}
	if f.detail != "" {
		sb.WriteString("\r\n" + f.detail)
	}
	setText(hDetail, sb.String())
}

// ---------------------------------------------------------------------------
// 해결
// ---------------------------------------------------------------------------

func startFix() {
	if busy || result == nil {
		return
	}
	var items []finding
	browser := false
	for i, f := range displayed {
		if f.fix != fixNone && lvChecked(i) {
			items = append(items, f)
			if f.browserExe != "" {
				browser = true
			}
		}
	}
	if len(items) == 0 {
		msgBox(hwnd, T("체크된 해결 항목이 없습니다."), appTitle, MB_ICONINFO)
		return
	}
	if result.optimizeMode {
		var sb strings.Builder
		sb.WriteString(T("다음 정리를 합니다:\n\n"))
		for _, f := range items {
			sb.WriteString("• " + f.title + "\n")
		}
		sb.WriteString(T("\n사용 중인 파일은 건너뜁니다. 계속할까요?"))
		if msgBox(hwnd, sb.String(), appTitle+T(" - PC 간단 최적화"), MB_YESNO|MB_ICONQUESTION) != IDYES {
			return
		}
		setBusy(true, T("정리 중..."))
		go func() {
			o := applyOptimize(items, hwnd)
			o.optimize = true
			mu.Lock()
			pendingFix = o
			mu.Unlock()
			pPostMessageW.Call(hwnd, wmFixDone, 0, 0)
		}()
		return
	}
	var sb strings.Builder
	sb.WriteString(T("다음 작업을 합니다:\n\n"))
	for _, f := range items {
		sb.WriteString("• " + f.fix.label() + " — " + f.title + "\n")
	}
	sb.WriteString(T("\n니케 런처가 켜져 있으면 강제로 종료합니다.\n레지스트리는 삭제 전에 백업합니다 (") + sessionDir + T(").\n\n계속할까요?"))
	sb.WriteString(T("\n\n(지우기 전에 보고서를 같은 폴더에 먼저 저장하며, 저장하지 못하면 아무것도 지우지 않습니다.)"))
	if msgBox(hwnd, sb.String(), appTitle+T(" - 해결 확인"), MB_YESNO|MB_ICONQUESTION) != IDYES {
		return
	}
	wipe := false
	for _, f := range items {
		if f.sev == sevOpt {
			wipe = true
		}
	}
	if wipe && msgBox(hwnd, T("선택 사항(쿠키·데이터 삭제)이 포함되어 있습니다.\n\n")+
		T("· 쿠키를 지우면 그 브라우저의 모든 사이트에서 로그아웃됩니다.\n")+
		T("· 사이트 데이터를 지우면 일부 사이트 설정이 초기화됩니다. (확장 프로그램 저장소는 지우지 않습니다)\n")+
		T("· 런처 데이터를 지우면 니케 런처에 다시 로그인해야 합니다.\n")+
		T("· 비밀번호·북마크·방문 기록은 지우지 않습니다.\n\n")+
		T("웹 지갑을 쓴다면 시드 구문을 따로 보관했는지 먼저 확인하세요.\n\n정말 지울까요?"),
		appTitle+T(" - 쿠키·데이터 삭제 확인"), MB_YESNO|MB_ICONWARNING) != IDYES {
		return
	}
	closeBrowsers := false
	if browser {
		r := msgBox(hwnd, T("악성 DLL을 지우려면 감염된 브라우저를 닫아야 합니다.\n\n")+
			T("[예] 브라우저를 지금 강제로 닫고 진행 (열려 있는 작업은 먼저 저장하세요)\n")+
			T("[아니요] 닫지 않고 진행 — 잠긴 파일은 재부팅 후 정리합니다\n")+
			T("[취소] 해결 취소"), appTitle, MB_YESNOCANCEL|MB_ICONWARNING)
		if r != IDYES && r != IDNO {
			return
		}
		closeBrowsers = r == IDYES
	}
	setBusy(true, T("해결 중..."))
	reportText := buildReport()
	go func() {
		o := applyFixes(items, closeBrowsers, func() (string, error) { return writeReport(reportText, T("해결전_보고서_")) })
		mu.Lock()
		pendingFix = o
		mu.Unlock()
		pPostMessageW.Call(hwnd, wmFixDone, 0, 0)
	}()
}

func onFixDone() {
	mu.Lock()
	o := pendingFix
	mu.Unlock()
	if o.optimize {
		lastFixLog = o.log
		setBusy(false, "")
		msgBox(hwnd, fmt.Sprintf(T("정리 완료: 성공 %d건, 실패 %d건\n\n%s"), o.done, o.failed, strings.Join(o.log, "\n")), appTitle, MB_ICONINFO)
		startOptimize()
		return
	}
	if !o.aborted && (o.doBlock || o.doOldPersist) {
		setBusy(true, T("관리자 권한 확인 창에서 [예]를 눌러 주세요..."))
		exe, _ := os.Executable()
		params := "--elevated"
		if o.doBlock {
			params += " block"
		}
		if o.doOldPersist {
			params += " oldpersist"
		}
		go func() {
			runtime.LockOSThread()
			pCoInitializeEx.Call(0, 0x2|0x4) // APARTMENTTHREADED | DISABLE_OLE1DDE
			code, ok := runElevatedAndWait(hwnd, exe, params)
			mu.Lock()
			pendingBlock.code, pendingBlock.ok = code, ok
			mu.Unlock()
			pPostMessageW.Call(hwnd, wmBlockDone, 0, 0)
		}()
		return
	}
	finishFix(o)
}

func onBlockDone() {
	mu.Lock()
	o := pendingFix
	b := pendingBlock
	mu.Unlock()
	if !b.ok {
		o.log = append(o.log, T("× 관리자 작업(서버 차단·구버전 파일 삭제): 관리자 권한이 거부되어 하지 못했습니다."))
		o.failed++
		finishFix(o)
		return
	}
	if o.doBlock {
		switch {
		case b.code&3 == 0:
			o.log = append(o.log, T("○ 공격자 서버 차단: hosts 파일과 윈도우 방화벽에 차단 규칙을 추가했습니다. (hosts 백업: hosts.nikke_backup)"))
			o.done++
		case b.code&1 != 0:
			o.log = append(o.log, T("× hosts 파일 차단 실패. 백신이 hosts 파일 수정을 막았을 수 있습니다."))
			o.failed++
		}
		if b.code&2 != 0 {
			o.log = append(o.log, T("× 방화벽 차단 규칙을 만들지 못했습니다."))
			o.failed++
		}
	}
	if o.doOldPersist {
		if b.code&4 == 0 {
			o.log = append(o.log, T("○ Program Files 의 구버전 크롬 지속성 파일 삭제"))
			o.done++
		} else {
			o.log = append(o.log, T("△ 구버전 크롬 지속성 파일 일부를 못 지웠습니다 (크롬을 닫고 재부팅 후 다시 실행하세요)"))
			o.failed++
			o.needReboot = true
		}
	}
	finishFix(o)
}

func finishFix(o fixOutcome) {
	lastFixLog = o.log
	setBusy(false, "")
	summary := fmt.Sprintf(T("해결 작업 완료: 성공 %d건, 실패/보류 %d건\n\n%s"), o.done, o.failed, strings.Join(o.log, "\n"))
	if o.needReboot {
		summary += T("\n\n일부 악성 파일이 사용 중이라 아직 못 지웠습니다. 레지스트리 키를 지웠으므로 재부팅하면 더 이상 로드되지 않습니다.\n\n재부팅 후 이 프로그램이 자동으로 다시 열려서 남은 것을 정리하도록 할까요?")
		if msgBox(hwnd, summary, appTitle, MB_YESNO|MB_ICONWARNING) == IDYES {
			if err := registerRunOnce(); err == nil {
				msgBox(hwnd, T("등록했습니다. 윈도우를 다시 시작한 뒤 자동으로 열리면 [③ 체크한 항목 해결]을 한 번 더 눌러 주세요.\n\n(이 exe 파일을 옮기거나 지우지 마세요.)"), appTitle, MB_ICONINFO)
			}
		}
	} else {
		msgBox(hwnd, summary, appTitle, MB_ICONINFO)
	}
	if hadCrit {
		msgBox(hwnd, guideText, appTitle+T(" - 털렸을 때 할 일"), MB_ICONWARNING)
	}
	startScan(result != nil && result.noInstallMode) // 해결 후 같은 방식으로 다시 검사해서 결과 확인
}

// ---------------------------------------------------------------------------
// 보고서
// ---------------------------------------------------------------------------

func buildReport() string {
	var sb strings.Builder
	host, _ := os.Hostname()
	sb.WriteString(appTitle + " (" + appVersion + T(") 보고서\r\n"))
	sb.WriteString(T("작성: ") + time.Now().Format("2006-01-02 15:04:05") + "  PC: " + host + "  " + os.Getenv("USERNAME") + "\r\n")
	if result != nil {
		sb.WriteString(fmt.Sprintf(T("감염 흔적 %d건, 주의 %d건\r\n검사한 니케 폴더: %s\r\n"), result.crit, result.warn, strings.Join(result.roots, ", ")))
		if result.noInstallMode {
			sb.WriteString(T("점검 방식: 니케를 지운 상태로 점검 (설치 폴더 없이)\r\n"))
		}
		if result.fullScan {
			sb.WriteString(T("전체 드라이브 정밀 검사: 함\r\n"))
		}
	}
	if result != nil {
		for _, f := range result.findings {
			sb.WriteString("\r\n────────────────────────────\r\n[" + f.sev.label() + "] " + f.title + "\r\n")
			if f.where != "" {
				sb.WriteString(T("위치: ") + f.where + "\r\n")
			}
			if f.fix != fixNone {
				sb.WriteString(T("해결 방법: ") + f.fix.label() + "\r\n")
			}
			if f.detail != "" {
				sb.WriteString(f.detail + "\r\n")
			}
		}
	}
	if len(lastFixLog) > 0 {
		sb.WriteString(T("\r\n════ 해결 작업 기록 ════\r\n") + strings.Join(lastFixLog, "\r\n") + "\r\n")
	}
	sb.WriteString(T("\r\n════ 털렸을 때 할 일 ════\r\n") + strings.ReplaceAll(guideText, "\n", "\r\n") + "\r\n")
	return sb.String()
}

func writeReport(text, prefix string) (string, error) {
	dir, err := ensureSessionDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, prefix+time.Now().Format("150405")+".txt")
	if err := os.WriteFile(p, append([]byte{0xEF, 0xBB, 0xBF}, []byte(text)...), 0644); err != nil {
		return "", err
	}
	return p, nil
}

func saveReport() {
	if result == nil {
		msgBox(hwnd, T("먼저 검사를 실행하세요."), appTitle, MB_ICONINFO)
		return
	}
	p, err := writeReport(buildReport(), T("점검보고서_"))
	if err != nil {
		msgBox(hwnd, T("저장 실패: ")+err.Error(), appTitle, MB_ICONERROR)
		return
	}
	openInExplorer(filepath.Dir(p))
}

// ---------------------------------------------------------------------------
// 창 메시지 처리
// ---------------------------------------------------------------------------

func wndProc(h, msg, wp, lp uintptr) uintptr {
	switch uint32(msg) {
	case WM_SIZE:
		layout()
		return 0
	case WM_GETMINMAXINFO:
		mmi := (*MINMAXINFO)(unsafe.Pointer(lp))
		mmi.ptMinTrackSize.x, mmi.ptMinTrackSize.y = sc(820), sc(700)
		return 0
	case WM_CTLCOLORSTATIC:
		if lp == hDetail {
			pSetBkMode.Call(wp, 2) // 읽기 전용 편집창은 불투명해야 스크롤할 때 글자가 겹치지 않음
		} else {
			pSetBkMode.Call(wp, 1)
		}
		pSetBkColor.Call(wp, uintptr(rgb(255, 255, 255)))
		switch lp {
		case hVerdict:
			pSetTextColor.Call(wp, uintptr(verdictClr))
		case hHint, hVerdictSub:
			pSetTextColor.Call(wp, uintptr(rgb(95, 95, 95)))
		case hTitle:
			pSetTextColor.Call(wp, uintptr(rgb(25, 45, 90)))
		}
		return whiteBrush
	case WM_COMMAND:
		id := int(wp & 0xFFFF)
		code := (wp >> 16) & 0xFFFF
		if code != 0 && id != idList {
			break
		}
		switch id {
		case idAdd:
			if p := pickFolder(hwnd, T("니케 설치 폴더 선택 (Launcher 폴더가 들어 있는 곳)")); p != "" {
				if addPath(p, false) {
					showFoundMessage()
				}
			}
		case idAuto:
			startAutoFind(false)
		case idRemove:
			i := int(int32(sendMsg(hPathList, LB_GETCURSEL, 0, 0)))
			if i >= 0 && i < len(roots) {
				roots = append(roots[:i], roots[i+1:]...)
				refreshPathList()
				showFoundMessage()
			} else {
				msgBox(hwnd, T("목록에서 뺄 경로를 먼저 클릭하세요."), appTitle, MB_ICONINFO)
			}
		case idScan:
			if len(roots) == 0 && msgBox(hwnd, T("검사할 니케 설치 폴더가 목록에 없습니다.\n\n")+
				T("니케가 설치되어 있다면 [아니요]를 누르고 [자동으로 찾기]나 [폴더 선택해서 추가]로 먼저 추가하세요.\n")+
				T("이미 니케를 지웠다면 [예]를 누르면 설치 폴더 없이 점검합니다."), appTitle, MB_YESNO|MB_ICONQUESTION) != IDYES {
				break
			}
			startScan(false)
		case idDeleted:
			startScan(true)
		case idOptim:
			startOptimize()
		case idFix:
			startFix()
		case idCheckAll:
			for i, f := range displayed {
				if f.fix != fixNone && f.sev != sevOpt { // 선택 사항(쿠키·데이터 삭제)은 직접 체크해야 함
					lvSetCheck(i, 2)
				}
			}
		case idGuide:
			msgBox(hwnd, guideText, appTitle+T(" - 털렸을 때 할 일"), MB_ICONINFO)
		case idSave:
			saveReport()
		}
		return 0
	case WM_NOTIFY:
		hdr := (*NMHDR)(unsafe.Pointer(lp))
		if hdr.hwndFrom != hLV {
			break
		}
		switch hdr.code {
		case NM_CUSTOMDRAW:
			cd := (*NMLVCUSTOMDRAW)(unsafe.Pointer(lp))
			switch cd.dwDrawStage {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW
			case CDDS_ITEMPREPAINT:
				i := int(cd.dwItemSpec)
				if i < len(displayed) {
					switch displayed[i].sev {
					case sevCrit:
						cd.clrText, cd.clrTextBk = rgb(190, 20, 20), rgb(255, 238, 238)
					case sevWarn:
						cd.clrText, cd.clrTextBk = rgb(170, 85, 0), rgb(255, 246, 230)
					case sevFix:
						cd.clrText, cd.clrTextBk = rgb(20, 80, 170), rgb(238, 245, 255)
					case sevOpt:
						cd.clrText, cd.clrTextBk = rgb(105, 55, 160), rgb(246, 241, 252)
					case sevTune:
						cd.clrText, cd.clrTextBk = rgb(20, 120, 80), rgb(236, 249, 242)
					default:
						cd.clrText = rgb(110, 110, 110)
					}
				}
				return CDRF_NEWFONT
			}
		case LVN_ITEMCHANGING:
			nm := (*NMLISTVIEW)(unsafe.Pointer(lp))
			i := int(nm.iItem)
			if !populating && nm.uChanged&LVIF_STATE != 0 && (nm.uNewState^nm.uOldState)&LVIS_STATEIMAGEMASK != 0 &&
				i >= 0 && i < len(displayed) && displayed[i].fix == fixNone {
				return 1 // 해결할 게 없는 항목은 체크 못 하게
			}
		case LVN_ITEMCHANGED:
			nm := (*NMLISTVIEW)(unsafe.Pointer(lp))
			if nm.uNewState&0x2 != 0 && nm.uOldState&0x2 == 0 {
				showDetail(int(nm.iItem))
			}
		}
	case WM_DROPFILES:
		hdrop := wp
		n, _, _ := pDragQueryFileW.Call(hdrop, 0xFFFFFFFF, 0, 0)
		added, failed := 0, []string{}
		for i := uintptr(0); i < n; i++ {
			buf := make([]uint16, 1024)
			pDragQueryFileW.Call(hdrop, i, uintptr(unsafe.Pointer(&buf[0])), 1024)
			p := syscall.UTF16ToString(buf)
			if strings.HasSuffix(strings.ToLower(p), ".lnk") {
				p = resolveShortcut(p)
			}
			if addPath(p, true) {
				added++
			} else {
				failed = append(failed, p)
			}
		}
		pDragFinish.Call(hdrop)
		if len(failed) > 0 {
			msgBox(hwnd, T("다음 위치에서 니케를 찾지 못했습니다:\n")+strings.Join(failed, "\n")+T("\n\n'Launcher' 폴더가 들어 있는 니케 최상위 폴더를 넣어 주세요."), appTitle, MB_ICONWARNING)
		}
		if added > 0 && !busy {
			showFoundMessage()
		}
		return 0
	case wmAutoFindDone:
		mu.Lock()
		found := pendingRoots
		mu.Unlock()
		for _, r := range found {
			roots = appendUnique(roots, r)
		}
		refreshPathList()
		setBusy(false, "")
		if wp == 1 {
			startScan(false)
		} else {
			showFoundMessage()
		}
		return 0
	case wmScanDone:
		mu.Lock()
		r := pendingScan
		mu.Unlock()
		setBusy(false, "")
		showResult(r)
		setBusy(false, "")
		if afterReboot {
			afterReboot = false
			if hasFixable() && r.crit > 0 {
				msgBox(hwnd, T("재부팅 후 다시 검사했습니다. 남은 항목이 있으면 [③ 체크한 항목 해결]을 눌러 마저 정리하세요."), appTitle, MB_ICONINFO)
			}
		}
		return 0
	case wmFixDone:
		onFixDone()
		return 0
	case wmStatus:
		mu.Lock()
		st := pendingStatus
		mu.Unlock()
		if busy {
			verdictClr = rgb(60, 60, 60)
			setText(hVerdict, st)
		}
		return 0
	case wmBlockDone:
		onBlockDone()
		return 0
	case WM_DESTROY:
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(h, msg, wp, lp)
	return r
}

// .lnk 바로가기를 끌어다 놓은 경우: 파일 안의 UTF-16 문자열에서 .exe 경로를 찾습니다.
func resolveShortcut(lnk string) string {
	b, err := os.ReadFile(lnk)
	if err != nil {
		return lnk
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	// UTF-16 조각마다 확인
	start := 0
	for i := 0; i <= len(u); i++ {
		if i == len(u) || u[i] == 0 {
			part := string(utf16ToRunes(u[start:i]))
			if j := strings.Index(part, `:\`); j >= 1 && strings.HasSuffix(strings.ToLower(part), ".exe") {
				return part[j-1:]
			}
			start = i + 1
		}
	}
	return lnk
}

func utf16ToRunes(u []uint16) []rune {
	return []rune(syscall.UTF16ToString(append(append([]uint16{}, u...), 0)))
}
