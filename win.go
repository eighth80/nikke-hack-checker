//go:build windows

// Win32 API 바인딩 (외부 패키지 없이 표준 syscall만 사용)
package main

import (
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")

	pRegisterClassExW   = user32.NewProc("RegisterClassExW")
	pCreateWindowExW    = user32.NewProc("CreateWindowExW")
	pDefWindowProcW     = user32.NewProc("DefWindowProcW")
	pGetMessageW        = user32.NewProc("GetMessageW")
	pTranslateMessage   = user32.NewProc("TranslateMessage")
	pDispatchMessageW   = user32.NewProc("DispatchMessageW")
	pIsDialogMessageW   = user32.NewProc("IsDialogMessageW")
	pPostMessageW       = user32.NewProc("PostMessageW")
	pSendMessageW       = user32.NewProc("SendMessageW")
	pPostQuitMessage    = user32.NewProc("PostQuitMessage")
	pShowWindow         = user32.NewProc("ShowWindow")
	pUpdateWindow       = user32.NewProc("UpdateWindow")
	pMoveWindow         = user32.NewProc("MoveWindow")
	pSetWindowTextW     = user32.NewProc("SetWindowTextW")
	pEnableWindow       = user32.NewProc("EnableWindow")
	pMessageBoxW        = user32.NewProc("MessageBoxW")
	pLoadCursorW        = user32.NewProc("LoadCursorW")
	pLoadIconW          = user32.NewProc("LoadIconW")
	pGetClientRect      = user32.NewProc("GetClientRect")
	pGetDC              = user32.NewProc("GetDC")
	pReleaseDC          = user32.NewProc("ReleaseDC")
	pInvalidateRect     = user32.NewProc("InvalidateRect")
	pSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	pGetSystemMetrics   = user32.NewProc("GetSystemMetrics")

	pCreateFontW      = gdi32.NewProc("CreateFontW")
	pGetDeviceCaps    = gdi32.NewProc("GetDeviceCaps")
	pSetTextColor     = gdi32.NewProc("SetTextColor")
	pSetBkColor       = gdi32.NewProc("SetBkColor")
	pSetBkMode        = gdi32.NewProc("SetBkMode")
	pGetStockObject   = gdi32.NewProc("GetStockObject")
	pCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")

	pGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	pCreateActCtxW    = kernel32.NewProc("CreateActCtxW")
	pActivateActCtx   = kernel32.NewProc("ActivateActCtx")

	pDragAcceptFiles      = shell32.NewProc("DragAcceptFiles")
	pDragQueryFileW       = shell32.NewProc("DragQueryFileW")
	pDragFinish           = shell32.NewProc("DragFinish")
	pShellExecuteExW      = shell32.NewProc("ShellExecuteExW")
	pShellExecuteW        = shell32.NewProc("ShellExecuteW")
	pSHBrowseForFolderW   = shell32.NewProc("SHBrowseForFolderW")
	pSHGetPathFromIDListW = shell32.NewProc("SHGetPathFromIDListW")

	pOleInitialize    = ole32.NewProc("OleInitialize")
	pCoCreateInstance = ole32.NewProc("CoCreateInstance")
	pCoTaskMemFree    = ole32.NewProc("CoTaskMemFree")

	pInitCommonControlsEx = comctl32.NewProc("InitCommonControlsEx")
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_TABSTOP          = 0x00010000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_CLIPCHILDREN     = 0x02000000
	WS_EX_CLIENTEDGE    = 0x00000200
	WS_EX_ACCEPTFILES   = 0x00000010

	BS_DEFPUSHBUTTON = 0x1
	SS_NOPREFIX      = 0x80
	ES_MULTILINE     = 0x4
	ES_AUTOVSCROLL   = 0x40
	ES_READONLY      = 0x800
	LBS_NOTIFY       = 0x1
	LBS_NOINTEGRAL   = 0x100

	LVS_REPORT        = 0x1
	LVS_SINGLESEL     = 0x4
	LVS_SHOWSELALWAYS = 0x8

	WM_DESTROY        = 0x0002
	WM_SIZE           = 0x0005
	WM_SETFONT        = 0x0030
	WM_GETMINMAXINFO  = 0x0024
	WM_NOTIFY         = 0x004E
	WM_COMMAND        = 0x0111
	WM_CTLCOLORSTATIC = 0x0138
	WM_DROPFILES      = 0x0233
	WM_APP            = 0x8000

	LB_ADDSTRING    = 0x0180
	LB_DELETESTRING = 0x0182
	LB_RESETCONTENT = 0x0184
	LB_GETCURSEL    = 0x0188

	LVM_DELETEALLITEMS           = 0x1009
	LVM_GETNEXTITEM              = 0x100C
	LVM_SETITEMSTATE             = 0x102B
	LVM_GETITEMSTATE             = 0x102C
	LVM_SETEXTENDEDLISTVIEWSTYLE = 0x1036
	LVM_INSERTITEMW              = 0x104D
	LVM_INSERTCOLUMNW            = 0x1061
	LVM_SETCOLUMNWIDTH           = 0x101E
	LVM_SETITEMTEXTW             = 0x1074

	LVS_EX_GRIDLINES     = 0x1
	LVS_EX_CHECKBOXES    = 0x4
	LVS_EX_FULLROWSELECT = 0x20
	LVS_EX_DOUBLEBUFFER  = 0x10000

	LVIF_TEXT           = 0x1
	LVIF_STATE          = 0x8
	LVCF_TEXT           = 0x4
	LVCF_WIDTH          = 0x2
	LVNI_SELECTED       = 0x2
	LVIS_STATEIMAGEMASK = 0xF000

	NM_CUSTOMDRAW    = ^uint32(11)  // -12
	LVN_ITEMCHANGING = ^uint32(99)  // -100
	LVN_ITEMCHANGED  = ^uint32(100) // -101

	CDDS_PREPAINT       = 0x1
	CDDS_ITEMPREPAINT   = 0x10001
	CDRF_NEWFONT        = 0x2
	CDRF_NOTIFYITEMDRAW = 0x20

	MB_OK           = 0x0
	MB_YESNO        = 0x4
	MB_YESNOCANCEL  = 0x3
	MB_ICONERROR    = 0x10
	MB_ICONQUESTION = 0x20
	MB_ICONWARNING  = 0x30
	MB_ICONINFO     = 0x40
	IDYES           = 6
	IDNO            = 7

	SW_SHOW = 5
)

type WNDCLASSEXW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type MSG struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
	private uint32
}

type RECT struct{ left, top, right, bottom int32 }

type LVCOLUMNW struct {
	mask       uint32
	fmt        int32
	cx         int32
	pszText    *uint16
	cchTextMax int32
	iSubItem   int32
	iImage     int32
	iOrder     int32
	cxMin      int32
	cxDefault  int32
	cxIdeal    int32
}

type LVITEMW struct {
	mask       uint32
	iItem      int32
	iSubItem   int32
	state      uint32
	stateMask  uint32
	pszText    *uint16
	cchTextMax int32
	iImage     int32
	lParam     uintptr
	iIndent    int32
	iGroupId   int32
	cColumns   uint32
	puColumns  uintptr
	piColFmt   uintptr
	iGroup     int32
}

type NMHDR struct {
	hwndFrom uintptr
	idFrom   uintptr
	code     uint32
}

type NMLISTVIEW struct {
	hdr       NMHDR
	iItem     int32
	iSubItem  int32
	uNewState uint32
	uOldState uint32
	uChanged  uint32
	ptAction  struct{ x, y int32 }
	lParam    uintptr
}

type NMLVCUSTOMDRAW struct {
	hdr         NMHDR
	dwDrawStage uint32
	hdc         uintptr
	rc          RECT
	dwItemSpec  uintptr
	uItemState  uint32
	lItemlParam uintptr
	clrText     uint32
	clrTextBk   uint32
	iSubItem    int32
}

type MINMAXINFO struct {
	ptReserved, ptMaxSize, ptMaxPosition, ptMinTrackSize, ptMaxTrackSize struct{ x, y int32 }
}

type ACTCTXW struct {
	cbSize                 uint32
	dwFlags                uint32
	lpSource               *uint16
	wProcessorArchitecture uint16
	wLangId                uint16
	lpAssemblyDirectory    *uint16
	lpResourceName         *uint16
	lpApplicationName      *uint16
	hModule                uintptr
}

type SHELLEXECUTEINFOW struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

type BROWSEINFOW struct {
	hwndOwner      uintptr
	pidlRoot       uintptr
	pszDisplayName *uint16
	lpszTitle      *uint16
	ulFlags        uint32
	lpfn           uintptr
	lParam         uintptr
	iImage         int32
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func u16ptrToString(p uintptr) string {
	if p == 0 {
		return ""
	}
	var buf []uint16
	for i := uintptr(0); ; i += 2 {
		c := *(*uint16)(unsafe.Pointer(p + i))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return syscall.UTF16ToString(buf)
}

func sendMsg(h uintptr, msg uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), w, l)
	return r
}

// 포인터를 넘길 때는 변환을 Call 인자 안에서 해야 GC 규칙상 안전합니다.
func sendMsgP(h uintptr, msg uint32, w uintptr, p unsafe.Pointer) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), w, uintptr(p))
	return r
}

// 컨트롤에 넣은 글자를 기억해 두고(높이 계산용), 안내 문구가 바뀌면 배치를 다시 계산합니다.
var ctlText = map[uintptr]string{}

func setText(h uintptr, s string) {
	ctlText[h] = s
	pSetWindowTextW.Call(h, uintptr(unsafe.Pointer(u16(s))))
	if h != 0 && (h == hVerdict || h == hVerdictSub || h == hResLabel || h == hHint) {
		layout()
	}
}

var (
	pDrawTextW    = user32.NewProc("DrawTextW")
	pSelectObject = gdi32.NewProc("SelectObject")
)

// 주어진 폰트·너비에서 글자가 차지하는 크기. wrap=false 면 한 줄 너비를 잽니다.
func measureText(text string, font uintptr, width int32, wrap bool, ctl uintptr) (int32, int32) {
	if text == "" {
		return 0, 0
	}
	// 실제로 그려질 컨트롤의 DC 로 잼 (화면 배율이 다른 모니터에서도 맞도록)
	hdc, _, _ := pGetDC.Call(ctl)
	defer pReleaseDC.Call(ctl, hdc)
	old, _, _ := pSelectObject.Call(hdc, font)
	defer pSelectObject.Call(hdc, old)
	rc := RECT{0, 0, width, 0}
	flags := uintptr(0x400 | 0x800) // DT_CALCRECT | DT_NOPREFIX
	if wrap {
		flags |= 0x10 // DT_WORDBREAK
	} else {
		flags |= 0x20 // DT_SINGLELINE
	}
	t := u16(text)
	pDrawTextW.Call(hdc, uintptr(unsafe.Pointer(t)), ^uintptr(0), uintptr(unsafe.Pointer(&rc)), flags)
	return rc.right - rc.left, rc.bottom - rc.top
}

func enable(h uintptr, on bool) {
	v := uintptr(0)
	if on {
		v = 1
	}
	pEnableWindow.Call(h, v)
}

func msgBox(owner uintptr, text, title string, flags uint32) int {
	r, _, _ := pMessageBoxW.Call(owner, uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), uintptr(flags))
	return int(r)
}

func rgb(r, g, b uint32) uint32 { return r | g<<8 | b<<16 }

// ---------------------------------------------------------------------------
// 폴더 선택 창 (최신 IFileOpenDialog, 실패 시 예전 SHBrowseForFolder)
// ---------------------------------------------------------------------------

var (
	clsidFileOpenDialog = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog  = GUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

func comCall(obj uintptr, index int, args ...uintptr) uintptr {
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{obj}, args...)...)
	return r
}

// 성공 시 경로, 취소 시 "" 를 돌려줍니다.
func pickFolder(owner uintptr, title string) string {
	var dlg uintptr
	hr, _, _ := pCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidFileOpenDialog)), 0, 1, /*CLSCTX_INPROC_SERVER*/
		uintptr(unsafe.Pointer(&iidIFileOpenDialog)), uintptr(unsafe.Pointer(&dlg)))
	if hr != 0 || dlg == 0 {
		return pickFolderLegacy(owner, title)
	}
	defer comCall(dlg, 2) // Release
	var opts uint32
	comCall(dlg, 10, uintptr(unsafe.Pointer(&opts))) // GetOptions
	const FOS_PICKFOLDERS, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST = 0x20, 0x40, 0x800
	comCall(dlg, 9, uintptr(opts|FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST)) // SetOptions
	t := u16(title)
	comCall(dlg, 17, uintptr(unsafe.Pointer(t))) // SetTitle
	if comCall(dlg, 3, owner) != 0 {             // Show (취소 시 HRESULT 오류)
		return ""
	}
	var item uintptr
	if comCall(dlg, 20, uintptr(unsafe.Pointer(&item))) != 0 || item == 0 { // GetResult
		return ""
	}
	defer comCall(item, 2)
	var pstr uintptr
	const SIGDN_FILESYSPATH = 0x80058000
	if comCall(item, 5, SIGDN_FILESYSPATH, uintptr(unsafe.Pointer(&pstr))) != 0 { // GetDisplayName
		return ""
	}
	s := u16ptrToString(pstr)
	pCoTaskMemFree.Call(pstr)
	return s
}

func pickFolderLegacy(owner uintptr, title string) string {
	name := make([]uint16, 260)
	bi := BROWSEINFOW{hwndOwner: owner, pszDisplayName: &name[0], lpszTitle: u16(title), ulFlags: 0x1 | 0x40 /*RETURNONLYFSDIRS|NEWDIALOGSTYLE*/}
	pidl, _, _ := pSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return ""
	}
	defer pCoTaskMemFree.Call(pidl)
	path := make([]uint16, 1024)
	pSHGetPathFromIDListW.Call(pidl, uintptr(unsafe.Pointer(&path[0])))
	return syscall.UTF16ToString(path)
}

// 관리자 권한으로 프로그램을 실행하고 끝날 때까지 기다립니다. 반환: (종료 코드, 실행 여부)
func runElevatedAndWait(owner uintptr, exe, params string) (uint32, bool) {
	sei := SHELLEXECUTEINFOW{
		fMask:        0x40 | 0x100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		hwnd:         owner,
		lpVerb:       u16("runas"),
		lpFile:       u16(exe),
		lpParameters: u16(params),
		nShow:        0,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	r, _, _ := pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 || sei.hProcess == 0 {
		return 0, false
	}
	h := syscall.Handle(sei.hProcess)
	defer syscall.CloseHandle(h)
	syscall.WaitForSingleObject(h, syscall.INFINITE)
	var code uint32
	syscall.GetExitCodeProcess(h, &code)
	return code, true
}

func openInExplorer(path string) {
	pShellExecuteW.Call(0, uintptr(unsafe.Pointer(u16("open"))), uintptr(unsafe.Pointer(u16(path))), 0, 0, SW_SHOW)
}
