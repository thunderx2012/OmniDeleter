//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ══════════════════════════════════════════════════════════════════
// Windows API 常數
// ══════════════════════════════════════════════════════════════════

const (
	// Window styles
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_TABSTOP          = 0x00010000
	WS_CLIPCHILDREN     = 0x02000000

	// Button styles
	BS_PUSHBUTTON = 0x00000000

	// Static styles
	SS_LEFT   = 0x00000000
	SS_RIGHT  = 0x00000002
	SS_NOTIFY = 0x00000100

	// Bottom-right Threads attribution control.
	linkControlStyle = WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_NOTIFY

	// ListBox styles & messages
	LBS_NOTIFY           = 0x0001
	LBS_EXTENDEDSEL      = 0x0800
	LBS_HASSTRINGS       = 0x0040
	LBS_NOINTEGRALHEIGHT = 0x0100
	LB_ADDSTRING         = 0x0180
	LB_RESETCONTENT      = 0x0184
	LB_GETCOUNT          = 0x018B
	LB_GETSEL            = 0x0187
	LBN_SELCHANGE        = 1

	// Messages
	WM_DESTROY         = 0x0002
	WM_SIZE            = 0x0005
	WM_PAINT           = 0x000F
	WM_NCDESTROY       = 0x0082
	WM_COMMAND         = 0x0111
	WM_DROPFILES       = 0x0233
	WM_GETMINMAXINFO   = 0x0024
	WM_CLOSE           = 0x0010
	WM_CTLCOLORSTATIC  = 0x0138
	WM_CTLCOLORLISTBOX = 0x0134
	WM_SETFONT         = 0x0030
	WM_APP             = 0x8000
	WM_APP_DELETE_DONE = WM_APP + 1
	WM_APP_LOCK_PROMPT = WM_APP + 3

	// MessageBox
	IDYES           = 6
	MB_OK           = 0x00000000
	MB_YESNO        = 0x00000004
	MB_ICONWARNING  = 0x00000030
	MB_ICONERROR    = 0x00000010
	MB_ICONQUESTION = 0x00000020
	MB_DEFBUTTON2   = 0x00000100

	// Static control notification
	STN_CLICKED = 0

	// GDI
	TRANSPARENT       = 1
	DEFAULT_CHARSET   = 1
	CLEARTYPE_QUALITY = 5
	FF_DONTCARE       = 0
	VARIABLE_PITCH    = 2
	FIXED_PITCH       = 1
	FW_NORMAL         = 400

	// DrawText / subclassing
	DT_SINGLELINE = 0x00000020
	DT_CENTER     = 0x00000001
	DT_VCENTER    = 0x00000004
	DT_NOPREFIX   = 0x00000800
	GWLP_WNDPROC  = ^uintptr(3)

	// ShowWindow
	SW_SHOW = 5

	// Extended styles
	WS_EX_ACCEPTFILES   = 0x00000010
	WS_EX_APPWINDOW     = 0x00040000
	WS_EX_CONTROLPARENT = 0x00010000
	WS_EX_CLIENTEDGE    = 0x00000200

	// Unicode legacy Open dialog options. This path is deliberately used for
	// file selection because it avoids fragile hand-written IFileOpenDialog
	// vtable calls while still supporting large Unicode selection buffers.
	OFN_HIDEREADONLY       = 0x00000004
	OFN_NOCHANGEDIR        = 0x00000008
	OFN_EXPLORER           = 0x00080000
	OFN_ALLOWMULTISELECT   = 0x00000200
	OFN_PATHMUSTEXIST      = 0x00000800
	OFN_FILEMUSTEXIST      = 0x00001000
	OFN_LONGNAMES          = 0x00200000
	OFN_NODEREFERENCELINKS = 0x00100000

	// Modern file/folder picker options (IFileOpenDialog / FILEOPENDIALOGOPTIONS).
	FOS_PICKFOLDERS         = 0x00000020
	FOS_FORCEFILESYSTEM     = 0x00000040
	FOS_PATHMUSTEXIST       = 0x00000800
	CLSCTX_INPROC_SERVER    = 0x00000001
	HRESULT_ERROR_CANCELLED = 0x800704C7

	// Win32 file APIs
	FILE_ATTRIBUTE_READONLY      = 0x00000001
	FILE_ATTRIBUTE_DIRECTORY     = 0x00000010
	FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
	FILE_READ_DATA               = 0x00000001
	FILE_READ_ATTRIBUTES         = 0x00000080
	FILE_WRITE_ATTRIBUTES        = 0x00000100
	INVALID_FILE_ATTRIBUTES      = 0xFFFFFFFF
	INVALID_HANDLE_VALUE         = ^uintptr(0)

	ERROR_SUCCESS           = 0
	ERROR_INVALID_FUNCTION  = 1
	ERROR_FILE_NOT_FOUND    = 2
	ERROR_PATH_NOT_FOUND    = 3
	ERROR_ACCESS_DENIED     = 5
	ERROR_INVALID_PARAMETER = 87
	ERROR_NOT_SUPPORTED     = 50
	ERROR_INVALID_DRIVE     = 15
	ERROR_NO_MORE_FILES     = 18
	ERROR_SHARING_VIOLATION = 32
	ERROR_LOCK_VIOLATION    = 33
	ERROR_DIR_NOT_EMPTY     = 145
	ERROR_USER_MAPPED_FILE  = 1224
	ERROR_MORE_DATA         = 234
	ERROR_ALREADY_EXISTS    = 183

	// File access/share flags used for lock probing.
	DELETE_ACCESS                              = 0x00010000
	FILE_SHARE_READ                            = 0x00000001
	FILE_SHARE_WRITE                           = 0x00000002
	FILE_SHARE_DELETE                          = 0x00000004
	OPEN_EXISTING                              = 3
	FILE_FLAG_BACKUP_SEMANTICS                 = 0x02000000
	FILE_FLAG_OPEN_REPARSE_POINT               = 0x00200000
	FileAttributeTagInfoClass                  = 9
	FileDispositionInfoClass                   = 4
	FILE_DISPOSITION_DELETE                    = 0x00000001
	FILE_DISPOSITION_POSIX_SEMANTICS           = 0x00000002
	FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK = 0x00000004
	FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010

	// OLE clipboard/file drag formats
	CF_HDROP         = 15
	TYMED_HGLOBAL    = 1
	DVASPECT_CONTENT = 1

	// Shell PIDL display path
	SIGDN_FILESYSPATH = 0x80058000

	// OLE drag-and-drop
	DROPEFFECT_NONE = 0x0
	DROPEFFECT_COPY = 0x1
	S_OK            = 0x00000000
	E_NOINTERFACE   = 0x80004002
	E_INVALIDARG    = 0x80070057
)

// ══════════════════════════════════════════════════════════════════
// 型別
// ══════════════════════════════════════════════════════════════════

type (
	HWND      uintptr
	HINSTANCE uintptr
	HCURSOR   uintptr
	HBRUSH    uintptr
	HFONT     uintptr
	HDC       uintptr
)

type RECT struct{ Left, Top, Right, Bottom int32 }

type POINT struct{ X, Y int32 }

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     HINSTANCE
	HIcon         uintptr
	HCursor       HCURSOR
	HbrBackground HBRUSH
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type MSG struct {
	Hwnd    HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type MINMAXINFO struct {
	PtReserved     POINT
	PtMaxSize      POINT
	PtMaxPosition  POINT
	PtMinTrackSize POINT
	PtMaxTrackSize POINT
}

type LOGFONT struct {
	LfHeight         int32
	LfWidth          int32
	LfEscapement     int32
	LfOrientation    int32
	LfWeight         int32
	LfItalic         byte
	LfUnderline      byte
	LfStrikeOut      byte
	LfCharSet        byte
	LfOutPrecision   byte
	LfClipPrecision  byte
	LfQuality        byte
	LfPitchAndFamily byte
	LfFaceName       [32]uint16
}

type FILETIME struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type WIN32_FIND_DATA struct {
	DwFileAttributes uint32
	FtCreationTime   FILETIME
	FtLastAccessTime FILETIME
	FtLastWriteTime  FILETIME
	NFileSizeHigh    uint32
	NFileSizeLow     uint32
	DwReserved0      uint32
	DwReserved1      uint32
	CFileName        [260]uint16
	CAlternateName   [14]uint16
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// OLE IDataObject / CF_HDROP structures. Layout follows the Win32 ABI.
type FORMATETC struct {
	CfFormat uint16
	Pad      [6]byte
	Ptd      uintptr
	DwAspect uint32
	Lindex   int32
	Tymed    uint32
}

// STGMEDIUM is 24 bytes on x64: DWORD + padding + union pointer + IUnknown*.
type STGMEDIUM struct {
	Tymed          uint32
	Pad            uint32
	Data           uintptr
	PUnkForRelease uintptr
}

// DROPFILES header followed by a double-NUL-terminated path list.
type DROPFILES struct {
	PFiles uint32
	Pt     POINT
	FNC    int32
	FWide  int32
}

// OPENFILENAMEW Windows layout. The lpEditInfo/lpstrPrompt fields are
// guarded by _MAC in the Windows SDK and are NOT present in the Windows build.
type OPENFILENAMEW struct {
	LStructSize       uint32
	HwndOwner         HWND
	HInstance         HINSTANCE
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        uintptr
	DwReserved        uint32
	FlagsEx           uint32
}

// ══════════════════════════════════════════════════════════════════
// COM GUID
// ══════════════════════════════════════════════════════════════════

var (
	IIDUnknown          = GUID{0x00000000, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IIDDropTarget       = GUID{0x00000122, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	CLSIDFileOpenDialog = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	IIDFileOpenDialog   = GUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

// COM vtable indices used by the remaining Shell item / data-object helpers.
const (
	vIDataObjectGetData = 3
)

// ══════════════════════════════════════════════════════════════════
// DLL / Proc 宣告
// ══════════════════════════════════════════════════════════════════

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	gdi32              = syscall.NewLazyDLL("gdi32.dll")
	shell32            = syscall.NewLazyDLL("shell32.dll")
	ole32              = syscall.NewLazyDLL("ole32.dll")
	comdlg32           = syscall.NewLazyDLL("comdlg32.dll")
	pRegisterClassExW  = user32.NewProc("RegisterClassExW")
	pCreateWindowExW   = user32.NewProc("CreateWindowExW")
	pDefWindowProcW    = user32.NewProc("DefWindowProcW")
	pCallWindowProcW   = user32.NewProc("CallWindowProcW")
	pSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	pDrawTextW         = user32.NewProc("DrawTextW")
	pGetDC             = user32.NewProc("GetDC")
	pReleaseDC         = user32.NewProc("ReleaseDC")
	pGetMessageW       = user32.NewProc("GetMessageW")
	pTranslateMessage  = user32.NewProc("TranslateMessage")
	pDispatchMessageW  = user32.NewProc("DispatchMessageW")
	pPostQuitMessage   = user32.NewProc("PostQuitMessage")
	pPostMessageW      = user32.NewProc("PostMessageW")
	pDestroyWindow     = user32.NewProc("DestroyWindow")
	pShowWindow        = user32.NewProc("ShowWindow")
	pUpdateWindow      = user32.NewProc("UpdateWindow")
	pGetClientRect     = user32.NewProc("GetClientRect")
	pMoveWindow        = user32.NewProc("MoveWindow")
	pSendMessageW      = user32.NewProc("SendMessageW")
	pMessageBoxW       = user32.NewProc("MessageBoxW")
	pLoadCursorW       = user32.NewProc("LoadCursorW")
	pLoadIconW         = user32.NewProc("LoadIconW")
	pSetWindowTextW    = user32.NewProc("SetWindowTextW")
	pInvalidateRect    = user32.NewProc("InvalidateRect")
	pEnableWindow      = user32.NewProc("EnableWindow")

	pShellExecuteW            = shell32.NewProc("ShellExecuteW")
	pDragAcceptFiles          = shell32.NewProc("DragAcceptFiles")
	pDragQueryFileW           = shell32.NewProc("DragQueryFileW")
	pDragFinish               = shell32.NewProc("DragFinish")
	pSHGetPathFromIDListEx    = shell32.NewProc("SHGetPathFromIDListEx")
	pSHGetNameFromIDList      = shell32.NewProc("SHGetNameFromIDList")
	pILCombine                = shell32.NewProc("ILCombine")
	pCoCreateInstance         = ole32.NewProc("CoCreateInstance")
	pRegisterClipboardFormatW = user32.NewProc("RegisterClipboardFormatW")
	pRegisterDragDrop         = ole32.NewProc("RegisterDragDrop")
	pRevokeDragDrop           = ole32.NewProc("RevokeDragDrop")

	pGetModuleHandleW             = kernel32.NewProc("GetModuleHandleW")
	pGetFileAttributesW           = kernel32.NewProc("GetFileAttributesW")
	pSetFileAttributesW           = kernel32.NewProc("SetFileAttributesW")
	pDeleteFileW                  = kernel32.NewProc("DeleteFileW")
	pRemoveDirectoryW             = kernel32.NewProc("RemoveDirectoryW")
	pFindFirstFileW               = kernel32.NewProc("FindFirstFileW")
	pFindNextFileW                = kernel32.NewProc("FindNextFileW")
	pFindClose                    = kernel32.NewProc("FindClose")
	pCreateFileW                  = kernel32.NewProc("CreateFileW")
	pGetFileInformationByHandle   = kernel32.NewProc("GetFileInformationByHandle")
	pGetFileInformationByHandleEx = kernel32.NewProc("GetFileInformationByHandleEx")
	pGetFinalPathNameByHandleW    = kernel32.NewProc("GetFinalPathNameByHandleW")
	pSetFileInformationByHandle   = kernel32.NewProc("SetFileInformationByHandle")
	pCloseHandle                  = kernel32.NewProc("CloseHandle")
	pCreateMutexW                 = kernel32.NewProc("CreateMutexW")
	pSetDefaultDllDirectories     = kernel32.NewProc("SetDefaultDllDirectories")

	pCreateFontIndirectW = gdi32.NewProc("CreateFontIndirectW")
	pDeleteObject        = gdi32.NewProc("DeleteObject")
	pCreateSolidBrush    = gdi32.NewProc("CreateSolidBrush")
	pSetBkColor          = gdi32.NewProc("SetBkColor")
	pSetTextColor        = gdi32.NewProc("SetTextColor")
	pSetBkMode           = gdi32.NewProc("SetBkMode")
	pSelectObject        = gdi32.NewProc("SelectObject")

	pOleInitialize        = ole32.NewProc("OleInitialize")
	pOleUninitialize      = ole32.NewProc("OleUninitialize")
	pCoTaskMemAlloc       = ole32.NewProc("CoTaskMemAlloc")
	pCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
	pReleaseStgMedium     = ole32.NewProc("ReleaseStgMedium")
	pGlobalLock           = kernel32.NewProc("GlobalLock")
	pGlobalUnlock         = kernel32.NewProc("GlobalUnlock")
	pGlobalSize           = kernel32.NewProc("GlobalSize")
	pGetOpenFileNameW     = comdlg32.NewProc("GetOpenFileNameW")
	pCommDlgExtendedError = comdlg32.NewProc("CommDlgExtendedError")
)

// ══════════════════════════════════════════════════════════════════
// 顏色
// ══════════════════════════════════════════════════════════════════

func rgb(c uint32) uint32 {
	return ((c & 0xFF) << 16) | (c & 0x00FF00) | ((c >> 16) & 0xFF)
}

const (
	cBg      = uint32(0x1E1E1E)
	cListBg  = uint32(0x141414)
	cText    = uint32(0xDDDDDD)
	cSubText = uint32(0x888888)
	cLink    = uint32(0x5CA9FF)
)

// ══════════════════════════════════════════════════════════════════
// 控件 ID
// ══════════════════════════════════════════════════════════════════

const (
	idListBox   = 101
	idBtnAdd    = 102
	idBtnAddDir = 103
	idBtnRemove = 104
	idBtnClear  = 105
	idBtnDelete = 106
	idBtnRename = 107
	idBtnRescue = 108
	idStatus    = 109
	idLink      = 110

	appTitle = "OmniDeleter"

	appIconResourceID = 1
	initialWindowW    = 695
	initialWindowH    = 530

	threadsLinkText  = "@thunderx2012"
	threadsLinkURL   = "https://www.threads.com/@thunderx2012"
	emptyListText    = "清單是空的，請拖曳檔案/資料夾到此處，或使用滑鼠左鍵加入"
	clearAllText     = "清除全部"
	clearConfirmText = "確定要清空所有項目嗎？"
)

// ══════════════════════════════════════════════════════════════════
// App state
// ══════════════════════════════════════════════════════════════════

type App struct {
	hwnd            HWND
	hInst           HINSTANCE
	hFont           HFONT
	hFontSm         HFONT
	hFontMono       HFONT
	hFontLink       HFONT
	hwndList        HWND
	hwndBtnAdd      HWND
	hwndBtnDir      HWND
	hwndBtnRemove   HWND
	hwndBtnClear    HWND
	hwndBtnDelete   HWND
	hwndBtnRename   HWND
	hwndBtnRescue   HWND
	hwndStatus      HWND
	hwndLink        HWND
	hBrushBg        HBRUSH
	hBrushList      HBRUSH
	items           []string
	busy            int32
	cancelRequested int32
	resultQueue     chan deleteResult
	lockQueue       chan lockPromptRequest
}

var gApp App
var wndProcCallback = syscall.NewCallback(wndProc)
var listWndProcCallback = syscall.NewCallback(listWndProc)
var originalListWndProc uintptr
var instanceMutex uintptr

// ══════════════════════════════════════════════════════════════════
// 一般輔助
// ══════════════════════════════════════════════════════════════════

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func msgBox(owner HWND, title, text string, flags uint32) int {
	r, _, _ := pMessageBoxW.Call(uintptr(owner), uintptr(unsafe.Pointer(u16(text))), uintptr(unsafe.Pointer(u16(title))), uintptr(flags))
	return int(r)
}

func makeFont(size, weight int32, face string, mono bool) HFONT {
	return makeFontWithUnderline(size, weight, face, mono, false)
}

func makeFontWithUnderline(size, weight int32, face string, mono, underline bool) HFONT {
	var lf LOGFONT
	lf.LfHeight = -size
	lf.LfWeight = weight
	lf.LfUnderline = boolByte(underline)
	lf.LfCharSet = DEFAULT_CHARSET
	lf.LfQuality = CLEARTYPE_QUALITY
	if mono {
		lf.LfPitchAndFamily = FIXED_PITCH | FF_DONTCARE
	} else {
		lf.LfPitchAndFamily = VARIABLE_PITCH | FF_DONTCARE
	}
	copy(lf.LfFaceName[:], syscall.StringToUTF16(face))
	h, _, _ := pCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return HFONT(h)
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

func sendFont(hwnd HWND, hf HFONT) {
	if hwnd != 0 && hf != 0 {
		pSendMessageW.Call(uintptr(hwnd), WM_SETFONT, uintptr(hf), 1)
	}
}

func installListWndProc(hwnd HWND) {
	if hwnd == 0 || originalListWndProc != 0 {
		return
	}
	r, _, _ := pSetWindowLongPtrW.Call(uintptr(hwnd), GWLP_WNDPROC, listWndProcCallback)
	if r != 0 {
		originalListWndProc = r
	}
}

func listWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if originalListWndProc == 0 {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}

	r, _, _ := pCallWindowProcW.Call(originalListWndProc, hwnd, uintptr(msg), wParam, lParam)
	if msg != WM_PAINT {
		if msg == WM_NCDESTROY {
			originalListWndProc = 0
		}
		return r
	}

	// The list's own window procedure has already painted the normal control.
	// Draw only the empty-state hint on top of that existing ListBox surface.
	// Use application state instead of sending LB_GETCOUNT back to the same
	// window from inside its window procedure.
	if gApp.hwndList == 0 || len(gApp.items) != 0 {
		return r
	}

	var rc RECT
	pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	if rc.Right <= rc.Left || rc.Bottom <= rc.Top {
		return r
	}

	hdc, _, _ := pGetDC.Call(hwnd)
	if hdc == 0 {
		return r
	}
	defer pReleaseDC.Call(hwnd, hdc)

	oldFont, _, _ := pSelectObject.Call(hdc, uintptr(gApp.hFont))
	oldBkMode, _, _ := pSetBkMode.Call(hdc, TRANSPARENT)
	pSetTextColor.Call(hdc, uintptr(rgb(cSubText)))
	drawFlags := uintptr(DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX)
	pDrawTextW.Call(
		hdc,
		uintptr(unsafe.Pointer(u16("拖曳檔案/資料夾到這裡"))),
		^uintptr(0),
		uintptr(unsafe.Pointer(&rc)),
		drawFlags,
	)
	pSetBkMode.Call(hdc, oldBkMode)
	if oldFont != 0 {
		pSelectObject.Call(hdc, oldFont)
	}
	return r
}

func newControl(class, text string, style, exStyle uint32, parent HWND, id int) HWND {
	h, _, _ := pCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(u16(class))),
		uintptr(unsafe.Pointer(u16(text))),
		uintptr(style),
		0, 0, 0, 0,
		uintptr(parent),
		uintptr(id),
		uintptr(gApp.hInst), 0)
	return HWND(h)
}

func move(hwnd HWND, x, y, w, h int) {
	if hwnd != 0 {
		pMoveWindow.Call(uintptr(hwnd), uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
	}
}

func lbSend(msg uint32, wp, lp uintptr) uintptr {
	return sendControlMessage(gApp.hwndList, msg, wp, lp)
}

func sendControlMessage(hwnd HWND, msg uint32, wp, lp uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(uintptr(hwnd), uintptr(msg), wp, lp)
	return r
}

func lbCount() int { return int(int32(lbSend(LB_GETCOUNT, 0, 0))) }

func lbGetSel(i int) bool {
	r := lbSend(LB_GETSEL, uintptr(i), 0)
	return int32(r) > 0
}

func lbSelectedIndices() []int {
	n := lbCount()
	out := make([]int, 0)
	for i := 0; i < n; i++ {
		if lbGetSel(i) {
			out = append(out, i)
		}
	}
	return out
}

func utf16PtrString(p *uint16) string {
	if p == nil {
		return ""
	}
	buf := make([]uint16, 0, 256)
	for i := uintptr(0); ; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + i*2))
		if c == 0 {
			break
		}
		buf = append(buf, c)
		if len(buf) > windowsMaxExtendedPath+1 {
			break
		}
	}
	return syscall.UTF16ToString(buf)
}

func comMethod(obj uintptr, index int, args ...uintptr) uintptr {
	if obj == 0 {
		return 0x80004003 // E_POINTER
	}
	vtbl := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	params := make([]uintptr, 1, 1+len(args))
	params[0] = obj
	params = append(params, args...)
	r, _, _ := syscall.SyscallN(fn, params...)
	return r
}

func guidEqual(a, b *GUID) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func hresultFailed(hr uintptr) bool { return int32(uint32(hr)) < 0 }

func hresultError(hr uintptr) error {
	return fmt.Errorf("HRESULT 0x%08X", uint32(hr))
}

func procError(err error) uint32 {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return uint32(e)
	}
	return 0
}

type win32CodeError uint32

func (e win32CodeError) Error() string {
	return fmt.Sprintf("Win32 error %d (0x%X)", uint32(e), uint32(e))
}

func win32Error(code uint32) error {
	return win32CodeError(code)
}

func acquireSingleInstance() (bool, error) {
	name := u16(`Local\OmniDeleter`)
	h, _, createErr := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return false, fmt.Errorf("CreateMutexW 失敗：%v", win32Error(procError(createErr)))
	}
	last := procError(createErr)
	if last == ERROR_ALREADY_EXISTS {
		pCloseHandle.Call(h)
		return false, nil
	}
	instanceMutex = h
	return true, nil
}

func releaseSingleInstance() {
	if instanceMutex != 0 && instanceMutex != INVALID_HANDLE_VALUE {
		pCloseHandle.Call(instanceMutex)
		instanceMutex = 0
	}
}

func cancellationRequested() bool {
	return atomic.LoadInt32(&gApp.cancelRequested) != 0
}

// ══════════════════════════════════════════════════════════════════
// OLE 長路徑拖曳接收
// ══════════════════════════════════════════════════════════════════

// WM_DROPFILES / CF_HDROP 在長路徑情境並不可靠。現代 OLE 拖曳使用
// IDropTarget，並優先從 IDataObject 轉成 IShellItemArray；Shell IDList
// 不必把完整路徑塞進 MAX_PATH 固定大小的緩衝區。
type rawDropTarget struct {
	vtbl uintptr
	refs uint32
	pad  uint32
}

var (
	dropTargetQueryInterface = syscall.NewCallback(dropTargetQI)
	dropTargetAddRef         = syscall.NewCallback(dropTargetAddRefFn)
	dropTargetRelease        = syscall.NewCallback(dropTargetReleaseFn)
	dropTargetDragEnter      = syscall.NewCallback(dropTargetDragEnterFn)
	dropTargetDragOver       = syscall.NewCallback(dropTargetDragOverFn)
	dropTargetDragLeave      = syscall.NewCallback(dropTargetDragLeaveFn)
	dropTargetDrop           = syscall.NewCallback(dropTargetDropFn)
)

var registeredDropTarget uintptr
var cfShellIDList uint16

func newDropTarget() uintptr {
	vtableSize := uintptr(7) * unsafe.Sizeof(uintptr(0))
	vtblMem, _, _ := pCoTaskMemAlloc.Call(vtableSize)
	objMem, _, _ := pCoTaskMemAlloc.Call(unsafe.Sizeof(rawDropTarget{}))
	if vtblMem == 0 || objMem == 0 {
		if vtblMem != 0 {
			pCoTaskMemFree.Call(vtblMem)
		}
		if objMem != 0 {
			pCoTaskMemFree.Call(objMem)
		}
		return 0
	}
	vtbl := unsafe.Slice((*uintptr)(unsafe.Pointer(vtblMem)), 7)
	vtbl[0] = dropTargetQueryInterface
	vtbl[1] = dropTargetAddRef
	vtbl[2] = dropTargetRelease
	vtbl[3] = dropTargetDragEnter
	vtbl[4] = dropTargetDragOver
	vtbl[5] = dropTargetDragLeave
	vtbl[6] = dropTargetDrop

	obj := (*rawDropTarget)(unsafe.Pointer(objMem))
	obj.vtbl = vtblMem
	obj.refs = 1
	return objMem
}

func dropTargetQI(this, riid, ppv uintptr) uintptr {
	if this == 0 || riid == 0 || ppv == 0 {
		return E_INVALIDARG
	}
	requested := (*GUID)(unsafe.Pointer(riid))
	if guidEqual(requested, &IIDUnknown) || guidEqual(requested, &IIDDropTarget) {
		*(*uintptr)(unsafe.Pointer(ppv)) = this
		dropTargetAddRefFn(this)
		return S_OK
	}
	*(*uintptr)(unsafe.Pointer(ppv)) = 0
	return E_NOINTERFACE
}

func dropTargetAddRefFn(this uintptr) uintptr {
	if this == 0 {
		return 0
	}
	obj := (*rawDropTarget)(unsafe.Pointer(this))
	return uintptr(atomic.AddUint32(&obj.refs, 1))
}

func dropTargetReleaseFn(this uintptr) uintptr {
	if this == 0 {
		return 0
	}
	obj := (*rawDropTarget)(unsafe.Pointer(this))
	refs := atomic.AddUint32(&obj.refs, ^uint32(0))
	if refs == 0 {
		vtbl := obj.vtbl
		if vtbl != 0 {
			pCoTaskMemFree.Call(vtbl)
		}
		pCoTaskMemFree.Call(this)
	}
	return uintptr(refs)
}

func setDropEffect(ptr uintptr, effect uintptr) {
	if ptr != 0 {
		*(*uint32)(unsafe.Pointer(ptr)) = uint32(effect)
	}
}

func dropTargetDragEnterFn(this, dataObj, keyState, point, effect uintptr) uintptr {
	setDropEffect(effect, DROPEFFECT_COPY)
	return S_OK
}

func dropTargetDragOverFn(this, keyState, point, effect uintptr) uintptr {
	setDropEffect(effect, DROPEFFECT_COPY)
	return S_OK
}

func dropTargetDragLeaveFn(this uintptr) uintptr {
	return S_OK
}

func dropTargetDropFn(this, dataObj, keyState, point, effect uintptr) uintptr {
	paths := shellPathsFromDataObject(dataObj)
	if len(paths) == 0 {
		setDropEffect(effect, DROPEFFECT_NONE)
		return S_OK
	}
	for _, p := range paths {
		gApp.addPath(p)
	}
	gApp.rebuildList()
	setDropEffect(effect, DROPEFFECT_COPY)
	return S_OK
}

func shellPathsFromDataObject(dataObj uintptr) []string {
	if dataObj == 0 {
		return nil
	}
	if paths := pathsFromDataObjectCFHDrop(dataObj); len(paths) > 0 {
		return paths
	}
	// Windows Explorer uses the Shell IDList Array format for long-path drags.
	if paths := pathsFromDataObjectShellIDList(dataObj); len(paths) > 0 {
		return paths
	}
	return nil
}

func getDataFromFormat(dataObj uintptr, format uint16) (STGMEDIUM, bool) {
	var medium STGMEDIUM
	if dataObj == 0 || format == 0 {
		return medium, false
	}
	fe := FORMATETC{CfFormat: format, DwAspect: DVASPECT_CONTENT, Lindex: -1, Tymed: TYMED_HGLOBAL}
	hr := comMethod(dataObj, vIDataObjectGetData, uintptr(unsafe.Pointer(&fe)), uintptr(unsafe.Pointer(&medium)))
	if hresultFailed(hr) || medium.Tymed != TYMED_HGLOBAL || medium.Data == 0 {
		return STGMEDIUM{}, false
	}
	return medium, true
}

func pidlFitsBlock(base uintptr, blockSize, off uintptr) bool {
	if base == 0 || off >= blockSize || blockSize-off < 2 {
		return false
	}
	pos := off
	for {
		if pos+2 > blockSize {
			return false
		}
		cb := uintptr(*(*uint16)(unsafe.Pointer(base + pos)))
		if cb == 0 {
			return true
		}
		if cb < 2 || pos+cb > blockSize {
			return false
		}
		pos += cb
	}
}

func pathsFromDataObjectShellIDList(dataObj uintptr) []string {
	medium, ok := getDataFromFormat(dataObj, cfShellIDList)
	if !ok {
		return nil
	}
	defer pReleaseStgMedium.Call(uintptr(unsafe.Pointer(&medium)))
	base, _, _ := pGlobalLock.Call(medium.Data)
	if base == 0 {
		return nil
	}
	defer pGlobalUnlock.Call(medium.Data)
	sz, _, _ := pGlobalSize.Call(medium.Data)
	blockSize := uintptr(sz)
	if blockSize < 8 {
		return nil
	}
	cidl := *(*uint32)(unsafe.Pointer(base))
	if cidl == 0 || cidl > 4096 {
		return nil
	}
	if uintptr(4)+(uintptr(cidl)+1)*4 > blockSize {
		return nil
	}
	offsets := unsafe.Slice((*uint32)(unsafe.Pointer(base+4)), int(cidl)+1)
	parentOff := uintptr(offsets[0])
	if !pidlFitsBlock(base, blockSize, parentOff) {
		return nil
	}
	parent := base + parentOff
	paths := make([]string, 0, int(cidl))
	for i := uint32(0); i < cidl; i++ {
		itemOff := uintptr(offsets[i+1])
		if !pidlFitsBlock(base, blockSize, itemOff) {
			continue
		}
		abs, _, _ := pILCombine.Call(parent, base+itemOff)
		if abs == 0 {
			continue
		}
		path := pathFromPIDL(abs)
		pCoTaskMemFree.Call(abs)
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func pathFromPIDL(pidl uintptr) string {
	if pidl == 0 {
		return ""
	}
	buf := make([]uint16, windowsMaxExtendedPath+1)
	r, _, _ := pSHGetPathFromIDListEx.Call(pidl, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if r != 0 {
		return normalizeInputPath(syscall.UTF16ToString(buf))
	}
	var raw *uint16
	hr, _, _ := pSHGetNameFromIDList.Call(pidl, SIGDN_FILESYSPATH, uintptr(unsafe.Pointer(&raw)))
	if hresultFailed(hr) || raw == nil {
		return ""
	}
	defer pCoTaskMemFree.Call(uintptr(unsafe.Pointer(raw)))
	return normalizeInputPath(utf16PtrString(raw))
}

func pathsFromDataObjectCFHDrop(dataObj uintptr) []string {
	medium, ok := getDataFromFormat(dataObj, CF_HDROP)
	if !ok {
		return nil
	}
	defer pReleaseStgMedium.Call(uintptr(unsafe.Pointer(&medium)))
	base, _, _ := pGlobalLock.Call(medium.Data)
	if base == 0 {
		return nil
	}
	defer pGlobalUnlock.Call(medium.Data)
	sz, _, _ := pGlobalSize.Call(medium.Data)
	if sz < unsafe.Sizeof(DROPFILES{}) {
		return nil
	}
	blockSize := uintptr(sz)
	df := (*DROPFILES)(unsafe.Pointer(base))
	off := uintptr(df.PFiles)
	if off >= blockSize || df.FWide == 0 {
		return nil
	}
	listBase := base + off
	remaining := blockSize - off
	paths := make([]string, 0, 4)
	for remaining >= 2 {
		units := uintptr(0)
		terminated := false
		for units*2+2 <= remaining {
			c := *(*uint16)(unsafe.Pointer(listBase + units*2))
			if c == 0 {
				terminated = true
				break
			}
			units++
			if units > uintptr(windowsMaxExtendedPath) {
				return paths
			}
		}
		if !terminated || units == 0 {
			break
		}
		path := syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(listBase)), int(units)))
		if path != "" {
			paths = append(paths, normalizeInputPath(path))
		}
		consumed := (units + 1) * 2
		if consumed > remaining {
			break
		}
		listBase += consumed
		remaining -= consumed
	}
	return paths
}

func registerOleDropTarget(hwnd HWND) error {
	obj := newDropTarget()
	if obj == 0 {
		return errors.New("無法配置 OLE 拖曳接收器記憶體")
	}
	hr, _, _ := pRegisterDragDrop.Call(uintptr(hwnd), obj)
	if hresultFailed(hr) {
		// We still own the initial reference because registration failed.
		dropTargetReleaseFn(obj)
		return hresultError(hr)
	}
	// RegisterDragDrop holds its own reference. Drop our creation reference.
	dropTargetReleaseFn(obj)
	registeredDropTarget = 1
	return nil
}

func revokeOleDropTarget(hwnd HWND) {
	if registeredDropTarget == 0 || hwnd == 0 {
		return
	}
	pRevokeDragDrop.Call(uintptr(hwnd))
	registeredDropTarget = 0
}

// ══════════════════════════════════════════════════════════════════
// Shell / Common Item Dialog
// ══════════════════════════════════════════════════════════════════

// File selection remains on the legacy Unicode common dialog for compatibility
// with the existing multi-select behavior. Folder selection uses IFileOpenDialog
// in PICKFOLDERS mode because the legacy shell folder browser can reject deep
// paths during navigation even when the filesystem itself can handle them.
func pickPathsOnSTA(owner HWND, folders bool) ([]string, error) {
	if folders {
		return pickFolderModern(owner)
	}
	return pickFilesLegacy(owner)
}

func commonDialogError(code uint32) error {
	switch code {
	case 0x3001:
		return errors.New("檔案選取對話框無法建立必要的控制項（FNERR_SUBCLASSFAILURE）")
	case 0x3002:
		return errors.New("檔案名稱無效（FNERR_INVALIDFILENAME）")
	case 0x3003:
		return errors.New("檔案名稱緩衝區不足（FNERR_BUFFERTOOSMALL）")
	default:
		return fmt.Errorf("檔案選取對話框失敗：CommDlgExtendedError 0x%04X", code)
	}
}

func pickFilesLegacy(owner HWND) ([]string, error) {
	const bufferSize = 128 * 1024
	buf := make([]uint16, bufferSize)
	buf[0] = 0
	// OPENFILENAME filter strings are double-NUL terminated; u16 intentionally
	// rejects embedded NULs, so construct the buffer explicitly and keep it alive
	// for the duration of the Win32 call.
	filter := append(syscall.StringToUTF16("所有檔案"), syscall.StringToUTF16("*.*")...)
	filter = append(filter, 0)
	title := u16("選擇要加入的檔案")
	ofn := OPENFILENAMEW{
		LStructSize:  uint32(unsafe.Sizeof(OPENFILENAMEW{})),
		HwndOwner:    owner,
		LpstrFilter:  &filter[0],
		NFilterIndex: 1,
		LpstrFile:    &buf[0],
		NMaxFile:     uint32(len(buf)),
		LpstrTitle:   title,
		Flags:        OFN_EXPLORER | OFN_ALLOWMULTISELECT | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY | OFN_LONGNAMES | OFN_NODEREFERENCELINKS,
	}
	ret, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		code, _, _ := pCommDlgExtendedError.Call()
		if code == 0 {
			return nil, nil
		}
		return nil, commonDialogError(uint32(code))
	}
	read := func(pos int) (string, int) {
		if pos >= len(buf) {
			return "", len(buf)
		}
		i := pos
		for i < len(buf) && buf[i] != 0 {
			i++
		}
		return syscall.UTF16ToString(buf[pos:i]), i + 1
	}
	first, pos := read(0)
	if first == "" {
		return nil, nil
	}
	if pos >= len(buf) || buf[pos] == 0 {
		return []string{normalizeInputPath(first)}, nil
	}
	paths := make([]string, 0, 4)
	for pos < len(buf) {
		name, next := read(pos)
		if name == "" {
			break
		}
		paths = append(paths, normalizeInputPath(makePathCandidate(first, name)))
		pos = next
	}
	return paths, nil
}

func pickFolderModern(owner HWND) ([]string, error) {
	// IFileOpenDialog in FOS_PICKFOLDERS mode is used instead of the legacy
	// SHBrowseForFolder tree. The latter can reject otherwise valid deep paths
	// while navigating/selecting them. The modern dialog returns an IShellItem,
	// from which SIGDN_FILESYSPATH gives the filesystem path directly.
	var dialog uintptr
	hr, _, _ := pCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSIDFileOpenDialog)),
		0,
		uintptr(CLSCTX_INPROC_SERVER),
		uintptr(unsafe.Pointer(&IIDFileOpenDialog)),
		uintptr(unsafe.Pointer(&dialog)),
	)
	if hresultFailed(hr) || dialog == 0 {
		return nil, fmt.Errorf("無法建立資料夾選取對話框：%w", hresultError(hr))
	}
	defer func() { comMethod(dialog, 2) }() // IUnknown::Release

	var options uint32
	hr = comMethod(dialog, 10, uintptr(unsafe.Pointer(&options))) // IFileDialog::GetOptions
	if hresultFailed(hr) {
		return nil, fmt.Errorf("無法讀取資料夾選取對話框設定：%w", hresultError(hr))
	}
	newOptions := uintptr(options) | uintptr(FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST)
	if hr := comMethod(dialog, 9, newOptions); hresultFailed(hr) { // IFileDialog::SetOptions
		return nil, fmt.Errorf("無法設定資料夾選取模式：%w", hresultError(hr))
	}
	titlePtr := u16("選擇要加入的資料夾")
	if hr := comMethod(dialog, 17, uintptr(unsafe.Pointer(titlePtr))); hresultFailed(hr) { // SetTitle
		return nil, fmt.Errorf("無法設定資料夾選取標題：%w", hresultError(hr))
	}
	runtime.KeepAlive(titlePtr)

	hr = comMethod(dialog, 3, uintptr(owner)) // IModalWindow::Show
	if uint32(hr) == HRESULT_ERROR_CANCELLED {
		return nil, nil
	}
	if hresultFailed(hr) {
		return nil, fmt.Errorf("資料夾選取失敗：%w", hresultError(hr))
	}

	var item uintptr
	hr = comMethod(dialog, 20, uintptr(unsafe.Pointer(&item))) // IFileDialog::GetResult
	if hresultFailed(hr) || item == 0 {
		return nil, fmt.Errorf("無法取得所選資料夾：%w", hresultError(hr))
	}
	defer func() { comMethod(item, 2) }() // IShellItem::Release

	var raw *uint16
	hr = comMethod(item, 5, uintptr(SIGDN_FILESYSPATH), uintptr(unsafe.Pointer(&raw))) // GetDisplayName
	if hresultFailed(hr) || raw == nil {
		return nil, errors.New("無法從所選資料夾取得完整檔案系統路徑")
	}
	defer pCoTaskMemFree.Call(uintptr(unsafe.Pointer(raw)))
	path := normalizeInputPath(utf16PtrString(raw))
	if path == "" {
		return nil, errors.New("無法從所選資料夾取得完整檔案系統路徑")
	}
	return []string{path}, nil
}

// ══════════════════════════════════════════════════════════════════
// 路徑狀態與安全檢查
// ══════════════════════════════════════════════════════════════════

type pathState int

const (
	pathExists pathState = iota
	pathMissing
	pathUnknown
)

func pathStateOf(path string) (pathState, uint32) {
	op := toOperationPath(path)
	r, _, err := pGetFileAttributesW.Call(uintptr(unsafe.Pointer(u16(op))))
	if uint32(r) != INVALID_FILE_ATTRIBUTES {
		return pathExists, 0
	}
	code := procError(err)
	switch code {
	case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_INVALID_DRIVE:
		return pathMissing, code
	default:
		return pathUnknown, code
	}
}

func isDeviceNamespace(path string) bool {
	upper := strings.ToUpper(path)
	return strings.HasPrefix(upper, `\\.\`) || strings.HasPrefix(upper, `\\?\GLOBALROOT\`)
}

func isRootPath(path string) bool {
	upper := strings.ToUpper(path)
	trimmedOriginal := strings.TrimRight(path, `\`)
	if strings.HasPrefix(upper, `\\?\VOLUME{`) && strings.HasSuffix(trimmedOriginal, `}`) {
		return true
	}

	p := displayPath(path)
	p = strings.TrimRight(p, `\`)
	if len(p) == 2 && p[1] == ':' {
		return true
	}
	if strings.HasPrefix(p, `\\`) {
		parts := strings.Split(strings.TrimPrefix(p, `\\`), `\`)
		n := 0
		for _, part := range parts {
			if part != "" {
				n++
			}
		}
		return n <= 2
	}
	return false
}

func finalPathForProtectedCheck(path string) (string, bool) {
	op := toOperationPath(path)
	attr, code := getAttributes(op)
	if attr == INVALID_FILE_ATTRIBUTES {
		_ = code
		return "", false
	}
	// A reparse point is itself the object being deleted. Do not follow its
	// target for the protected-root check; junctions/symlinks to system roots
	// are safely removed by deleteReparsePoint without descending into the target.
	if attr&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", false
	}
	flags := uintptr(0)
	if attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
		flags = FILE_FLAG_BACKUP_SEMANTICS
	}
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0, OPEN_EXISTING, flags, 0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		_ = e
		return "", false
	}
	defer pCloseHandle.Call(h)

	size := uint32(1024)
	const max = uint32(windowsMaxExtendedPath + 1)
	for size <= max {
		buf := make([]uint16, size)
		n, _, err := pGetFinalPathNameByHandleW.Call(
			h, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), 0, // VOLUME_NAME_DOS | FILE_NAME_NORMALIZED
		)
		if n == 0 {
			_ = err
			return "", false
		}
		if n < uintptr(size) {
			return canonicalComparePath(syscall.UTF16ToString(buf[:n])), true
		}
		if n >= uintptr(max) {
			return "", false
		}
		size = uint32(n + 1)
	}
	return "", false
}

func protectedRootCandidates() []string {
	roots := make([]string, 0, 20)
	seen := make(map[string]struct{})
	add := func(v string) {
		v = canonicalComparePath(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		roots = append(roots, v)
	}
	if w := systemWindowsDirectory(); w != "" {
		add(w)
		add(w + `\System32`)
		add(w + `\SysWOW64`)
		root := volumeRootForWindowsPath(w)
		if root != "" {
			add(root + `System Volume Information`)
			add(root + `Boot`)
			add(root + `EFI`)
			add(root + `Users`)
		}
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE"} {
		add(os.Getenv(env))
	}
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		p := displayPath(normalizeInputPath(profile))
		if root := volumeRootForWindowsPath(p); root != "" {
			add(root + `Users`)
		}
	}
	if v := os.Getenv("WINDIR"); v != "" {
		add(v)
	}
	return roots
}

func volumeRootForWindowsPath(path string) string {
	p := displayPath(normalizeInputPath(path))
	p = strings.ReplaceAll(p, "/", `\`)
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		return p[:3]
	}
	if strings.HasPrefix(p, `\\`) {
		parts := strings.Split(strings.TrimPrefix(p, `\\`), `\`)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return `\\` + parts[0] + `\` + parts[1] + `\`
		}
	}
	return ""
}

func pathWithinProtectedRoot(candidate, root string) bool {
	candidate = canonicalComparePath(candidate)
	root = canonicalComparePath(root)
	if candidate == "" || root == "" {
		return false
	}
	return candidate == root || strings.HasPrefix(candidate, root+`\`)
}

func protectedPathMatch(path string) (root string, exact bool, matched bool) {
	candidate := canonicalComparePath(path)
	if candidate == "" {
		return "", false, false
	}
	for _, r := range protectedRootCandidates() {
		if pathWithinProtectedRoot(candidate, r) {
			return r, candidate == r, true
		}
	}
	if finalPath, ok := finalPathForProtectedCheck(path); ok && finalPath != candidate {
		for _, r := range protectedRootCandidates() {
			if pathWithinProtectedRoot(finalPath, r) {
				return r, finalPath == r, true
			}
		}
	}
	return "", false, false
}

func protectedDirectoryReason(path string) string {
	root, exact, matched := protectedPathMatch(path)
	if !matched {
		return ""
	}
	if exact || protectedCriticalSubtree(path, root) {
		return fmt.Sprintf("為避免誤刪，禁止永久刪除受保護的系統關鍵路徑：%s（%s）", displayPath(path), displayPath(root))
	}
	return ""
}

func protectedCriticalSubtree(path, root string) bool {
	candidate := strings.TrimRight(canonicalComparePath(path), `\`)
	base := strings.TrimRight(canonicalComparePath(root), `\`)
	if candidate == "" || base == "" {
		return false
	}
	rel := strings.TrimPrefix(candidate, base)
	if rel == candidate {
		return false
	}
	rel = strings.TrimLeft(rel, `\`)
	critical := []string{
		`System32`, `SysWOW64`, `WinSxS`, `servicing`, `Boot`, `EFI`, `System Volume Information`, `Recovery`,
	}
	first := rel
	if i := strings.IndexByte(first, '\\'); i >= 0 {
		first = first[:i]
	}
	for _, item := range critical {
		if strings.EqualFold(first, item) {
			return true
		}
	}
	return false
}

func protectedPathWarning(path string) string {
	root, exact, matched := protectedPathMatch(path)
	if !matched || exact {
		return ""
	}
	return fmt.Sprintf("目標位於受保護的系統／主要使用者路徑 %s 之下：%s", displayPath(root), displayPath(path))
}

func validateTarget(path string) error {
	path = normalizeInputPath(path)
	if path == "" {
		return errors.New("空白路徑")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return errors.New("路徑包含無效的 NUL 字元")
	}
	if isDeviceNamespace(path) {
		return errors.New("不支援直接操作 Windows device / GLOBALROOT 命名空間")
	}
	if !filepath.IsAbs(displayPath(path)) {
		return errors.New("路徑必須是完整的絕對路徑")
	}
	if isRootPath(path) {
		return errors.New("為避免誤刪，禁止直接刪除磁碟或 UNC 共用根目錄")
	}
	if attr, code := getAttributes(toOperationPath(path)); attr != INVALID_FILE_ATTRIBUTES {
		if reason := protectedDirectoryReason(path); reason != "" {
			return errors.New(reason)
		}
		_ = code
	}
	if utf16Len(displayPath(path)) > windowsMaxExtendedPath {
		return fmt.Errorf("路徑超過 Windows extended-length 上限 %d 個 UTF-16 字元", windowsMaxExtendedPath)
	}
	return nil
}

func makePathCandidate(path, name string) string {
	if strings.HasSuffix(path, `\`) {
		return path + name
	}
	return path + `\` + name
}

func makeSearchPattern(path string) string {
	if strings.HasSuffix(path, `\`) {
		return path + `*`
	}
	return path + `\*`
}

// ══════════════════════════════════════════════════════════════════
// 永久刪除引擎：Win32 + extended-length path
// ══════════════════════════════════════════════════════════════════

type deletePathError struct {
	path       string
	err        error
	code       uint32
	restoreErr error
}

func (e *deletePathError) Error() string {
	if e == nil {
		return ""
	}
	primary := e.err
	if primary == nil && e.code != 0 {
		primary = win32Error(e.code)
	}
	if primary == nil {
		primary = errors.New("未知刪除錯誤")
	}
	if e.restoreErr != nil {
		return fmt.Sprintf("刪除 %q 時失敗：%v；原始檔案屬性復原亦失敗：%v", displayPath(e.path), primary, e.restoreErr)
	}
	return fmt.Sprintf("刪除 %q 時失敗：%v", displayPath(e.path), primary)
}

func (e *deletePathError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.err != nil {
		return e.err
	}
	if e.code != 0 {
		return win32Error(e.code)
	}
	return nil
}

// deleteAggregateError preserves every independently failed child while still
// allowing errors.As/errors.Is to inspect the contained primary errors.
type deleteAggregateError struct {
	items []deleteError
}

func (e *deleteAggregateError) Error() string {
	if e == nil || len(e.items) == 0 {
		return ""
	}
	return fmt.Sprintf("刪除作業中有 %d 個項目失敗", len(e.items))
}

func (e *deleteAggregateError) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, len(e.items))
	for _, item := range e.items {
		out = append(out, item.err)
	}
	return out
}

func getAttributes(path string) (uint32, uint32) {
	r, _, err := pGetFileAttributesW.Call(uintptr(unsafe.Pointer(u16(path))))
	if uint32(r) != INVALID_FILE_ATTRIBUTES {
		return uint32(r), 0
	}
	return INVALID_FILE_ATTRIBUTES, procError(err)
}

func clearReadOnly(path string, attr uint32) (bool, error) {
	if attr&FILE_ATTRIBUTE_READONLY == 0 {
		return false, nil
	}
	newAttr := attr &^ FILE_ATTRIBUTE_READONLY
	if newAttr == 0 {
		newAttr = 0x00000080 // FILE_ATTRIBUTE_NORMAL
	}
	r, _, err := pSetFileAttributesW.Call(uintptr(unsafe.Pointer(u16(path))), uintptr(newAttr))
	if r == 0 {
		return false, win32Error(procError(err))
	}
	return true, nil
}

func restoreOriginalAttributes(path string, attr uint32, changed bool) error {
	if !changed {
		return nil
	}
	r, _, err := pSetFileAttributesW.Call(uintptr(unsafe.Pointer(u16(path))), uintptr(attr))
	if r == 0 {
		return win32Error(procError(err))
	}
	return nil
}

type deleteBudget struct {
	retrySpent time.Duration
}

const deleteRetryBudget = 90 * time.Second

func newDeleteBudget() *deleteBudget {
	return &deleteBudget{}
}

func (b *deleteBudget) check() error {
	if cancellationRequested() {
		return errors.New("使用者要求停止目前刪除作業")
	}
	if b == nil {
		return nil
	}
	if b.retrySpent >= deleteRetryBudget {
		return errors.New("永久刪除作業的重試等待時間超過安全預算 90 秒，已停止以避免重試迴圈長時間卡住")
	}
	return nil
}

func (b *deleteBudget) sleepRetry(d time.Duration) error {
	if cancellationRequested() {
		return errors.New("使用者要求停止目前刪除作業")
	}
	if b == nil {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if cancellationRequested() {
				return errors.New("使用者要求停止目前刪除作業")
			}
			step := 50 * time.Millisecond
			remain := time.Until(deadline)
			if remain < step {
				step = remain
			}
			if step > 0 {
				time.Sleep(step)
			}
		}
		return nil
	}
	if d < 0 {
		d = 0
	}
	if b.retrySpent+d > deleteRetryBudget {
		return errors.New("永久刪除作業的重試等待時間超過安全預算 90 秒，已停止以避免重試迴圈長時間卡住")
	}
	b.retrySpent += d
	return sleepCancellable(d)
}

func deleteFileTransientRetryBudget(path string, attr uint32, deleteFn func() (bool, uint32), budget *deleteBudget) error {
	const attempts = 3
	var last uint32
	changed := false
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := budget.check(); err != nil {
			_ = restoreOriginalAttributes(path, attr, changed)
			return err
		}
		if didChange, err := clearReadOnly(path, attr); err != nil {
			_ = restoreOriginalAttributes(path, attr, changed)
			return err
		} else {
			changed = changed || didChange
		}
		ok, code := deleteFn()
		if ok {
			return nil
		}
		last = code
		if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
			return nil
		}
		if code != ERROR_SHARING_VIOLATION && code != ERROR_LOCK_VIOLATION && code != ERROR_DIR_NOT_EMPTY {
			restoreErr := restoreOriginalAttributes(path, attr, changed)
			if restoreErr != nil {
				return &deletePathError{path: path, code: code, restoreErr: restoreErr}
			}
			return win32Error(code)
		}
		if attempt < attempts {
			if err := budget.sleepRetry(150 * time.Millisecond); err != nil {
				_ = restoreOriginalAttributes(path, attr, changed)
				return err
			}
		}
	}
	restoreErr := restoreOriginalAttributes(path, attr, changed)
	if restoreErr != nil {
		return &deletePathError{path: path, code: last, restoreErr: restoreErr}
	}
	return win32Error(last)
}

func deleteFilePermanent(path string, attr uint32) error {
	return deleteFilePermanentBudget(path, attr, nil)
}

func deleteFileByHandle(path string, attr uint32) (bool, uint32) {
	op := toOperationPath(path)
	flags := uintptr(FILE_FLAG_OPEN_REPARSE_POINT)
	share := uintptr(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
	h, _, openErr := pCreateFileW.Call(uintptr(unsafe.Pointer(u16(op))), uintptr(DELETE_ACCESS|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES), share, 0, OPEN_EXISTING, flags, 0)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return false, procError(openErr)
	}
	defer pCloseHandle.Call(h)
	type fileDispositionInfo struct{ DeleteFile byte }
	fdi := fileDispositionInfo{DeleteFile: 1}
	r, _, setErr := pSetFileInformationByHandle.Call(h, FileDispositionInfoClass, uintptr(unsafe.Pointer(&fdi)), unsafe.Sizeof(fdi))
	if r != 0 {
		return true, ERROR_SUCCESS
	}
	code := procError(setErr)
	// Compatibility path: FileDispositionInfoEx is only used when the classic
	// handle disposition is rejected as unavailable/unsupported. FORCE_IMAGE_SECTION_CHECK
	// preserves the classic refusal to delete an executable image section; POSIX semantics
	// remove the directory entry promptly when the filesystem supports it.
	if code == ERROR_INVALID_PARAMETER || code == ERROR_NOT_SUPPORTED || code == ERROR_INVALID_FUNCTION {
		type fileDispositionInfoEx struct{ Flags uint32 }
		ex := fileDispositionInfoEx{Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE}
		r, _, exErr := pSetFileInformationByHandle.Call(h, 21, uintptr(unsafe.Pointer(&ex)), unsafe.Sizeof(ex))
		if r != 0 {
			return true, ERROR_SUCCESS
		}
		return false, procError(exErr)
	}
	return false, code
}

func deleteFilePermanentBudget(path string, attr uint32, budget *deleteBudget) error {
	return deleteFileTransientRetryBudget(path, attr, func() (bool, uint32) {
		if attr&FILE_ATTRIBUTE_REPARSE_POINT == 0 {
			if ok, _ := deleteFileByHandle(path, attr); ok {
				return true, ERROR_SUCCESS
			}
		}
		r, _, err := pDeleteFileW.Call(uintptr(unsafe.Pointer(u16(path))))
		if r != 0 {
			return true, ERROR_SUCCESS
		}
		return false, procError(err)
	}, budget)
}

func isCloudReparseTag(tag uint32) bool { return (tag & 0xF00000FF) == 0x9000001A }
func isKnownTraversableReparseDirectory(tag uint32) bool {
	return isCloudReparseTag(tag) || tag == 0x9000001C || tag == 0x8000001E || tag == 0x90000027
}

func isNameSurrogateReparseTag(tag uint32) bool { return (tag & 0x20000000) != 0 }

func deleteReparsePoint(path string, attr uint32, tag uint32) error {
	if cancellationRequested() {
		return errors.New("使用者要求停止目前刪除作業")
	}
	changed, err := clearReadOnly(path, attr)
	if err != nil {
		return err
	}
	if attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
		if !isNameSurrogateReparseTag(tag) {
			if tag == 0 {
				_ = restoreOriginalAttributes(path, attr, changed)
				return errors.New("無法取得 reparse tag，為避免誤刪已拒絕遞迴")
			}
			// Non-name-surrogate reparse directories (for example Cloud Files / ProjFS)
			// may contain real child entries. The caller will recurse them through the
			// ordinary directory engine instead of removing the reparse container itself.
			if restoreErr := restoreOriginalAttributes(path, attr, changed); restoreErr != nil {
				return &deletePathError{path: path, err: errors.New("非連結型 reparse 目錄需遞迴處理"), restoreErr: restoreErr}
			}
			return errors.New("非連結型 reparse 目錄需遞迴處理")
		}
		r, _, removeErr := pRemoveDirectoryW.Call(uintptr(unsafe.Pointer(u16(path))))
		if r == 0 {
			code := procError(removeErr)
			if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
				return nil
			}
			if restoreErr := restoreOriginalAttributes(path, attr, changed); restoreErr != nil {
				return &deletePathError{path: path, code: code, restoreErr: restoreErr}
			}
			return win32Error(code)
		}
		return nil
	}
	r, _, delErr := pDeleteFileW.Call(uintptr(unsafe.Pointer(u16(path))))
	if r == 0 {
		code := procError(delErr)
		if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
			return nil
		}
		if restoreErr := restoreOriginalAttributes(path, attr, changed); restoreErr != nil {
			return &deletePathError{path: path, code: code, restoreErr: restoreErr}
		}
		return win32Error(code)
	}
	return nil
}

func openDirectoryGuard(path string) (uintptr, uint32, uint32, error) {
	op := toOperationPath(path)
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0,
		OPEN_EXISTING,
		uintptr(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT),
		0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0, 0, 0, win32Error(procError(e))
	}
	var tag struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	r, _, e := pGetFileInformationByHandleEx.Call(h, FileAttributeTagInfoClass, uintptr(unsafe.Pointer(&tag)), unsafe.Sizeof(tag))
	if r == 0 {
		pCloseHandle.Call(h)
		return 0, 0, 0, win32Error(procError(e))
	}
	return h, tag.FileAttributes, tag.ReparseTag, nil
}

func reparseTagForFile(path string) uint32 {
	h, _, _ := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(path))),
		uintptr(FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0, OPEN_EXISTING, uintptr(FILE_FLAG_OPEN_REPARSE_POINT), 0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0
	}
	defer pCloseHandle.Call(h)
	var tag struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	r, _, _ := pGetFileInformationByHandleEx.Call(h, FileAttributeTagInfoClass, uintptr(unsafe.Pointer(&tag)), unsafe.Sizeof(tag))
	if r == 0 {
		return 0
	}
	return tag.ReparseTag
}

func utf16NameHasUnpairedSurrogate(v []uint16) bool {
	for i := 0; i < len(v); i++ {
		u := v[i]
		if u >= 0xD800 && u <= 0xDBFF {
			if i+1 >= len(v) || v[i+1] < 0xDC00 || v[i+1] > 0xDFFF {
				return true
			}
			i++
		} else if u >= 0xDC00 && u <= 0xDFFF {
			return true
		}
		if u == 0 {
			break
		}
	}
	return false
}

func findDataSafeName(data WIN32_FIND_DATA) (string, bool) {
	raw := data.CFileName[:]
	if !utf16NameHasUnpairedSurrogate(raw) {
		return syscall.UTF16ToString(raw), true
	}
	alt := syscall.UTF16ToString(data.CAlternateName[:])
	if alt != "" && !strings.ContainsRune(alt, '\uFFFD') {
		return alt, true
	}
	return "", false
}

func deleteDirOnePassBudget(path string, attr uint32, budget *deleteBudget) (error, bool) {
	if err := budget.check(); err != nil {
		return err, false
	}
	guard, guardAttr, guardTag, err := openDirectoryGuard(path)
	if err != nil {
		var code win32CodeError
		if errors.As(err, &code) && (uint32(code) == ERROR_FILE_NOT_FOUND || uint32(code) == ERROR_PATH_NOT_FOUND) {
			return nil, false
		}
		return err, false
	}
	defer pCloseHandle.Call(guard)
	if guardAttr&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		if isNameSurrogateReparseTag(guardTag) {
			return deleteReparsePoint(path, guardAttr, guardTag), false
		}
		if guardTag == 0 || !isKnownTraversableReparseDirectory(guardTag) {
			return fmt.Errorf("不支援的 reparse 目錄 tag 0x%08X，為避免誤刪已停止", guardTag), false
		}
	}

	pattern := makeSearchPattern(path)
	var data WIN32_FIND_DATA
	h, _, findErr := pFindFirstFileW.Call(uintptr(unsafe.Pointer(u16(pattern))), uintptr(unsafe.Pointer(&data)))
	if h == INVALID_HANDLE_VALUE {
		code := procError(findErr)
		if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
			return nil, false
		}
		return win32Error(code), false
	}
	defer pFindClose.Call(h)

	var childFailures []deleteError
	retryAny := false
	for {
		if err := budget.check(); err != nil {
			return err, false
		}
		name, ok := findDataSafeName(data)
		if !ok {
			child := makePathCandidate(path, "<無法安全解碼的檔名>")
			childFailures = append(childFailures, deleteError{path: child, err: errors.New("檔名包含無法安全保真的 UTF-16 surrogate，且無可用 8.3 備援名稱；為避免刪錯已停止處理此項")})
		} else if name != "." && name != ".." {
			child := makePathCandidate(path, name)
			if err := validateTarget(child); err != nil {
				childFailures = append(childFailures, deleteError{path: child, err: err})
			} else {
				childAttr := data.DwFileAttributes
				var childErr error
				switch {
				case childAttr&FILE_ATTRIBUTE_REPARSE_POINT != 0 && childAttr&FILE_ATTRIBUTE_DIRECTORY != 0:
					tag := data.DwReserved0
					if isNameSurrogateReparseTag(tag) {
						childErr = deleteReparsePoint(child, childAttr, tag)
					} else if isKnownTraversableReparseDirectory(tag) {
						childErr = deleteDirPermanentBudget(child, childAttr, budget)
					} else {
						childErr = fmt.Errorf("不支援的 reparse 目錄 tag 0x%08X，為避免誤刪已停止", tag)
					}
				case childAttr&FILE_ATTRIBUTE_REPARSE_POINT != 0:
					childErr = deleteReparsePoint(child, childAttr, data.DwReserved0)
				case childAttr&FILE_ATTRIBUTE_DIRECTORY != 0:
					childErr = deleteDirPermanentBudget(child, childAttr, budget)
				default:
					childErr = deleteFilePermanentBudget(child, childAttr, budget)
				}
				if childErr != nil {
					retryHere := false
					var code win32CodeError
					if errors.As(childErr, &code) {
						c := uint32(code)
						retryHere = c == ERROR_DIR_NOT_EMPTY || c == ERROR_SHARING_VIOLATION || c == ERROR_LOCK_VIOLATION || c == ERROR_USER_MAPPED_FILE
					}
					if retryHere {
						retryAny = true
					}
					var nested *deleteAggregateError
					if errors.As(childErr, &nested) && len(nested.items) > 0 {
						childFailures = append(childFailures, nested.items...)
					} else {
						childFailures = append(childFailures, deleteError{path: child, err: childErr})
					}
				}
			}
		}
		var nextData WIN32_FIND_DATA
		r, _, nextErr := pFindNextFileW.Call(h, uintptr(unsafe.Pointer(&nextData)))
		if r == 0 {
			code := procError(nextErr)
			if code == ERROR_NO_MORE_FILES || code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
				break
			}
			childFailures = append(childFailures, deleteError{path: path, err: win32Error(code)})
			break
		}
		data = nextData
	}

	if len(childFailures) > 0 {
		return &deleteAggregateError{items: childFailures}, retryAny
	}
	changed, err := clearReadOnly(path, attr)
	if err != nil {
		return err, false
	}
	if err := budget.check(); err != nil {
		_ = restoreOriginalAttributes(path, attr, changed)
		return err, false
	}
	if guardIdentity, guardKnown := fileIdentityFromHandle(guard); guardKnown {
		currentHandle, _, openErr := pCreateFileW.Call(uintptr(unsafe.Pointer(u16(toOperationPath(path)))), uintptr(FILE_READ_ATTRIBUTES), uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE), 0, OPEN_EXISTING, uintptr(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT), 0)
		if currentHandle == 0 || currentHandle == INVALID_HANDLE_VALUE {
			_ = restoreOriginalAttributes(path, attr, changed)
			return win32Error(procError(openErr)), false
		}
		currentIdentity, currentKnown := fileIdentityFromHandle(currentHandle)
		pCloseHandle.Call(currentHandle)
		if !currentKnown || !sameFileIdentity(guardIdentity, currentIdentity) {
			_ = restoreOriginalAttributes(path, attr, changed)
			return errors.New("刪除前偵測到資料夾識別資訊已變更，為避免 TOCTOU 誤刪已停止"), false
		}
	}
	r, _, removeErr := pRemoveDirectoryW.Call(uintptr(unsafe.Pointer(u16(path))))
	if r != 0 {
		return nil, false
	}
	code := procError(removeErr)
	if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
		return nil, false
	}
	if code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION || code == ERROR_DIR_NOT_EMPTY {
		if ok, _ := deleteDirectoryByHandleFallback(path); ok {
			return nil, false
		}
	}
	if restoreErr := restoreOriginalAttributes(path, attr, changed); restoreErr != nil {
		return &deletePathError{path: path, code: code, restoreErr: restoreErr}, false
	}
	retryHere := code == ERROR_DIR_NOT_EMPTY || code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION || code == ERROR_USER_MAPPED_FILE
	return win32Error(code), retryHere
}

func deleteDirectoryByHandleFallback(path string) (bool, uint32) {
	op := toOperationPath(path)
	h, _, e := pCreateFileW.Call(uintptr(unsafe.Pointer(u16(op))), uintptr(DELETE_ACCESS|FILE_READ_ATTRIBUTES), uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE), 0, OPEN_EXISTING, uintptr(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT), 0)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return false, procError(e)
	}
	defer pCloseHandle.Call(h)
	type disposition struct{ Delete byte }
	d := disposition{Delete: 1}
	r, _, setErr := pSetFileInformationByHandle.Call(h, FileDispositionInfoClass, uintptr(unsafe.Pointer(&d)), unsafe.Sizeof(d))
	if r != 0 {
		return true, ERROR_SUCCESS
	}
	return false, procError(setErr)
}

func deleteDirPermanentBudget(path string, attr uint32, budget *deleteBudget) error {
	if err := budget.check(); err != nil {
		return err
	}
	// Directory reparse points are classified inside the guard-open path.
	// Name-surrogate tags (junction/symlink) are removed as link objects; known
	// non-surrogate provider tags are traversed like real directories.
	const passes = 4
	var last error
	for pass := 0; pass < passes; pass++ {
		if err := budget.check(); err != nil {
			return err
		}
		var retryHere bool
		last, retryHere = deleteDirOnePassBudget(path, attr, budget)
		if last == nil {
			return nil
		}
		if !retryHere {
			return last
		}
		if pass+1 < passes {
			if err := budget.sleepRetry(100 * time.Millisecond); err != nil {
				return err
			}
		}
	}
	return last
}

func deleteDirPermanent(path string, attr uint32) error {
	return deleteDirPermanentBudget(path, attr, newDeleteBudget())
}

func deletePermanent(path string) error {
	op := toOperationPath(path)
	attr, code := getAttributes(op)
	if attr == INVALID_FILE_ATTRIBUTES {
		if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
			return os.ErrNotExist
		}
		return win32Error(code)
	}
	if attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
		return deleteDirPermanent(op, attr)
	}
	if attr&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return deleteReparsePoint(op, attr, reparseTagForFile(op))
	}
	return deleteFilePermanent(op, attr)
}

// ══════════════════════════════════════════════════════════════════
// 刪除結果與驗證
// ══════════════════════════════════════════════════════════════════

type deleteError struct {
	path string
	err  error
}

type deleteResult struct {
	total    int
	success  int
	missing  int
	failed   int
	targets  []string
	errors   []deleteError
	warnings []string
}

func verifyDeleted(path string) (bool, error) {
	state, code := pathStateOf(path)
	switch state {
	case pathMissing:
		return true, nil
	case pathUnknown:
		return false, win32Error(code)
	default:
		return false, nil
	}
}

func (a *App) performDelete(paths []string) deleteResult {
	result := deleteResult{total: len(paths), targets: append([]string(nil), paths...)}
	for _, p := range paths {
		if cancellationRequested() {
			remaining := len(paths) - result.success - result.missing - result.failed
			if remaining > 0 {
				result.failed += remaining
			}
			result.warnings = append(result.warnings, "使用者要求停止；尚未處理的目標已保留，沒有再進行強制占用解除。")
			break
		}
		if err := validateTarget(p); err != nil {
			result.failed++
			result.errors = append(result.errors, deleteError{path: p, err: err})
			continue
		}
		state, code := pathStateOf(p)
		if state == pathMissing {
			result.missing++
			continue
		}
		if state == pathUnknown {
			result.failed++
			result.errors = append(result.errors, deleteError{path: p, err: win32Error(code)})
			continue
		}

		err := deletePermanent(p)
		if errors.Is(err, os.ErrNotExist) {
			result.missing++
			continue
		}
		if err != nil {
			result.failed++
			var agg *deleteAggregateError
			if errors.As(err, &agg) && len(agg.items) > 0 {
				for _, item := range agg.items {
					result.errors = append(result.errors, item)
				}
			} else {
				errorPath := p
				var pe *deletePathError
				if errors.As(err, &pe) && pe.path != "" {
					errorPath = pe.path
				}
				result.errors = append(result.errors, deleteError{path: errorPath, err: err})
			}
			continue
		}
		deleted, verifyErr := verifyDeleted(p)
		if deleted {
			result.success++
		} else {
			result.failed++
			if verifyErr == nil {
				verifyErr = errors.New("刪除 API 已返回成功，但路徑仍存在")
			}
			result.errors = append(result.errors, deleteError{path: p, err: verifyErr})
		}
	}
	return result
}

func (a *App) startInitialDeleteFlow(paths []string) {
	if !atomic.CompareAndSwapInt32(&a.busy, 0, 1) {
		return
	}
	atomic.StoreInt32(&a.cancelRequested, 0)
	a.setControlsEnabled(false)
	pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在嘗試永久刪除…"))))
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				result := deleteResult{total: len(paths), failed: len(paths), targets: append([]string(nil), paths...)}
				result.errors = append(result.errors, deleteError{path: "", err: fmt.Errorf("刪除 worker 發生未處理例外：%v", r)})
				result.warnings = append(result.warnings, "刪除 worker 發生未處理例外，未再繼續執行後續強制處理。")
				a.resultQueue <- result
				pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			}
		}()

		result := a.performDelete(paths)
		lockedPaths := failedLockRecoveryPaths(result)
		if len(lockedPaths) == 0 {
			a.resultQueue <- result
			pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			return
		}

		// Lock discovery can inspect Restart Manager / system handles and must
		// never run on the GUI thread.
		pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在辨識占用程序…"))))
		lockers, _ := discoverLockers(lockedPaths)
		request := lockPromptRequest{
			result:  result,
			locked:  lockedPaths,
			lockers: lockers,
		}
		a.lockQueue <- request
		pPostMessageW.Call(uintptr(a.hwnd), WM_APP_LOCK_PROMPT, 0, 0)
	}()
}

type lockPromptRequest struct {
	result  deleteResult
	locked  []string
	lockers []lockProcess
}

func hasForceEligibleLockers(lockers []lockProcess) bool {
	for _, l := range lockers {
		if canForceTerminateLocker(l) {
			return true
		}
	}
	return false
}

func (a *App) continueForceDelete(req lockPromptRequest) {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result := req.result
		terminated := []terminatedLocker(nil)
		shellPrivilegeChanged := false
		cleaned := false
		cleanup := func() {
			if cleaned {
				return
			}
			cleaned = true
			if len(terminated) > 0 {
				if err := restoreTerminatedDesktopShells(terminated); err != nil {
					result.warnings = append(result.warnings, err.Error())
				}
			}
			if shellPrivilegeChanged {
				if err := disableShellRecoveryPrivilege(); err != nil {
					result.warnings = append(result.warnings, fmt.Sprintf("Explorer 恢復完成後停用 SeImpersonatePrivilege 失敗：%v", err))
				}
			}
		}
		defer func() {
			if r := recover(); r != nil {
				cleanup()
				result.warnings = append(result.warnings, fmt.Sprintf("強制處理 worker 發生未處理例外：%v；已執行 Explorer recovery cleanup。", r))
				if result.failed == 0 {
					result.failed = result.total - result.success - result.missing
					if result.failed < 0 {
						result.failed = 0
					}
				}
				a.resultQueue <- result
				pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			}
		}()

		if cancellationRequested() {
			result.warnings = append(result.warnings, "使用者要求停止；未執行強制終止占用程序。")
			a.resultQueue <- result
			pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			return
		}
		pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在解除目前確認的檔案占用…"))))
		var killErr error
		var shellUnconfirmed bool
		terminated, killErr, shellPrivilegeChanged, shellUnconfirmed = forceTerminateLockers(req.lockers)
		if killErr != nil {
			result.warnings = append(result.warnings, killErr.Error())
		}
		if shellUnconfirmed {
			result.warnings = append(result.warnings, "Explorer 終止狀態未能確認；為避免黑屏與競態，本次未繼續刪除該占用目標。")
		} else {
			priorWarnings := append([]string(nil), req.result.warnings...)
			result = a.performDeleteAfterForceTermination(req.result.targets)
			result.warnings = append(result.warnings, priorWarnings...)
		}

		// Normal-path cleanup must complete before the result is published.
		cleanup()
		if result.failed == 0 {
			a.resultQueue <- result
			pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			return
		}
		lockedPaths := failedLockRecoveryPaths(result)
		if len(lockedPaths) > 0 && !cancellationRequested() {
			pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("發現新的／仍存在的檔案占用，重新辨識中…"))))
			lockers, _ := discoverLockers(lockedPaths)
			a.lockQueue <- lockPromptRequest{result: result, locked: lockedPaths, lockers: lockers}
			pPostMessageW.Call(uintptr(a.hwnd), WM_APP_LOCK_PROMPT, 0, 0)
			return
		}
		a.resultQueue <- result
		pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
	}()
}

func isPostTerminationRetryCode(code uint32) bool {
	switch code {
	case ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_USER_MAPPED_FILE, ERROR_DIR_NOT_EMPTY, ERROR_ACCESS_DENIED:
		// ERROR_ACCESS_DENIED is normally a permission error and must not be
		// globally treated as a locker. It is retriable here only because this
		// function is reached after a confirmed force-termination of the exact
		// locker set, where Windows can briefly return ACCESS_DENIED while an
		// image/DLL/handle teardown is still settling. The bounded retry window
		// converts only this post-termination transient into another delete
		// attempt; it does not change the general locker classification policy.
		return true
	default:
		return false
	}
}

// performDeleteAfterForceTermination gives Windows kernel/user-mode teardown
// a bounded settle window before publishing the first failed result. Process
// termination can be confirmed while file-image/DLL/FS handles are still
// unwinding briefly; requiring a second user-initiated delete is undesirable.
// A newly acquired locker is never force-terminated under the old consent: it
// remains a fresh lock-discovery/confirmation candidate.
func (a *App) performDeleteAfterForceTermination(paths []string) deleteResult {
	// Re-run the original user-authorized top-level targets, not just the
	// individual locked children. A locked file such as an EXE or DLL may be
	// inside a directory selected for deletion. Once the
	// locker exits, deleting only the child leaves the now-empty container
	// directory behind, which previously made the user press "永久刪除" again.
	//
	// A full top-level re-pass is safe here because every target is still
	// revalidated immediately before destructive work, and the pass is entered
	// only after the user has explicitly authorized termination of the exact
	// discovered locker set. Newly acquired lockers are never terminated by
	// this retry; they return to fresh discovery/confirmation below.
	result := a.performDelete(paths)
	if result.failed == 0 || cancellationRequested() {
		return result
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !cancellationRequested() {
		hasTransient := false
		for _, item := range result.errors {
			var code win32CodeError
			if errors.As(item.err, &code) && isPostTerminationRetryCode(uint32(code)) {
				hasTransient = true
				break
			}
		}
		if !hasTransient {
			return result
		}

		if err := sleepCancellable(200 * time.Millisecond); err != nil {
			return result
		}

		// Re-evaluate the complete original target set. This is intentional:
		// for a selected directory, the locked child may disappear while the
		// directory itself remains; the same transaction must finish that parent
		// deletion instead of handing a leftover directory back to the UI.
		result = a.performDelete(paths)
		if result.failed == 0 {
			return result
		}
	}
	return result
}

func sleepCancellable(d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cancellationRequested() {
			return errors.New("使用者要求停止目前刪除作業")
		}
		step := 50 * time.Millisecond
		remain := time.Until(deadline)
		if remain < step {
			step = remain
		}
		if step > 0 {
			time.Sleep(step)
		}
	}
	return nil
}

func failedLockRecoveryPaths(result deleteResult) []string {
	if len(result.errors) == 0 {
		return nil
	}
	paths := make([]string, 0)
	seen := make(map[string]struct{})
	for _, e := range result.errors {
		var code win32CodeError
		if !errors.As(e.err, &code) {
			continue
		}
		c := uint32(code)
		if !isLockRecoveryError(c) {
			continue
		}
		key := strings.ToLower(normalizeInputPath(e.path))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		paths = append(paths, e.path)
	}
	return paths
}

// ══════════════════════════════════════════════════════════════════
// 清單操作
// ══════════════════════════════════════════════════════════════════

func (a *App) addPath(p string) {
	p = normalizeInputPath(p)
	if p == "" {
		return
	}
	for _, existing := range a.items {
		if strings.EqualFold(existing, p) {
			return
		}
	}
	a.items = append(a.items, p)
}

// hasOtherItemPath reports whether another list entry already refers to the
// same path. List paths are normalized before comparison, matching addPath's
// case-insensitive duplicate policy.
func (a *App) hasOtherItemPath(path string, skipIndex int) bool {
	path = normalizeInputPath(path)
	if path == "" {
		return false
	}
	for i, existing := range a.items {
		if i == skipIndex {
			continue
		}
		if strings.EqualFold(normalizeInputPath(existing), path) {
			return true
		}
	}
	return false
}

// replaceItemAndDeduplicatePath updates one list entry and removes only other
// entries that now duplicate the same resulting filesystem path. It never
// performs additional filesystem operations.
func (a *App) replaceItemAndDeduplicatePath(index int, newPath string) int {
	if index < 0 || index >= len(a.items) {
		return 0
	}
	newPath = normalizeInputPath(newPath)
	updated := make([]string, 0, len(a.items))
	removed := 0
	for i, existing := range a.items {
		if i == index {
			updated = append(updated, newPath)
			continue
		}
		if strings.EqualFold(normalizeInputPath(existing), newPath) {
			removed++
			continue
		}
		updated = append(updated, existing)
	}
	a.items = updated
	return removed
}

func (a *App) removeItemAt(index int) {
	if index < 0 || index >= len(a.items) {
		return
	}
	a.items = append(a.items[:index], a.items[index+1:]...)
}

func (a *App) rebuildList() {
	lbSend(LB_RESETCONTENT, 0, 0)
	for _, p := range a.items {
		n := utf16Len(displayPath(p))
		var label string
		if n >= windowsMaxPath {
			label = fmt.Sprintf("⚠ %d 字元  %s", n, displayPath(p))
		} else {
			label = fmt.Sprintf("   %d 字元  %s", n, displayPath(p))
		}
		pSendMessageW.Call(uintptr(a.hwndList), LB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16(label))))
	}
	a.updateStatus()
	if a.hwndList != 0 {
		pInvalidateRect.Call(uintptr(a.hwndList), 0, 1)
	}
}

func (a *App) updateStatus() {
	over := 0
	for _, p := range a.items {
		if utf16Len(displayPath(p)) >= windowsMaxPath {
			over++
		}
	}
	selected := a.selectedCount()
	var s string
	switch {
	case len(a.items) == 0:
		s = emptyListText
	case over > 0:
		s = fmt.Sprintf("共 %d 個路徑 · 已選 %d 個 · %d 個達到／超過 260 字元 ⚠", len(a.items), selected, over)
	default:
		s = fmt.Sprintf("共 %d 個路徑 · 已選 %d 個 · 有選取就刪除所選，未選取則刪除全部", len(a.items), selected)
	}
	pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16(s))))
	a.updateActionButtons()
}

func (a *App) updateActionButtons() {
	if a.hwndBtnRename == 0 && a.hwndBtnRescue == 0 {
		return
	}
	enableRename := false
	enableRescue := false
	sel := lbSelectedIndices()
	if len(sel) == 1 && sel[0] >= 0 && sel[0] < len(a.items) {
		p := a.items[sel[0]]
		attr, _ := getAttributes(toOperationPath(p))
		if attr != INVALID_FILE_ATTRIBUTES {
			if attr&FILE_ATTRIBUTE_DIRECTORY == 0 {
				enableRename = true
			} else {
				enableRescue = true
			}
		}
	}
	pEnableWindow.Call(uintptr(a.hwndBtnRename), uintptr(boolToInt(enableRename)))
	pEnableWindow.Call(uintptr(a.hwndBtnRescue), uintptr(boolToInt(enableRescue)))
}

func (a *App) browseFiles() {
	paths, err := pickPathsOnSTA(a.hwnd, false)
	if err != nil {
		msgBox(a.hwnd, appTitle, "無法開啟檔案選取對話框。\n\n"+err.Error(), MB_OK|MB_ICONERROR)
		return
	}
	for _, p := range paths {
		a.addPath(p)
	}
	if len(paths) > 0 {
		a.rebuildList()
	}
}

func (a *App) browseFolder() {
	paths, err := pickPathsOnSTA(a.hwnd, true)
	if err != nil {
		msgBox(a.hwnd, appTitle, "無法開啟資料夾選取對話框。\n\n"+err.Error(), MB_OK|MB_ICONERROR)
		return
	}
	for _, p := range paths {
		a.addPath(p)
	}
	if len(paths) > 0 {
		a.rebuildList()
	}
}

func (a *App) removePaths(paths []string) {
	if len(paths) == 0 {
		return
	}
	removeSet := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		removeSet[strings.ToLower(p)] = struct{}{}
	}
	keep := make([]string, 0, len(a.items))
	for _, p := range a.items {
		if _, ok := removeSet[strings.ToLower(p)]; !ok {
			keep = append(keep, p)
		}
	}
	a.items = keep
	a.rebuildList()
}

func (a *App) removeSelected() {
	sel := lbSelectedIndices()
	if len(sel) == 0 {
		msgBox(a.hwnd, appTitle, "請先在右側清單中選取要移除的項目。可用 Ctrl／Shift 進行多選。", MB_OK|MB_ICONWARNING)
		return
	}
	selSet := make(map[int]bool, len(sel))
	for _, i := range sel {
		selSet[i] = true
	}
	keep := make([]string, 0, len(a.items))
	for i, p := range a.items {
		if !selSet[i] {
			keep = append(keep, p)
		}
	}
	a.items = keep
	a.rebuildList()
}

func (a *App) selectedCount() int {
	return len(lbSelectedIndices())
}

func (a *App) selectedTargets() []string {
	sel := lbSelectedIndices()
	if len(sel) == 0 {
		return append([]string(nil), a.items...)
	}
	out := make([]string, 0, len(sel))
	for _, i := range sel {
		if i >= 0 && i < len(a.items) {
			out = append(out, a.items[i])
		}
	}
	return out
}

func (a *App) doDelete() {
	if atomic.LoadInt32(&a.busy) != 0 {
		return
	}
	targets := a.selectedTargets()
	if len(targets) == 0 {
		msgBox(a.hwnd, appTitle, "清單是空的，請先加入要刪除的路徑。", MB_OK|MB_ICONWARNING)
		return
	}

	for _, p := range targets {
		if err := validateTarget(p); err != nil {
			msgBox(a.hwnd, appTitle, fmt.Sprintf("無法刪除：\n%s\n\n原因：%v", displayPath(p), err), MB_OK|MB_ICONWARNING)
			return
		}
	}

	selectionMode := "全部清單"
	if selected := a.selectedCount(); selected > 0 {
		selectionMode = fmt.Sprintf("目前選取的 %d 個", selected)
	}

	header := fmt.Sprintf(
		"⚠ 即將【永久刪除】%d 個路徑（%s）。\n\n"+
			"這些檔案與資料夾不會移至資源回收筒。\n"+
			"刪除完成後無法從資源回收筒還原，操作通常無法挽回。\n\n",
		len(targets), selectionMode,
	)
	preview := header
	for i, p := range targets {
		if i >= 10 {
			preview += fmt.Sprintf("  … 以及其他 %d 個路徑\n", len(targets)-10)
			break
		}
		preview += "  " + displayPath(p) + "\n"
	}
	preview += "\n確定要永久刪除這些項目嗎？"

	if msgBox(a.hwnd, appTitle, preview, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES {
		return
	}

	var protectedWarnings []string
	for _, p := range targets {
		if warning := protectedPathWarning(p); warning != "" {
			protectedWarnings = append(protectedWarnings, warning)
		}
	}
	if len(protectedWarnings) > 0 {
		confirm := "再次確認：以下目標位於受保護路徑之下。永久刪除可能影響系統、程式或使用者資料。\n\n"
		for i, warning := range protectedWarnings {
			if i >= 8 {
				confirm += fmt.Sprintf("……另有 %d 個受保護路徑項目\n", len(protectedWarnings)-8)
				break
			}
			confirm += "• " + warning + "\n"
		}
		confirm += "\n仍要永久刪除嗎？"
		if msgBox(a.hwnd, appTitle, confirm, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) != IDYES {
			return
		}
	}

	a.startInitialDeleteFlow(targets)
}

// ══════════════════════════════════════════════════════════════════
// 非破壞性檔案處理
// ══════════════════════════════════════════════════════════════════

func (a *App) renameSelectedFile() {
	sel := lbSelectedIndices()
	if len(sel) != 1 || sel[0] < 0 || sel[0] >= len(a.items) {
		return
	}
	oldPath := a.items[sel[0]]
	attr, _ := getAttributes(toOperationPath(oldPath))
	if attr == INVALID_FILE_ATTRIBUTES || attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
		return
	}
	currentName := fileBaseName(oldPath)
	nameStem, nameExt := splitRenameName(currentName)
	newStem, ok := promptFileRename(a.hwnd, nameStem)
	if !ok {
		return
	}
	newPathCandidate := normalizeInputPath(makePathCandidate(filepathDirDisplay(oldPath), newStem+nameExt))
	if a.hasOtherItemPath(newPathCandidate, sel[0]) {
		msgBox(a.hwnd, appTitle, "清單中已存在相同的目標路徑。\n\n為避免產生重複清單項目，本次更名未執行。", MB_OK|MB_ICONWARNING)
		return
	}
	pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在進行檔案更名…"))))
	newPath, err := renameSingleFile(oldPath, newStem+nameExt)
	if err != nil {
		a.rebuildList()
		msgBox(a.hwnd, appTitle, "檔案更名失敗。\n\n原始檔案未主動刪除。\n\n原因："+err.Error(), MB_OK|MB_ICONWARNING)
		return
	}
	removed := a.replaceItemAndDeduplicatePath(sel[0], newPath)
	a.rebuildList()
	message := fmt.Sprintf("檔案更名完成。\n\n新名稱：%s", fileBaseName(newPath))
	if removed > 0 {
		message += "\n\n清單中原有的相同路徑項目已自動合併。"
	}
	msgBox(a.hwnd, appTitle, message, MB_OK)
}

func (a *App) rescueSelectedFolder() {
	sel := lbSelectedIndices()
	if len(sel) != 1 || sel[0] < 0 || sel[0] >= len(a.items) {
		return
	}
	oldPath := a.items[sel[0]]
	attr, _ := getAttributes(toOperationPath(oldPath))
	if attr == INVALID_FILE_ATTRIBUTES || attr&FILE_ATTRIBUTE_DIRECTORY == 0 {
		return
	}
	root := volumeRootForWindowsPath(displayPath(oldPath))
	if root == "" {
		msgBox(a.hwnd, appTitle, "無法取得資料夾所在的 volume 根目錄，因此未執行路徑救援。", MB_OK|MB_ICONWARNING)
		return
	}
	preview := makePathCandidate(root, "OmniDeleter_x") + `\A`
	if msgBox(a.hwnd, appTitle, "將選定的資料夾整體移至同一個 volume 的短路徑救援位置。\n\n固定結構：\n"+displayPath(preview)+"\n\n原始資料夾內部結構不會改變。\n原始深層父資料夾成功救援後也不會由本功能刪除。\n\n是否開始救援？", MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2) != IDYES {
		return
	}
	pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在進行資料夾路徑救援…"))))
	newPath, err := pathRescueFolder(oldPath)
	if err != nil {
		a.rebuildList()
		msgBox(a.hwnd, appTitle, rescueFailureMessage(err), MB_OK|MB_ICONWARNING)
		return
	}
	a.removeItemAt(sel[0])
	a.rebuildList()
	message := rescueDisplayMessage(oldPath, newPath) + "\n\n救援完成後，原資料夾已從目前清單移除，以降低後續誤刪救援結果的風險。"
	msgBox(a.hwnd, appTitle, message, MB_OK)
}

// ══════════════════════════════════════════════════════════════════
// 拖曳
// ══════════════════════════════════════════════════════════════════

func (a *App) handleDrop(hDrop uintptr) {
	defer pDragFinish.Call(hDrop)
	const countAll = 0xFFFFFFFF
	n, _, _ := pDragQueryFileW.Call(hDrop, countAll, 0, 0)
	for i := uintptr(0); i < n; i++ {
		needed, _, _ := pDragQueryFileW.Call(hDrop, i, 0, 0)
		if needed == 0 {
			continue
		}
		buf := make([]uint16, needed+1)
		copied, _, _ := pDragQueryFileW.Call(hDrop, i, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if copied == 0 || copied >= uintptr(len(buf)) {
			continue
		}
		path := syscall.UTF16ToString(buf[:copied])
		if path != "" {
			a.addPath(path)
		}
	}
	a.rebuildList()
}

// ══════════════════════════════════════════════════════════════════
// UI enable / state reconciliation
// ══════════════════════════════════════════════════════════════════

func (a *App) setControlsEnabled(enabled bool) {
	for _, hwnd := range []HWND{
		a.hwndBtnAdd, a.hwndBtnDir, a.hwndBtnRename, a.hwndBtnRescue,
		a.hwndBtnRemove, a.hwndBtnClear, a.hwndBtnDelete,
	} {
		pEnableWindow.Call(uintptr(hwnd), uintptr(boolToInt(enabled)))
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ══════════════════════════════════════════════════════════════════
// Layout
// ══════════════════════════════════════════════════════════════════

func (a *App) layout() {
	var rc RECT
	pGetClientRect.Call(uintptr(a.hwnd), uintptr(unsafe.Pointer(&rc)))
	W, H := int(rc.Right), int(rc.Bottom)

	const (
		pad     = 12
		btnH    = 30
		btnW    = 116
		statusH = 24
		gap     = 8
	)

	bx, by := pad, pad
	move(a.hwndBtnAdd, bx, by, btnW, btnH)
	by += btnH + 5
	move(a.hwndBtnDir, bx, by, btnW, btnH)
	by += btnH + gap*2
	move(a.hwndBtnRename, bx, by, btnW, btnH)
	by += btnH + 5
	move(a.hwndBtnRescue, bx, by, btnW, btnH)
	by += btnH + gap*2
	move(a.hwndBtnRemove, bx, by, btnW, btnH)
	by += btnH + 5
	move(a.hwndBtnClear, bx, by, btnW, btnH)

	move(a.hwndBtnDelete, bx, H-pad-btnH, btnW, btnH)

	lx := pad*2 + btnW
	lw := W - lx - pad
	lh := H - pad - statusH - gap - pad
	move(a.hwndList, lx, pad, lw, lh)
	const linkW = 140
	const linkGap = 8
	statusW := lw - linkW - linkGap
	move(a.hwndStatus, lx, H-statusH-4, statusW, statusH)
	move(a.hwndLink, lx+statusW+linkGap, H-statusH-4, linkW, statusH)
}

// ══════════════════════════════════════════════════════════════════
// WndProc
// ══════════════════════════════════════════════════════════════════

func wndProc(hwnd HWND, msg uint32, wParam, lParam uintptr) uintptr {
	a := &gApp
	switch msg {
	case WM_DROPFILES:
		a.handleDrop(wParam)

	case WM_SIZE:
		a.layout()

	case WM_COMMAND:
		id := int(wParam & 0xFFFF)
		code := uint16((wParam >> 16) & 0xFFFF)
		if id == idListBox && code == LBN_SELCHANGE {
			a.updateStatus()
			break
		}
		if id == idLink && code == STN_CLICKED {
			verb := u16("open")
			target := u16(threadsLinkURL)
			r, _, _ := pShellExecuteW.Call(
				uintptr(a.hwnd),
				uintptr(unsafe.Pointer(verb)),
				uintptr(unsafe.Pointer(target)),
				0, 0, uintptr(SW_SHOW),
			)
			if r <= 32 {
				msgBox(a.hwnd, appTitle, "無法開啟 Threads 連結。", MB_OK|MB_ICONWARNING)
			}
			break
		}
		switch id {
		case idBtnAdd:
			a.browseFiles()
		case idBtnAddDir:
			a.browseFolder()
		case idBtnRename:
			a.renameSelectedFile()
		case idBtnRescue:
			a.rescueSelectedFolder()
		case idBtnRemove:
			a.removeSelected()
		case idBtnClear:
			if len(a.items) > 0 && msgBox(hwnd, appTitle, clearConfirmText, MB_YESNO|MB_ICONQUESTION) == IDYES {
				a.items = nil
				a.rebuildList()
			}
		case idBtnDelete:
			a.doDelete()
		}

	case WM_APP_LOCK_PROMPT:
		select {
		case req := <-a.lockQueue:
			lockPrompt := fmt.Sprintf("偵測到 %d 個項目目前被其他程式占用，Windows 暫時不允許刪除。\n\n", len(req.locked))
			lockPrompt += "這次確認只授權終止下方列出的程序；若之後有新的程序重新取得占用，工具會再次詢問，不會沿用本次授權。\n"
			lockPrompt += "\n⚠ 強制終止會立即結束程序及其所有執行緒。未儲存的工作可能遺失。\n"
			lockPrompt += "系統 Critical process 與 Windows Service 不會由本工具強制終止。\n\n"
			if len(req.lockers) > 0 {
				lockPrompt += fmt.Sprintf("目前辨識到 %d 個占用程序：\n", len(req.lockers))
				eligible := false
				for i, l := range req.lockers {
					if i >= 8 {
						lockPrompt += fmt.Sprintf("  ……另有 %d 個\n", len(req.lockers)-8)
						break
					}
					label := l.name
					if label == "" {
						label = "未知程序"
					}
					lockPrompt += fmt.Sprintf("  • 程序：%s\n    PID：%d", label, l.pid)
					if l.imagePath != "" && !strings.EqualFold(displayPath(l.imagePath), label) {
						lockPrompt += "\n    路徑：" + displayPath(l.imagePath)
					}
					if l.source != "" {
						lockPrompt += "\n    辨識來源：" + l.source
					}
					if l.desktopShell {
						lockPrompt += "\n    身分：Windows Desktop Shell"
						lockPrompt += "\n    處理方式：終止後自動重新啟動 Explorer"
					} else if isExplorerProcess(l) && !l.desktopShellKnown {
						lockPrompt += "\n    身分：Explorer（Desktop Shell 狀態暫時無法確認）"
						lockPrompt += "\n    處理方式：終止後重新檢查並在需要時恢復 Desktop Shell"
					}
					if canForceTerminateLocker(l) {
						lockPrompt += "\n    強制處理：可"
						eligible = true
					} else {
						lockPrompt += "\n    強制處理：不可（" + forceTerminationBlockReason(l) + "）"
					}
					lockPrompt += "\n"
				}
				if !eligible {
					lockPrompt += "\n目前辨識到的占用程序皆不符合安全強制終止條件。\n"
				}
			} else {
				lockPrompt += "目前無法辨識占用程序名稱與 PID。\n"
			}
			// Internal Restart Manager registry failures are deliberately not shown
			// here; the user needs an actionable owner, not implementation noise.
			lockPrompt += "\n"
			allLockersVisible := len(req.lockers) > 0 && len(req.lockers) <= 8
			if allLockersVisible && hasForceEligibleLockers(req.lockers) {
				lockPrompt += "選「是」＝僅強制終止上方列出的占用程序並重試永久刪除。\n選「否」＝保留檔案並結束本次操作。"
				if msgBox(a.hwnd, appTitle, lockPrompt, MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2) == IDYES {
					a.continueForceDelete(req)
				} else {
					a.resultQueue <- req.result
					pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
				}
			} else {
				if len(req.lockers) > 8 {
					lockPrompt += "占用程序數量超過目前一次確認可安全列出的上限（8 個），因此本次不執行強制終止；請縮小刪除範圍後再試。\n"
				} else {
					lockPrompt += "目前辨識到的占用程序皆不符合安全強制終止條件，因此本次刪除已停止，檔案保留。\n"
				}
				msgBox(a.hwnd, appTitle, lockPrompt, MB_OK|MB_ICONWARNING)
				a.resultQueue <- req.result
				pPostMessageW.Call(uintptr(a.hwnd), WM_APP_DELETE_DONE, 0, 0)
			}
		default:
		}

	case WM_APP_DELETE_DONE:
		select {
		case result := <-a.resultQueue:
			// Reconcile using the result's original targets. Errors are kept visible.
			a.finishDeleteMessage(result)
			if cancellationRequested() {
				pDestroyWindow.Call(uintptr(hwnd))
			}
		default:
		}

	case WM_CTLCOLORLISTBOX:
		hdc := HDC(wParam)
		pSetBkColor.Call(uintptr(hdc), uintptr(rgb(cListBg)))
		pSetTextColor.Call(uintptr(hdc), uintptr(rgb(cText)))
		pSetBkMode.Call(uintptr(hdc), TRANSPARENT)
		return uintptr(a.hBrushList)

	case WM_CTLCOLORSTATIC:
		hdc := HDC(wParam)
		pSetBkColor.Call(uintptr(hdc), uintptr(rgb(cBg)))
		if HWND(lParam) == a.hwndLink {
			pSetTextColor.Call(uintptr(hdc), uintptr(rgb(cLink)))
		} else {
			pSetTextColor.Call(uintptr(hdc), uintptr(rgb(cSubText)))
		}
		pSetBkMode.Call(uintptr(hdc), TRANSPARENT)
		return uintptr(a.hBrushBg)

	case WM_GETMINMAXINFO:
		mi := (*MINMAXINFO)(unsafe.Pointer(lParam))
		mi.PtMinTrackSize = POINT{X: initialWindowW, Y: initialWindowH}

	case WM_CLOSE:
		if atomic.LoadInt32(&a.busy) != 0 {
			atomic.StoreInt32(&a.cancelRequested, 1)
			pSetWindowTextW.Call(uintptr(a.hwndStatus), uintptr(unsafe.Pointer(u16("正在停止目前刪除作業；完成目前 Windows 呼叫後會停止後續處理…"))))
			return 0
		}
		pDestroyWindow.Call(uintptr(hwnd))

	case WM_DESTROY:
		pPostQuitMessage.Call(0)

	default:
		r, _, _ := pDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
		return r
	}
	return 0
}

// ══════════════════════════════════════════════════════════════════
// 刪除完成 UI
// ══════════════════════════════════════════════════════════════════

func (a *App) finishDeleteMessage(result deleteResult) {
	atomic.StoreInt32(&a.busy, 0)
	a.setControlsEnabled(true)

	var confirmedMissing []string
	for _, p := range result.targets {
		deleted, _ := verifyDeleted(p)
		if deleted {
			confirmedMissing = append(confirmedMissing, p)
		}
	}
	if len(confirmedMissing) > 0 {
		a.removePaths(confirmedMissing)
	} else {
		a.rebuildList()
	}

	if result.failed == 0 && result.success+result.missing == result.total && len(result.warnings) == 0 && len(result.errors) == 0 {
		msgBox(a.hwnd, appTitle, fmt.Sprintf("已完成：%d 個路徑已永久刪除。\n\n這些項目未移至資源回收筒。", result.success), MB_OK)
		return
	}

	msg := fmt.Sprintf("永久刪除作業完成：成功 %d · 已不存在 %d · 失敗 %d。", result.success, result.missing, result.failed)
	if len(result.warnings) > 0 {
		msg += "\n\n注意：\n"
		for _, w := range result.warnings {
			msg += fmt.Sprintf("• %s\n", w)
		}
	}
	if len(result.errors) > 0 {
		msg += "\n\n失敗範例：\n"
		for i, e := range result.errors {
			if i >= 5 {
				msg += fmt.Sprintf("… 另有 %d 個錯誤。\n", len(result.errors)-5)
				break
			}
			msg += fmt.Sprintf("• %s\n  %v\n", displayPath(e.path), e.err)
		}
	}
	msgBox(a.hwnd, appTitle, msg, MB_OK|MB_ICONWARNING)
	a.rebuildList()
}

// ══════════════════════════════════════════════════════════════════
// 建立子控件
// ══════════════════════════════════════════════════════════════════

func (a *App) createControls() {
	const (
		btnStyle    = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON
		listStyle   = WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | WS_BORDER | LBS_NOTIFY | LBS_EXTENDEDSEL | LBS_HASSTRINGS | LBS_NOINTEGRALHEIGHT
		staticStyle = WS_CHILD | WS_VISIBLE | SS_LEFT
	)

	a.hwndBtnAdd = newControl("BUTTON", "加入檔案…", btnStyle, 0, a.hwnd, idBtnAdd)
	a.hwndBtnDir = newControl("BUTTON", "加入資料夾…", btnStyle, 0, a.hwnd, idBtnAddDir)
	a.hwndBtnRemove = newControl("BUTTON", "移除所選項目", btnStyle, 0, a.hwnd, idBtnRemove)
	a.hwndBtnClear = newControl("BUTTON", clearAllText, btnStyle, 0, a.hwnd, idBtnClear)
	a.hwndBtnRename = newControl("BUTTON", "檔案更名", btnStyle, 0, a.hwnd, idBtnRename)
	a.hwndBtnRescue = newControl("BUTTON", "資料夾救援", btnStyle, 0, a.hwnd, idBtnRescue)
	a.hwndBtnDelete = newControl("BUTTON", "永久刪除", btnStyle, 0, a.hwnd, idBtnDelete)
	a.hwndList = newControl("LISTBOX", "", listStyle, WS_EX_CLIENTEDGE, a.hwnd, idListBox)
	installListWndProc(a.hwndList)
	a.hwndStatus = newControl("STATIC", "", staticStyle, 0, a.hwnd, idStatus)
	a.hwndLink = newControl("STATIC", threadsLinkText, linkControlStyle, 0, a.hwnd, idLink)

	for _, h := range []HWND{
		a.hwndBtnAdd, a.hwndBtnDir, a.hwndBtnRename, a.hwndBtnRescue,
		a.hwndBtnRemove, a.hwndBtnClear, a.hwndBtnDelete,
	} {
		sendFont(h, a.hFont)
	}
	sendFont(a.hwndList, a.hFontMono)
	sendFont(a.hwndStatus, a.hFontSm)
	gApp.hFontLink = makeFontWithUnderline(11, FW_NORMAL, "Segoe UI", false, true)
	sendFont(a.hwndLink, a.hFontLink)
}

// ══════════════════════════════════════════════════════════════════
// main
// ══════════════════════════════════════════════════════════════════

func main() {
	// Restrict implicit DLL loading to the Windows System32 directory before any
	// non-KnownDLL helper (notably Restart Manager) can be resolved.
	const loadLibrarySearchSystem32 = 0x00000800
	if r, _, e := pSetDefaultDllDirectories.Call(loadLibrarySearchSystem32); r == 0 {
		msgBox(0, appTitle, "無法啟用安全 DLL 搜尋路徑。\n\n"+win32Error(procError(e)).Error(), MB_OK|MB_ICONERROR)
		return
	}

	// The native handle scanner uses unsupported/low-level Windows handle APIs.
	// Run it in an isolated child process so an unexpected OS/API failure can
	// never tear down the GUI process that owns the user's state.
	if len(os.Args) >= 2 && os.Args[1] == "--scan-handles-child" {
		const maxHandleScanInput = 8 << 20
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxHandleScanInput+1))
		if err != nil || len(data) > maxHandleScanInput {
			os.Exit(2)
		}
		var scanPaths []string
		if err := json.Unmarshal(data, &scanPaths); err != nil {
			os.Exit(2)
		}
		debugChanged, _ := enableDebugPrivilege()
		if debugChanged {
			defer disableDebugPrivilege()
		}
		lockers, err := handleScanLockers(scanPaths)
		if err != nil {
			os.Exit(2)
		}
		wire := make([]lockProcessWire, 0, len(lockers))
		for _, l := range lockers {
			wire = append(wire, lockProcessWire{PID: l.pid, HandleValue: l.handleEvidence})
		}
		if err := json.NewEncoder(os.Stdout).Encode(wire); err != nil {
			os.Exit(2)
		}
		return
	}

	if acquired, err := acquireSingleInstance(); err != nil {
		msgBox(0, appTitle, "無法建立單一實例保護。\n\n"+err.Error(), MB_OK|MB_ICONERROR)
		return
	} else if !acquired {
		msgBox(0, appTitle, "OmniDeleter 已在目前 Windows 工作階段中執行。\n\n為避免同時操作同一批路徑，本次不會再啟動第二個執行個體。", MB_OK|MB_ICONWARNING)
		return
	}
	defer releaseSingleInstance()

	// Win32 windows, OLE, and their message queues are thread-affine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hrOle, _, _ := pOleInitialize.Call(0)
	if hresultFailed(hrOle) {
		msgBox(0, appTitle, "無法初始化 Windows OLE/COM。\n\n"+hresultError(hrOle).Error(), MB_OK|MB_ICONERROR)
		return
	}
	defer pOleUninitialize.Call()
	if format, _, _ := pRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(u16("Shell IDList Array")))); format != 0 {
		cfShellIDList = uint16(format)
	}

	r, _, _ := pGetModuleHandleW.Call(0)
	gApp.hInst = HINSTANCE(r)
	if err := protectOwnExecutable(); err != nil {
		msgBox(0, appTitle, "無法啟用自身執行檔保護。\n\n"+err.Error()+"\n\n為避免自替換風險，本次啟動已停止。", MB_OK|MB_ICONERROR)
		return
	}
	defer releaseOwnExecutable()
	gApp.resultQueue = make(chan deleteResult, 1)
	gApp.lockQueue = make(chan lockPromptRequest, 1)
	gApp.hFont = makeFont(14, FW_NORMAL, "Segoe UI", false)
	gApp.hFontSm = makeFont(11, FW_NORMAL, "Segoe UI", false)
	gApp.hFontMono = makeFont(12, FW_NORMAL, "Consolas", true)
	gApp.hBrushBg = HBRUSH(mustCreateBrush(cBg))
	gApp.hBrushList = HBRUSH(mustCreateBrush(cListBg))

	cursor, _, _ := pLoadCursorW.Call(0, 32512)
	className := u16("OmniDeleterClass")
	iconHandle, _, _ := pLoadIconW.Call(uintptr(gApp.hInst), uintptr(appIconResourceID))

	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:         0x0003,
		LpfnWndProc:   wndProcCallback,
		HInstance:     gApp.hInst,
		HIcon:         iconHandle,
		HCursor:       HCURSOR(cursor),
		HbrBackground: gApp.hBrushBg,
		LpszClassName: className,
		HIconSm:       iconHandle,
	}
	if reg, _, _ := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); reg == 0 {
		msgBox(0, appTitle, "無法註冊視窗類別。", MB_OK|MB_ICONERROR)
		return
	}

	hwnd, _, _ := pCreateWindowExW.Call(
		WS_EX_APPWINDOW|WS_EX_ACCEPTFILES|WS_EX_CONTROLPARENT,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(u16(appTitle))),
		WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
		100, 100, initialWindowW, initialWindowH,
		0, 0, uintptr(gApp.hInst), 0)
	if hwnd == 0 {
		cleanupGDI()
		msgBox(0, appTitle, "無法建立主視窗。", MB_OK|MB_ICONERROR)
		return
	}

	gApp.hwnd = HWND(hwnd)
	gApp.createControls()
	gApp.layout()
	gApp.updateStatus()

	// Keep WM_DROPFILES as a compatibility fallback, but use OLE IDropTarget
	// as the primary path because it can carry long paths via Shell IDList.
	pDragAcceptFiles.Call(uintptr(hwnd), 1)
	if err := registerOleDropTarget(HWND(hwnd)); err != nil {
		pSetWindowTextW.Call(uintptr(gApp.hwndStatus), uintptr(unsafe.Pointer(u16("OLE 長路徑拖曳初始化失敗；仍保留相容拖曳模式： "+err.Error()))))
	}
	pShowWindow.Call(uintptr(hwnd), SW_SHOW)
	pUpdateWindow.Call(uintptr(hwnd))

	var msg MSG
	for {
		ret, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	revokeOleDropTarget(HWND(hwnd))
	cleanupGDI()
}

func mustCreateBrush(c uint32) uintptr {
	b, _, _ := pCreateSolidBrush.Call(uintptr(rgb(c)))
	return b
}

func cleanupGDI() {
	for _, h := range []uintptr{
		uintptr(gApp.hFont), uintptr(gApp.hFontSm), uintptr(gApp.hFontMono), uintptr(gApp.hFontLink),
		uintptr(gApp.hBrushBg), uintptr(gApp.hBrushList),
	} {
		if h != 0 {
			pDeleteObject.Call(h)
		}
	}
}
