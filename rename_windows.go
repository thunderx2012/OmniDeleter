//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

const (
	fileRenameInfoClass = 3

	FILE_ADD_SUBDIRECTORY = 0x00000004

	WS_POPUP            = 0x80000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_EX_DLGMODALFRAME = 0x00000001
	WS_EX_WINDOWEDGE    = 0x00000100
	ES_LEFT             = 0x0000
	ES_AUTOHSCROLL      = 0x0080
	EM_SETSEL           = 0x00B1
	IDOK                = 1
	IDCANCEL            = 2
)

var (
	pCreateDirectoryW = kernel32.NewProc("CreateDirectoryW")
	pGetWindowTextW   = user32.NewProc("GetWindowTextW")
	pSetFocus         = user32.NewProc("SetFocus")
	pGetWindowRect    = user32.NewProc("GetWindowRect")
	pIsDialogMessageW = user32.NewProc("IsDialogMessageW")
)

type renameDialogState struct {
	hwnd     HWND
	edit     HWND
	accepted bool
	done     bool
	result   string
}

var activeRenameDialog *renameDialogState
var renameDialogWndProcCallback = syscall.NewCallback(renameDialogWndProc)

func validateNewFileName(name string) error {
	if name == "" {
		return errors.New("檔名不可為空白")
	}
	if name == "." || name == ".." {
		return errors.New("檔名不可為 . 或 ..")
	}
	if !utf8.ValidString(name) {
		return errors.New("檔名包含無效的 UTF-8 字元")
	}
	if utf16Len(name) > 255 {
		return errors.New("檔名超過 255 個 UTF-16 字元")
	}
	if strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") {
		return errors.New("檔名不可用空白或句點結尾")
	}
	const forbiddenNameChars = `<>:"/\|?*`
	for _, r := range name {
		if r == 0 || r < 0x20 || strings.ContainsRune(forbiddenNameChars, r) {
			return fmt.Errorf("檔名包含 Windows 不允許的字元：%q", r)
		}
	}

	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " .")
	upper := strings.ToUpper(base)
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return fmt.Errorf("%q 是 Windows 保留裝置名稱", base)
	}
	if len(base) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return fmt.Errorf("%q 是 Windows 保留裝置名稱", base)
	}
	return nil
}

func fileBaseName(path string) string {
	p := strings.TrimRight(displayPath(path), `\\`)
	if i := strings.LastIndexAny(p, `\\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func splitRenameName(name string) (stem, ext string) {
	// Keep the final extension outside the editable field. A leading dot is
	// treated as part of the base name rather than as an extension.
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[:i], name[i:]
	}
	return name, ""
}

func validateRenameTargetPath(path string) error {
	if err := validateTarget(path); err != nil {
		return err
	}
	attr, code := getAttributes(toOperationPath(path))
	if attr == INVALID_FILE_ATTRIBUTES {
		return win32Error(code)
	}
	if attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
		return errors.New("「檔案更名」只能處理單一檔案")
	}
	return nil
}

func openRenameSource(path string, isDir bool) (uintptr, error) {
	flags := uintptr(FILE_FLAG_OPEN_REPARSE_POINT)
	if isDir {
		flags |= FILE_FLAG_BACKUP_SEMANTICS
	}
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(toOperationPath(path)))),
		uintptr(DELETE_ACCESS|FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0, OPEN_EXISTING, flags, 0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0, win32Error(procError(e))
	}
	return h, nil
}

func openRenameParent(path string, access uint32) (uintptr, error) {
	op := toOperationPath(path)
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(access|FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0, OPEN_EXISTING,
		uintptr(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT),
		0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0, win32Error(procError(e))
	}
	return h, nil
}

type byHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       FILETIME
	LastAccessTime     FILETIME
	LastWriteTime      FILETIME
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

type objectIdentity struct {
	volumeSerial uint32
	fileIndexHi  uint32
	fileIndexLo  uint32
}

func fileInformationFromHandle(h uintptr) (byHandleFileInformation, error) {
	var info byHandleFileInformation
	r, _, e := pGetFileInformationByHandle.Call(h, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return byHandleFileInformation{}, win32Error(procError(e))
	}
	return info, nil
}

func objectIdentityFromFileInformation(info byHandleFileInformation) objectIdentity {
	return objectIdentity{
		volumeSerial: info.VolumeSerialNumber,
		fileIndexHi:  info.FileIndexHigh,
		fileIndexLo:  info.FileIndexLow,
	}
}

func objectIdentityFromHandle(h uintptr) (objectIdentity, error) {
	info, err := fileInformationFromHandle(h)
	if err != nil {
		return objectIdentity{}, err
	}
	return objectIdentityFromFileInformation(info), nil
}

func openIdentityPath(path string, isDir bool) (uintptr, error) {
	flags := uintptr(FILE_FLAG_OPEN_REPARSE_POINT)
	if isDir {
		flags |= FILE_FLAG_BACKUP_SEMANTICS
	}
	op := toOperationPath(path)
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
		0, OPEN_EXISTING, flags, 0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0, win32Error(procError(e))
	}
	return h, nil
}

func objectIdentityAtPath(path string, isDir bool) (objectIdentity, error) {
	h, err := openIdentityPath(path, isDir)
	if err != nil {
		return objectIdentity{}, err
	}
	defer pCloseHandle.Call(h)
	return objectIdentityFromHandle(h)
}

func sameObjectIdentity(a, b objectIdentity) bool {
	return a.volumeSerial == b.volumeSerial && a.fileIndexHi == b.fileIndexHi && a.fileIndexLo == b.fileIndexLo
}

type fileRenameInfoBase struct {
	ReplaceIfExists byte
	Reserved        [7]byte
	RootDirectory   uintptr
	FileNameLength  uint32
}

type fileRenameInfoBuffer struct {
	buffer          []byte
	name            []uint16
	replaceIfExists byte
}

func makeFileRenameInfo(destinationPath string) (*fileRenameInfoBuffer, error) {
	if destinationPath == "" {
		return nil, errors.New("更名目標名稱不可為空")
	}
	name16 := syscall.StringToUTF16(destinationPath)
	// FILE_RENAME_INFO has pointer-sized alignment on Win64, so sizeof(struct)
	// is 24 bytes, but the variable-length FileName member starts at byte 20
	// immediately after FileNameLength. Do not use sizeof(struct) as the
	// FileName offset.
	nameOffset := unsafe.Offsetof(fileRenameInfoBase{}.FileNameLength) + unsafe.Sizeof(uint32(0))
	// FileNameLength is the byte length of the name itself; the terminating
	// NUL is not part of the reported length and is not required in the
	// supplied buffer.
	nameUnits := len(name16) - 1
	buf := make([]byte, int(nameOffset)+nameUnits*2)
	base := (*fileRenameInfoBase)(unsafe.Pointer(&buf[0]))
	base.ReplaceIfExists = 0
	base.RootDirectory = 0
	base.FileNameLength = uint32(nameUnits * 2)
	namePtr := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + nameOffset)
	dst := unsafe.Slice((*uint16)(namePtr), nameUnits)
	copy(dst, name16[:nameUnits])
	return &fileRenameInfoBuffer{
		buffer:          buf,
		name:            append([]uint16(nil), name16[:nameUnits]...),
		replaceIfExists: base.ReplaceIfExists,
	}, nil
}

func renameByHandle(h uintptr, destinationPath string) error {
	info, err := makeFileRenameInfo(destinationPath)
	if err != nil {
		return err
	}
	r, _, e := pSetFileInformationByHandle.Call(
		h,
		fileRenameInfoClass,
		uintptr(unsafe.Pointer(&info.buffer[0])),
		uintptr(len(info.buffer)),
	)
	if r == 0 {
		return win32Error(procError(e))
	}
	return nil
}

func handleReachesPath(h uintptr, expected string) bool {
	got := finalPathFromHandle(h)
	if got == "" {
		return false
	}
	return canonicalComparePath(got) == canonicalComparePath(expected)
}

func waitForHandlePath(h uintptr, expected string, attempts int, delay time.Duration) bool {
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if handleReachesPath(h, expected) {
			return true
		}
		if i+1 < attempts && delay > 0 {
			time.Sleep(delay)
		}
	}
	return false
}

func renameSingleFile(oldPath, newName string) (string, error) {
	if err := validateRenameTargetPath(oldPath); err != nil {
		return "", err
	}
	if err := validateNewFileName(newName); err != nil {
		return "", err
	}

	parent := filepathDirDisplay(oldPath)
	newPath := makePathCandidate(parent, newName)
	if utf16Len(displayPath(newPath)) > windowsMaxExtendedPath {
		return "", fmt.Errorf("更名後路徑超過 Windows extended-length 上限 %d 個 UTF-16 字元", windowsMaxExtendedPath)
	}
	if state, code := pathStateOf(newPath); state == pathExists {
		return "", errors.New("目標名稱已存在，為避免覆蓋資料本次未執行")
	} else if state == pathUnknown {
		return "", win32Error(code)
	}

	src, err := openRenameSource(oldPath, false)
	if err != nil {
		return "", fmt.Errorf("來源檔案無法以更名所需權限開啟：%w", err)
	}
	defer pCloseHandle.Call(src)

	before, err := objectIdentityFromHandle(src)
	if err != nil {
		return "", fmt.Errorf("無法確認來源檔案身分：%w", err)
	}

	// Pass the fully-qualified operation path with RootDirectory == NULL. This
	// avoids the Win32 relative-name/current-directory resolution rules while
	// also working for extended-length paths and network paths.
	err = renameByHandle(src, toOperationPath(newPath))
	// A successful SetFileInformationByHandle call is the authoritative commit
	// result. Do not turn a transient post-commit observation failure into a
	// false rename failure: the caller must update the in-memory list immediately.
	if err == nil {
		return normalizeInputPath(newPath), nil
	}

	// Only an error return is ambiguous. In that case, use the still-open source
	// handle and the original object identity as conservative evidence that the
	// rename may nevertheless have committed. Never delete or overwrite anything
	// during this verification path.
	if waitForHandlePath(src, newPath, 8, 50*time.Millisecond) {
		return normalizeInputPath(newPath), nil
	}
	if identity, verifyErr := objectIdentityAtPath(newPath, false); verifyErr == nil {
		if sameObjectIdentity(before, identity) {
			return normalizeInputPath(newPath), nil
		}
	}
	return "", err
}

func filepathDirDisplay(path string) string {
	p := displayPath(normalizeInputPath(path))
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			if i == 2 && len(p) >= 3 && p[1] == ':' {
				return p[:3]
			}
			return strings.TrimRight(p[:i], `\\`)
		}
	}
	return "."
}

func registerRenameDialogClass() {
	className := u16("OmniDeleterRenameDialogClass")
	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:         0x0003,
		LpfnWndProc:   renameDialogWndProcCallback,
		HInstance:     gApp.hInst,
		HCursor:       HCURSOR(mustLoadCursor()),
		HbrBackground: gApp.hBrushBg,
		LpszClassName: className,
	}
	_, _, _ = pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
}

func mustLoadCursor() uintptr {
	c, _, _ := pLoadCursorW.Call(0, 32512)
	return c
}

func renameDialogWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	state := activeRenameDialog
	switch msg {
	case WM_COMMAND:
		id := int(wParam & 0xFFFF)
		switch id {
		case IDOK:
			if state == nil || state.edit == 0 {
				break
			}
			buf := make([]uint16, 256)
			n, _, _ := pGetWindowTextW.Call(uintptr(state.edit), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			name := syscall.UTF16ToString(buf[:n])
			if err := validateNewFileName(name); err != nil {
				msgBox(HWND(hwnd), appTitle, err.Error(), MB_OK|MB_ICONWARNING)
				pSetFocus.Call(uintptr(state.edit))
				return 0
			}
			state.result = name
			state.accepted = true
			state.done = true
			pDestroyWindow.Call(hwnd)
			return 0
		case IDCANCEL:
			if state != nil {
				state.accepted = false
				state.done = true
			}
			pDestroyWindow.Call(hwnd)
			return 0
		}
	case WM_CLOSE:
		if state != nil {
			state.accepted = false
			state.done = true
		}
		pDestroyWindow.Call(hwnd)
		return 0
	case WM_CTLCOLORSTATIC:
		hdc := HDC(wParam)
		pSetBkColor.Call(uintptr(hdc), uintptr(rgb(cBg)))
		pSetTextColor.Call(uintptr(hdc), uintptr(rgb(cSubText)))
		pSetBkMode.Call(uintptr(hdc), TRANSPARENT)
		return uintptr(gApp.hBrushBg)
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}

func promptFileRename(owner HWND, currentName string) (string, bool) {
	registerRenameDialogClass()
	state := &renameDialogState{}
	activeRenameDialog = state
	defer func() { activeRenameDialog = nil }()

	var ownerRect RECT
	pGetWindowRect.Call(uintptr(owner), uintptr(unsafe.Pointer(&ownerRect)))
	width, height := 440, 170
	x := int(ownerRect.Left) + (int(ownerRect.Right-ownerRect.Left)-width)/2
	y := int(ownerRect.Top) + (int(ownerRect.Bottom-ownerRect.Top)-height)/2

	className := u16("OmniDeleterRenameDialogClass")
	title := u16("檔案更名")
	hwnd, _, _ := pCreateWindowExW.Call(
		WS_EX_DLGMODALFRAME|WS_EX_WINDOWEDGE,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		WS_POPUP|WS_CAPTION|WS_SYSMENU,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		uintptr(owner), 0, uintptr(gApp.hInst), 0,
	)
	if hwnd == 0 {
		return "", false
	}
	state.hwnd = HWND(hwnd)
	pEnableWindow.Call(uintptr(owner), 0)
	defer pEnableWindow.Call(uintptr(owner), 1)

	newControlChild := func(class, text string, style, exStyle uint32, id int, cx, cy, cw, ch int) HWND {
		h, _, _ := pCreateWindowExW.Call(
			uintptr(exStyle), uintptr(unsafe.Pointer(u16(class))), uintptr(unsafe.Pointer(u16(text))),
			uintptr(style), uintptr(cx), uintptr(cy), uintptr(cw), uintptr(ch),
			hwnd, uintptr(id), uintptr(gApp.hInst), 0)
		return HWND(h)
	}

	static := newControlChild("STATIC", "新檔案名稱：", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 18, 20, 110, 24)
	state.edit = newControlChild("EDIT", currentName, WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_LEFT|ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, 100, 18, 48, 380, 28)
	ok := newControlChild("BUTTON", "確定", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, IDOK, 260, 96, 80, 30)
	cancel := newControlChild("BUTTON", "取消", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, IDCANCEL, 350, 96, 80, 30)
	_ = static
	sendFont(static, gApp.hFontSm)
	sendFont(state.edit, gApp.hFont)
	sendFont(ok, gApp.hFont)
	sendFont(cancel, gApp.hFont)

	pShowWindow.Call(hwnd, SW_SHOW)
	pUpdateWindow.Call(hwnd)
	pSetFocus.Call(uintptr(state.edit))
	pSendMessageW.Call(uintptr(state.edit), EM_SETSEL, 0, ^uintptr(0))

	for !state.done {
		var msg MSG
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) == -1 || r == 0 {
			state.done = true
			state.accepted = false
			break
		}
		handled, _, _ := pIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&msg)))
		if handled != 0 {
			continue
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	return state.result, state.accepted
}
