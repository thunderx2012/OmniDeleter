//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Desktop Shell-aware Explorer recovery. The target Explorer token is captured
// before termination, then explorer.exe is recreated with the same user token.
// This prevents an elevated OmniDeleter from accidentally creating an elevated
// Explorer shell and prevents the desktop/taskbar from being left missing.

const (
	shellDesktopName         = `winsta0\default`
	shellTokenDuplicate      = 0x0002
	shellTokenAssignPrimary  = 0x0001
	shellTokenQuery          = 0x0008
	securityImpersonation    = 2
	tokenPrimary             = 1
	createUnicodeEnvironment = 0x00000400
	startupfUseShowWindow    = 0x00000001
	swShowShell              = 5
)

type securityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      int32
}

type startupInfoW struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	Reserved2     *byte
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
}

type processInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessID uint32
	ThreadID  uint32
}

var (
	user32Shell   = syscall.NewLazyDLL("user32.dll")
	advapi32Shell = syscall.NewLazyDLL("advapi32.dll")
	userenvShell  = syscall.NewLazyDLL("userenv.dll")

	pGetShellWindow               = user32Shell.NewProc("GetShellWindow")
	pEnumWindows                  = user32Shell.NewProc("EnumWindows")
	pGetClassNameW                = user32Shell.NewProc("GetClassNameW")
	pFindWindowW                  = user32Shell.NewProc("FindWindowW")
	pGetWindowThreadProcess       = user32Shell.NewProc("GetWindowThreadProcessId")
	pDuplicateTokenExShell        = advapi32Shell.NewProc("DuplicateTokenEx")
	pCreateProcessWithToken       = advapi32Shell.NewProc("CreateProcessWithTokenW")
	pOpenProcessTokenShell        = advapi32Shell.NewProc("OpenProcessToken")
	pGetTokenInformationShell     = advapi32Shell.NewProc("GetTokenInformation")
	pLookupPrivilegeValueShell    = advapi32Shell.NewProc("LookupPrivilegeValueW")
	pAdjustTokenPrivilegesShell   = advapi32Shell.NewProc("AdjustTokenPrivileges")
	pCreateEnvironmentBlockShell  = userenvShell.NewProc("CreateEnvironmentBlock")
	pDestroyEnvironmentBlockShell = userenvShell.NewProc("DestroyEnvironmentBlock")
	pGetSystemWindowsDirectory    = kernel32.NewProc("GetSystemWindowsDirectoryW")
)

func processIDFromWindow(hwnd uintptr) uint32 {
	if hwnd == 0 {
		return 0
	}
	var pid uint32
	pGetWindowThreadProcess.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	return pid
}

func desktopShellPID() uint32 {
	// Primary authoritative shell handle.
	if hwnd, _, _ := pGetShellWindow.Call(); hwnd != 0 {
		if pid := processIDFromWindow(hwnd); pid != 0 {
			return pid
		}
	}

	// The main taskbar and secondary-monitor taskbar are strong shell anchors.
	for _, className := range []string{"Shell_TrayWnd", "Shell_SecondaryTrayWnd"} {
		cn := u16(className)
		if hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cn)), 0); hwnd != 0 {
			if pid := processIDFromWindow(hwnd); pid != 0 {
				return pid
			}
		}
		if pid := enumTopLevelWindowPIDByClass(className); pid != 0 {
			return pid
		}
	}

	currentSID, sidKnown := currentSessionID()
	if !sidKnown {
		return 0
	}

	// Desktop hosts used by Explorer can expose Progman / WorkerW during shell
	// transitions. Only accept an explorer.exe owner in the current session.
	for _, className := range []string{"Progman", "WorkerW"} {
		cn := u16(className)
		var pid uint32
		if hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cn)), 0); hwnd != 0 {
			pid = processIDFromWindow(hwnd)
		} else {
			pid = enumTopLevelWindowPIDByClass(className)
		}
		if pid != 0 {
			if sid, ok := processSessionID(pid); ok && sid == currentSID && strings.EqualFold(processSnapshotName(pid), "explorer.exe") {
				return pid
			}
		}
	}

	// Final fallback: one and only one explorer.exe in the current interactive
	// session is the only plausible shell host. Multiple Explorer processes stay
	// ambiguous, but that ambiguity is no longer a reason to block an exact,
	// same-session Explorer locker from being processed; force termination captures
	// its token and the post-delete shell recovery checks the actual shell again.
	return uniqueExplorerPIDForSession(currentSID)
}

var enumWindowScanMu sync.Mutex
var enumWindowScanWant string
var enumWindowScanFound uint32
var enumWindowScanCallback = syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
	var buf [256]uint16
	n, _, _ := pGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || strings.ToLower(syscall.UTF16ToString(buf[:n])) != enumWindowScanWant {
		return 1
	}
	if pid := processIDFromWindow(hwnd); pid != 0 {
		enumWindowScanFound = pid
		return 0
	}
	return 1
})

func enumTopLevelWindowPIDByClass(className string) uint32 {
	want := strings.ToLower(strings.TrimSpace(className))
	if want == "" {
		return 0
	}
	enumWindowScanMu.Lock()
	defer enumWindowScanMu.Unlock()
	enumWindowScanWant = want
	enumWindowScanFound = 0
	pEnumWindows.Call(enumWindowScanCallback, 0)
	found := enumWindowScanFound
	enumWindowScanWant = ""
	enumWindowScanFound = 0
	return found
}

func isDesktopShellPID(pid uint32) (bool, bool) {
	if pid == 0 {
		return false, true
	}
	shellPID := desktopShellPID()
	if shellPID == 0 {
		return false, false
	}
	return shellPID == pid, true
}

func uniqueExplorerPIDForSession(sessionID uint32) uint32 {
	const th32csSnapProcess = 0x00000002
	const invalidSnapshot = ^uintptr(0)
	snap, _, _ := pCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == invalidSnapshot {
		return 0
	}
	defer pCloseHandle.Call(snap)
	entry := processEntry32W{Size: uint32(unsafe.Sizeof(processEntry32W{}))}
	r, _, _ := pProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return 0
	}
	var candidate uint32
	for {
		if strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), "explorer.exe") {
			if sid, ok := processSessionID(entry.ProcessID); ok && sid == sessionID {
				if candidate != 0 && candidate != entry.ProcessID {
					return 0
				}
				candidate = entry.ProcessID
			}
		}
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return candidate
}

func systemWindowsDirectory() string {
	buf := make([]uint16, 512)
	n, _, _ := pGetSystemWindowsDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || n >= uintptr(len(buf)) {
		return ""
	}
	return strings.TrimRight(syscall.UTF16ToString(buf[:n]), `\\`)
}

func isSystemExplorerProcess(l lockProcess) bool {
	if !isExplorerProcess(l) {
		return false
	}
	root := systemWindowsDirectory()
	if root == "" || l.imagePath == "" {
		return false
	}
	return isSystemExplorerImagePath(l.imagePath, root)
}

func isSystemExplorerImagePath(imagePath, windowsRoot string) bool {
	imagePath = strings.TrimRight(displayPath(imagePath), `\`)
	windowsRoot = strings.TrimRight(displayPath(windowsRoot), `\`)
	if imagePath == "" || windowsRoot == "" {
		return false
	}
	return strings.EqualFold(imagePath, windowsRoot+`\explorer.exe`)
}

func shellPrivilegeEnabled(token uintptr, luid *struct {
	LowPart  uint32
	HighPart int32
}) (bool, error) {
	const tokenPrivilegesInfoClass = 3 // TokenPrivileges
	var needed uint32
	pGetTokenInformationShell.Call(token, tokenPrivilegesInfoClass, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 1<<20 {
		return false, errors.New("無法取得目前 token 的 privilege 資訊大小")
	}
	buf := make([]byte, int(needed))
	if r, _, e := pGetTokenInformationShell.Call(token, tokenPrivilegesInfoClass, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return false, fmt.Errorf("GetTokenInformation(TokenPrivileges) 失敗：%v", win32Error(procError(e)))
	}
	type luidAndAttributes struct {
		Luid struct {
			LowPart  uint32
			HighPart int32
		}
		Attributes uint32
	}
	const enabled = 0x00000002
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	stride := unsafe.Sizeof(luidAndAttributes{})
	maxCount := (uintptr(len(buf)) - unsafe.Sizeof(uint32(0))) / stride
	if uintptr(count) > maxCount {
		count = uint32(maxCount)
	}
	for i := uint32(0); i < count; i++ {
		entry := (*luidAndAttributes)(unsafe.Pointer(base + uintptr(i)*stride))
		if entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart {
			return entry.Attributes&enabled != 0, nil
		}
	}
	return false, nil
}

// ensureShellRecoveryPrivilege enables SeImpersonatePrivilege only when it is
// already present in the current token. The bool result is true only when this
// function changed the token state and therefore needs a matching disable.
func ensureShellRecoveryPrivilege() (bool, error) {
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	self, _, _ := getCurrentProcess.Call()
	if self == 0 {
		return false, errors.New("無法取得目前程序 handle")
	}
	const tokenAdjustPrivilegesShell = 0x00000020
	const tokenQueryShell = 0x00000008
	var token uintptr
	if r, _, e := pOpenProcessTokenShell.Call(self, tokenAdjustPrivilegesShell|tokenQueryShell, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false, fmt.Errorf("OpenProcessToken 失敗：%v", win32Error(procError(e)))
	}
	defer pCloseHandle.Call(token)

	name := u16("SeImpersonatePrivilege")
	var luid struct {
		LowPart  uint32
		HighPart int32
	}
	if r, _, e := pLookupPrivilegeValueShell.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid))); r == 0 {
		return false, fmt.Errorf("LookupPrivilegeValue(SeImpersonatePrivilege) 失敗：%v", win32Error(procError(e)))
	}
	alreadyEnabled, err := shellPrivilegeEnabled(token, &luid)
	if err != nil {
		return false, err
	}
	if alreadyEnabled {
		return false, nil
	}

	type luidAndAttributes struct {
		Luid struct {
			LowPart  uint32
			HighPart int32
		}
		Attributes uint32
	}
	type tokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     luidAndAttributes
	}
	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: luidAndAttributes{
			Luid:       luid,
			Attributes: 0x00000002, // SE_PRIVILEGE_ENABLED
		},
	}
	r, _, adjustErr := pAdjustTokenPrivilegesShell.Call(token, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return false, fmt.Errorf("AdjustTokenPrivileges 失敗：%v", win32Error(procError(adjustErr)))
	}
	// AdjustTokenPrivileges may return nonzero while GetLastError from that
	// exact call is ERROR_NOT_ALL_ASSIGNED. Preserve that exact error value.
	if code := procError(adjustErr); code != ERROR_SUCCESS {
		return false, fmt.Errorf("目前程序沒有可用的 SeImpersonatePrivilege（Win32 %d）", code)
	}
	return true, nil
}

func disableShellRecoveryPrivilege() error {
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	self, _, _ := getCurrentProcess.Call()
	if self == 0 {
		return errors.New("無法取得目前程序 handle")
	}
	const tokenAdjustPrivilegesShell = 0x00000020
	const tokenQueryShell = 0x00000008
	var token uintptr
	if r, _, e := pOpenProcessTokenShell.Call(self, tokenAdjustPrivilegesShell|tokenQueryShell, uintptr(unsafe.Pointer(&token))); r == 0 {
		return fmt.Errorf("OpenProcessToken 失敗：%v", win32Error(procError(e)))
	}
	defer pCloseHandle.Call(token)

	name := u16("SeImpersonatePrivilege")
	var luid struct {
		LowPart  uint32
		HighPart int32
	}
	if r, _, e := pLookupPrivilegeValueShell.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid))); r == 0 {
		return fmt.Errorf("LookupPrivilegeValue(SeImpersonatePrivilege) 失敗：%v", win32Error(procError(e)))
	}
	type luidAndAttributes struct {
		Luid struct {
			LowPart  uint32
			HighPart int32
		}
		Attributes uint32
	}
	type tokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     luidAndAttributes
	}
	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: luidAndAttributes{
			Luid:       luid,
			Attributes: 0,
		},
	}
	r, _, adjustErr := pAdjustTokenPrivilegesShell.Call(token, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("停用 SeImpersonatePrivilege 失敗：%v", win32Error(procError(adjustErr)))
	}
	if code := procError(adjustErr); code != ERROR_SUCCESS {
		return fmt.Errorf("停用 SeImpersonatePrivilege 失敗（Win32 %d）", code)
	}
	return nil
}

func duplicatePrimaryUserToken(processHandle uintptr) (uintptr, error) {
	if processHandle == 0 || processHandle == INVALID_HANDLE_VALUE {
		return 0, errors.New("無效的 Explorer 程序 handle")
	}
	desired := uintptr(shellTokenDuplicate | shellTokenAssignPrimary | shellTokenQuery)
	var sourceToken uintptr
	r, _, e := pOpenProcessTokenShell.Call(processHandle, desired, uintptr(unsafe.Pointer(&sourceToken)))
	if r == 0 {
		return 0, fmt.Errorf("OpenProcessToken 失敗：%v", win32Error(procError(e)))
	}
	defer pCloseHandle.Call(sourceToken)

	var primary uintptr
	var sa securityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	r, _, e = pDuplicateTokenExShell.Call(
		sourceToken,
		desired,
		uintptr(unsafe.Pointer(&sa)),
		securityImpersonation,
		tokenPrimary,
		uintptr(unsafe.Pointer(&primary)),
	)
	if r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx 失敗：%v", win32Error(procError(e)))
	}
	return primary, nil
}

func launchExplorerWithToken(token uintptr) error {
	if token == 0 || token == INVALID_HANDLE_VALUE {
		return errors.New("無效的 Explorer 使用者 token")
	}
	windir := systemWindowsDirectory()
	if windir == "" {
		return errors.New("無法取得 Windows 系統目錄")
	}
	exe := windir + `\explorer.exe`
	app := u16(exe)
	cmd := syscall.StringToUTF16(exe)
	desktop := u16(shellDesktopName)
	si := startupInfoW{Cb: uint32(unsafe.Sizeof(startupInfoW{})), Desktop: desktop, Flags: startupfUseShowWindow, ShowWindow: swShowShell}
	var environment uintptr
	if r, _, e := pCreateEnvironmentBlockShell.Call(uintptr(unsafe.Pointer(&environment)), token, 0); r == 0 || environment == 0 {
		return fmt.Errorf("CreateEnvironmentBlock 失敗：%v", win32Error(procError(e)))
	}
	defer pDestroyEnvironmentBlockShell.Call(environment)
	var pi processInformation
	r, _, e := pCreateProcessWithToken.Call(
		token,
		0,
		uintptr(unsafe.Pointer(app)),
		uintptr(unsafe.Pointer(&cmd[0])),
		createUnicodeEnvironment,
		environment,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW 失敗：%v", win32Error(procError(e)))
	}
	runtime.KeepAlive(desktop)
	if pi.Thread != 0 {
		pCloseHandle.Call(pi.Thread)
	}
	if pi.Process != 0 {
		pCloseHandle.Call(pi.Process)
	}
	return nil
}

func restoreDesktopShell(token uintptr, terminatedPID uint32) error {
	if token == 0 || token == INVALID_HANDLE_VALUE {
		return errors.New("沒有可用的 Explorer 使用者 token")
	}

	// Never launch a replacement shell until the terminated Explorer PID is
	// confirmed to be fully exited. Otherwise a slow termination could create a
	// duplicate Explorer shell and make the recovery state ambiguous.
	if terminatedPID != 0 {
		h, _, openErr := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(terminatedPID))
		if h != 0 && h != INVALID_HANDLE_VALUE {
			exited, exitCode, known := processExitState(h)
			pCloseHandle.Call(h)
			if !known || !exited || exitCode == STILL_ACTIVE {
				return errors.New("原 Explorer 程序尚未確認完全終止，拒絕啟動第二個 Desktop Shell")
			}
		} else if code := procError(openErr); code != ERROR_INVALID_PARAMETER {
			return fmt.Errorf("無法確認原 Explorer 程序已完全終止（Win32 %d），拒絕啟動第二個 Desktop Shell", code)
		}
	}

	targetIdentity, tokenOK := tokenIdentityFromToken(token)
	if !tokenOK || !targetIdentity.known() {
		return errors.New("無法驗證保存的 Explorer 使用者 token 身分")
	}

	validShell := func() (uint32, bool) {
		pid := desktopShellPID()
		if pid == 0 || pid == terminatedPID {
			return 0, false
		}
		h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(pid))
		if h == 0 || h == INVALID_HANDLE_VALUE {
			return 0, false
		}
		defer pCloseHandle.Call(h)
		path := processImagePath(h)
		if !isSystemExplorerImagePath(path, systemWindowsDirectory()) {
			return 0, false
		}
		identity, ok := tokenIdentityFromHandle(h)
		if !ok || !identity.known() {
			return 0, false
		}
		if identity.sessionID != targetIdentity.sessionID ||
			!strings.EqualFold(identity.sid, targetIdentity.sid) ||
			!sameAuthenticationID(identity, targetIdentity) {
			return 0, false
		}
		return pid, true
	}

	// Windows may restart Explorer itself after a shell exit. If a correct shell
	// already exists, do not create another copy. A wrong-user shell is never
	// accepted as proof of recovery.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := validShell(); ok {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	if pid := desktopShellPID(); pid != 0 && pid != terminatedPID {
		// A shell exists, but it does not match the token we deliberately captured.
		// Do not start a duplicate Explorer process.
		return errors.New("目前已有 Explorer Desktop Shell，但無法確認與原使用者登入身分一致；拒絕建立第二個 Shell")
	}

	if err := launchExplorerWithToken(token); err != nil {
		return err
	}
	deadline = time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := validShell(); ok {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("Explorer 已終止，但 Windows Desktop Shell 在逾時前未恢復到原使用者登入身分")
}
