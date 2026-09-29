//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	rmMaxAppName = 255
	rmMaxSvcName = 63
	rmSessionKey = 32

	rmUnknownApp  = 0
	rmServiceApp  = 3
	rmCriticalApp = 1000

	PROCESS_TERMINATE                 = 0x0001
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	SYNCHRONIZE                       = 0x00100000
	WAIT_OBJECT_0                     = 0x00000000
	WAIT_TIMEOUT                      = 0x00000102
	WAIT_FAILED                       = 0xFFFFFFFF
	STILL_ACTIVE                      = 259
)

type RM_UNIQUE_PROCESS struct {
	ProcessID        uint32
	ProcessStartTime FILETIME
}

type RM_PROCESS_INFO struct {
	Process          RM_UNIQUE_PROCESS
	AppName          [rmMaxAppName + 1]uint16
	ServiceShortName [rmMaxSvcName + 1]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

type lockProcess struct {
	name              string
	source            string
	imagePath         string
	pid               uint32
	kind              uint32
	startTime         FILETIME
	startKnown        bool
	sessionID         uint32
	sessionKnown      bool
	critical          bool
	criticalKnown     bool
	protected         bool
	protectedKnown    bool
	serviceAccount    bool
	serviceKnown      bool
	serviceProcess    bool
	serviceProcKnown  bool
	userSID           string
	userSIDKnown      bool
	authLow           uint32
	authHigh          int32
	authKnown         bool
	desktopShell      bool
	desktopShellKnown bool
	// handleEvidence is populated only by the isolated system-handle scanner.
	// The parent revalidates this exact remote handle before accepting its PID.
	handleEvidence uintptr
}

var (
	rstrtmgr             = syscall.NewLazyDLL("rstrtmgr.dll")
	pRmStartSession      = rstrtmgr.NewProc("RmStartSession")
	pRmRegisterResources = rstrtmgr.NewProc("RmRegisterResources")
	pRmGetList           = rstrtmgr.NewProc("RmGetList")
	pRmEndSession        = rstrtmgr.NewProc("RmEndSession")

	pOpenProcess               = kernel32.NewProc("OpenProcess")
	pTerminateProcess          = kernel32.NewProc("TerminateProcess")
	pWaitForSingleObject       = kernel32.NewProc("WaitForSingleObject")
	pGetProcessTimes           = kernel32.NewProc("GetProcessTimes")
	pGetExitCodeProcess        = kernel32.NewProc("GetExitCodeProcess")
	pQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	pGetShortPathName          = kernel32.NewProc("GetShortPathNameW")
	pCreateToolhelp32Snapshot  = kernel32.NewProc("CreateToolhelp32Snapshot")
	pProcess32FirstW           = kernel32.NewProc("Process32FirstW")
	pProcess32NextW            = kernel32.NewProc("Process32NextW")
)

func shortPathForRM(path string) string {
	// Restart Manager's resource registration is more reliable with a legacy
	// DOS path when the long path has an available 8.3 alias. This is only a
	// best-effort extra resource name; the canonical path is still registered.
	op := toOperationPath(path)
	bufLen := uint32(windowsMaxExtendedPath + 1)
	buf := make([]uint16, bufLen)
	r, _, _ := pGetShortPathName.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufLen),
	)
	if r == 0 || r >= uintptr(len(buf)) {
		return ""
	}
	return displayPath(syscall.UTF16ToString(buf[:r]))
}

func restartManagerSupportsPath(path string) bool {
	// Restart Manager stores registrations in its own registry-backed session.
	// Very long paths are a poor fit for that mechanism and have repeatedly
	// produced ERROR_WRITE_FAULT on the target scenario, so long paths go
	// directly to the isolated native handle scanner instead.
	return pathDisplayLength(path) <= windowsMaxPath-1
}

func filterRestartManagerPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths)*2)
	for _, p := range paths {
		// Ordinary paths can use their readable DOS path. Long paths should not be
		// registered directly because Restart Manager may fail with ERROR_WRITE_FAULT
		// for registry-backed resource registration. If an 8.3 alias exists, however,
		// that short path is a useful, independent way to identify the same file.
		if restartManagerSupportsPath(p) {
			candidate := displayPath(p)
			key := strings.ToLower(candidate)
			if candidate != "" {
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					out = append(out, p)
				}
			}
			continue
		}
		if short := shortPathForRM(p); short != "" && utf16Len(short) <= windowsMaxPath-1 {
			key := strings.ToLower(short)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				// Keep the original path in the list. restartManagerSession will add
				// the short alias when constructing its actual registration payload.
				out = append(out, p)
			}
		}
	}
	return out
}

func restartManagerSession(paths []string) (uint32, error) {
	if len(paths) == 0 {
		return 0, errors.New("沒有可註冊的路徑")
	}
	var session uint32
	key := make([]uint16, rmSessionKey+1)
	rc, _, _ := pRmStartSession.Call(uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0])))
	if uint32(rc) != ERROR_SUCCESS {
		return 0, fmt.Errorf("Restart Manager 啟動失敗：Win32 error %d", uint32(rc))
	}

	resourcePaths := make([]string, 0, len(paths)*2)
	seen := make(map[string]struct{}, len(paths)*2)
	for _, path := range paths {
		candidates := make([]string, 0, 2)
		if restartManagerSupportsPath(path) {
			candidates = append(candidates, displayPath(path))
		}
		if short := shortPathForRM(path); short != "" && utf16Len(short) <= windowsMaxPath-1 {
			candidates = append(candidates, short)
		}
		for _, candidate := range candidates {
			candidate = strings.TrimRight(candidate, `\\`)
			key := strings.ToLower(candidate)
			if candidate == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			resourcePaths = append(resourcePaths, candidate)
		}
	}
	if len(resourcePaths) == 0 {
		pRmEndSession.Call(uintptr(session))
		return 0, errors.New("沒有可註冊的有效路徑")
	}

	ptrs := make([]uintptr, 0, len(resourcePaths))
	keep := make([]*uint16, 0, len(resourcePaths))
	for _, path := range resourcePaths {
		p := u16(path)
		keep = append(keep, p)
		ptrs = append(ptrs, uintptr(unsafe.Pointer(p)))
	}
	rc, _, _ = pRmRegisterResources.Call(
		uintptr(session), uintptr(len(ptrs)), uintptr(unsafe.Pointer(&ptrs[0])), 0, 0, 0, 0,
	)
	if uint32(rc) != ERROR_SUCCESS {
		pRmEndSession.Call(uintptr(session))
		return 0, fmt.Errorf("Restart Manager 註冊檔案失敗：Win32 error %d", uint32(rc))
	}
	runtime.KeepAlive(keep)
	return session, nil
}

func processImagePath(h uintptr) string {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return ""
	}
	buf := make([]uint16, windowsMaxExtendedPath+1)
	size := uint32(len(buf))
	r, _, _ := pQueryFullProcessImageName.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func processStartTime(h uintptr) (FILETIME, bool) {
	var creation, exit, kernel, user FILETIME
	r, _, _ := pGetProcessTimes.Call(
		h,
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return FILETIME{}, false
	}
	return creation, true
}

func sameFileTime(a, b FILETIME) bool {
	return a.LowDateTime == b.LowDateTime && a.HighDateTime == b.HighDateTime
}

func restartManagerLockers(paths []string) ([]lockProcess, error) {
	session, err := restartManagerSession(paths)
	if err != nil {
		return nil, err
	}
	defer pRmEndSession.Call(uintptr(session))

	var needed uint32
	var count uint32
	var reasons uint32
	rc, _, _ := pRmGetList.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(unsafe.Pointer(&count)),
		0,
		uintptr(unsafe.Pointer(&reasons)),
	)
	if uint32(rc) != ERROR_SUCCESS && uint32(rc) != ERROR_MORE_DATA {
		return nil, fmt.Errorf("Restart Manager 取得占用清單失敗：Win32 error %d", uint32(rc))
	}
	if needed == 0 {
		return nil, nil
	}

	const maxRMEntries = 4096
	capacity := int(needed)
	if capacity > maxRMEntries {
		capacity = maxRMEntries
	}
	if capacity <= 0 {
		return nil, nil
	}

	var infos []RM_PROCESS_INFO
	for attempt := 0; attempt < 5; attempt++ {
		infos = make([]RM_PROCESS_INFO, capacity)
		count = uint32(capacity)
		needed = 0
		reasons = 0
		rc, _, _ = pRmGetList.Call(
			uintptr(session),
			uintptr(unsafe.Pointer(&needed)),
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&infos[0])),
			uintptr(unsafe.Pointer(&reasons)),
		)
		if uint32(rc) == ERROR_SUCCESS {
			break
		}
		if uint32(rc) != ERROR_MORE_DATA {
			return nil, fmt.Errorf("Restart Manager 取得占用清單失敗：Win32 error %d", uint32(rc))
		}
		if needed == 0 || int(needed) <= capacity {
			// The list changed without exposing a larger required count. Retry with
			// a modest growth instead of treating an inherently racy snapshot as fatal.
			if capacity >= maxRMEntries {
				return nil, errors.New("Restart Manager 占用清單持續變動，超過安全重試上限")
			}
			capacity *= 2
			if capacity > maxRMEntries {
				capacity = maxRMEntries
			}
			continue
		}
		capacity = int(needed)
		if capacity > maxRMEntries {
			return nil, errors.New("Restart Manager 占用清單超過安全大小上限")
		}
	}
	if uint32(rc) != ERROR_SUCCESS {
		return nil, errors.New("Restart Manager 占用清單在安全重試次數內仍無法穩定取得")
	}

	currentPID := uint32(os.Getpid())
	out := make([]lockProcess, 0, int(count))
	seen := make(map[uint32]struct{})
	for i := 0; i < int(count) && i < len(infos); i++ {
		info := infos[i]
		pid := info.Process.ProcessID
		if pid == 0 || pid == currentPID {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		name := syscall.UTF16ToString(info.AppName[:])
		if name == "" {
			name = "未知應用程式"
		}

		lp := lockProcess{
			name:         name,
			source:       "Restart Manager",
			pid:          pid,
			kind:         info.ApplicationType,
			startTime:    info.Process.ProcessStartTime,
			startKnown:   true,
			sessionID:    info.TSSessionID,
			sessionKnown: true,
		}

		h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(pid))
		if h != 0 {
			lp.imagePath = processImagePath(h)
			lp.critical, lp.criticalKnown, lp.protected, lp.protectedKnown = processSafetyInfo(h)
			lp.serviceAccount, lp.serviceKnown = processRunsAsServiceAccount(h)
			if identity, ok := processIdentityFromHandle(h); ok {
				lp.userSID = identity.sid
				lp.userSIDKnown = identity.sidKnown
				lp.authLow, lp.authHigh, lp.authKnown = identity.authLow, identity.authHigh, identity.authKnown
				lp.sessionID, lp.sessionKnown = identity.sessionID, identity.sessionKnown
			}
			pCloseHandle.Call(h)
		}
		lp.serviceProcess, lp.serviceProcKnown = isServiceProcessPID(pid)
		lp.desktopShell, lp.desktopShellKnown = isDesktopShellPID(pid)
		out = append(out, lp)
	}
	return out, nil
}

func isCriticalLocker(l lockProcess) bool {
	if l.kind == rmCriticalApp || l.kind == rmServiceApp {
		return true
	}
	if l.criticalKnown && l.critical {
		return true
	}
	if l.protectedKnown && l.protected {
		return true
	}
	if l.serviceProcKnown && l.serviceProcess {
		return true
	}
	if l.serviceKnown && l.serviceAccount {
		return true
	}
	switch strings.ToLower(l.name) {
	case "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe":
		return true
	}
	return false
}

func isExplorerProcess(l lockProcess) bool {
	// Restart Manager may report AppName such as "Windows Explorer" rather
	// than the executable filename. Prefer the verified image path whenever it
	// is available; only fall back to the reported name when no image path exists.
	if path := strings.TrimSpace(l.imagePath); path != "" {
		path = strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
		trimmed := strings.TrimRight(path, "\\")
		if i := strings.LastIndex(trimmed, "\\"); i >= 0 {
			return trimmed[i+1:] == "explorer.exe"
		}
		return trimmed == "explorer.exe"
	}
	return strings.EqualFold(strings.TrimSpace(l.name), "explorer.exe")
}

func canForceTerminateLockerForIdentity(l lockProcess, identity processIdentity) bool {
	if l.pid == 0 || l.pid == uint32(os.Getpid()) {
		return false
	}
	if isExplorerProcess(l) && !isSystemExplorerProcess(l) {
		return false
	}
	if isCriticalLocker(l) {
		return false
	}
	if !l.startKnown || l.imagePath == "" {
		return false
	}
	if !l.criticalKnown || !l.protectedKnown || !l.serviceKnown || !l.serviceProcKnown {
		return false
	}
	if !identity.known() || !l.sessionKnown || l.sessionID != identity.sessionID {
		return false
	}
	if !l.userSIDKnown {
		return false
	}
	live := processIdentity{sid: l.userSID, sidKnown: l.userSIDKnown, sessionID: l.sessionID, sessionKnown: l.sessionKnown, authLow: l.authLow, authHigh: l.authHigh, authKnown: l.authKnown}
	if !strings.EqualFold(live.sid, identity.sid) {
		return false
	}
	// AuthenticationId is an additional protection against RunAs/session mixups.
	// When Windows does not expose TOKEN_STATISTICS for an otherwise queryable
	// process, SID + interactive session remains the authoritative same-user gate.
	return sameAuthenticationID(live, identity)
}

func canForceTerminateLocker(l lockProcess) bool {
	identity, ok := currentTerminationIdentity()
	if !ok {
		return false
	}
	return canForceTerminateLockerForIdentity(l, identity)
}

func forceTerminationBlockReason(l lockProcess) string {
	if l.serviceProcKnown && l.serviceProcess {
		return "Windows Service 程序"
	}
	if l.serviceKnown && l.serviceAccount {
		return "系統服務帳戶／服務程序"
	}
	if l.protectedKnown && l.protected {
		return "Protected Process / PPL"
	}
	if l.criticalKnown && l.critical {
		return "Critical process"
	}
	if l.kind == rmServiceApp {
		return "Windows Service"
	}
	if !l.criticalKnown || !l.protectedKnown || !l.serviceKnown || !l.serviceProcKnown {
		return "無法完成程序安全性檢查"
	}
	if l.imagePath == "" {
		return "無法取得程序執行檔路徑"
	}
	identity, ok := currentTerminationIdentity()
	if !ok || !identity.known() {
		return "無法確認目前使用者身分"
	}
	if !l.sessionKnown {
		return "無法確認程序工作階段"
	}
	if l.sessionID != identity.sessionID {
		return "不同 Windows 工作階段"
	}
	if isExplorerProcess(l) && !isSystemExplorerProcess(l) {
		return "無法確認 explorer.exe 是 Windows 系統 Explorer"
	}
	if !l.startKnown {
		return "無法驗證程序建立時間"
	}
	if !l.userSIDKnown {
		return "無法確認程序使用者身分"
	}
	identity, identityOK := currentTerminationIdentity()
	if !identityOK || !identity.known() {
		return "無法確認目前使用者身分"
	}
	if !strings.EqualFold(identity.sid, l.userSID) {
		return "不同使用者身分"
	}
	if !l.sessionKnown {
		return "無法確認程序工作階段"
	}
	if identity.sessionID != l.sessionID {
		return "不同 Windows 工作階段"
	}
	live := processIdentity{sid: l.userSID, sidKnown: l.userSIDKnown, sessionID: l.sessionID, sessionKnown: l.sessionKnown, authLow: l.authLow, authHigh: l.authHigh, authKnown: l.authKnown}
	if !sameAuthenticationID(identity, live) {
		return "不同使用者登入工作階段"
	}
	return ""
}

// forceTerminateLockers terminates only candidates that passed the discovery
// pipeline and the live identity/safety checks. PID reuse is guarded by comparing
// the recorded process creation FILETIME with GetProcessTimes before termination.
type terminatedLocker struct {
	locker     lockProcess
	shellToken uintptr
}

func processExitState(h uintptr) (exited bool, exitCode uint32, known bool) {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return false, 0, false
	}
	r, _, _ := pGetExitCodeProcess.Call(h, uintptr(unsafe.Pointer(&exitCode)))
	if r == 0 {
		return false, 0, false
	}
	return exitCode != STILL_ACTIVE, exitCode, true
}

func forceTerminateLockers(lockers []lockProcess) ([]terminatedLocker, error, bool, bool) {
	if len(lockers) == 0 {
		return nil, errors.New("沒有可強制終止的占用程序"), false, false
	}

	// Best-effort privilege elevation for inspecting/terminating elevated user-mode
	// processes. This only enables a privilege already present in the token; it
	// never changes account policy. Normal user-mode processes can still be tried
	// when the privilege is unavailable.
	debugEnabled, debugErr := enableDebugPrivilege()
	if debugEnabled {
		defer disableDebugPrivilege()
	}

	terminated := make([]terminatedLocker, 0, len(lockers))
	var failures []string
	seenIdentity := make(map[string]struct{})
	shellPrivilegeChanged := false
	shellTerminationUnconfirmed := false
	if !debugEnabled && debugErr != 0 {
		failures = append(failures, fmt.Sprintf("SeDebugPrivilege 未啟用（Win32 error %d）；仍會嘗試處理目前權限可終止的程序。", debugErr))
	}

	for _, l := range lockers {
		if cancellationRequested() {
			failures = append(failures, "使用者要求停止；尚未處理的占用程序未執行強制終止。")
			break
		}
		identity := processIdentityKey(l)
		if _, seen := seenIdentity[identity]; seen {
			continue
		}
		seenIdentity[identity] = struct{}{}
		if !canForceTerminateLocker(l) {
			reason := forceTerminationBlockReason(l)
			if reason == "" {
				reason = "未通過安全終止條件"
			}
			failures = append(failures, fmt.Sprintf("%s (PID %d)：不允許強制終止（%s）", l.name, l.pid, reason))
			continue
		}

		h, _, err := pOpenProcess.Call(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(l.pid))
		if h == 0 {
			failures = append(failures, fmt.Sprintf("%s (PID %d)：OpenProcess 失敗：%v", l.name, l.pid, win32Error(procError(err))))
			continue
		}

		actualStart, ok := processStartTime(h)
		if !ok || !sameFileTime(actualStart, l.startTime) {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：程序已變更，為避免誤殺未執行終止", l.name, l.pid))
			continue
		}

		actualCritical, actualCriticalKnown, actualProtected, actualProtectedKnown := processSafetyInfo(h)
		actualServiceAccount, actualServiceKnown := processRunsAsServiceAccount(h)
		actualServiceProcess, actualServiceProcKnown := isServiceProcessPID(l.pid)
		if !actualCriticalKnown || !actualProtectedKnown || !actualServiceKnown || !actualServiceProcKnown {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：終止前安全分類無法完整驗證，未執行終止", l.name, l.pid))
			continue
		}
		if actualCritical || actualProtected || actualServiceAccount || actualServiceProcess {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：終止前安全分類顯示為受保護／服務程序，未執行終止", l.name, l.pid))
			continue
		}

		currentIdentity, currentIdentityOK := currentTerminationIdentity()
		targetIdentity, targetIdentityOK := processIdentityFromHandle(h)
		if !currentIdentityOK || !targetIdentityOK || !currentIdentity.known() || !targetIdentity.known() ||
			currentIdentity.sessionID != targetIdentity.sessionID ||
			!strings.EqualFold(currentIdentity.sid, targetIdentity.sid) ||
			!sameAuthenticationID(currentIdentity, targetIdentity) {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：程序身分在真正終止前未通過即時驗證，未執行終止", l.name, l.pid))
			continue
		}

		actualName := processImagePath(h)
		if actualName == "" {
			actualName = l.name
		}
		actualImage := l
		actualImage.imagePath = actualName
		if isExplorerProcess(actualImage) && !isSystemExplorerProcess(actualImage) {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：無法確認為系統 Explorer，未執行終止", actualName, l.pid))
			continue
		}

		// Explorer receives a fail-closed shell-identity gate. A system explorer.exe
		// in the same session is not sufficient evidence that it is the Desktop Shell.
		isShellNow, shellKnown := isDesktopShellPID(l.pid)
		if isSystemExplorerProcess(actualImage) && !shellKnown {
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：無法唯一確認為 Desktop Shell，為安全起見未終止。", actualName, l.pid))
			continue
		}

		var shellToken uintptr
		if isShellNow {
			if !shellPrivilegeChanged {
				changed, privilegeErr := ensureShellRecoveryPrivilege()
				if privilegeErr != nil {
					pCloseHandle.Call(h)
					failures = append(failures, fmt.Sprintf("%s (PID %d)：無法預先確認 Explorer 恢復所需權限，為避免黑屏未終止：%v", actualName, l.pid, privilegeErr))
					continue
				}
				shellPrivilegeChanged = changed
			}
			shellToken, err = duplicatePrimaryUserToken(h)
			if err != nil {
				pCloseHandle.Call(h)
				failures = append(failures, fmt.Sprintf("%s (PID %d)：無法先保存 Explorer 使用者 token，為避免留下黑屏未執行終止：%v", actualName, l.pid, err))
				continue
			}
		}

		r, _, termErr := pTerminateProcess.Call(h, 1)
		if r == 0 {
			if shellToken != 0 {
				pCloseHandle.Call(shellToken)
			}
			failures = append(failures, fmt.Sprintf("%s (PID %d)：TerminateProcess 失敗：%v", actualName, l.pid, win32Error(procError(termErr))))
			pCloseHandle.Call(h)
			continue
		}

		wait, _, _ := pWaitForSingleObject.Call(h, 5000)
		exited, exitCode, exitKnown := processExitState(h)
		if wait != WAIT_OBJECT_0 && (!exitKnown || !exited) {
			if shellToken != 0 {
				pCloseHandle.Call(shellToken)
				shellTerminationUnconfirmed = true
			}
			pCloseHandle.Call(h)
			if wait == WAIT_TIMEOUT {
				failures = append(failures, fmt.Sprintf("%s (PID %d)：等待程序終止逾時，未確認程序已退出", actualName, l.pid))
			} else if wait == WAIT_FAILED || wait != WAIT_OBJECT_0 {
				failures = append(failures, fmt.Sprintf("%s (PID %d)：等待程序終止失敗：0x%X", actualName, l.pid, wait))
			}
			continue
		}
		if exitKnown && !exited && exitCode == STILL_ACTIVE {
			if shellToken != 0 {
				pCloseHandle.Call(shellToken)
				shellTerminationUnconfirmed = true
			}
			pCloseHandle.Call(h)
			failures = append(failures, fmt.Sprintf("%s (PID %d)：程序仍在執行，未執行後續刪除", actualName, l.pid))
			continue
		}

		pCloseHandle.Call(h)
		terminated = append(terminated, terminatedLocker{locker: l, shellToken: shellToken})
	}

	if len(failures) > 0 {
		return terminated, errors.New(strings.Join(failures, "\n")), shellPrivilegeChanged, shellTerminationUnconfirmed
	}
	return terminated, nil, shellPrivilegeChanged, shellTerminationUnconfirmed
}

func restoreTerminatedDesktopShells(terminated []terminatedLocker) error {
	var failures []string
	for _, item := range terminated {
		if item.shellToken == 0 {
			continue
		}
		if err := restoreDesktopShell(item.shellToken, item.locker.pid); err != nil {
			failures = append(failures, fmt.Sprintf("Explorer (PID %d) 已終止，但 Desktop Shell 無法恢復：%v", item.locker.pid, err))
		}
		pCloseHandle.Call(item.shellToken)
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "\n"))
	}
	return nil
}

type lockProcessWire struct {
	Name              string  `json:"name"`
	ImagePath         string  `json:"imagePath"`
	PID               uint32  `json:"pid"`
	Kind              uint32  `json:"kind"`
	StartLow          uint32  `json:"startLow"`
	StartHigh         uint32  `json:"startHigh"`
	StartKnown        bool    `json:"startKnown"`
	SessionID         uint32  `json:"sessionID"`
	SessionKnown      bool    `json:"sessionKnown"`
	Critical          bool    `json:"critical"`
	CriticalKnown     bool    `json:"criticalKnown"`
	Protected         bool    `json:"protected"`
	ProtectedKnown    bool    `json:"protectedKnown"`
	ServiceAccount    bool    `json:"serviceAccount"`
	ServiceKnown      bool    `json:"serviceKnown"`
	ServiceProcess    bool    `json:"serviceProcess"`
	ServiceProcKnown  bool    `json:"serviceProcKnown"`
	UserSID           string  `json:"userSID,omitempty"`
	UserSIDKnown      bool    `json:"userSIDKnown"`
	DesktopShell      bool    `json:"desktopShell"`
	DesktopShellKnown bool    `json:"desktopShellKnown"`
	HandleValue       uintptr `json:"handleValue,omitempty"`
}

func handleScanLockersExternal(paths []string) ([]lockProcess, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("無法取得自身執行檔：%w", err)
	}
	payload, err := json.Marshal(paths)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--scan-handles-child")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = bytes.NewReader(payload)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("handle 掃描逾時；已隔離掃描程序，主程式未受影響")
		}
		return nil, fmt.Errorf("handle 掃描程序失敗：%w", err)
	}
	var wire []lockProcessWire
	if err := json.Unmarshal(stdout.Bytes(), &wire); err != nil {
		return nil, fmt.Errorf("handle 掃描結果格式無效：%w", err)
	}

	// The child returns only exact remote-handle evidence (PID + handle value).
	// The parent independently verifies each handle by documented file identity
	// when the target is openable, and by canonical final path when exclusive sharing
	// prevents opening the target directly.
	targetIDs, _ := fileIdentitiesForPaths(paths)

	debugEnabled, _ := enableDebugPrivilege()
	if debugEnabled {
		defer disableDebugPrivilege()
	}
	seen := make(map[uint32]struct{})
	out := make([]lockProcess, 0, len(wire))
	for _, w := range wire {
		if w.PID == 0 || w.PID == uint32(os.Getpid()) || w.HandleValue == 0 || w.HandleValue == INVALID_HANDLE_VALUE {
			continue
		}
		if _, dup := seen[w.PID]; dup {
			continue
		}
		procH, _, _ := pOpenProcess.Call(processDupHandle, 0, uintptr(w.PID))
		if procH == 0 || procH == INVALID_HANDLE_VALUE {
			continue
		}
		dupH, ok := duplicateRemoteHandle(procH, w.HandleValue)
		pCloseHandle.Call(procH)
		if !ok {
			continue
		}
		id, idOK := fileIdentityFromHandle(dupH)
		matched := false
		if idOK {
			for _, targetID := range targetIDs {
				if sameFileIdentity(id, targetID) {
					matched = true
					break
				}
			}
		}
		if !matched {
			if key := canonicalComparePath(finalPathFromHandle(dupH)); key != "" {
				for _, path := range paths {
					if key == canonicalComparePath(path) {
						matched = true
						break
					}
				}
			}
		}
		pCloseHandle.Call(dupH)
		if !matched {
			continue
		}
		lp := lockProcessFromPID(w.PID, "Windows Handle Scan")
		if lp.pid == 0 {
			continue
		}
		lp.handleEvidence = w.HandleValue
		seen[w.PID] = struct{}{}
		out = append(out, lp)
	}
	return out, nil
}

func discoverLockers(paths []string) ([]lockProcess, error) {
	// Restart Manager identifies applications registered against the resource.
	// It remains the first process-level candidate source because it is designed
	// for resource-lock discovery and already feeds the existing live identity
	// gate before any termination is allowed.
	rmPaths := filterRestartManagerPaths(paths)
	var rmErr error
	if len(rmPaths) > 0 {
		rmLockers, err := restartManagerLockers(rmPaths)
		rmErr = err
		if len(rmLockers) > 0 {
			return rmLockers, nil
		}
	}

	// Final isolated fallback for cases where Restart Manager cannot identify the
	// locker. This path stays out of the GUI
	// process so a low-level handle-table problem cannot take down the UI.
	handleLockers, handleErr := handleScanLockersExternal(paths)
	if len(handleLockers) > 0 {
		return handleLockers, nil
	}

	if handleErr != nil {
		if rmErr != nil {
			return nil, fmt.Errorf("無法取得占用程序資訊；Restart Manager 與隔離 handle 掃描皆未取得可用程序：%v", handleErr)
		}
		return nil, handleErr
	}
	if rmErr != nil && len(rmPaths) > 0 {
		return nil, errors.New("目前無法由 Windows 取得可辨識的占用程序；檔案仍可能被核心、驅動程式、服務或受保護程序使用")
	}
	return nil, errors.New("未能辨識占用程序；檔案仍可能被核心、驅動程式、服務或受保護程序使用")
}

func processIdentityKey(l lockProcess) string {
	return fmt.Sprintf("%d:%08X:%08X", l.pid, l.startTime.HighDateTime, l.startTime.LowDateTime)
}

func isLockRecoveryError(code uint32) bool {
	switch code {
	case ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_USER_MAPPED_FILE:
		return true
	default:
		return false
	}
}
