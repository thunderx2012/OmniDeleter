//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Windows process-identity and protection helpers used by locker discovery.

const (
	tokenAdjustPrivileges = 0x0020
	tokenQuery            = 0x0008
	sePrivilegeEnabled    = 0x00000002
)

var (
	advapi32Locker               = syscall.NewLazyDLL("advapi32.dll")
	pOpenProcessTokenLocker      = advapi32Locker.NewProc("OpenProcessToken")
	pLookupPrivilegeValueLocker  = advapi32Locker.NewProc("LookupPrivilegeValueW")
	pAdjustTokenPrivilegesLocker = advapi32Locker.NewProc("AdjustTokenPrivileges")
	pGetTokenInformationLocker   = advapi32Locker.NewProc("GetTokenInformation")
	pConvertSidToStringSidLocker = advapi32Locker.NewProc("ConvertSidToStringSidW")
	pIsProcessCriticalLocker     = kernel32.NewProc("IsProcessCritical")
	pGetProcessInformationLocker = kernel32.NewProc("GetProcessInformation")
	pLocalFreeLocker             = kernel32.NewProc("LocalFree")
)

// enableDebugPrivilege enables SeDebugPrivilege only when the token already
// contains it. It never attempts to change account policy or add privileges.
func tokenHasEnabledPrivilege(token uintptr, luid struct {
	LowPart  uint32
	HighPart int32
}) (bool, bool) {
	var needed uint32
	pGetTokenInformationLocker.Call(token, 3, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 1<<20 {
		return false, false
	}
	buf := make([]byte, int(needed))
	if r, _, _ := pGetTokenInformationLocker.Call(token, 3, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return false, false
	}
	if len(buf) < 4 {
		return false, false
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := uintptr(unsafe.Sizeof(luidAndAttributesLocker{}))
	base := uintptr(unsafe.Pointer(&buf[4]))
	for i := uint32(0); i < count; i++ {
		off := uintptr(i) * entrySize
		if 4+off+entrySize > uintptr(len(buf)) {
			return false, false
		}
		entry := (*luidAndAttributesLocker)(unsafe.Pointer(base + off))
		if entry.Luid == luid {
			return entry.Attributes&sePrivilegeEnabled != 0, true
		}
	}
	return false, true
}

type luidAndAttributesLocker struct {
	Luid struct {
		LowPart  uint32
		HighPart int32
	}
	Attributes uint32
}

func enableDebugPrivilege() (bool, uint32) {
	self, _, _ := kernel32.NewProc("GetCurrentProcess").Call()
	var token uintptr
	r, _, e := pOpenProcessTokenLocker.Call(
		self,
		tokenAdjustPrivileges|tokenQuery,
		uintptr(unsafe.Pointer(&token)),
	)
	if r == 0 {
		return false, procError(e)
	}
	defer pCloseHandle.Call(token)

	privilegeName := u16("SeDebugPrivilege")
	var luid struct {
		LowPart  uint32
		HighPart int32
	}
	r, _, e = pLookupPrivilegeValueLocker.Call(
		0,
		uintptr(unsafe.Pointer(privilegeName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r == 0 {
		return false, procError(e)
	}

	if enabled, known := tokenHasEnabledPrivilege(token, luid); known && enabled {
		return false, 0
	}
	tp := struct {
		PrivilegeCount uint32
		Privileges     luidAndAttributesLocker
	}{
		PrivilegeCount: 1,
		Privileges: luidAndAttributesLocker{
			Luid:       luid,
			Attributes: sePrivilegeEnabled,
		},
	}

	r, _, e = pAdjustTokenPrivilegesLocker.Call(
		token,
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r == 0 {
		return false, procError(e)
	}
	last := procError(e)
	if last != ERROR_SUCCESS {
		return false, last
	}
	return true, 0
}

func disableDebugPrivilege() (bool, uint32) {
	self, _, _ := kernel32.NewProc("GetCurrentProcess").Call()
	var token uintptr
	r, _, e := pOpenProcessTokenLocker.Call(self, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false, procError(e)
	}
	defer pCloseHandle.Call(token)
	privilegeName := u16("SeDebugPrivilege")
	var luid struct {
		LowPart  uint32
		HighPart int32
	}
	r, _, e = pLookupPrivilegeValueLocker.Call(0, uintptr(unsafe.Pointer(privilegeName)), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return false, procError(e)
	}
	type luidAndAttributes struct {
		Luid struct {
			LowPart  uint32
			HighPart int32
		}
		Attributes uint32
	}
	tp := struct {
		PrivilegeCount uint32
		Privileges     luidAndAttributes
	}{1, luidAndAttributes{Luid: luid, Attributes: 0}}
	r, _, e = pAdjustTokenPrivilegesLocker.Call(token, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return false, procError(e)
	}
	last := procError(e)
	if last != ERROR_SUCCESS {
		return false, last
	}
	return true, 0
}

type processProtectionLevelInformation struct {
	ProtectionLevel uint32
}

// Windows uses 0xFFFFFFFE for PROTECTION_LEVEL_NONE. Zero is not the
// "unprotected" sentinel. Any other successfully queried level is a
// protected-process classification (including PPL variants). Query failure
// remains unknown and is never treated as protected or safe.
const protectionLevelNone uint32 = 0xFFFFFFFE

func isProtectedProcessLevel(level uint32) bool {
	return level != protectionLevelNone
}

func processSafetyInfo(h uintptr) (critical, criticalKnown, protected, protectedKnown bool) {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return
	}
	var crit int32
	if r, _, _ := pIsProcessCriticalLocker.Call(h, uintptr(unsafe.Pointer(&crit))); r != 0 {
		criticalKnown = true
		critical = crit != 0
	}
	var pli processProtectionLevelInformation
	if r, _, _ := pGetProcessInformationLocker.Call(h, 7, uintptr(unsafe.Pointer(&pli)), unsafe.Sizeof(pli)); r != 0 {
		protectedKnown = true
		protected = isProtectedProcessLevel(pli.ProtectionLevel)
	}
	return
}

type tokenUserInfoHeader struct {
	Sid        uintptr
	Attributes uint32
}

type luidValue struct {
	LowPart  uint32
	HighPart int32
}

// TOKEN_STATISTICS is used only for AuthenticationId (logon-session identity).
// SID alone is insufficient because the same account can have multiple logon
// sessions (for example RunAs / remote sessions).
type tokenStatistics struct {
	TokenID            luidValue
	AuthenticationID   luidValue
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         luidValue
}

const (
	tokenStatisticsInfoClass = 10 // TokenStatistics
	tokenUserInfoClass       = 1  // TokenUser
)

type processIdentity struct {
	sid          string
	sidKnown     bool
	sessionID    uint32
	sessionKnown bool
	authLow      uint32
	authHigh     int32
	authKnown    bool
}

func (i processIdentity) known() bool {
	// SID + Windows session is the minimum reliable interactive identity.
	// AuthenticationId is an additional hardening signal when the token exposes
	// it; callers compare it when both sides are known, but do not turn an
	// otherwise valid same-user/session operation into a blanket failure merely
	// because TOKEN_STATISTICS is unavailable on a particular process.
	return i.sidKnown && i.sessionKnown
}

func sameAuthenticationID(a, b processIdentity) bool {
	if !a.authKnown || !b.authKnown {
		return true
	}
	return a.authLow == b.authLow && a.authHigh == b.authHigh
}

func tokenIdentityFromToken(token uintptr) (processIdentity, bool) {
	var out processIdentity
	if token == 0 || token == INVALID_HANDLE_VALUE {
		return out, false
	}

	var needed uint32
	pGetTokenInformationLocker.Call(token, tokenUserInfoClass, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 1<<20 {
		return out, false
	}
	buf := make([]byte, int(needed))
	if r, _, _ := pGetTokenInformationLocker.Call(token, tokenUserInfoClass, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return out, false
	}
	info := (*tokenUserInfoHeader)(unsafe.Pointer(&buf[0]))
	if info.Sid == 0 {
		return out, false
	}
	var sidText uintptr
	if r, _, _ := pConvertSidToStringSidLocker.Call(info.Sid, uintptr(unsafe.Pointer(&sidText))); r == 0 || sidText == 0 {
		return out, false
	}
	out.sid = utf16PtrString((*uint16)(unsafe.Pointer(sidText)))
	out.sidKnown = out.sid != ""
	pLocalFreeLocker.Call(sidText)

	needed = 0
	var sessionID uint32
	if r, _, _ := pGetTokenInformationLocker.Call(token, 12, uintptr(unsafe.Pointer(&sessionID)), unsafe.Sizeof(sessionID), uintptr(unsafe.Pointer(&needed))); r != 0 {
		out.sessionID = sessionID
		out.sessionKnown = true
	}

	var stats tokenStatistics
	needed = 0
	if r, _, _ := pGetTokenInformationLocker.Call(token, tokenStatisticsInfoClass, uintptr(unsafe.Pointer(&stats)), unsafe.Sizeof(stats), uintptr(unsafe.Pointer(&needed))); r != 0 {
		out.authLow = stats.AuthenticationID.LowPart
		out.authHigh = stats.AuthenticationID.HighPart
		out.authKnown = true
	}
	return out, out.known()
}

func tokenIdentityFromHandle(h uintptr) (processIdentity, bool) {
	token, ok := openProcessTokenQuery(h)
	if !ok {
		return processIdentity{}, false
	}
	defer pCloseHandle.Call(token)
	return tokenIdentityFromToken(token)
}

func processIdentityFromHandle(h uintptr) (processIdentity, bool) {
	return tokenIdentityFromHandle(h)
}

func openProcessTokenQuery(h uintptr) (uintptr, bool) {
	var token uintptr
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return 0, false
	}
	if r, _, _ := pOpenProcessTokenLocker.Call(h, tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 || token == 0 || token == INVALID_HANDLE_VALUE {
		return 0, false
	}
	return token, true
}

func processUserSID(h uintptr) (string, bool) {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return "", false
	}
	var token uintptr
	if r, _, _ := pOpenProcessTokenLocker.Call(h, tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 {
		return "", false
	}
	defer pCloseHandle.Call(token)
	var needed uint32
	pGetTokenInformationLocker.Call(token, 1, 0, 0, uintptr(unsafe.Pointer(&needed))) // TokenUser = 1
	if needed == 0 || needed > 1<<20 {
		return "", false
	}
	buf := make([]byte, int(needed))
	if r, _, _ := pGetTokenInformationLocker.Call(token, 1, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return "", false
	}
	info := (*tokenUserInfoHeader)(unsafe.Pointer(&buf[0]))
	if info.Sid == 0 {
		return "", false
	}
	var sidText uintptr
	if r, _, _ := pConvertSidToStringSidLocker.Call(info.Sid, uintptr(unsafe.Pointer(&sidText))); r == 0 || sidText == 0 {
		return "", false
	}
	defer pLocalFreeLocker.Call(sidText)
	return utf16PtrString((*uint16)(unsafe.Pointer(sidText))), true
}

func currentInteractiveIdentity() (processIdentity, bool) {
	currentSession, ok := currentSessionID()
	if !ok {
		return processIdentity{}, false
	}
	shellPID := desktopShellPID()
	if shellPID == 0 {
		return processIdentity{}, false
	}
	if shellSession, ok := processSessionID(shellPID); !ok || shellSession != currentSession {
		return processIdentity{}, false
	}
	h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(shellPID))
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return processIdentity{}, false
	}
	defer pCloseHandle.Call(h)
	if !isSystemExplorerImagePath(processImagePath(h), systemWindowsDirectory()) {
		return processIdentity{}, false
	}
	identity, ok := processIdentityFromHandle(h)
	if !ok || !identity.sessionKnown || identity.sessionID != currentSession {
		return processIdentity{}, false
	}
	return identity, true
}

func currentProcessIdentity() (processIdentity, bool) {
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	self, _, _ := getCurrentProcess.Call()
	if self == 0 || self == INVALID_HANDLE_VALUE {
		return processIdentity{}, false
	}
	return processIdentityFromHandle(self)
}

// currentTerminationIdentity prefers the actual interactive Desktop Shell identity.
// If that evidence is temporarily unavailable (for example during shell startup),
// fall back to the current process primary-token identity rather than reporting a
// false "different user" state. The fallback is still constrained by SID + Session
// and, when available, AuthenticationId at termination time.
func currentTerminationIdentity() (processIdentity, bool) {
	if identity, ok := currentInteractiveIdentity(); ok && identity.known() {
		return identity, true
	}
	return currentProcessIdentity()
}

func isServiceAccountSID(sid uintptr) bool {
	if sid == 0 {
		return false
	}
	type sidHead struct {
		Revision  byte
		Count     byte
		Authority [6]byte
	}
	sh := (*sidHead)(unsafe.Pointer(sid))
	if sh.Count == 0 || sh.Authority != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	first := *(*uint32)(unsafe.Pointer(sid + 8))
	switch first {
	case 18, 19, 20:
		// LocalSystem / LocalService / NetworkService are exactly one
		// subauthority under the SECURITY_NT_AUTHORITY.
		return sh.Count == 1
	case 80:
		// NT SERVICE\...
		return true
	case 90, 96:
		// DWM / UMFD virtual accounts: classify conservatively as system-like.
		return true
	default:
		return false
	}
}

func processRunsAsServiceAccount(h uintptr) (bool, bool) {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return false, false
	}
	var token uintptr
	r, _, _ := pOpenProcessTokenLocker.Call(h, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false, false
	}
	defer pCloseHandle.Call(token)
	var needed uint32
	pGetTokenInformationLocker.Call(token, 1, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed < uint32(unsafe.Sizeof(tokenUserInfoHeader{})) || needed > 1<<20 {
		return false, false
	}
	buf := make([]byte, int(needed))
	r, _, _ = pGetTokenInformationLocker.Call(token, 1, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return false, false
	}
	info := (*tokenUserInfoHeader)(unsafe.Pointer(&buf[0]))
	if info.Sid == 0 {
		return false, false
	}
	return isServiceAccountSID(info.Sid), true
}

func lockProcessFromPID(pid uint32, source string) lockProcess {
	lp := lockProcess{pid: pid, source: source, kind: rmUnknownApp}
	currentPID := uint32(os.Getpid())
	if pid == 0 || pid == currentPID {
		return lp
	}

	h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, uintptr(pid))
	if h != 0 && h != INVALID_HANDLE_VALUE {
		lp.imagePath = processImagePath(h)
		lp.startTime, lp.startKnown = processStartTime(h)
		lp.critical, lp.criticalKnown, lp.protected, lp.protectedKnown = processSafetyInfo(h)
		lp.serviceAccount, lp.serviceKnown = processRunsAsServiceAccount(h)
		if identity, ok := processIdentityFromHandle(h); ok {
			lp.userSID, lp.userSIDKnown = identity.sid, identity.sidKnown
			lp.sessionID, lp.sessionKnown = identity.sessionID, identity.sessionKnown
			lp.authLow, lp.authHigh, lp.authKnown = identity.authLow, identity.authHigh, identity.authKnown
		} else {
			lp.userSID, lp.userSIDKnown = processUserSID(h)
		}
		pCloseHandle.Call(h)
	}
	lp.serviceProcess, lp.serviceProcKnown = isServiceProcessPID(pid)
	if lp.imagePath != "" {
		lp.name = lp.imagePath
		if i := strings.LastIndexAny(lp.imagePath, `\\/`); i >= 0 && i+1 < len(lp.imagePath) {
			lp.name = lp.imagePath[i+1:]
		}
	}
	if lp.name == "" {
		lp.name = processSnapshotName(pid)
	}
	if lp.name == "" {
		lp.name = fmt.Sprintf("PID %d", pid)
	}
	if !lp.sessionKnown {
		lp.sessionID, lp.sessionKnown = processSessionID(pid)
	}
	return lp
}
