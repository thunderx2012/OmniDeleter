//go:build windows

package main

import "unsafe"

// Service PID detection using the Service Control Manager. This closes a gap
// that cannot be covered reliably by process-name or service-account heuristics:
// a normal user-session process may still host a Windows service.
// EnumServicesStatusExW returns SERVICE_STATUS_PROCESS entries containing the
// actual service PID. We use it only for safety classification; we never stop a
// service from this tool.

const (
	scManagerEnumerateService  = 0x0004
	scEnumProcessInfo          = 0
	serviceWin32OwnProcess     = 0x00000010
	serviceWin32ShareProcess   = 0x00000020
	serviceUserService         = 0x00000040
	serviceUserServiceInstance = 0x00000080
	// Include Win32 and per-user service types. Per-user services run under the
	// interactive user's SID, so service-account SID heuristics alone cannot
	// classify their host processes safely. Older Windows versions that do not
	// support these newer service-type bits are handled conservatively if the
	// SCM query rejects the filter.
	serviceWin32 = serviceWin32OwnProcess | serviceWin32ShareProcess |
		serviceUserService | serviceUserServiceInstance
	serviceStateAll      = 0x00000003
	errorMoreData        = 234
	maxServiceEnumBuffer = 256 << 10
)

type serviceStatusProcess struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessID               uint32
	ServiceFlags            uint32
}

type enumServiceStatusProcessW struct {
	ServiceName uintptr
	DisplayName uintptr
	Status      serviceStatusProcess
}

var (
	pOpenSCManagerW       = advapi32Locker.NewProc("OpenSCManagerW")
	pCloseServiceHandle   = advapi32Locker.NewProc("CloseServiceHandle")
	pEnumServicesStatusEx = advapi32Locker.NewProc("EnumServicesStatusExW")
)

// isServiceProcessPID returns (true,true) when PID is currently owned by one or
// more SCM-registered Win32 services; (false,true) means the SCM query succeeded
// and this PID is not a service process; (false,false) means the query could not
// be completed and safety classification must remain conservative.
func isServiceProcessPID(pid uint32) (bool, bool) {
	if pid == 0 {
		return false, true
	}
	scm, _, _ := pOpenSCManagerW.Call(
		0, 0, scManagerEnumerateService,
	)
	if scm == 0 {
		return false, false
	}
	defer pCloseServiceHandle.Call(scm)

	entrySize := unsafe.Sizeof(enumServiceStatusProcessW{})
	if entrySize == 0 {
		return false, false
	}

	resume := uint32(0)
	buffer := make([]byte, maxServiceEnumBuffer)
	for page := 0; page < 128; page++ {
		var bytesNeeded uint32
		var servicesReturned uint32
		r, _, callErr := pEnumServicesStatusEx.Call(
			scm,
			scEnumProcessInfo,
			serviceWin32,
			serviceStateAll,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&bytesNeeded)),
			uintptr(unsafe.Pointer(&servicesReturned)),
			uintptr(unsafe.Pointer(&resume)),
			0,
		)
		errCode := procError(callErr)
		if r == 0 && errCode != errorMoreData {
			// An SCM enumeration failure is not evidence that the PID is safe.
			// Preserve a conservative "unknown" result.
			return false, false
		}

		count := uintptr(servicesReturned)
		maxCount := uintptr(len(buffer)) / entrySize
		if count > maxCount {
			count = maxCount
		}
		base := uintptr(unsafe.Pointer(&buffer[0]))
		for i := uintptr(0); i < count; i++ {
			entry := (*enumServiceStatusProcessW)(unsafe.Pointer(base + i*entrySize))
			if entry.Status.ProcessID == pid && entry.Status.ProcessID != 0 {
				return true, true
			}
		}

		if r != 0 || errCode != errorMoreData {
			return false, true
		}
		if bytesNeeded == 0 {
			// ERROR_MORE_DATA means enumeration is incomplete. A zero required
			// size therefore cannot prove that the PID is not a service.
			return false, false
		}
		// The SCM API caps the output buffer size at 256 KB. If the returned
		// buffer is insufficient and the resume handle is non-zero, the next
		// call continues enumeration with the same buffer.
		if len(buffer) < maxServiceEnumBuffer && int(bytesNeeded) > len(buffer) {
			next := int(bytesNeeded)
			if next > maxServiceEnumBuffer {
				next = maxServiceEnumBuffer
			}
			if next > len(buffer) {
				buffer = make([]byte, next)
			}
		}
		// Keep enumerating from the resume handle. It is valid until the call
		// completes, so do not reset it between pages.
	}
	return false, false
}
