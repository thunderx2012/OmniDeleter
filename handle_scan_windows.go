//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Native handle scan fallback.
// Restart Manager is the preferred mechanism, but it is not guaranteed to
// identify a user-mode process for every file handle, especially when the
// resource is a very long path. This fallback enumerates system handles,
// duplicates only candidate file handles into this process, and validates their
// file identity. It never closes or modifies a foreign handle.

const (
	systemExtendedHandleInformation = 64
	statusInfoLengthMismatch        = 0xC0000004
	processDupHandle                = 0x00000040
	fileTypeDisk                    = 0x0001
)

type systemHandleTableEntryInfoEx struct {
	Object              uintptr
	UniqueProcessID     uintptr
	HandleValue         uintptr
	GrantedAccess       uint32
	CreatorBackTraceIdx uint16
	ObjectTypeIndex     uint16
	HandleAttributes    uint32
	Reserved            uint32
}

var (
	ntdll                     = syscall.NewLazyDLL("ntdll.dll")
	pNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
	pDuplicateHandle          = kernel32.NewProc("DuplicateHandle")
	pProcessIdToSessionId     = kernel32.NewProc("ProcessIdToSessionId")
	pGetFileType              = kernel32.NewProc("GetFileType")
	pGetFinalPathNameByHandle = kernel32.NewProc("GetFinalPathNameByHandleW")
)

func queryExtendedHandleBuffer() ([]byte, error) {
	size := uintptr(1 << 20) // 1 MiB initial buffer
	const maxSize = uintptr(256 << 20)
	for size <= maxSize {
		buf := make([]byte, int(size))
		var returnLength uint32
		status, _, _ := pNtQuerySystemInformation.Call(
			systemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			size,
			uintptr(unsafe.Pointer(&returnLength)),
		)
		if uint32(status) == 0 {
			return buf, nil
		}
		if uint32(status) != statusInfoLengthMismatch {
			return nil, fmt.Errorf("NtQuerySystemInformation failed: NTSTATUS 0x%08X", uint32(status))
		}
		next := size * 2
		if returnLength > 0 && uintptr(returnLength) > next {
			next = uintptr(returnLength) + (1 << 20)
		}
		if next <= size {
			return nil, errors.New("system handle buffer size overflow")
		}
		size = next
	}
	return nil, errors.New("system handle table exceeded safety limit")
}

func duplicateRemoteHandle(sourceProcess, sourceHandle uintptr) (uintptr, bool) {
	var dup uintptr
	currentProcess := ^uintptr(0)
	r, _, _ := pDuplicateHandle.Call(
		sourceProcess,
		sourceHandle,
		currentProcess,
		uintptr(unsafe.Pointer(&dup)),
		0,
		0,
		0x00000002, // DUPLICATE_SAME_ACCESS
	)
	if r == 0 || dup == 0 || dup == INVALID_HANDLE_VALUE {
		return 0, false
	}
	return dup, true
}

// fileIdentity uses the documented FILE_ID_INFO 128-bit identifier plus the
// volume serial number. This avoids truncating ReFS file IDs to 64 bits.
const fileIdInfoClass = 0x12 // FileIdInfo

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type legacyByHandleFileInformation struct {
	FileAttributes uint32
	CreationTime   FILETIME
	LastAccessTime FILETIME
	LastWriteTime  FILETIME
	VolumeSerial   uint32
	FileSizeHigh   uint32
	FileSizeLow    uint32
	NumberOfLinks  uint32
	FileIndexHigh  uint32
	FileIndexLow   uint32
}

type fileIdentity struct {
	volume uint64
	id     [16]byte
}

func fileIdentityFromHandle(h uintptr) (fileIdentity, bool) {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return fileIdentity{}, false
	}
	var info fileIDInfo
	if r, _, _ := pGetFileInformationByHandleEx.Call(
		h, fileIdInfoClass, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
	); r != 0 {
		return fileIdentity{volume: info.VolumeSerialNumber, id: info.FileID}, true
	}

	// Compatibility fallback for file systems that do not implement FileIdInfo.
	// Both the target and candidate handle go through the same function, so the
	// fallback remains internally consistent while modern ReFS gets the full ID.
	var legacy legacyByHandleFileInformation
	if r, _, _ := pGetFileInformationByHandle.Call(h, uintptr(unsafe.Pointer(&legacy))); r == 0 {
		return fileIdentity{}, false
	}
	var id [16]byte
	*(*uint32)(unsafe.Pointer(&id[0])) = legacy.FileIndexHigh
	*(*uint32)(unsafe.Pointer(&id[4])) = legacy.FileIndexLow
	return fileIdentity{volume: uint64(legacy.VolumeSerial), id: id}, true
}

func sameFileIdentity(a, b fileIdentity) bool {
	return a.volume == b.volume && a.id == b.id
}

func fileIdentitiesForPaths(paths []string) ([]fileIdentity, error) {
	seen := make(map[fileIdentity]struct{})
	out := make([]fileIdentity, 0, len(paths))
	var lastErr error
	for _, path := range paths {
		op := toOperationPath(path)
		attr, code := getAttributes(op)
		if attr == INVALID_FILE_ATTRIBUTES {
			if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
				continue
			}
			lastErr = win32Error(code)
			continue
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
			lastErr = win32Error(procError(e))
			continue
		}
		id, ok := fileIdentityFromHandle(h)
		pCloseHandle.Call(h)
		if !ok {
			lastErr = errors.New("無法取得目標檔案識別資訊")
			continue
		}
		if _, exists := seen[id]; !exists {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

func processSessionID(pid uint32) (uint32, bool) {
	var sid uint32
	r, _, _ := pProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid)))
	if r == 0 {
		return 0, false
	}
	return sid, true
}

func currentSessionID() (uint32, bool) {
	return processSessionID(uint32(os.Getpid()))
}

func canonicalComparePath(p string) string {
	p = displayPath(normalizeInputPath(p))
	p = strings.TrimRight(p, `\\`)
	return strings.ToLower(p)
}

type processEntry32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

func processSnapshotName(pid uint32) string {
	const th32csSnapProcess = 0x00000002
	const invalidSnapshot = ^uintptr(0)
	snap, _, _ := pCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == invalidSnapshot {
		return ""
	}
	defer pCloseHandle.Call(snap)
	entry := processEntry32W{Size: uint32(unsafe.Sizeof(processEntry32W{}))}
	r, _, _ := pProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return ""
	}
	for {
		if entry.ProcessID == pid {
			return syscall.UTF16ToString(entry.ExeFile[:])
		}
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return ""
}

func lockerFromPID(pid uint32, currentPID uint32) (lockProcess, bool) {
	if pid == 0 || pid == currentPID {
		return lockProcess{}, false
	}
	h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|processDupHandle, 0, uintptr(pid))
	if h == 0 {
		return lockProcess{}, false
	}
	defer pCloseHandle.Call(h)

	start, ok := processStartTime(h)
	if !ok {
		return lockProcess{}, false
	}
	critical, criticalKnown, protected, protectedKnown := processSafetyInfo(h)
	serviceAccount, serviceKnown := processRunsAsServiceAccount(h)
	userSID, userSIDKnown := processUserSID(h)
	image := processImagePath(h)
	name := image
	if i := strings.LastIndexAny(image, `\\/`); i >= 0 && i+1 < len(image) {
		name = image[i+1:]
	}
	if name == "" {
		name = fmt.Sprintf("PID %d", pid)
	}
	sid, sidOK := processSessionID(pid)
	lp := lockProcess{name: name, imagePath: image, pid: pid, kind: rmUnknownApp, startTime: start, startKnown: true, sessionID: sid, sessionKnown: sidOK, critical: critical, criticalKnown: criticalKnown, protected: protected, protectedKnown: protectedKnown, serviceAccount: serviceAccount, serviceKnown: serviceKnown, userSID: userSID, userSIDKnown: userSIDKnown}
	return lp, true
}

func finalPathFromHandle(h uintptr) string {
	if h == 0 || h == INVALID_HANDLE_VALUE {
		return ""
	}
	size := uintptr(512)
	const maxSize = uintptr(32768)
	for size <= maxSize {
		buf := make([]uint16, int(size))
		n, _, _ := pGetFinalPathNameByHandle.Call(h, uintptr(unsafe.Pointer(&buf[0])), size, 0)
		if n == 0 {
			return ""
		}
		// A successful return excludes the terminating NUL from n. The buffer
		// only needs one extra WCHAR for that terminator, so n == size-1 is
		// already a valid success case. If the buffer is too small, Windows
		// returns the required size including the NUL.
		if n < size {
			return syscall.UTF16ToString(buf[:n])
		}
		if n >= maxSize {
			return ""
		}
		if n > maxSize/2 {
			size = maxSize
		} else {
			size *= 2
		}
	}
	return ""
}

func handleScanLockers(paths []string) ([]lockProcess, error) {
	targetKeys := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if key := canonicalComparePath(p); key != "" {
			targetKeys[key] = struct{}{}
		}
	}
	if len(targetKeys) == 0 {
		return nil, errors.New("沒有可掃描的目標")
	}

	// Prefer documented file identity when the target can be opened with compatible
	// sharing. Exclusive-sharing targets may reject this open, so canonical path
	// matching remains available as a conservative fallback using the remote handle.
	type targetHandle struct {
		handle uintptr
		id     fileIdentity
	}
	targets := make([]targetHandle, 0, len(paths))
	currentPID := uint32(os.Getpid())
	for _, path := range paths {
		op := toOperationPath(path)
		attr, _ := getAttributes(op)
		flags := uintptr(0)
		if attr != INVALID_FILE_ATTRIBUTES && attr&FILE_ATTRIBUTE_DIRECTORY != 0 {
			flags = FILE_FLAG_BACKUP_SEMANTICS
		}
		h, _, _ := pCreateFileW.Call(
			uintptr(unsafe.Pointer(u16(op))),
			uintptr(FILE_READ_ATTRIBUTES),
			uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),
			0, OPEN_EXISTING, flags, 0,
		)
		if h == 0 || h == INVALID_HANDLE_VALUE {
			continue
		}
		if id, ok := fileIdentityFromHandle(h); ok {
			targets = append(targets, targetHandle{handle: h, id: id})
		} else {
			pCloseHandle.Call(h)
		}
	}
	defer func() {
		for _, t := range targets {
			if t.handle != 0 && t.handle != INVALID_HANDLE_VALUE {
				pCloseHandle.Call(t.handle)
			}
		}
	}()

	buf, err := queryExtendedHandleBuffer()
	if err != nil {
		return nil, err
	}
	ptrSize := unsafe.Sizeof(uintptr(0))
	headerSize := ptrSize * 2
	entrySize := unsafe.Sizeof(systemHandleTableEntryInfoEx{})
	if uintptr(len(buf)) < headerSize || entrySize == 0 {
		return nil, errors.New("系統 handle 表格式無效")
	}

	base := uintptr(unsafe.Pointer(&buf[0]))
	count := *(*uintptr)(unsafe.Pointer(base))
	maxEntries := (uintptr(len(buf)) - headerSize) / entrySize
	if count > maxEntries {
		count = maxEntries
	}

	// ObjectTypeIndex is stable across handles of the same kernel object type
	// within a single snapshot. Restricting the scan to the target's type avoids
	// probing unrelated process/thread/token/section handles while still allowing
	// different opens of the same file to be matched by file identity.
	fileTypeIndices := make(map[uint16]struct{})
	for _, t := range targets {
		for i := uintptr(0); i < count; i++ {
			entry := (*systemHandleTableEntryInfoEx)(unsafe.Pointer(base + headerSize + i*entrySize))
			if uint32(entry.UniqueProcessID) == currentPID && entry.HandleValue == t.handle {
				fileTypeIndices[entry.ObjectTypeIndex] = struct{}{}
				break
			}
		}
	}
	if len(fileTypeIndices) == 0 {
		// Exclusive-sharing targets cannot be opened locally, so discover the
		// Windows File object type index from the live handle table. A single
		// duplicated sample per distinct type is enough; GetFileType identifies
		// disk-backed File objects without trusting the object-type number itself.
		typeProbeAttempts := make(map[uint16]int)
		const maxTypeProbeAttempts = 4
		for i := uintptr(0); i < count; i++ {
			entry := (*systemHandleTableEntryInfoEx)(unsafe.Pointer(base + headerSize + i*entrySize))
			pid64 := entry.UniqueProcessID
			if pid64 == 0 || pid64 > uintptr(^uint32(0)) {
				continue
			}
			pid := uint32(pid64)
			if pid == currentPID || entry.HandleValue == 0 {
				continue
			}
			idx := entry.ObjectTypeIndex
			if typeProbeAttempts[idx] >= maxTypeProbeAttempts {
				continue
			}
			procH, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|processDupHandle, 0, uintptr(pid))
			if procH == 0 || procH == INVALID_HANDLE_VALUE {
				typeProbeAttempts[idx]++
				continue
			}
			dup, ok := duplicateRemoteHandle(procH, entry.HandleValue)
			pCloseHandle.Call(procH)
			if !ok {
				typeProbeAttempts[idx]++
				continue
			}
			fileType, _, _ := pGetFileType.Call(dup)
			pCloseHandle.Call(dup)
			if uint32(fileType) == fileTypeDisk {
				fileTypeIndices[idx] = struct{}{}
				break
			}
			typeProbeAttempts[idx]++
		}
	}
	if len(fileTypeIndices) == 0 {
		return nil, errors.New("無法從系統 handle 表取得目標檔案類型")
	}

	const maxPIDs = 8192
	processHandles := make(map[uint32]uintptr)
	lockers := make(map[uint32]lockProcess)
	currentSID, currentSIDKnown := currentSessionID()

	for i := uintptr(0); i < count; i++ {
		entry := (*systemHandleTableEntryInfoEx)(unsafe.Pointer(base + headerSize + i*entrySize))
		pid64 := entry.UniqueProcessID
		if pid64 == 0 || pid64 > uintptr(^uint32(0)) {
			continue
		}
		pid := uint32(pid64)
		if pid == currentPID {
			continue
		}
		if _, ok := lockers[pid]; ok {
			continue
		}
		if _, ok := fileTypeIndices[entry.ObjectTypeIndex]; !ok {
			continue
		}

		procH, ok := processHandles[pid]
		if !ok {
			if len(processHandles) >= maxPIDs {
				continue
			}
			procH, _, _ = pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|processDupHandle, 0, uintptr(pid))
			processHandles[pid] = procH
		}
		if procH == 0 {
			continue
		}

		dup, ok := duplicateRemoteHandle(procH, entry.HandleValue)
		if !ok {
			continue
		}

		// Do not spend time probing pipes, consoles or other synchronous kernel
		// objects. The fallback exists to find file lockers, so only a disk handle
		// is relevant to the deletion decision.
		fileType, _, _ := pGetFileType.Call(dup)
		if uint32(fileType) != fileTypeDisk {
			pCloseHandle.Call(dup)
			continue
		}

		// A type-index match only says "some file-like kernel object". Confirm the
		// exact target by documented file identity when available, or by the
		// canonical final path fallback when exclusive sharing blocks target opening.
		matched := false
		if id, ok := fileIdentityFromHandle(dup); ok {
			for _, t := range targets {
				if sameFileIdentity(id, t.id) {
					matched = true
					break
				}
			}
		}
		if !matched {
			if key := canonicalComparePath(finalPathFromHandle(dup)); key != "" {
				_, matched = targetKeys[key]
			}
		}
		pCloseHandle.Call(dup)
		if !matched {
			continue
		}

		lp, ok := lockerFromPID(pid, currentPID)
		if !ok {
			// We still want to report the PID even if image/start-time inspection
			// is temporarily unavailable; termination will remain disabled because
			// the start time cannot be verified.
			lp = lockProcess{
				name:         processSnapshotName(pid),
				source:       "Windows Handle Scan",
				pid:          pid,
				kind:         rmUnknownApp,
				sessionID:    currentSID,
				sessionKnown: currentSIDKnown,
			}
			if lp.name == "" {
				lp.name = fmt.Sprintf("PID %d", pid)
			}
		}
		lp.source = "Windows Handle Scan"
		lp.handleEvidence = entry.HandleValue
		lockers[pid] = lp
	}

	for _, h := range processHandles {
		if h != 0 {
			pCloseHandle.Call(h)
		}
	}

	out := make([]lockProcess, 0, len(lockers))
	for _, l := range lockers {
		out = append(out, l)
	}
	return out, nil
}
