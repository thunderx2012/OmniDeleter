//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"
	"unsafe"
)

type rescueContainer struct {
	path     string
	handle   uintptr
	identity objectIdentity
}

func createUniqueRescueRoot(volumeRoot string) (*rescueContainer, error) {
	// Check the volume root with only the attributes permission required for
	// identity verification. Creating a child directory does not require DELETE
	// access on the volume root itself.
	rootHandle, err := openRenameParent(volumeRoot, FILE_ADD_SUBDIRECTORY)
	if err != nil {
		return nil, fmt.Errorf("無法在 volume 根目錄建立救援容器：%w", err)
	}
	pCloseHandle.Call(rootHandle)

	for x := 1; x <= 1000000; x++ {
		name := fmt.Sprintf("OmniDeleter_%d", x)
		candidate := makePathCandidate(volumeRoot, name)
		state, code := pathStateOf(candidate)
		if state == pathExists {
			continue
		}
		if state == pathUnknown {
			// An unreadable candidate is conservatively treated as occupied.
			_ = code
			continue
		}
		r, _, e := pCreateDirectoryW.Call(uintptr(unsafe.Pointer(u16(toOperationPath(candidate)))), 0)
		if r == 0 {
			if procError(e) == ERROR_ALREADY_EXISTS {
				continue
			}
			continue
		}

		// Keep an identity-bearing read handle to the exact directory we just
		// created. Do not require DELETE access at this point: Windows security
		// software, indexers, or other transient actors may briefly deny-delete
		// opens on a newly-created directory even though the directory is fully
		// usable as the rescue destination. DELETE access is acquired lazily only
		// if a failed rescue actually needs cleanup.
		h, openErr := openIdentityPath(candidate, true)
		if openErr != nil {
			return nil, fmt.Errorf("救援容器建立後無法確認其身分：%w", openErr)
		}
		info, infoErr := fileInformationFromHandle(h)
		if infoErr != nil {
			pCloseHandle.Call(h)
			return nil, fmt.Errorf("救援容器建立後無法確認其身分：%w", infoErr)
		}
		if info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			pCloseHandle.Call(h)
			return nil, errors.New("救援容器建立後不是普通資料夾，為避免誤操作本次救援停止")
		}
		return &rescueContainer{
			path:     normalizeInputPath(candidate),
			handle:   h,
			identity: objectIdentityFromFileInformation(info),
		}, nil
	}
	return nil, errors.New("無法建立可用的 OmniDeleter_x 救援容器")
}

func markRescueContainerDeleteByHandle(container *rescueContainer) error {
	if container == nil || container.handle == 0 || container.handle == INVALID_HANDLE_VALUE {
		return errors.New("救援容器控制權無效，未自動清理")
	}
	info, err := fileInformationFromHandle(container.handle)
	if err != nil {
		return fmt.Errorf("無法重新確認救援容器身分：%w", err)
	}
	if info.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("救援容器已不是本工具建立的普通空資料夾，為避免誤刪未自動清理")
	}
	if !sameObjectIdentity(container.identity, objectIdentityFromFileInformation(info)) {
		return errors.New("救援容器身分已改變，為避免誤刪未自動清理")
	}

	// Acquire DELETE only when failure cleanup is actually required. This avoids
	// turning a transient deny-delete handle on a freshly-created destination
	// into a false rescue failure. The identity-bearing read handle remains held
	// while this second handle is opened and is also checked again below.
	var deleteHandle uintptr
	var openErr error
	for attempt := 0; attempt < 8; attempt++ {
		deleteHandle, openErr = openRenameParent(container.path, DELETE_ACCESS)
		if openErr == nil {
			break
		}
		var codeErr win32CodeError
		code := uint32(0)
		if errors.As(openErr, &codeErr) {
			code = uint32(codeErr)
		}
		if code != ERROR_SHARING_VIOLATION && code != ERROR_LOCK_VIOLATION {
			break
		}
		if attempt < 7 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if openErr != nil {
		return fmt.Errorf("無法取得救援容器的清理權限：%w", openErr)
	}
	defer pCloseHandle.Call(deleteHandle)
	deleteInfo, deleteInfoErr := fileInformationFromHandle(deleteHandle)
	if deleteInfoErr != nil {
		return fmt.Errorf("無法確認救援容器清理 handle 身分：%w", deleteInfoErr)
	}
	if deleteInfo.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 || deleteInfo.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 || !sameObjectIdentity(container.identity, objectIdentityFromFileInformation(deleteInfo)) {
		return errors.New("救援容器清理 handle 的身分已改變，為避免誤刪未自動清理")
	}

	type fileDispositionInfo struct {
		DeleteFile byte
	}
	fdi := fileDispositionInfo{DeleteFile: 1}
	r, _, setErr := pSetFileInformationByHandle.Call(
		deleteHandle,
		FileDispositionInfoClass,
		uintptr(unsafe.Pointer(&fdi)),
		unsafe.Sizeof(fdi),
	)
	if r != 0 {
		return nil
	}
	code := procError(setErr)
	if code == ERROR_INVALID_PARAMETER || code == ERROR_NOT_SUPPORTED || code == ERROR_INVALID_FUNCTION {
		type fileDispositionInfoEx struct {
			Flags uint32
		}
		ex := fileDispositionInfoEx{
			Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK,
		}
		r, _, exErr := pSetFileInformationByHandle.Call(
			deleteHandle,
			21,
			uintptr(unsafe.Pointer(&ex)),
			unsafe.Sizeof(ex),
		)
		if r != 0 {
			return nil
		}
		return win32Error(procError(exErr))
	}
	return win32Error(code)
}

func cleanupRescueContainer(container *rescueContainer) error {
	if container == nil {
		return nil
	}
	if container.handle != 0 && container.handle != INVALID_HANDLE_VALUE {
		defer func() {
			pCloseHandle.Call(container.handle)
			container.handle = 0
		}()
		return markRescueContainerDeleteByHandle(container)
	}
	return errors.New("救援容器控制權無效，未自動清理")
}

func pathRescueFolder(path string) (string, error) {
	path = normalizeInputPath(path)
	if err := validateTarget(path); err != nil {
		return "", err
	}
	attr, code := getAttributes(toOperationPath(path))
	if attr == INVALID_FILE_ATTRIBUTES {
		return "", win32Error(code)
	}
	if attr&FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", errors.New("「資料夾救援」只能處理單一資料夾")
	}
	if attr&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("為避免改動特殊連結／Reparse Point，本次路徑救援拒絕處理該資料夾")
	}

	volumeRoot := volumeRootForWindowsPath(displayPath(path))
	if volumeRoot == "" {
		return "", errors.New("無法可靠取得此資料夾所在的 volume 根目錄，因此未執行救援")
	}

	container, err := createUniqueRescueRoot(volumeRoot)
	if err != nil {
		return "", err
	}
	keepContainer := false
	defer func() {
		if keepContainer {
			if container != nil && container.handle != 0 && container.handle != INVALID_HANDLE_VALUE {
				pCloseHandle.Call(container.handle)
				container.handle = 0
			}
			return
		}
		_ = cleanupRescueContainer(container)
	}()

	destPath := makePathCandidate(container.path, "A")
	if state, code := pathStateOf(destPath); state == pathExists {
		return "", errors.New("救援目的地 A 已存在，為避免覆蓋資料本次未執行")
	} else if state == pathUnknown {
		return "", win32Error(code)
	}

	// Preparation: prove that the source object can be opened with DELETE
	// access and the new parent can accept a child directory. No move occurs
	// until both handles and the source identity are valid.
	src, err := openRenameSource(path, true)
	if err != nil {
		return "", fmt.Errorf("來源資料夾目前無法以搬移所需權限開啟：%w", err)
	}
	defer pCloseHandle.Call(src)

	// The destination container is held by identity-bearing handle from the
	// moment it is created. Recheck that same object immediately before commit.
	rootInfo, rootErr := fileInformationFromHandle(container.handle)
	if rootErr != nil {
		return "", fmt.Errorf("無法再次確認救援容器：%w", rootErr)
	}
	if rootInfo.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0 || rootInfo.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 || !sameObjectIdentity(container.identity, objectIdentityFromFileInformation(rootInfo)) {
		return "", errors.New("救援容器身分在搬移前已改變，為避免誤操作本次救援停止")
	}

	before, err := objectIdentityFromHandle(src)
	if err != nil {
		return "", fmt.Errorf("無法確認來源資料夾身分：%w", err)
	}

	// Final pre-commit identity check through the same source handle. The
	// target container already exists and is controlled by this operation.
	finalAttr, finalCode := getAttributes(toOperationPath(path))
	if finalAttr == INVALID_FILE_ATTRIBUTES {
		return "", win32Error(finalCode)
	}
	if finalAttr&FILE_ATTRIBUTE_DIRECTORY == 0 || finalAttr&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("來源資料夾狀態在搬移前已改變，本次救援停止")
	}
	current, err := objectIdentityFromHandle(src)
	if err != nil || !sameObjectIdentity(before, current) {
		return "", errors.New("來源資料夾身分在搬移前無法再次確認，本次救援停止")
	}
	volumeIdentity, err := objectIdentityAtPath(volumeRoot, true)
	if err != nil {
		return "", fmt.Errorf("無法再次確認救援目的地所在的 volume：%w", err)
	}
	if volumeIdentity.volumeSerial != before.volumeSerial {
		return "", errors.New("救援目的地與來源不在同一個 volume，為避免 Copy→Delete 本次救援停止")
	}

	err = renameByHandle(src, toOperationPath(destPath))
	// A successful SetFileInformationByHandle(FileRenameInfo) is the authoritative
	// move commit, just as it is for file rename. Do not re-open destPath merely
	// to re-prove an operation that Windows has already reported as successful;
	// a transient sharing/indexing denial can make that observation fail even
	// though the directory was moved successfully. The source handle remains
	// valid after the move and the caller can safely commit the new list state.
	if err == nil {
		keepContainer = true
		return normalizeInputPath(destPath), nil
	}

	// Only a failed move call is ambiguous. Preserve the existing conservative
	// fallback: first use the still-open source handle, then re-check the
	// destination identity before deciding whether the operation actually
	// committed despite the API error. Never delete or overwrite the source in
	// this verification path.
	if waitForHandlePath(src, destPath, 8, 50*time.Millisecond) {
		keepContainer = true
		return normalizeInputPath(destPath), nil
	}
	if identity, verifyErr := objectIdentityAtPath(destPath, true); verifyErr == nil {
		oldState, _ := pathStateOf(path)
		if oldState == pathMissing && sameObjectIdentity(before, identity) {
			keepContainer = true
			return normalizeInputPath(destPath), nil
		}
	}
	return "", err
}

func rescueDisplayMessage(oldPath, newPath string) string {
	return fmt.Sprintf("路徑救援完成。\n\n原始物件：%s\n已移至：%s\n\n原本的深層父資料夾與其內容未由本功能刪除。", displayPath(oldPath), displayPath(newPath))
}

func rescueFailureMessage(err error) string {
	if err == nil {
		return "資料夾救援失敗。原始物件未主動刪除。"
	}
	return fmt.Sprintf("資料夾救援失敗。\n\n原始物件未主動刪除。\n\n原因：%v", err)
}
