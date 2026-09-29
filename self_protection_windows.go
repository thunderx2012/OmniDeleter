//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var selfExecutableHandle uintptr

func protectOwnExecutable() error {
	if selfExecutableHandle != 0 && selfExecutableHandle != INVALID_HANDLE_VALUE {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	op := toOperationPath(exe)
	h, _, e := pCreateFileW.Call(
		uintptr(unsafe.Pointer(u16(op))),
		uintptr(FILE_READ_DATA|FILE_READ_ATTRIBUTES),
		uintptr(FILE_SHARE_READ), // deny both rename/delete and write-through replacement while running
		0, OPEN_EXISTING, 0, 0,
	)
	if h == 0 || h == INVALID_HANDLE_VALUE {
		code := procError(e)
		if code == 0 {
			return errors.New("無法保護自身執行檔")
		}
		return syscall.Errno(code)
	}
	selfExecutableHandle = h
	return nil
}

func releaseOwnExecutable() {
	if selfExecutableHandle != 0 && selfExecutableHandle != INVALID_HANDLE_VALUE {
		pCloseHandle.Call(selfExecutableHandle)
		selfExecutableHandle = 0
	}
}
