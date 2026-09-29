package main

import (
	"path/filepath"
	"strings"
	"unicode/utf16"
)

const windowsMaxPath = 260
const windowsMaxExtendedPath = 32767

func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}

func isExtendedPath(p string) bool {
	return strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`)
}

func isExtendedUNCPath(p string) bool {
	return strings.HasPrefix(p, `\\?\UNC\`)
}

func displayPath(p string) string {
	switch {
	case isExtendedUNCPath(p):
		return `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		return p[len(`\\?\`):]
	default:
		return p
	}
}

// normalizeInputPath keeps user-facing paths readable while normalizing
// ordinary filesystem paths. Extended/device namespaces are preserved.
func normalizeInputPath(p string) string {
	p = strings.TrimRight(p, "\x00")
	if p == "" || isExtendedPath(p) {
		return p
	}
	return filepath.Clean(p)
}

// toOperationPath returns an extended-length path for filesystem Win32 APIs.
// Device paths are deliberately left untouched because they are not normal
// filesystem targets and are rejected separately by the caller.
func toOperationPath(p string) string {
	p = normalizeInputPath(p)
	if p == "" || isExtendedPath(p) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:]
	}
	return `\\?\` + p
}

func pathDisplayLength(p string) int {
	return utf16Len(displayPath(p))
}
