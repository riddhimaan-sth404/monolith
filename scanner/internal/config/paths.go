package config

import (
	"log/slog"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32                 = windows.NewLazySystemDLL("shell32.dll")
	procSHGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
)

type knownFolderID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	folderIDDesktop    = &knownFolderID{0xB4BFCC3A, 0xDB2C, 0x424C, [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}}
	folderIDDownloads  = &knownFolderID{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}
	folderIDDocuments  = &knownFolderID{0xFDD39AD0, 0x238F, 0x46AF, [8]byte{0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}
	folderIDLocalAppData = &knownFolderID{0xF1B32785, 0x6FBA, 0x4FCF, [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}
	folderIDStartMenu  = &knownFolderID{0xA4115719, 0xD62E, 0x491D, [8]byte{0xAA, 0x7C, 0xE7, 0x4B, 0x8B, 0xE3, 0xB0, 0x67}}
)

func getKnownFolderPath(folderID *knownFolderID) string {
	if err := procSHGetKnownFolderPath.Find(); err != nil {
		slog.Warn("SHGetKnownFolderPath not available", "error", err)
		return ""
	}
	var path *uint16
	hr, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(folderID)),
		0,
		0,
		uintptr(unsafe.Pointer(&path)),
	)
	if hr != 0 {
		slog.Warn("SHGetKnownFolderPath failed", "hr", hr)
		return ""
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(path))
	return windows.UTF16PtrToString(path)
}

// ResolveQuickPaths returns the actual user folder paths using the Windows
// Shell API, which correctly handles OneDrive redirects and other known-folder
// redirections. Falls back to the input patterns if the API fails.
func ResolveQuickPaths(patterns []string) []string {
	tokens := map[string]func() string{
		"{Desktop}":     func() string { return getKnownFolderPath(folderIDDesktop) },
		"{Downloads}":   func() string { return getKnownFolderPath(folderIDDownloads) },
		"{Documents}":   func() string { return getKnownFolderPath(folderIDDocuments) },
		"{LocalAppData}": func() string { return getKnownFolderPath(folderIDLocalAppData) },
		"{StartMenu}":   func() string { return getKnownFolderPath(folderIDStartMenu) },
	}

	var resolved []string
	for _, p := range patterns {
		replaced := p
		for token, resolver := range tokens {
			r := resolver()
			if r == "" {
				continue
			}
			replaced = strings.ReplaceAll(replaced, token, r)
		}
		resolved = append(resolved, replaced)
	}
	return resolved
}
