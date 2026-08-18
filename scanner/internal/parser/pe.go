package parser

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"time"
)

// PE constants missing from Go 1.26 debug/pe for uint16 comparisons.
const (
	imageFileMachineI386   = 0x014c
	imageFileMachineAMD64  = 0x8664
	imageFileMachineIA64   = 0x0200
	imageFileMachineARM64  = 0xAA64
	imageFileMachineARMNT  = 0x01c4
	imageFileMachineThumb  = 0x01c2

	imageFileExecutableImage   = 0x0002
	imageFileLineNumsStripped  = 0x0004
	imageFileLocalSymsStripped = 0x0008
	imageFileLargeAddressAware = 0x0020
	imageFile32BitMachine      = 0x0100
	imageFileDebugStripped     = 0x0200
	imageFileSystem            = 0x1000
	imageFileDLL               = 0x2000

	imageSubsystemNative                  = 1
	imageSubsystemWindowsGUI              = 2
	imageSubsystemWindowsCUI              = 3
	imageSubsystemEFIApplication          = 10
	imageSubsystemEFIBootServiceDriver    = 11
	imageSubsystemEFIRuntimeDriver        = 12

	imageDLLCharacteristicsDynamicBase          = 0x0040
	imageDLLCharacteristicsForceIntegrity       = 0x0080
	imageDLLCharacteristicsNXCompat             = 0x0100
	imageDLLCharacteristicsNoIsolation          = 0x0200
	imageDLLCharacteristicsNoSEH                = 0x0400
	imageDLLCharacteristicsNoBind               = 0x0800
	imageDLLCharacteristicsAppContainer         = 0x1000
	imageDLLCharacteristicsWDMDriver            = 0x2000
	imageDLLCharacteristicsGuardCF              = 0x4000
	imageDLLCharacteristicsTerminalServerAware  = 0x8000

	imageScnCntInitData        = 0x00000040
	imageScnCntUninitData      = 0x00000080
	imageScnMemDiscardable     = 0x02000000
	imageScnMemNotCached       = 0x04000000
	imageScnMemNotPaged        = 0x08000000
	imageScnMemShared          = 0x10000000
	imageScnMemExecute         = 0x20000000
	imageScnMemRead            = 0x40000000
	imageScnMemWrite           = 0x80000000
)

// SectionDetail holds per-section metadata for heuristic analysis.
type SectionDetail struct {
	Name            string  `json:"name"`
	VirtualSize     uint32  `json:"virtual_size"`
	VirtualAddress  uint32  `json:"virtual_address"`
	RawDataSize     uint32  `json:"raw_data_size"`
	RawDataPtr      uint32  `json:"raw_data_ptr"`
	Entropy         float64 `json:"entropy"`
	Characteristics string  `json:"characteristics"`
	MD5             string  `json:"md5"`
}

// PEInfo holds parsed PE metadata used by heuristics, EMBER features, and reporting.
type PEInfo struct {
	Subsystem         string          `json:"subsystem"`
	MachineType       string          `json:"machine_type"`
	NumberOfSections  int             `json:"number_of_sections"`
	SectionNames      []string        `json:"section_names"`
	Sections          []SectionDetail `json:"sections"`
	ImportedDLLs      []string        `json:"imported_dlls"`
	ImportedFunctions []string        `json:"imported_functions"`
	ExportedFunctions []string        `json:"exported_functions"`
	CompileTimestamp  string          `json:"compile_timestamp"`
	EntryPoint        string          `json:"entry_point"`
	ImageBase         uint64          `json:"image_base"`
	ImageSize         uint32          `json:"image_size"`
	SizeOfCode        uint32          `json:"size_of_code"`
	SizeOfInitData    uint32          `json:"size_of_init_data"`
	SizeOfUninitData  uint32          `json:"size_of_uninit_data"`
	IsDriver          bool            `json:"is_driver"`
	IsDLL             bool            `json:"is_dll"`
	HasAuthenticode   bool            `json:"has_authenticode"`
	HasRelocations    bool            `json:"has_relocations"`
	HasTLS            bool            `json:"has_tls"`
	HasResources      bool            `json:"has_resources"`
	ResourceTypes     []string        `json:"resource_types"`
	Packed            bool            `json:"packed"`
	LinkerMajor       uint8           `json:"linker_major"`
	LinkerMinor       uint8           `json:"linker_minor"`
	OSMajor           uint16          `json:"os_major"`
	OSMinor           uint16          `json:"os_minor"`
	ImageMajor        uint16          `json:"image_major"`
	ImageMinor        uint16          `json:"image_minor"`
	SubsystemMajor    uint16          `json:"subsystem_major"`
	SubsystemMinor    uint16          `json:"subsystem_minor"`
	Characteristics   string          `json:"characteristics"`
	DllCharacteristics string         `json:"dll_characteristics"`
	StackReserve      uint64          `json:"stack_reserve"`
	StackCommit       uint64          `json:"stack_commit"`
	HeapReserve       uint64          `json:"heap_reserve"`
	HeapCommit        uint64          `json:"heap_commit"`
	RichHeaderHash    string          `json:"rich_header_hash"`
	IsDotNet          bool            `json:"is_dotnet"`
}

// ParsePE reads a PE file from disk and returns parsed metadata.
func ParsePE(path string) (*PEInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePEFromBytes(data)
}

// ParsePEFromBytes parses a PE file from an in-memory byte slice.
// Used by the staged scanner pipeline after hashing to avoid re-reading the file.
func ParsePEFromBytes(data []byte) (*PEInfo, error) {
	reader := bytes.NewReader(data)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return nil, fmt.Errorf("not a valid PE file: %w", err)
	}
	defer peFile.Close()

	info := &PEInfo{}

	// Machine type (uint16 in Go 1.26)
	info.MachineType = machineTypeString(peFile.FileHeader.Machine)

	// File header characteristics
	info.Characteristics = characteristicsString(peFile.FileHeader.Characteristics)

	// Optional header info
	populateOptionalHeader(peFile, info)

	// Compile timestamp
	if peFile.FileHeader.TimeDateStamp != 0 {
		t := time.Unix(int64(peFile.FileHeader.TimeDateStamp), 0)
		info.CompileTimestamp = t.UTC().Format(time.RFC3339)
	}

	// Sections
	info.NumberOfSections = len(peFile.Sections)
	for _, section := range peFile.Sections {
		info.SectionNames = append(info.SectionNames, section.Name)
		sd := buildSectionDetail(section)
		info.Sections = append(info.Sections, sd)
	}

	// Imports — Go 1.26 uses methods instead of direct fields
	libraries, err := peFile.ImportedLibraries()
	if err == nil {
		info.ImportedDLLs = libraries
	}
	symbols, err := peFile.ImportedSymbols()
	if err == nil {
		info.ImportedFunctions = symbols
	}

	// Exports — Go 1.26 has no direct export API; parse via data directory
	exports := parseExports(peFile, data)
	info.ExportedFunctions = exports

	// .NET detection: check COM descriptor directory entry (index 14)
	info.IsDotNet = isDotNetAssembly(peFile, data)

	// Data directory analysis
	checkDataDirectories(peFile, info)

	// Packing detection
	info.Packed = detectPacking(info.Sections)

	// Rich header extraction
	info.RichHeaderHash = extractRichHeaderHash(data)

	return info, nil
}

// --- helpers ---

func machineTypeString(m uint16) string {
	switch m {
	case imageFileMachineI386:
		return "I386"
	case imageFileMachineAMD64:
		return "AMD64"
	case imageFileMachineIA64:
		return "IA64"
	case imageFileMachineARM64:
		return "ARM64"
	case imageFileMachineARMNT:
		return "ARMNT"
	case imageFileMachineThumb:
		return "THUMB"
	default:
		return fmt.Sprintf("0x%x", m)
	}
}

func characteristicsString(c uint16) string {
	var parts []string
	if c&pe.IMAGE_FILE_RELOCS_STRIPPED != 0 {
		parts = append(parts, "RELOCS_STRIPPED")
	}
	if c&imageFileExecutableImage != 0 {
		parts = append(parts, "EXECUTABLE")
	}
	if c&imageFileLineNumsStripped != 0 {
		parts = append(parts, "LINE_NUMS_STRIPPED")
	}
	if c&imageFileLocalSymsStripped != 0 {
		parts = append(parts, "LOCAL_SYMS_STRIPPED")
	}
	if c&imageFileLargeAddressAware != 0 {
		parts = append(parts, "LARGE_ADDRESS_AWARE")
	}
	if c&imageFile32BitMachine != 0 {
		parts = append(parts, "32BIT_MACHINE")
	}
	if c&imageFileDebugStripped != 0 {
		parts = append(parts, "DEBUG_STRIPPED")
	}
	if c&imageFileDLL != 0 {
		parts = append(parts, "DLL")
	}
	if c&imageFileSystem != 0 {
		parts = append(parts, "SYSTEM")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", c)
	}
	return joinStrings(parts, "|")
}

func dllCharacteristicsString(c uint16) string {
	var parts []string
	if c&imageDLLCharacteristicsDynamicBase != 0 {
		parts = append(parts, "DYNAMIC_BASE")
	}
	if c&imageDLLCharacteristicsForceIntegrity != 0 {
		parts = append(parts, "FORCE_INTEGRITY")
	}
	if c&imageDLLCharacteristicsNXCompat != 0 {
		parts = append(parts, "NX_COMPAT")
	}
	if c&imageDLLCharacteristicsNoIsolation != 0 {
		parts = append(parts, "NO_ISOLATION")
	}
	if c&imageDLLCharacteristicsNoSEH != 0 {
		parts = append(parts, "NO_SEH")
	}
	if c&imageDLLCharacteristicsNoBind != 0 {
		parts = append(parts, "NO_BIND")
	}
	if c&imageDLLCharacteristicsAppContainer != 0 {
		parts = append(parts, "APPCONTAINER")
	}
	if c&imageDLLCharacteristicsWDMDriver != 0 {
		parts = append(parts, "WDM_DRIVER")
	}
	if c&imageDLLCharacteristicsGuardCF != 0 {
		parts = append(parts, "GUARD_CF")
	}
	if c&imageDLLCharacteristicsTerminalServerAware != 0 {
		parts = append(parts, "TERMINAL_SERVER_AWARE")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", c)
	}
	return joinStrings(parts, "|")
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	b := []byte(parts[0])
	for _, s := range parts[1:] {
		b = append(b, sep...)
		b = append(b, s...)
	}
	return string(b)
}

func populateOptionalHeader(peFile *pe.File, info *PEInfo) {
	if oh64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		info.ImageBase = oh64.ImageBase
		info.SizeOfCode = oh64.SizeOfCode
		info.SizeOfInitData = oh64.SizeOfInitializedData
		info.SizeOfUninitData = oh64.SizeOfUninitializedData
		info.EntryPoint = fmt.Sprintf("0x%x", oh64.AddressOfEntryPoint)
		info.ImageSize = oh64.SizeOfImage
		info.LinkerMajor = oh64.MajorLinkerVersion
		info.LinkerMinor = oh64.MinorLinkerVersion
		info.OSMajor = oh64.MajorOperatingSystemVersion
		info.OSMinor = oh64.MinorOperatingSystemVersion
		info.ImageMajor = oh64.MajorImageVersion
		info.ImageMinor = oh64.MinorImageVersion
		info.SubsystemMajor = oh64.MajorSubsystemVersion
		info.SubsystemMinor = oh64.MinorSubsystemVersion
		info.DllCharacteristics = dllCharacteristicsString(oh64.DllCharacteristics)
		info.StackReserve = oh64.SizeOfStackReserve
		info.StackCommit = oh64.SizeOfStackCommit
		info.HeapReserve = oh64.SizeOfHeapReserve
		info.HeapCommit = oh64.SizeOfHeapCommit
		info.Subsystem = subsystemString(oh64.Subsystem, &info.IsDriver)
		info.IsDLL = peFile.FileHeader.Characteristics&imageFileDLL != 0
		return
	}

	if oh32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		info.ImageBase = uint64(oh32.ImageBase)
		info.SizeOfCode = oh32.SizeOfCode
		info.SizeOfInitData = oh32.SizeOfInitializedData
		info.SizeOfUninitData = oh32.SizeOfUninitializedData
		info.EntryPoint = fmt.Sprintf("0x%x", oh32.AddressOfEntryPoint)
		info.ImageSize = oh32.SizeOfImage
		info.LinkerMajor = oh32.MajorLinkerVersion
		info.LinkerMinor = oh32.MinorLinkerVersion
		info.OSMajor = oh32.MajorOperatingSystemVersion
		info.OSMinor = oh32.MinorOperatingSystemVersion
		info.ImageMajor = oh32.MajorImageVersion
		info.ImageMinor = oh32.MinorImageVersion
		info.SubsystemMajor = oh32.MajorSubsystemVersion
		info.SubsystemMinor = oh32.MinorSubsystemVersion
		info.DllCharacteristics = dllCharacteristicsString(oh32.DllCharacteristics)
		info.StackReserve = uint64(oh32.SizeOfStackReserve)
		info.StackCommit = uint64(oh32.SizeOfStackCommit)
		info.HeapReserve = uint64(oh32.SizeOfHeapReserve)
		info.HeapCommit = uint64(oh32.SizeOfHeapCommit)
		info.Subsystem = subsystemString(oh32.Subsystem, &info.IsDriver)
		info.IsDLL = peFile.FileHeader.Characteristics&imageFileDLL != 0
	}
}

func subsystemString(s uint16, isDriver *bool) string {
	switch s {
	case imageSubsystemNative:
		*isDriver = true
		return "NATIVE"
	case imageSubsystemWindowsGUI:
		return "WINDOWS_GUI"
	case imageSubsystemWindowsCUI:
		return "WINDOWS_CUI"
	case imageSubsystemEFIApplication:
		return "EFI_APPLICATION"
	case imageSubsystemEFIBootServiceDriver:
		*isDriver = true
		return "EFI_BOOT"
	case imageSubsystemEFIRuntimeDriver:
		*isDriver = true
		return "EFI_RUNTIME"
	default:
		return fmt.Sprintf("SUBSYSTEM_%d", s)
	}
}

func buildSectionDetail(s *pe.Section) SectionDetail {
	sd := SectionDetail{
		Name:            s.Name,
		VirtualSize:     s.VirtualSize,
		VirtualAddress:  s.VirtualAddress,
		RawDataSize:     s.Size,
		RawDataPtr:      s.Offset,
		Characteristics: sectionCharacteristicsString(s.Characteristics),
	}

	sectionData, err := s.Data()
	if err == nil && len(sectionData) > 0 {
		sd.Entropy = computeEntropy(sectionData)
		h := md5.Sum(sectionData)
		sd.MD5 = hex.EncodeToString(h[:])
	}

	return sd
}

func sectionCharacteristicsString(c uint32) string {
	var parts []string
	if c&pe.IMAGE_SCN_CNT_CODE != 0 {
		parts = append(parts, "CODE")
	}
	if c&imageScnCntInitData != 0 {
		parts = append(parts, "INIT_DATA")
	}
	if c&imageScnCntUninitData != 0 {
		parts = append(parts, "UNINIT_DATA")
	}
	if c&imageScnMemExecute != 0 {
		parts = append(parts, "EXECUTE")
	}
	if c&imageScnMemRead != 0 {
		parts = append(parts, "READ")
	}
	if c&imageScnMemWrite != 0 {
		parts = append(parts, "WRITE")
	}
	if c&imageScnMemDiscardable != 0 {
		parts = append(parts, "DISCARDABLE")
	}
	if c&imageScnMemNotCached != 0 {
		parts = append(parts, "NOT_CACHED")
	}
	if c&imageScnMemNotPaged != 0 {
		parts = append(parts, "NOT_PAGED")
	}
	if c&imageScnMemShared != 0 {
		parts = append(parts, "SHARED")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", c)
	}
	return joinStrings(parts, "|")
}

func computeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	e := 0.0
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			e -= p * math.Log2(p)
		}
	}
	return math.Round(e*100) / 100
}

// parseExports attempts to extract exported function names from the export
// directory. Go 1.26 removed the Exports field, so we parse manually from the
// data directory entry in the raw bytes.
func parseExports(peFile *pe.File, data []byte) []string {
	oh, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		oh32, ok32 := peFile.OptionalHeader.(*pe.OptionalHeader32)
		if !ok32 {
			return nil
		}
		// PE32+ but PE32 uses DataDirectory
		if int(oh32.NumberOfRvaAndSizes) <= pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			return nil
		}
		exportDir := oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		return readExportNames(data, exportDir)
	}

	if int(oh.NumberOfRvaAndSizes) <= pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		return nil
	}
	exportDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	return readExportNames(data, exportDir)
}

func readExportNames(data []byte, dir pe.DataDirectory) []string {
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	// Locate the export directory RVA within the file.
	// We need to translate the RVA to a file offset by finding which section
	// contains it. For simplicity, we assume the export directory is in a
	// section that is mapped 1:1 (typical for .exp or .edata).
	// Without full section mapping, we conservatively return nil.
	// Full implementation would walk sections and compute file offset from RVA.
	return nil
}

func checkDataDirectories(peFile *pe.File, info *PEInfo) {
	// Check for resources by section name
	for _, s := range peFile.Sections {
		if s.Name == ".rsrc" {
			info.HasResources = true
			info.ResourceTypes = extractResourceTypes(s)
			break
		}
	}

	// TLS section
	for _, s := range peFile.Sections {
		if s.Name == ".tls" {
			info.HasTLS = true
			break
		}
	}

	// Relocations
	if peFile.FileHeader.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED == 0 {
		info.HasRelocations = true
	}

	info.HasAuthenticode = checkAuthenticode(peFile)
}

func checkAuthenticode(peFile *pe.File) bool {
	return false
}

func extractResourceTypes(s *pe.Section) []string {
	return []string{"present"}
}

// extractRichHeaderHash extracts and hashes the Rich header from the DOS stub area.
func extractRichHeaderHash(data []byte) string {
	if len(data) < 64 {
		return ""
	}

	e_lfanew := binary.LittleEndian.Uint32(data[0x3C:])
	if e_lfanew >= uint32(len(data)) || e_lfanew < 64 {
		return ""
	}

	start := uint32(64)
	end := e_lfanew
	if start >= end || end-start > 4096 {
		return ""
	}

	richArea := data[start:end]
	richPos := findRichMarker(richArea)
	if richPos < 0 {
		return ""
	}

	h := md5.Sum(richArea[richPos:])
	return hex.EncodeToString(h[:])
}

func findRichMarker(data []byte) int {
	marker := []byte{0x52, 0x69, 0x63, 0x68, 0x00}
	for i := len(data) - len(marker); i >= 0; i-- {
		match := true
		for j := 0; j < len(marker); j++ {
			if data[i+j] != marker[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// detectPacking uses section-level heuristics to detect packed executables.
func detectPacking(sections []SectionDetail) bool {
	for i, section := range sections {
		switch section.Name {
		case ".UPX0", ".UPX1", ".packed", ".themida", ".MPRESS",
			".ASPack", ".ASPack1", ".aspr", ".enigma",
			".vmp0", ".vmp1", ".vmp2", ".armadillo",
			".nsp0", ".nsp1", ".nsp2":
			return true
		}
		if section.RawDataSize > 0 && section.VirtualSize > section.RawDataSize*10 {
			return true
		}
		if section.VirtualSize > 0 && section.RawDataSize == 0 && i > 0 {
			return true
		}
		if section.Entropy > 7.5 {
			return true
		}
	}
	return false
}

// ReadUint64At reads a uint64 from a byte slice at the given offset.
func ReadUint64At(data []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(data[offset:])
}

const imageDirectoryEntryCOMDescriptor = 14

// isDotNetAssembly checks whether the PE file has a .NET CLI header (COM descriptor).
// It reads the data directory entry 14 from the optional header.
func isDotNetAssembly(peFile *pe.File, data []byte) bool {
	// Locate the optional header
	oh, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		oh32, ok32 := peFile.OptionalHeader.(*pe.OptionalHeader32)
		if !ok32 {
			return false
		}
		if int(oh32.NumberOfRvaAndSizes) <= imageDirectoryEntryCOMDescriptor {
			return false
		}
		dir := oh32.DataDirectory[imageDirectoryEntryCOMDescriptor]
		return dir.Size > 0
	}

	if int(oh.NumberOfRvaAndSizes) <= imageDirectoryEntryCOMDescriptor {
		return false
	}
	dir := oh.DataDirectory[imageDirectoryEntryCOMDescriptor]
	return dir.Size > 0
}

// CLIHeaderSize is the size of a .NET CLI header (COR20) in bytes.
const CLIHeaderSize = 72
