package parser

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
)

// PDFInfo holds parsed PDF metadata for feature extraction and heuristics.
type PDFInfo struct {
	Version       string   `json:"version"`
	PageCount     int      `json:"page_count"`
	ObjectCount   int      `json:"object_count"`
	StreamCount   int      `json:"stream_count"`
	HasJS         bool     `json:"has_js"`
	HasOpenAction bool     `json:"has_open_action"`
	HasLaunch     bool     `json:"has_launch"`
	HasEmbedded   bool     `json:"has_embedded"`
	HasURI        bool     `json:"has_uri"`
	Encrypted     bool     `json:"encrypted"`
	Linearized    bool     `json:"linearized"`
	XrefTableSize int      `json:"xref_table_size"`
	Filters       []string `json:"filters"`
	URLCount      int      `json:"url_count"`
	JSSnippets    int      `json:"js_snippets"`
	StreamSizes   []int64  `json:"-"`
	Objects       int      `json:"objects"`
}

var (
	pdfHeaderRe = regexp.MustCompile(`%PDF-(\d+\.\d+)`)
	objRe       = regexp.MustCompile(`(\d+)\s+\d+\s+obj`)
	streamRe    = regexp.MustCompile(`stream\n`)
	filterRe    = regexp.MustCompile(`/Filter\s*(\[.*?\]|/\w+)`)
	jsRe        = regexp.MustCompile(`(?i)/JavaScript|/JS\b`)
	actionRe    = regexp.MustCompile(`(?i)/OpenAction|/AA\b|/AdditionalAction`)
	launchRe    = regexp.MustCompile(`(?i)/Launch\b`)
	embeddedRe  = regexp.MustCompile(`(?i)/EmbeddedFile|/F\s*\(|/EF\b`)
	uriRe       = regexp.MustCompile(`(?i)/URI\b|/Action\s*<</URI`)
	encryptRe   = regexp.MustCompile(`(?i)/Encrypt\b`)
	linearRe    = regexp.MustCompile(`(?i)/Linearized\b`)
	urlRe       = regexp.MustCompile(`https?://[^\s)>\/"]+`)
	xrefRe      = regexp.MustCompile(`\bxref\b`)
	pageRe      = regexp.MustCompile(`(?i)/Type\s*/Page[^s]`)
)

// ParsePDFFromBytes extracts PDF metadata from raw file bytes.
func ParsePDFFromBytes(data []byte) (*PDFInfo, error) {
	info := &PDFInfo{}
	text := string(data)

	if m := pdfHeaderRe.FindStringSubmatch(text); len(m) > 1 {
		info.Version = m[1]
	}

	objMatches := objRe.FindAllStringSubmatch(text, -1)
	info.ObjectCount = len(objMatches)

	streams := streamRe.FindAllString(text, -1)
	info.StreamCount = len(streams)

	for _, sm := range streamRe.FindAllStringIndex(text, -1) {
		start := sm[1]
		endIdx := bytes.Index(data[start:], []byte("\nendstream"))
		if endIdx > 0 && endIdx < 10*1024*1024 {
			info.StreamSizes = append(info.StreamSizes, int64(endIdx))
		}
	}

	jsSnippets := jsRe.FindAllString(text, -1)
	info.HasJS = len(jsSnippets) > 0
	info.JSSnippets = len(jsSnippets)

	info.HasOpenAction = actionRe.MatchString(text)
	info.HasLaunch = launchRe.MatchString(text)
	info.HasEmbedded = embeddedRe.MatchString(text)
	info.HasURI = uriRe.MatchString(text)
	info.Encrypted = encryptRe.MatchString(text)
	info.Linearized = linearRe.MatchString(text)

	urls := urlRe.FindAllString(text, -1)
	info.URLCount = len(urls)

	filterMatches := filterRe.FindAllStringSubmatch(text, -1)
	filterSet := make(map[string]struct{})
	for _, fm := range filterMatches {
		f := strings.TrimPrefix(fm[1], "/")
		f = strings.Trim(f, "[]")
		for _, part := range strings.Fields(f) {
			part = strings.TrimPrefix(part, "/")
			if part != "" {
				filterSet[part] = struct{}{}
			}
		}
	}
	for f := range filterSet {
		info.Filters = append(info.Filters, f)
	}

	if xm := xrefRe.FindAllString(text, -1); len(xm) > 0 {
		info.XrefTableSize = len(xm)
	}

	info.PageCount = len(pageRe.FindAllString(text, -1))
	info.Objects = info.ObjectCount

	return info, nil
}

// ParsePDF reads and parses a PDF file from the given path.
func ParsePDF(path string) (*PDFInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pdf: %w", err)
	}
	return ParsePDFFromBytes(data)
}

// IsPDFFile checks if a file is a PDF by its header.
func IsPDFFile(data []byte) bool {
	return len(data) >= 4 && string(data[:4]) == "%PDF"
}

// ExtractPDFStrings extracts printable string literals from PDF for EMBER features.
func ExtractPDFStrings(data []byte) []string {
	var out []string
	seen := make(map[string]struct{})

	inParen := false
	var buf bytes.Buffer
	for _, b := range data {
		if b == '(' && !inParen {
			inParen = true
			buf.Reset()
			continue
		}
		if b == ')' && inParen {
			s := buf.String()
			if len(s) >= 4 && !strings.HasPrefix(s, "\\") {
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					out = append(out, s)
				}
			}
			inParen = false
			continue
		}
		if inParen {
			if b >= 32 && b <= 126 {
				buf.WriteByte(b)
			}
		}
	}
	return out
}

// ComputePDFStringStats computes string statistics for EMBER features.
func ComputePDFStringStats(data []byte) (avgLen float64, entropy float64, count int) {
	strs := ExtractPDFStrings(data)
	if len(strs) == 0 {
		return 0, 0, 0
	}

	var totalLen int
	for _, s := range strs {
		totalLen += len(s)
	}
	avgLen = float64(totalLen) / float64(len(strs))

	freq := make(map[rune]int)
	for _, s := range strs {
		for _, ch := range s {
			freq[ch]++
		}
	}
	totalRunes := 0
	for _, n := range freq {
		totalRunes += n
	}
	if totalRunes > 0 {
		var e float64
		for _, n := range freq {
			p := float64(n) / float64(totalRunes)
			e -= p * math.Log2(p)
		}
		entropy = e
	}
	return avgLen, entropy, len(strs)
}
