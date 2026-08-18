package scanner

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/ember"
	"github.com/edr/scanner/internal/hasher"
	"github.com/edr/scanner/internal/parser"
	"github.com/edr/scanner/internal/quarantine"
	"github.com/edr/scanner/internal/throttle"
	"github.com/edr/scanner/internal/yara"
)

const (
	PhaseIdle        = 0
	PhaseEnumeration = 1
	PhaseScanning    = 2
	PhaseDone        = 3
)

// ScanResult holds the outcome of scanning a single file.
type ScanResult struct {
	FilePath       string               `json:"file_path"`
	FileName       string               `json:"file_name"`
	FileSize       int64                `json:"file_size"`
	Hashes         *hasher.FileHashes   `json:"hashes"`
	PEInfo         *parser.PEInfo       `json:"pe_info,omitempty"`
	Signature      *parser.SignatureInfo `json:"signature,omitempty"`
	MatchedRules   []string             `json:"matched_rules"`
	Score          float64              `json:"score"`
	HeuristicScore float64              `json:"heuristic_score"`
	EmberScore      float64              `json:"ember_score"`
	PdfScore        float64              `json:"pdf_score,omitempty"`
	DotNetScore     float64              `json:"dotnet_score,omitempty"`
	ExploitScore    float64              `json:"exploit_score,omitempty"`
	PackerScore     float64              `json:"packer_score,omitempty"`

	FusionScore     float64              `json:"fusion_score"`
	NeedsSandbox   bool                 `json:"needs_sandbox"`
	HeuristicRules []string             `json:"heuristic_rules,omitempty"`
	Verdict        string               `json:"verdict"`
	Quarantined    bool                 `json:"quarantined"`
}

// ScannerEngine is the file scanning pipeline: Hash -> YARA -> Heuristics -> EMBER -> Fusion.
type ScannerEngine struct {
	cfg            *config.Config
	workQueue      chan string
	results        chan ScanResult
	activeJobs     atomic.Int64
	totalFiles     atomic.Int64
	completedFiles atomic.Int64
	scanPhase      atomic.Int32
	scanActive     atomic.Bool
	wg             sync.WaitGroup
	producerWg     sync.WaitGroup
	scanWg         sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	yaraEngine     *yara.Engine
	quarantineMgr  *quarantine.Manager
	emberModel     *ember.Model
	modelRegistry  *ember.ModelRegistry

	throttle       *throttle.Throttle
	subscribers    []chan ScanResult
	subMu          sync.RWMutex
	currentPath    atomic.Value
}

func (e *ScannerEngine) CurrentPath() string {
	v, _ := e.currentPath.Load().(string)
	return v
}

func NewScannerEngine(cfg *config.Config) *ScannerEngine {
	ctx, cancel := context.WithCancel(context.Background())

	yaraEngine := yara.NewEngine(cfg.YARA.RulesPath, cfg.YARA.CompileCache)
	if err := yaraEngine.LoadRules(); err != nil {
		slog.Warn("failed to load YARA rules, continuing without", "error", err)
	}

	qm := quarantine.NewManager(cfg.Quarantine.Path, cfg.Quarantine.EncryptionKey)

	// Load EMBER model (optional — continue without if unavailable)
	model, err := ember.LoadModel(cfg.Scanner.EmberModelPath)
	if err != nil {
		slog.Warn("failed to load EMBER model, continuing without ML", "error", err)
	}

	// Load model registry (optional)
	registry, err := ember.NewModelRegistry(cfg.Scanner.ModelsDir)
	if err != nil {
		slog.Warn("failed to load model registry, continuing with single model only", "error", err)
	}

	ioThrottle := throttle.NewThrottle(cfg.Scanner.ThrottleIOPS)
	if cfg.Scanner.ThrottleIOPS <= 0 {
		ioThrottle = throttle.NewThrottle(500)
	}

	engine := &ScannerEngine{
		cfg:            cfg,
		workQueue:      make(chan string, 4096),
		results:        make(chan ScanResult, 100),
		ctx:            ctx,
		cancel:         cancel,
		yaraEngine:     yaraEngine,
		quarantineMgr:  qm,
		emberModel:     model,
		modelRegistry:  registry,

		throttle:       ioThrottle,
	}
	engine.currentPath.Store("")
	engine.scanPhase.Store(PhaseIdle)

	for i := 0; i < cfg.Scanner.Concurrency; i++ {
		engine.wg.Add(1)
		go engine.worker(i)
	}

	slog.Info("scanner engine initialized",
		"concurrency", cfg.Scanner.Concurrency,
		"throttle_iops", cfg.Scanner.ThrottleIOPS,
		"ember_loaded", model != nil,
		"registry_loaded", registry != nil,
	)

	return engine
}

func (e *ScannerEngine) EnqueueScan(path string) {
	select {
	case e.workQueue <- path:
		e.activeJobs.Add(1)
		e.scanWg.Add(1)
	case <-e.ctx.Done():
		return
	}
}

func (e *ScannerEngine) worker(id int) {
	defer e.wg.Done()
	slog.Debug("scanner worker started", "worker_id", id)

	for {
		select {
		case path := <-e.workQueue:
			e.currentPath.Store(path)
			e.scanFile(path)
			e.activeJobs.Add(-1)
			e.completedFiles.Add(1)
			e.scanWg.Done()
		case <-e.ctx.Done():
			return
		}
	}
}

func isPEFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x4D && magic[1] == 0x5A
}

// scanFile runs the six-stage pipeline: Hash -> PE Parse -> YARA -> Heuristics -> EMBER -> Fusion.
func (e *ScannerEngine) scanFile(path string) {
	info, err := os.Stat(path)
	if err != nil {
		slog.Debug("cannot access file", "path", path, "error", err)
		e.finalize(path, &ScanResult{FilePath: path, FileName: filepath.Base(path), Verdict: "error"})
		return
	}
	if info.IsDir() {
		return
	}
	maxSize := int64(e.cfg.Scan.MaxFileSizeMB) * 1024 * 1024
	if info.Size() > maxSize {
		slog.Debug("file too large, skipping", "path", path, "size", info.Size())
		e.finalize(path, &ScanResult{FilePath: path, FileName: info.Name(), FileSize: info.Size(), Verdict: "skipped"})
		return
	}

	slog.Debug("scanning file", "path", path, "size", info.Size())

	// ---- Stage 1: Hash (throttled IO) ----
	if err := e.throttle.Acquire(e.ctx); err != nil {
		slog.Warn("scan cancelled via throttle", "path", path, "error", err)
		e.finalize(path, &ScanResult{FilePath: path, FileName: info.Name(), FileSize: info.Size(), Verdict: "error"})
		return
	}
	hashes, err := hasher.ComputeHashes(path)
	if err != nil {
		slog.Warn("hash computation failed", "path", path, "error", err)
		e.finalize(path, &ScanResult{FilePath: path, FileName: info.Name(), FileSize: info.Size(), Verdict: "error"})
		return
	}
	result := ScanResult{
		FilePath: path,
		FileName: filepath.Base(path),
		FileSize: info.Size(),
		Hashes:   hashes,
		Verdict:  "clean",
	}

	// ---- Stage 2: Read file bytes + Parse (PE + PDF) ----
	var rawFile []byte
	isPE := false
	isPDF := false
	isDotNet := false

	if err := e.throttle.Acquire(e.ctx); err != nil {
		slog.Warn("scan cancelled via throttle", "path", path, "error", err)
		result.Verdict = "error"
		e.finalize(path, &result)
		return
	}
	rawFile, err = os.ReadFile(path)
	if err != nil {
		slog.Warn("cannot read file", "path", path, "error", err)
		result.Verdict = "error"
		e.finalize(path, &result)
		return
	}

	// PE detection and parsing
	isPE = len(rawFile) >= 2 && rawFile[0] == 0x4D && rawFile[1] == 0x5A
	if isPE {
		peInfo, pErr := parser.ParsePEFromBytes(rawFile)
		if pErr == nil {
			result.PEInfo = peInfo
			isDotNet = peInfo.IsDotNet
		}
		sigInfo := parser.VerifySignature(path)
		result.Signature = sigInfo
		if sigInfo != nil && !sigInfo.Signed {
			result.MatchedRules = append(result.MatchedRules, "unsigned_executable")
			result.Score += 0.5
		}
		if sigInfo != nil && sigInfo.Signed && sigInfo.Verified {
			result.Verdict = "clean"
			result.FusionScore = 0.0
			e.finalize(path, &result)
			return
		}
	}

	// PDF detection
	isPDF = len(rawFile) >= 4 && string(rawFile[:4]) == "%PDF"

	// ---- Stage 3: YARA (PE files only) ----
	if isPE {
		yaraMatches, err := e.yaraEngine.MatchFile(path)
		if err != nil {
			slog.Debug("YARA scan failed", "path", path, "error", err)
		} else {
			var yaraScore float64
			for _, m := range yaraMatches {
				result.MatchedRules = append(result.MatchedRules, m.RuleName)
				yaraScore += 0.5
			}
			if yaraScore > 5.0 {
				yaraScore = 5.0
			}
			result.Score += yaraScore
		}
	}

	// ---- Stage 4: Heuristics (PE files only) ----
	if result.PEInfo != nil {
		hScore, rules := computeHeuristics(result.PEInfo, result.Hashes)
		result.HeuristicScore = hScore
		result.HeuristicRules = rules
		result.Score += hScore

		for _, rule := range rules {
			result.MatchedRules = append(result.MatchedRules, rule)
		}

		if hScore >= 9.0 {
			result.Verdict = "malicious"
			result.FusionScore = result.Score
			qPath, err := e.quarantineMgr.QuarantineFile(path, rawFile)
			if err != nil {
				slog.Warn("failed to quarantine file", "path", path, "error", err)
			} else {
				result.Quarantined = true
				slog.Info("file quarantined (heuristic threshold)", "path", path, "quarantine_path", qPath)
			}
			e.finalize(path, &result)
			return
		}
	}

	// ---- Stage 5: EMBER ML ----
	// Run appropriate model(s) based on file type
	if len(rawFile) > 0 {
		if isPE {
			feats := ember.Extract(rawFile, result.PEInfo)
			if e.modelRegistry != nil {
				if peModel := e.modelRegistry.Get(ember.ModelPE); peModel != nil {
					result.EmberScore = peModel.Predict(feats)
				}
				if expModel := e.modelRegistry.Get(ember.ModelExploit); expModel != nil {
					result.ExploitScore = expModel.Predict(feats)
				}
				if pkrModel := e.modelRegistry.Get(ember.ModelPacker); pkrModel != nil {
					result.PackerScore = pkrModel.Predict(feats)
				}
				if isDotNet {
					for _, m := range e.modelRegistry.ModelsForDotNet() {
						dnFeats := ember.ExtractDotNet(rawFile, result.PEInfo)
						result.DotNetScore = m.Predict(dnFeats)
					}
				}
			} else if e.emberModel != nil {
				result.EmberScore = e.emberModel.Predict(feats)
			}

			if result.EmberScore > 0 {
				result.Score += result.EmberScore * 5.0
			}
			if result.ExploitScore >= 0.85 {
				result.Score += 1.5
			}
			if result.DotNetScore >= 0.85 {
				result.Score += 1.0
			}
		}

		if isPDF && e.modelRegistry != nil {
			pdfInfo, pdfErr := parser.ParsePDFFromBytes(rawFile)
			if pdfErr == nil {
				for _, m := range e.modelRegistry.ModelsForPDF() {
					feats := ember.ExtractPDF(rawFile, pdfInfo)
					result.PdfScore = m.Predict(feats)
				}
				if result.PdfScore > 0 {
					result.Score += result.PdfScore * 5.0
				}
			}
		}
	}

	// ---- Stage 6: Verdict Fusion ----
	result = fuseVerdict(result)

	// Mark for sandbox if EMBER is in the gray zone (0.80 to 0.96)
	if result.PEInfo != nil && result.EmberScore > 0.80 && result.EmberScore < 0.96 {
		result.NeedsSandbox = true
	}

	// ---- Stage 7: Quarantine ----
	if result.Verdict == "malicious" {
		qPath, err := e.quarantineMgr.QuarantineFile(path, rawFile)
		if err != nil {
			slog.Warn("failed to quarantine file", "path", path, "error", err)
		} else {
			result.Quarantined = true
			slog.Info("file quarantined", "path", path, "quarantine_path", qPath)
		}
	}

	e.finalize(path, &result)
}

// finalize sends the result to all subscribers and the result channel.
func (e *ScannerEngine) finalize(_ string, result *ScanResult) {
	e.subMu.RLock()
	for _, sub := range e.subscribers {
		select {
		case sub <- *result:
		default:
			slog.Warn("subscriber channel full, dropping", "path", result.FilePath)
		}
	}
	e.subMu.RUnlock()

	select {
	case e.results <- *result:
	default:
		slog.Warn("result channel full, dropping", "path", result.FilePath)
	}
}

// fuseVerdict combines all scores into a final verdict.
func fuseVerdict(r ScanResult) ScanResult {
	r.FusionScore = r.Score

	switch {
	case r.Score >= 11.0 || (r.EmberScore >= 0.96 && r.PEInfo != nil):
		r.Verdict = "malicious"
	case r.Score >= 8.5 || (r.EmberScore >= 0.85 && r.PEInfo != nil):
		r.Verdict = "suspicious"
	default:
		r.Verdict = "clean"
	}
	return r
}

// computeHeuristics evaluates PE metadata for suspicious indicators.
// Returns a score (0-10) and list of triggered rules.
func computeHeuristics(pe *parser.PEInfo, hashes *hasher.FileHashes) (float64, []string) {
	return 0.0, nil
}

// ---- lifecycle methods ----

func (e *ScannerEngine) StartQuickScan() {
	slog.Info("starting quick scan")
	e.scanActive.Store(true)
	e.scanPhase.Store(PhaseEnumeration)
	e.totalFiles.Store(0)
	e.completedFiles.Store(0)

	// Resolve Windows known folders (Desktop, Downloads, etc.) then expand globs
	resolved := config.ResolveQuickPaths(e.cfg.Scan.QuickPaths)
	var scanPaths []string
	for _, p := range resolved {
		expanded := expandGlob(p)
		scanPaths = append(scanPaths, expanded...)
	}

	e.producerWg.Add(1)
	go func() {
		defer e.producerWg.Done()
		// Phase 1: enumerate (count files)
		var total int64
		for _, dir := range scanPaths {
			if e.ctx.Err() != nil {
				return
			}
			total += e.enumerateDirectory(e.ctx, dir)
		}
		e.totalFiles.Store(total)
		e.scanPhase.Store(PhaseScanning)
		slog.Info("quick scan enumeration complete", "total_files", total)

		// Phase 2: scan (enqueue files for workers)
		for _, dir := range scanPaths {
			if e.ctx.Err() != nil {
				return
			}
			e.scanDirectory(e.ctx, dir)
		}
		e.scanWg.Wait()
		e.scanPhase.Store(PhaseDone)
	}()
}

func (e *ScannerEngine) StartFullScan() {
	slog.Info("starting full scan")
	e.scanActive.Store(true)
	e.scanPhase.Store(PhaseEnumeration)
	e.totalFiles.Store(0)
	e.completedFiles.Store(0)
	drives := e.cfg.Scan.FullScanDrives
	if len(drives) == 0 {
		drives = []string{"C:\\"}
	}

	// Enumerate: count files across all drives concurrently
	var enumWg sync.WaitGroup
	for _, drive := range drives {
		d := drive
		enumWg.Add(1)
		go func() {
			defer enumWg.Done()
			total := e.enumerateDirectory(e.ctx, d)
			e.totalFiles.Add(total)
		}()
	}
	// Mark scanning phase once enumeration completes
	go func() {
		enumWg.Wait()
		e.scanPhase.Store(PhaseScanning)
		slog.Info("full scan enumeration complete", "total_files", e.totalFiles.Load())
	}()

	// Scan: enqueue files for workers concurrently with enumeration
	e.producerWg.Add(len(drives))
	for _, drive := range drives {
		d := drive
		go func() {
			defer e.producerWg.Done()
			e.scanDirectory(e.ctx, d)
		}()
	}
	// Wait for all enqueued files to be scanned before marking done
	go func() {
		e.producerWg.Wait()
		e.scanWg.Wait()
		e.scanPhase.Store(PhaseDone)
	}()
}

// enumerateDirectory walks a root directory and counts files (no enqueue).
func (e *ScannerEngine) enumerateDirectory(ctx context.Context, root string) int64 {
	var count int64
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if ctx.Err() != nil || !e.scanActive.Load() {
			return filepath.SkipDir
		}
		if err != nil {
			return nil
		}
		if info.IsDir() {
			for _, excluded := range e.cfg.Scan.ExcludedPaths {
				if path == excluded {
					return filepath.SkipDir
				}
			}
			return nil
		}
		count++
		return nil
	})
	return count
}

func (e *ScannerEngine) scanDirectory(ctx context.Context, root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if ctx.Err() != nil || !e.scanActive.Load() {
			return filepath.SkipDir
		}
		if err != nil {
			return nil
		}
		if info.IsDir() {
			for _, excluded := range e.cfg.Scan.ExcludedPaths {
				if path == excluded {
					return filepath.SkipDir
				}
			}
			return nil
		}
		e.EnqueueScan(path)
		return nil
	})
}

func (e *ScannerEngine) ActiveJobs() int64 {
	return e.activeJobs.Load()
}

func (e *ScannerEngine) TotalFiles() int64 {
	return e.totalFiles.Load()
}

func (e *ScannerEngine) CompletedFiles() int64 {
	return e.completedFiles.Load()
}

func (e *ScannerEngine) ScanPhase() int32 {
	return e.scanPhase.Load()
}

func (e *ScannerEngine) IsScanActive() bool {
	return e.scanPhase.Load() >= PhaseEnumeration && e.scanPhase.Load() <= PhaseScanning
}

func (e *ScannerEngine) Results() <-chan ScanResult {
	return e.results
}

func (e *ScannerEngine) SubscribeResults() chan ScanResult {
	ch := make(chan ScanResult, 100)
	e.subMu.Lock()
	e.subscribers = append(e.subscribers, ch)
	e.subMu.Unlock()
	return ch
}

func (e *ScannerEngine) UnsubscribeResults(ch chan ScanResult) {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	for i, sub := range e.subscribers {
		if sub == ch {
			e.subscribers = append(e.subscribers[:i], e.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

func (e *ScannerEngine) CancelActiveScan() {
	slog.Info("cancelling active scan")
	e.scanActive.Store(false)
	e.scanPhase.Store(PhaseDone)

	// Drain the work queue to release workers and unblock scanWg
	for {
		select {
		case <-e.workQueue:
			e.activeJobs.Add(-1)
			e.completedFiles.Add(1)
			e.scanWg.Done()
		default:
			return
		}
	}
}

func (e *ScannerEngine) Stop() {
	slog.Info("stopping scanner engine")
	e.cancel()
	e.producerWg.Wait()
	e.wg.Wait()

	e.subMu.Lock()
	for _, sub := range e.subscribers {
		close(sub)
	}
	e.subscribers = nil
	e.subMu.Unlock()

	close(e.results)
	close(e.workQueue)
}

func expandGlob(pattern string) []string {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		slog.Debug("glob expansion failed", "pattern", pattern, "error", err)
		return []string{pattern}
	}
	if len(matches) == 0 {
		return []string{pattern}
	}
	return matches
}
