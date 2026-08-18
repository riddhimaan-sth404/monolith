package scanner

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type scanAPI struct {
	engine  *ScannerEngine
	server  *http.Server
	results []ScanResult
	mu      sync.Mutex
	subCh   chan ScanResult
}

// StartScanAPI starts the scanner HTTP API on the given address.
func StartScanAPI(engine *ScannerEngine, addr string) *scanAPI {
	api := &scanAPI{engine: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan/start", api.handleStart)
	mux.HandleFunc("/api/scan/cancel", api.handleCancel)
	mux.HandleFunc("/api/scan/status", api.handleStatus)
	mux.HandleFunc("/api/scan/results", api.handleResults)
	mux.HandleFunc("/api/scan/file", api.handleFileScan)
	mux.HandleFunc("/api/scan/memory", api.handleMemoryScan)
	mux.HandleFunc("/api/scan/process", api.handleProcessScan)

	api.server = &http.Server{Handler: mux}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("failed to start scan API server", "addr", addr, "error", err)
		return api
	}
	go func() {
		slog.Info("scan API server listening", "addr", addr)
		if err := api.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("scan API server error", "error", err)
		}
	}()
	// Subscribe to results
	ch := engine.SubscribeResults()
	api.subCh = ch
	go func() {
		defer engine.UnsubscribeResults(ch)
		for r := range ch {
			api.mu.Lock()
			if len(api.results) >= 1000 {
				api.results = api.results[1:]
			}
			api.results = append(api.results, r)
			api.mu.Unlock()
		}
	}()
	return api
}

func (a *scanAPI) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.server.Shutdown(ctx)
}

type startRequest struct {
	ScanType string   `json:"scan_type"`
	Paths    []string `json:"paths,omitempty"`
}

func (a *scanAPI) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	a.mu.Lock()
	if a.engine.IsScanActive() || a.engine.ActiveJobs() > 0 {
		a.mu.Unlock()
		http.Error(w, "scan already in progress", http.StatusConflict)
		return
	}
	a.results = a.results[:0]
	a.mu.Unlock()

	switch req.ScanType {
	case "quick":
		a.engine.StartQuickScan()
	case "full":
		a.engine.StartFullScan()
	case "custom":
		a.engine.scanActive.Store(true)
		a.engine.scanPhase.Store(PhaseEnumeration)
		a.engine.totalFiles.Store(0)
		a.engine.completedFiles.Store(0)
		a.engine.producerWg.Add(1)
		go func() {
			defer a.engine.producerWg.Done()
			// Phase 1: enumerate
			var total int64
			for _, path := range req.Paths {
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if info.IsDir() {
					total += a.engine.enumerateDirectory(a.engine.ctx, path)
				} else {
					total++
				}
			}
			a.engine.totalFiles.Store(total)
			a.engine.scanPhase.Store(PhaseScanning)

			// Phase 2: scan
			for _, path := range req.Paths {
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if info.IsDir() {
					filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
						if err != nil || fi.IsDir() {
							return nil
						}
						a.engine.EnqueueScan(p)
						return nil
					})
				} else {
					a.engine.EnqueueScan(path)
				}
			}
			a.engine.scanWg.Wait()
			a.engine.scanPhase.Store(PhaseDone)
		}()
	default:
		a.engine.StartQuickScan()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

type statusResponse struct {
	ActiveJobs     int64  `json:"active_jobs"`
	TotalFiles     int64  `json:"total_files"`
	CompletedFiles int64  `json:"completed_files"`
	Status         string `json:"status"`
	CurrentPath    string `json:"current_path"`
	Phase          string `json:"phase"`
}

func phaseString(p int32) string {
	switch p {
	case PhaseEnumeration:
		return "enumeration"
	case PhaseScanning:
		return "scanning"
	case PhaseDone:
		return "completed"
	default:
		return "idle"
	}
}

func (a *scanAPI) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	a.engine.CancelActiveScan()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

func (a *scanAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	jobs := a.engine.ActiveJobs()
	phase := a.engine.ScanPhase()
	total := a.engine.TotalFiles()
	completed := a.engine.CompletedFiles()

	status := "running"
	if phase == PhaseDone && jobs == 0 {
		status = "completed"
	} else if phase == PhaseScanning && total > 0 && completed >= total && jobs == 0 {
		status = "completed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{
		ActiveJobs:     jobs,
		TotalFiles:     total,
		CompletedFiles: completed,
		Status:         status,
		CurrentPath:    a.engine.CurrentPath(),
		Phase:          phaseString(phase),
	})
}

type fileScanRequest struct {
	Path string `json:"path"`
}

func (a *scanAPI) handleFileScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req fileScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}
	if _, err := os.Stat(req.Path); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "file not found: " + err.Error()})
		return
	}
	a.engine.EnqueueScan(req.Path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

func (a *scanAPI) handleResults(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()

	slog.Info("handleResults",
		"in_slice", len(a.results),
		"phase", phaseString(a.engine.ScanPhase()),
		"active_jobs", a.engine.ActiveJobs(),
		"total_files", a.engine.TotalFiles(),
		"completed_files", a.engine.CompletedFiles(),
	)
	allResults := make([]ScanResult, len(a.results))
	copy(allResults, a.results)
	a.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allResults)
}

func (a *scanAPI) handleMemoryScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req MemoryScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	result := a.engine.ScanMemory(req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type processScanRequest struct {
	ProcessID int `json:"process_id"`
}

func (a *scanAPI) handleProcessScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req processScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "accepted", "process_id": req.ProcessID})
}
