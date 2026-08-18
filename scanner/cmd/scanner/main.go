package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/grpc"
	"github.com/edr/scanner/internal/monitor"
	"github.com/edr/scanner/internal/scanner"
)

type scannerAlert struct {
	FilePath     string   `json:"file_path"`
	Verdict      string   `json:"verdict"`
	Score        float64  `json:"score"`
	MatchedRules []string `json:"matched_rules"`
	SHA256       string   `json:"sha256,omitempty"`
	Quarantined  bool     `json:"quarantined"`
}

func main() {
	cfg := config.Load()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel(),
	})))

	slog.Info("starting EDR scanner")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize scanner engine
	scanEngine := scanner.NewScannerEngine(cfg)

	// HTTP client for reporting to backend
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Backend.InsecureSkipVerify}
	if cfg.Backend.CACertPath != "" && !cfg.Backend.InsecureSkipVerify {
		caCert, err := os.ReadFile(cfg.Backend.CACertPath)
		if err == nil {
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			if rootCAs.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = rootCAs
				slog.Info("loaded CA certificate", "path", cfg.Backend.CACertPath)
			}
		} else {
			slog.Warn("failed to read CA certificate", "path", cfg.Backend.CACertPath, "error", err)
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// Consume results channel — log and forward all results to agent
	go func() {
		for result := range scanEngine.Results() {
			level := slog.LevelInfo
			if result.Verdict == "malicious" || result.Verdict == "suspicious" {
				level = slog.LevelWarn
			}
			slog.Log(ctx, level,
				"scan result",
				"path", result.FilePath,
				"verdict", result.Verdict,
				"score", result.Score,
				"matched_rules", result.MatchedRules,
				"quarantined", result.Quarantined,
			)

			// Forward every result to the agent event bridge
			alert := scannerAlert{
				FilePath:     result.FilePath,
				Verdict:      result.Verdict,
				Score:        result.Score,
				MatchedRules: result.MatchedRules,
				Quarantined:  result.Quarantined,
			}
			if result.Hashes != nil {
				alert.SHA256 = result.Hashes.SHA256
			}
			body, err := json.Marshal(alert)
			if err != nil {
				slog.Error("failed to marshal scan result", "error", err)
				continue
			}

			// Send to agent event bridge (non-blocking, fire-and-forget)
			agentURL := cfg.Backend.AgentURL + "/api/v1/scanner-result"
			resp, err := httpClient.Post(agentURL, "application/json", bytes.NewReader(body))
			if err != nil {
				slog.Debug("failed to forward result to agent", "path", result.FilePath, "error", err)
			} else {
				resp.Body.Close()
			}

			// Also report threats to the backend alert endpoint
			if result.Verdict == "malicious" || result.Verdict == "suspicious" {
				backendURL := cfg.Backend.URL + "/api/v1/scanner/report"
				resp, err := httpClient.Post(backendURL, "application/json", bytes.NewReader(body))
				if err != nil {
					slog.Warn("failed to report threat to backend", "path", result.FilePath, "error", err)
					continue
				}
				resp.Body.Close()
				slog.Info("threat reported to backend", "path", result.FilePath, "status", resp.StatusCode)
			}
		}
	}()

	// Initialize filesystem monitor
	fsMonitor := monitor.NewFsMonitor(cfg, scanEngine)
	go fsMonitor.Start(ctx)

	// Start gRPC server
	grpcServer := grpc.NewServer(cfg, scanEngine)
	go func() {
		if err := grpcServer.Start(ctx); err != nil {
			slog.Error("gRPC server failed", "error", err)
			cancel()
		}
	}()

	// Start scan HTTP API
	scanAPI := scanner.StartScanAPI(scanEngine, "127.0.0.1:50053")

	slog.Info("scanner initialized", "grpc_addr", cfg.GRPC.Listen, "scan_api", "127.0.0.1:50053")

	// Force GC to release startup memory (rule loading, etc.)
	runtime.GC()
	debug.FreeOSMemory()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig)
	case <-ctx.Done():
	}

	// Graceful shutdown
	slog.Info("shutting down scanner")
	grpcServer.Stop()
	scanAPI.Stop()
	fsMonitor.Stop()
	slog.Info("scanner stopped")
}
