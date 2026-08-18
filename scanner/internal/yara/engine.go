package yara

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

type Rule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	Content     string   `json:"content"`
	Tags        []string `json:"tags"`
}

type Match struct {
	RuleName string            `json:"rule_name"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
}

type Engine struct {
	serverURL string
	rulesPath string
	cachePath string
	mu        sync.RWMutex
}

func NewEngine(rulesPath, cachePath string) *Engine {
	return &Engine{
		serverURL: "http://127.0.0.1:50074",
		rulesPath: rulesPath,
		cachePath: cachePath,
	}
}

func (e *Engine) SetServerURL(url string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.serverURL = url
}

func (e *Engine) LoadRules() error {
	slog.Info("YARA rules are loaded by the matcher sidecar", "url", e.serverURL)
	for i := range 10 {
		resp, err := httpClient.Get(e.serverURL + "/health")
		if err == nil {
			resp.Body.Close()
			return nil
		}
		if i < 9 {
			slog.Warn("matcher sidecar not reachable, retrying", "attempt", i+1, "error", err)
			time.Sleep(time.Second)
		}
	}
	slog.Warn("matcher sidecar not reachable after 10 attempts, continuing without YARA")
	return nil
}

type matchRequest struct {
	Path string `json:"path"`
	Data string `json:"data,omitempty"`
}

type metaEntry struct {
	Identifier string `json:"identifier"`
	Value      string `json:"value"`
}

type ruleMatch struct {
	RuleName string     `json:"rule_name"`
	Metadata []metaEntry `json:"metadata"`
}

type matchResponse struct {
	Matches []ruleMatch `json:"matches"`
	Error   *string     `json:"error"`
}

func (e *Engine) match(request matchRequest) ([]Match, error) {
	e.mu.RLock()
	url := e.serverURL + "/match"
	e.mu.RUnlock()

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to call matcher: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var mr matchResponse
	if err := json.Unmarshal(respBody, &mr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if mr.Error != nil {
		return nil, fmt.Errorf("matcher error: %s", *mr.Error)
	}

	result := make([]Match, 0, len(mr.Matches))
	for _, m := range mr.Matches {
		meta := make(map[string]string)
		for _, me := range m.Metadata {
			meta[me.Identifier] = me.Value
		}
		result = append(result, Match{
			RuleName: m.RuleName,
			Tags:     nil,
			Metadata: meta,
		})
	}

	return result, nil
}

func (e *Engine) MatchFile(path string) ([]Match, error) {
	return e.match(matchRequest{Path: path})
}

func (e *Engine) MatchBytes(data []byte) ([]Match, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	return e.match(matchRequest{Data: encoded})
}

func (e *Engine) AddRule(content string) error {
	slog.Warn("AddRule not supported with sidecar matcher")
	return nil
}

func (e *Engine) RemoveRule(name string) error {
	slog.Warn("RemoveRule not supported with sidecar matcher")
	return nil
}
