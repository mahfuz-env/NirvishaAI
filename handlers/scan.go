package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nirvishaai/backend/ai"
	"nirvishaai/backend/config"
	"nirvishaai/backend/scanner"
	"nirvishaai/backend/store"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type StartScanRequest struct {
	Domain string `json:"domain"`
}

type ScanProgress struct {
	ScanID    string              `json:"scan_id"`
	Status    string              `json:"status"`
	CheckName string              `json:"check_name,omitempty"`
	Result    *scanner.CheckResult `json:"result,omitempty"`
	Message   string              `json:"message,omitempty"`
}

func StartScan(w http.ResponseWriter, r *http.Request) {
	var req StartScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonError(w, "invalid domain", http.StatusBadRequest)
		return
	}

	domain := cleanDomain(req.Domain)

	// Rate limiting — max 5 scans per IP per day
	ip := realIP(r)
	count, err := store.IncrWithTTL(store.RateLimitKey(ip), store.TTLRateLimit)
	if err == nil && count > 5 {
		jsonError(w, "rate limit exceeded: max 5 scans per day", http.StatusTooManyRequests)
		return
	}

	// Domain must be verified
	if !IsDomainVerified(domain) {
		jsonError(w, "domain not verified — complete verification first", http.StatusForbidden)
		return
	}

	scanID := uuid.New().String()

	// Store initial status
	initial := scanner.ScanResult{
		Domain:    domain,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
	store.Set(store.ScanKey(scanID), initial, store.TTLScanResult)
	store.SetString(store.ScanProgressKey(scanID), "running", store.TTLScanResult)

	// Run scan asynchronously
	go runScanAsync(scanID, domain)

	jsonOK(w, map[string]string{
		"scan_id": scanID,
		"status":  "running",
		"message": fmt.Sprintf("Scan started for %s", domain),
	})
}

func GetScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		jsonError(w, "scan id required", http.StatusBadRequest)
		return
	}

	// SSE stream
	if r.Header.Get("Accept") == "text/event-stream" {
		streamScanProgress(w, r, scanID)
		return
	}

	status, err := store.GetString(store.ScanProgressKey(scanID))
	if err != nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	jsonOK(w, map[string]string{"scan_id": scanID, "status": status})
}

func GetScanResult(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if scanID == "" {
		jsonError(w, "scan id required", http.StatusBadRequest)
		return
	}

	var result scanner.ScanResult
	if err := store.Get(store.ScanKey(scanID), &result); err != nil {
		jsonError(w, "scan result not found", http.StatusNotFound)
		return
	}

	jsonOK(w, result)
}

func streamScanProgress(w http.ResponseWriter, r *http.Request, scanID string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			status, err := store.GetString(store.ScanProgressKey(scanID))
			if err != nil {
				fmt.Fprintf(w, "data: {\"status\":\"not_found\"}\n\n")
				flusher.Flush()
				return
			}

			var result scanner.ScanResult
			store.Get(store.ScanKey(scanID), &result)

			payload, _ := json.Marshal(map[string]any{
				"scan_id": scanID,
				"status":  status,
				"score":   result.Score,
				"checks":  result.Checks,
			})

			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()

			if status == "completed" || status == "failed" {
				return
			}
		}
	}
}

func runScanAsync(scanID, domain string) {
	maxScans := make(chan struct{}, config.App.MaxConcurrentScans)
	maxScans <- struct{}{}
	defer func() { <-maxScans }()

	result := scanner.Run(domain, func(checkName string, check scanner.CheckResult) {
		// Update result incrementally in Redis
		var current scanner.ScanResult
		store.Get(store.ScanKey(scanID), &current)
		current.Checks = append(current.Checks, check)
		current.Score = scanner.CalculateScore(current.Checks)
		store.Set(store.ScanKey(scanID), current, store.TTLScanResult)
	})

	// AI analysis
	aiVulns, _ := ai.AnalyzeVulnerabilities(result.Checks)
	result.AIAnalysis = aiVulns

	store.Set(store.ScanKey(scanID), result, store.TTLScanResult)
	store.SetString(store.ScanProgressKey(scanID), "completed", store.TTLScanResult)
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
