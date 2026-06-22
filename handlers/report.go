package handlers

import (
	"net/http"

	"nirvishaai/backend/report"
	"nirvishaai/backend/scanner"
	"nirvishaai/backend/store"

	"github.com/go-chi/chi/v5"
)

func GeneratePDF(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	result, ok := getScanResult(w, scanID)
	if !ok {
		return
	}

	pdf, err := report.GeneratePDF(result)
	if err != nil {
		jsonError(w, "failed to generate PDF: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename=\"nirvishaai-report-"+scanID+".pdf\"")
	w.WriteHeader(http.StatusOK)
	w.Write(pdf)
}

func GenerateMD(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	result, ok := getScanResult(w, scanID)
	if !ok {
		return
	}

	md := report.GenerateMarkdown(result)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"nirvishaai-report-"+scanID+".md\"")
	w.WriteHeader(http.StatusOK)
	w.Write(md)
}

func getScanResult(w http.ResponseWriter, scanID string) (scanner.ScanResult, bool) {
	var result scanner.ScanResult
	if err := store.Get(store.ScanKey(scanID), &result); err != nil {
		jsonError(w, "scan result not found", http.StatusNotFound)
		return result, false
	}
	return result, true
}
