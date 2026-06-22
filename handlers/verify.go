package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"nirvishaai/backend/store"
)

type VerificationRecord struct {
	Domain    string    `json:"domain"`
	Token     string    `json:"token"`
	Method    string    `json:"method"`
	Verified  bool      `json:"verified"`
	CreatedAt time.Time `json:"created_at"`
}

type DNSVerifyRequest struct {
	Domain string `json:"domain"`
}

type FileVerifyRequest struct {
	Domain string `json:"domain"`
}

func StartDNSVerification(w http.ResponseWriter, r *http.Request) {
	var req DNSVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonError(w, "invalid domain", http.StatusBadRequest)
		return
	}

	domain := cleanDomain(req.Domain)
	token := generateToken(domain)

	record := VerificationRecord{
		Domain:    domain,
		Token:     token,
		Method:    "dns",
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := store.Set(store.VerifyKey(domain), record, store.TTLVerification); err != nil {
		jsonError(w, "failed to store verification", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{
		"domain":      domain,
		"token":       token,
		"txt_record":  fmt.Sprintf("nirvishaai-verify=%s", token),
		"instruction": fmt.Sprintf("Add a TXT record to %s with value: nirvishaai-verify=%s", domain, token),
	})
}

func CheckFileVerification(w http.ResponseWriter, r *http.Request) {
	var req FileVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		jsonError(w, "invalid domain", http.StatusBadRequest)
		return
	}

	domain := cleanDomain(req.Domain)

	var record VerificationRecord
	if err := store.Get(store.VerifyKey(domain), &record); err != nil {
		jsonError(w, "verification not initiated, call /api/verify/dns first", http.StatusBadRequest)
		return
	}

	fileURL := fmt.Sprintf("https://%s/.well-known/nirvishaai-verify.txt", domain)
	verified := checkFileToken(fileURL, record.Token)

	if verified {
		record.Verified = true
		record.Method = "file"
		store.Set(store.VerifyKey(domain), record, store.TTLVerification)
	}

	jsonOK(w, map[string]any{
		"domain":   domain,
		"verified": verified,
		"method":   "file",
		"file_url": fileURL,
	})
}

func GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	domain := cleanDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		jsonError(w, "domain query param required", http.StatusBadRequest)
		return
	}

	var record VerificationRecord
	if err := store.Get(store.VerifyKey(domain), &record); err != nil {
		jsonOK(w, map[string]any{"domain": domain, "verified": false, "initiated": false})
		return
	}

	// Also attempt DNS verification if not yet verified
	if !record.Verified && record.Method == "dns" {
		if checkDNSToken(domain, record.Token) {
			record.Verified = true
			store.Set(store.VerifyKey(domain), record, store.TTLVerification)
		}
	}

	jsonOK(w, map[string]any{
		"domain":   record.Domain,
		"verified": record.Verified,
		"method":   record.Method,
		"token":    record.Token,
	})
}

func IsDomainVerified(domain string) bool {
	var record VerificationRecord
	if err := store.Get(store.VerifyKey(domain), &record); err != nil {
		return false
	}
	return record.Verified
}

func checkDNSToken(domain, token string) bool {
	expected := fmt.Sprintf("nirvishaai-verify=%s", token)
	records, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}
	for _, r := range records {
		if strings.TrimSpace(r) == expected {
			return true
		}
	}
	return false
}

func checkFileToken(fileURL, token string) bool {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(fileURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(body)) == token
}

func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")
	return strings.ToLower(domain)
}

func generateToken(domain string) string {
	return fmt.Sprintf("%x", hashString(domain+fmt.Sprintf("%d", time.Now().UnixNano())))
}

func hashString(s string) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range []byte(s) {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}
