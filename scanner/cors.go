package scanner

import (
	"net/http"
	"time"
)

func CheckCORS(domain string) CheckResult {
	result := CheckResult{
		CheckName: "cors_misconfiguration",
		Title:     "CORS Misconfiguration",
		Severity:  High,
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	if err != nil {
		result.Passed = true
		result.Severity = Info
		result.Description = "Could not test CORS configuration"
		return result
	}
	req.Header.Set("Origin", "https://evil.com")

	resp, err := client.Do(req)
	if err != nil {
		result.Passed = true
		result.Severity = Info
		result.Description = "Could not test CORS configuration"
		return result
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")

	if acao == "*" {
		result.Passed = false
		result.Description = "CORS allows requests from any origin (Access-Control-Allow-Origin: *)"
		result.Evidence = "Access-Control-Allow-Origin: *"
		result.FixHint = "Restrict CORS to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com"
		return result
	}

	if acao == "https://evil.com" {
		result.Passed = false
		result.Severity = Critical
		result.Description = "CORS reflects arbitrary Origin header — any site can make authenticated requests"
		result.Evidence = "Access-Control-Allow-Origin: https://evil.com (reflected)"
		result.FixHint = "Maintain an explicit whitelist of allowed origins and validate against it."
		return result
	}

	result.Passed = true
	result.Severity = Info
	result.Description = "CORS configuration looks correct"
	if acao != "" {
		result.Evidence = "Access-Control-Allow-Origin: " + acao
	} else {
		result.Evidence = "No Access-Control-Allow-Origin header (restrictive)"
	}
	return result
}
