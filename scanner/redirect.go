package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

var redirectParams = []string{"url", "redirect", "next", "return", "returnUrl", "return_url", "goto", "dest", "destination"}

func CheckOpenRedirect(domain string) CheckResult {
	result := CheckResult{
		CheckName: "open_redirect",
		Title:     "Open Redirect",
		Severity:  Medium,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payload := "https://evil.com"

	for _, param := range redirectParams {
		testURL := fmt.Sprintf("https://%s/?%s=%s", domain, param, payload)
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") {
				result.Passed = false
				result.Description = "Open redirect vulnerability detected — users can be redirected to malicious sites"
				result.Evidence = fmt.Sprintf("Parameter '?%s=%s' redirected to: %s", param, payload, loc)
				result.FixHint = "Validate redirect URLs against a whitelist of allowed domains before redirecting."
				return result
			}
		}
	}

	result.Passed = true
	result.Severity = Info
	result.Description = "No open redirect vulnerability detected"
	result.Evidence = fmt.Sprintf("Tested parameters: %s", strings.Join(redirectParams, ", "))
	return result
}
