package scanner

import (
	"fmt"
	"net/http"
	"time"
)

type headerCheck struct {
	header      string
	checkName   string
	title       string
	severity    Severity
	description string
	fixHint     string
}

var securityHeaders = []headerCheck{
	{
		header:      "X-Content-Type-Options",
		checkName:   "header_x_content_type",
		title:       "X-Content-Type-Options Header",
		severity:    Medium,
		description: "Missing X-Content-Type-Options header allows MIME-type sniffing attacks",
		fixHint:     `Add header: X-Content-Type-Options: nosniff`,
	},
	{
		header:      "X-Frame-Options",
		checkName:   "header_x_frame_options",
		title:       "X-Frame-Options Header (Clickjacking)",
		severity:    High,
		description: "Missing X-Frame-Options header allows your site to be embedded in iframes (clickjacking risk)",
		fixHint:     `Add header: X-Frame-Options: DENY`,
	},
	{
		header:      "Content-Security-Policy",
		checkName:   "header_csp",
		title:       "Content-Security-Policy Header",
		severity:    High,
		description: "Missing Content-Security-Policy header increases XSS attack risk",
		fixHint:     `Add header: Content-Security-Policy: default-src 'self'`,
	},
	{
		header:      "Strict-Transport-Security",
		checkName:   "header_hsts",
		title:       "Strict-Transport-Security (HSTS)",
		severity:    High,
		description: "Missing HSTS header allows protocol downgrade attacks",
		fixHint:     `Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains`,
	},
	{
		header:      "Referrer-Policy",
		checkName:   "header_referrer_policy",
		title:       "Referrer-Policy Header",
		severity:    Low,
		description: "Missing Referrer-Policy header may leak sensitive URL information to third parties",
		fixHint:     `Add header: Referrer-Policy: strict-origin-when-cross-origin`,
	},
}

func CheckHeaders(domain string) []CheckResult {
	client := &http.Client{Timeout: time.Duration(10) * time.Second}
	resp, err := client.Get("https://" + domain)
	if err != nil {
		return []CheckResult{{
			CheckName:   "header_fetch",
			Title:       "Security Headers",
			Passed:      false,
			Severity:    High,
			Description: "Could not fetch headers from domain",
			Evidence:    err.Error(),
		}}
	}
	defer resp.Body.Close()

	var results []CheckResult
	for _, hc := range securityHeaders {
		val := resp.Header.Get(hc.header)
		passed := val != ""
		evidence := ""
		if passed {
			evidence = fmt.Sprintf("%s: %s", hc.header, val)
		} else {
			evidence = fmt.Sprintf("Header '%s' not found in response", hc.header)
		}

		results = append(results, CheckResult{
			CheckName:   hc.checkName,
			Title:       hc.title,
			Passed:      passed,
			Severity:    hc.severity,
			Description: hc.description,
			Evidence:    evidence,
			FixHint:     hc.fixHint,
		})
	}
	return results
}
