package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func CheckCookies(domain string) []CheckResult {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return []CheckResult{{
			CheckName:   "cookies",
			Title:       "Cookie Security",
			Passed:      true,
			Severity:    Info,
			Description: "No cookies set on initial response",
		}}
	}

	var results []CheckResult
	for _, cookie := range cookies {
		if !cookie.HttpOnly {
			results = append(results, CheckResult{
				CheckName:   fmt.Sprintf("cookie_httponly_%s", cookie.Name),
				Title:       fmt.Sprintf("Cookie '%s' missing HttpOnly flag", cookie.Name),
				Passed:      false,
				Severity:    High,
				Description: "Cookie without HttpOnly flag can be accessed by JavaScript, enabling session theft via XSS",
				Evidence:    fmt.Sprintf("Cookie: %s (HttpOnly=false)", cookie.Name),
				FixHint:     fmt.Sprintf("Set HttpOnly flag: Set-Cookie: %s=...; HttpOnly", cookie.Name),
			})
		}

		if !cookie.Secure {
			results = append(results, CheckResult{
				CheckName:   fmt.Sprintf("cookie_secure_%s", cookie.Name),
				Title:       fmt.Sprintf("Cookie '%s' missing Secure flag", cookie.Name),
				Passed:      false,
				Severity:    High,
				Description: "Cookie without Secure flag can be transmitted over HTTP, exposing it to interception",
				Evidence:    fmt.Sprintf("Cookie: %s (Secure=false)", cookie.Name),
				FixHint:     fmt.Sprintf("Set Secure flag: Set-Cookie: %s=...; Secure", cookie.Name),
			})
		}

		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			results = append(results, CheckResult{
				CheckName:   fmt.Sprintf("cookie_samesite_%s", cookie.Name),
				Title:       fmt.Sprintf("Cookie '%s' missing SameSite attribute", cookie.Name),
				Passed:      false,
				Severity:    Medium,
				Description: "Cookie without SameSite attribute is vulnerable to CSRF attacks",
				Evidence:    fmt.Sprintf("Cookie: %s (SameSite not set)", cookie.Name),
				FixHint:     fmt.Sprintf("Add SameSite: Set-Cookie: %s=...; SameSite=Strict", cookie.Name),
			})
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			CheckName:   "cookies",
			Title:       "Cookie Security",
			Passed:      true,
			Severity:    Info,
			Description: fmt.Sprintf("All %d cookie(s) have proper security flags", len(cookies)),
			Evidence:    fmt.Sprintf("Cookies checked: %s", cookieNames(cookies)),
		})
	}

	return results
}

func cookieNames(cookies []*http.Cookie) string {
	names := make([]string, len(cookies))
	for i, c := range cookies {
		names[i] = c.Name
	}
	return strings.Join(names, ", ")
}
