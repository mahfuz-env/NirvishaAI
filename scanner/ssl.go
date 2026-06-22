package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func CheckSSL(domain string) CheckResult {
	result := CheckResult{
		CheckName: "ssl_tls",
		Title:     "SSL/TLS Certificate",
		Severity:  Critical,
	}

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		result.Passed = false
		result.Description = "SSL certificate is invalid or missing"
		result.Evidence = err.Error()
		result.FixHint = "Install a valid SSL certificate. Use Let's Encrypt for free certificates."
		return result
	}
	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	if daysUntilExpiry < 0 {
		result.Passed = false
		result.Description = "SSL certificate has expired"
		result.Evidence = fmt.Sprintf("Expired on %s", cert.NotAfter.Format("2006-01-02"))
		result.FixHint = "Renew your SSL certificate immediately."
		return result
	}

	if daysUntilExpiry < 30 {
		result.Passed = false
		result.Severity = High
		result.Description = fmt.Sprintf("SSL certificate expires in %d days", daysUntilExpiry)
		result.Evidence = fmt.Sprintf("Expires on %s", cert.NotAfter.Format("2006-01-02"))
		result.FixHint = "Renew your SSL certificate before it expires."
		return result
	}

	// Check HTTPS redirect
	httpsRedirect := checkHTTPSRedirect(domain)

	result.Passed = true
	result.Severity = Info
	result.Description = fmt.Sprintf("Valid SSL certificate, expires in %d days", daysUntilExpiry)
	result.Evidence = fmt.Sprintf("Issued by: %s, Expires: %s", cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))

	if !httpsRedirect {
		result.Passed = false
		result.Severity = High
		result.Description = "HTTP does not redirect to HTTPS"
		result.FixHint = "Configure your web server to redirect all HTTP traffic to HTTPS."
	}

	return result
}

func checkHTTPSRedirect(domain string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + domain)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	isRedirect := resp.StatusCode == 301 || resp.StatusCode == 302 ||
		resp.StatusCode == 307 || resp.StatusCode == 308
	return isRedirect && len(loc) > 0 && loc[:5] == "https"
}
