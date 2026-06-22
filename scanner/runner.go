package scanner

import (
	"sync"
	"time"
)

type ProgressFunc func(checkName string, result CheckResult)

func Run(domain string, onProgress ProgressFunc) ScanResult {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var allChecks []CheckResult

	collect := func(results ...CheckResult) {
		mu.Lock()
		defer mu.Unlock()
		allChecks = append(allChecks, results...)
		for _, r := range results {
			if onProgress != nil {
				onProgress(r.CheckName, r)
			}
		}
	}

	// SSL check
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(CheckSSL(domain))
	}()

	// Headers check
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(CheckHeaders(domain)...)
	}()

	// Cookies check
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(CheckCookies(domain)...)
	}()

	// CORS check
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(CheckCORS(domain))
	}()

	// Open redirect check
	wg.Add(1)
	go func() {
		defer wg.Done()
		collect(CheckOpenRedirect(domain))
	}()

	wg.Wait()

	return ScanResult{
		Domain:    domain,
		Score:     CalculateScore(allChecks),
		Checks:    allChecks,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
