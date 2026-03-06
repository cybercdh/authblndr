package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const fakeAuthHeader = "foo"

type Result struct {
	Subdomain    string
	URL          string
	BaseStatus   int
	AuthStatus   int
	RedirectLocation string
	Vulnerable   bool
	Error        string
}

// noRedirectClient returns an HTTP client that never follows redirects.
func noRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func doGet(client *http.Client, url string, authHeader string) (status int, location string, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

// needsAuthProbe returns true for any response that indicates the resource is
// protected: 401, 403, or a 3xx redirect (which may lead to a login page).
func needsAuthProbe(code int) bool {
	return code == http.StatusUnauthorized ||
		code == http.StatusForbidden ||
		(code >= 300 && code < 400)
}

func isSuccess(code int) bool {
	return code >= 200 && code < 300
}

func probe(client *http.Client, subdomain string) Result {
	subdomain = strings.TrimSpace(subdomain)
	if subdomain == "" {
		return Result{}
	}

	url := subdomain
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	r := Result{Subdomain: subdomain, URL: url}

	baseStatus, location, err := doGet(client, url, "")
	if err != nil {
		// HTTPS failed — try HTTP fallback
		if strings.HasPrefix(url, "https://") {
			httpURL := "http://" + strings.TrimPrefix(url, "https://")
			baseStatus, location, err = doGet(client, httpURL, "")
			if err != nil {
				r.Error = err.Error()
				return r
			}
			r.URL = httpURL
		} else {
			r.Error = err.Error()
			return r
		}
	}

	r.BaseStatus = baseStatus
	r.RedirectLocation = location

	if !needsAuthProbe(baseStatus) {
		return r
	}

	authStatus, _, err := doGet(client, r.URL, fakeAuthHeader)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.AuthStatus = authStatus

	// Vulnerable: the bare request was blocked/redirected but the auth header
	// (with a nonsense value) bypassed the check entirely.
	r.Vulnerable = isSuccess(authStatus)

	return r
}

func colorize(s, code string) string {
	return "\033[" + code + "m" + s + "\033[0m"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func printResult(r Result, verbose bool) {
	if r.Subdomain == "" {
		return
	}

	if r.Error != "" {
		if verbose {
			fmt.Printf("  %s  %s  error: %s\n",
				colorize("ERR", "33"),
				r.URL,
				r.Error,
			)
		}
		return
	}

	if r.Vulnerable {
		extra := ""
		if r.RedirectLocation != "" {
			extra = fmt.Sprintf("  redirected→ %s", colorize(truncate(r.RedirectLocation, 80), "33"))
		}
		fmt.Printf("  %s  %s  base=%d auth=%d%s\n",
			colorize("VULN", "31;1"),
			r.URL,
			r.BaseStatus,
			r.AuthStatus,
			extra,
		)
		return
	}

	if verbose {
		if needsAuthProbe(r.BaseStatus) {
			extra := ""
			if r.RedirectLocation != "" {
				extra = fmt.Sprintf("  →%s", truncate(r.RedirectLocation, 60))
			}
			fmt.Printf("  %s  %s  base=%d auth=%d%s\n",
				colorize("SAFE", "32"),
				r.URL,
				r.BaseStatus,
				r.AuthStatus,
				extra,
			)
		} else {
			fmt.Printf("  %s  %s  status=%d\n",
				colorize(" OK ", "34"),
				r.URL,
				r.BaseStatus,
			)
		}
	}
}

func main() {
	concurrency := flag.Int("c", 20, "number of concurrent workers")
	timeout := flag.Duration("t", 10*time.Second, "HTTP request timeout")
	verbose := flag.Bool("v", false, "show all results, not just vulnerable hosts")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: cat subdomains.txt | authblndr [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
How it works:
  1. For each subdomain, make a GET request (redirects NOT followed).
  2. If the response is 401, 403, or a 3xx redirect (e.g. to a login page),
     retry the same URL with 'Authorization: foo'.
  3. If the retry returns 2xx, the endpoint is VULNERABLE — it accepts any
     Authorization header value without validating it.

Examples:
  cat subdomains.txt | authblndr
  cat subdomains.txt | authblndr -c 50 -t 5s -v
  echo "example.com/api/v1" | authblndr
`)
	}
	flag.Parse()

	client := noRedirectClient(*timeout)

	jobs := make(chan string, *concurrency)
	results := make(chan Result, *concurrency)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				results <- probe(client, subdomain)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			jobs <- line
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		}
		close(jobs)
	}()

	vulnCount := 0
	total := 0

	fmt.Println()
	for r := range results {
		if r.Subdomain == "" {
			continue
		}
		total++
		if r.Vulnerable {
			vulnCount++
		}
		printResult(r, *verbose)
	}

	fmt.Printf("\nScanned %d hosts — %s\n\n",
		total,
		colorize(fmt.Sprintf("%d vulnerable", vulnCount), map[bool]string{true: "31;1", false: "32"}[vulnCount > 0]),
	)
}
