package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type webResult struct {
	path   string
	status int
	size   int64
}

// defaultWordlist is a small built-in list used when no -wordlist is provided.
var defaultWordlist = []string{
	"admin", "administrator", "login", "dashboard", "api", "v1", "v2",
	"config", "backup", "uploads", "images", "static",
	"js", "css", "assets", "files", "data", "docs",
	"robots.txt", "sitemap.xml", ".env", ".git", "readme.md",
	"wp-admin", "wp-login.php", "phpinfo.php", "index.php",
	"index.html", "index.js", "server-status", "server-info",
	"test", "dev", "staging", "old", "tmp", "temp",
	"users", "user", "account", "accounts", "auth",
	"register", "signup", "logout", "profile", "settings",
	"search", "download", "downloads", "upload", "media",
	"include", "includes", "lib", "libs", "src",
	"panel", "console", "manage", "management", "portal",
	"private", "secret", "hidden", "internal", "debug",
}

// loadWordlist reads paths from a file, one per line, stripping comments and blank lines.
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	return words, scanner.Err()
}

// probe sends an HTTP GET to baseURL/path and returns the status code and body size.
func probe(client *http.Client, baseURL, path string) (int, int64, error) {
	target := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	resp, err := client.Get(target)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	// drain body so the connection can be reused
	size, _ := io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, size, nil
}

func main() {
	url := flag.String("url", "", "Base URL to fuzz (required), e.g. http://example.com")
	wordlistFile := flag.String("wordlist", "", "Path to wordlist file (one path per line); uses built-in list if omitted")
	workers := flag.Int("workers", 50, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 5*time.Second, "HTTP request timeout")
	codes := flag.String("codes", "200,201,204,301,302,307,401,403", "Comma-separated HTTP status codes to report, default is 200,201,204,301,302,307,401,403")
	logFlag := flag.Bool("log", false, "Write results to a file")
	outputFile := flag.String("filename", "", "Output filename (defaults to <host>.webscan)")
	flag.Parse()

	if *url == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse the status codes the user cares about.
	wanted := make(map[int]bool)
	for part := range strings.SplitSeq(*codes, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var code int
		if _, err := fmt.Sscan(part, &code); err != nil {
			fmt.Fprintf(os.Stderr, "invalid status code %q\n", part)
			os.Exit(1)
		}
		wanted[code] = true
	}

	var words []string
	if *wordlistFile != "" {
		var err error
		words, err = loadWordlist(*wordlistFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading wordlist: %v\n", err)
			os.Exit(1)
		}
	} else {
		words = defaultWordlist
	}

	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects; report them
		},
	}

	paths := make(chan string, *workers)
	results := make(chan webResult)
	var found []webResult

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Go(func() {
			for p := range paths {
				status, size, err := probe(client, *url, p)
				if err != nil {
					continue
				}
				if wanted[status] {
					results <- webResult{path: p, status: status, size: size}
				}
			}
		})
	}

	var collectorWg sync.WaitGroup
	collectorWg.Go(func() {
		for r := range results {
			found = append(found, r)
		}
	})

	for _, w := range words {
		paths <- w
	}
	close(paths)
	wg.Wait()
	close(results)
	collectorWg.Wait()

	sort.Slice(found, func(i, j int) bool {
		if found[i].status != found[j].status {
			return found[i].status < found[j].status
		}
		return found[i].path < found[j].path
	})

	// Determine output destination.
	writer := io.Writer(os.Stdout)

	if *logFlag {
		fname := *outputFile
		if fname == "" {
			host := strings.TrimRight(*url, "/")
			host = strings.TrimPrefix(host, "https://")
			host = strings.TrimPrefix(host, "http://")
			host = strings.ReplaceAll(host, "/", "_")
			fname = host + ".webscan"
		}
		f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening output file: %v\n", err)
			fmt.Fprintln(os.Stderr, "continuing without file output")
		} else {
			defer f.Close()
			writer = io.MultiWriter(os.Stdout, f)
		}
	}

	fmt.Fprintf(writer, "Fuzzing %s (%d paths)\n", *url, len(words))
	if len(found) == 0 {
		fmt.Fprintln(writer, "No interesting paths found.")
		return
	}
	fmt.Fprintf(writer, "%-6s  %-10s  %s\n", "CODE", "SIZE", "PATH")
	fmt.Fprintln(writer, strings.Repeat("-", 50))
	for _, r := range found {
		fmt.Fprintf(writer, "%-6d  %-10d  /%s\n", r.status, r.size, r.path)
	}
}
