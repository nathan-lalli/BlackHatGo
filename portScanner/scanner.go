package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type result struct {
	port    int
	service string
}

var knownPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

// probe dials the port and attempts to identify what's running.
// It first waits briefly to see if the server speaks unprompted (SSH, FTP, SMTP,
// Redis all send banners immediately). If nothing arrives, it sends an HTTP HEAD
// request as a fallback — this catches web servers on any port, not just well-known ones.
func probe(host string, port int, timeout time.Duration) (string, bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	buf := make([]byte, 1024)

	// Short passive read: services that speak first respond within a fraction of the timeout.
	conn.SetDeadline(time.Now().Add(timeout / 4))
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n]), true
	}

	// Server stayed silent — send an HTTP HEAD probe and read the response.
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	n, _ = conn.Read(buf)
	return string(buf[:n]), true
}

// serverHeader extracts the value of the "Server:" response header from an HTTP banner.
func serverHeader(banner string) string {
	for _, line := range strings.Split(banner, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

func detectService(banner string, port int) string {
	lower := strings.ToLower(banner)

	switch {
	case strings.Contains(lower, "ssh-"):
		for _, line := range strings.Split(banner, "\n") {
			if strings.HasPrefix(strings.ToLower(line), "ssh-") {
				return strings.TrimSpace(line)
			}
		}
		return "SSH"

	case strings.Contains(lower, "server: apache"):
		if s := serverHeader(banner); s != "" {
			return s
		}
		return "Apache httpd"

	case strings.Contains(lower, "server: nginx"):
		if s := serverHeader(banner); s != "" {
			return s
		}
		return "nginx"

	case strings.Contains(lower, "server: microsoft-iis"):
		if s := serverHeader(banner); s != "" {
			return s
		}
		return "IIS"

	case strings.Contains(lower, "http/") || strings.Contains(lower, "server:"):
		if s := serverHeader(banner); s != "" {
			return s
		}
		return "HTTP"

	case strings.HasPrefix(lower, "220") && strings.Contains(lower, "ftp"):
		return "FTP"

	case strings.HasPrefix(lower, "220") &&
		(strings.Contains(lower, "smtp") || strings.Contains(lower, "mail") ||
			strings.Contains(lower, "postfix") || strings.Contains(lower, "sendmail")):
		return "SMTP"

	case strings.HasPrefix(lower, "+pong"):
		return "Redis"

	case strings.Contains(lower, "mysql"):
		return "MySQL"

	case strings.Contains(lower, "postgresql"):
		return "PostgreSQL"

	case strings.Contains(lower, "mongodb"):
		return "MongoDB"
	}

	if svc, ok := knownPorts[port]; ok {
		return svc
	}
	return "unknown"
}

// parsePorts expands a spec like "22,21,80,8000-9000" into a sorted slice of port numbers.
func parsePorts(portsToScan string) ([]int, error) {
	seen := make(map[int]bool)
	for _, part := range strings.Split(portsToScan, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", bounds[0])
			}
			hi, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", bounds[1])
			}
			if lo > hi {
				return nil, fmt.Errorf("invalid range %d-%d", lo, hi)
			}
			for p := lo; p <= hi; p++ {
				seen[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			seen[p] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func main() {
	host := flag.String("host", "127.0.0.1", "Host to scan")
	portsToScan := flag.String("ports", "1-1024", "Ports to scan: e.g. 22,80,443,8000-9000")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 2*time.Second, "Per-port dial/read timeout")
	flag.Parse()

	targets, err := parsePorts(*portsToScan)
	if err != nil {
		fmt.Println("Error parsing ports:", err)
		return
	}

	ports := make(chan int, *workers)
	results := make(chan result)
	var open []result

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				banner, ok := probe(*host, port, *timeout)
				if ok {
					results <- result{port: port, service: detectService(banner, port)}
				}
			}
		}()
	}

	// Collector must finish before we sort; use its own WaitGroup to avoid the race.
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for r := range results {
			open = append(open, r)
		}
	}()

	for _, port := range targets {
		ports <- port
	}
	close(ports)
	wg.Wait()
	close(results)
	collectorWg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].port < open[j].port })

	fmt.Printf("Scanning %s (%d ports)\n", *host, len(targets))
	if len(open) == 0 {
		fmt.Println("No open ports found.")
		return
	}
	for _, r := range open {
		fmt.Printf("  %-6d/tcp  open  %s\n", r.port, r.service)
	}
}
