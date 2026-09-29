package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// parsePorts expands a spec like "22,21,80,8000-9000" into a slice of port numbers.
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
	flag.Parse()

	targets, err := parsePorts(*portsToScan)
	if err != nil {
		fmt.Println("Error parsing ports:", err)
		return
	}

	ports := make(chan int, *workers)
	results := make(chan int)
	var open []int
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", *host, port))
				if err == nil {
					conn.Close()
					results <- port
				}
			}
		}()
	}

	go func() {
		for port := range results {
			open = append(open, port)
		}
	}()

	for _, port := range targets {
		ports <- port
	}
	close(ports)
	wg.Wait()
	close(results)

	sort.Ints(open)
	fmt.Printf("Scanning %s (%d ports)\n", *host, len(targets))
	if len(open) == 0 {
		fmt.Println("No open ports found.")
		return
	}
	for _, port := range open {
		fmt.Printf("  %d/tcp open\n", port)
	}
}
