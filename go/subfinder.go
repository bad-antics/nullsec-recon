/*
 * SubFinder - Fast Subdomain Enumeration Tool
 * Author: bad-antics | GitHub: bad-antics | Discord: x.com/AnonAntics
 * License: NREC-XXX (Get key at x.com/AnonAntics)
 *
 *     ▓█████▄  ██▀███   ██▓ ██▓███       ██████  █    ██  ▄▄▄▄    █████▒
 *     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▒██    ▒  ██  ▓██▒▓█████▄ ▓██   ▒ 
 */

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	VERSION = "2.0.0"
	BANNER  = `
     ▓█████▄  ██▀███   ██▓ ██▓███       ██████  █    ██  ▄▄▄▄    █████▒██▓ ███▄    █ ▓█████▄ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▒██    ▒  ██  ▓██▒▓█████▄ ▓██   ▒▓██▒ ██ ▀█   █ ▒██▀ ██▌
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒   ░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒████ ░▒██▒▓██  ▀█ ██▒░██   █▌
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒     ▒   ██▒▓▓█  ░██░▒██░█▀  ░▓█▒  ░░██░▓██▒  ▐▌██▒░▓█▄   ▌
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░   ▒██████▒▒▒▒█████▓ ░▓█  ▀█▓░▒█░   ░██░▒██░   ▓██░░▒████▓ 
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░   ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒ ▒ ░   ░▓  ░ ▒░   ▒ ▒  ▒▒▓  ▒ 
     ══════════════════════════════════════════════════════════════════════════════════════════
                          SubFinder v2.0 | github.com/bad-antics
     ══════════════════════════════════════════════════════════════════════════════════════════`
)

type SubdomainResult struct {
	Domain    string   `json:"domain"`
	Source    string   `json:"source"`
	IPs       []string `json:"ips,omitempty"`
	Resolved  bool     `json:"resolved"`
	Timestamp string   `json:"timestamp"`
}

type SubFinder struct {
	domain     string
	wordlist   string
	threads    int
	timeout    time.Duration
	resolve    bool
	jsonOutput bool
	results    map[string]*SubdomainResult
	mutex      sync.Mutex
	httpClient *http.Client
}

func NewSubFinder(domain string, threads int, timeout time.Duration) *SubFinder {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}

	return &SubFinder{
		domain:  strings.ToLower(strings.TrimSpace(domain)),
		threads: threads,
		timeout: timeout,
		results: make(map[string]*SubdomainResult),
		httpClient: &http.Client{
			Timeout:   timeout * 2,
			Transport: transport,
		},
	}
}

// Certificate Transparency lookup via crt.sh
func (sf *SubFinder) queryCrtSh(ctx context.Context) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", sf.domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := sf.httpClient.Do(req)
	if err != nil {
		fmt.Printf("[!] crt.sh error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var certs []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &certs); err != nil {
		return
	}

	for _, cert := range certs {
		names := strings.Split(cert.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if strings.HasSuffix(name, sf.domain) {
				sf.addResult(name, "crt.sh")
			}
		}
	}
}

// DNS bruteforce
func (sf *SubFinder) bruteforce(ctx context.Context, wordlist []string) {
	jobs := make(chan string, sf.threads*2)
	var wg sync.WaitGroup

	// Workers
	for i := 0; i < sf.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: sf.timeout}
					return d.DialContext(ctx, "udp", "8.8.8.8:53")
				},
			}

			for word := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					subdomain := fmt.Sprintf("%s.%s", word, sf.domain)
					ips, err := resolver.LookupIP(ctx, "ip4", subdomain)
					if err == nil && len(ips) > 0 {
						sf.addResult(subdomain, "bruteforce")
					}
				}
			}
		}()
	}

	// Send jobs
	for _, word := range wordlist {
		select {
		case <-ctx.Done():
			close(jobs)
			return
		default:
			jobs <- word
		}
	}
	close(jobs)
	wg.Wait()
}

// Web archive lookup
func (sf *SubFinder) queryWebArchive(ctx context.Context) {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", sf.domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := sf.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	subdomainRegex := regexp.MustCompile(fmt.Sprintf(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)*%s`, regexp.QuoteMeta(sf.domain)))

	for scanner.Scan() {
		line := scanner.Text()
		matches := subdomainRegex.FindAllString(line, -1)
		for _, match := range matches {
			match = strings.TrimPrefix(match, "http://")
			match = strings.TrimPrefix(match, "https://")
			if idx := strings.Index(match, "/"); idx != -1 {
				match = match[:idx]
			}
			match = strings.ToLower(match)
			if strings.HasSuffix(match, sf.domain) {
				sf.addResult(match, "wayback")
			}
		}
	}
}

// VirusTotal (requires API key for premium)
func (sf *SubFinder) queryVirusTotal(ctx context.Context, apiKey string) {
	if apiKey == "" {
		return
	}

	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, sf.domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := sf.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		return
	}

	for _, sub := range result.Subdomains {
		sf.addResult(sub, "virustotal")
	}
}

// Resolve subdomains to IPs
func (sf *SubFinder) resolveSubdomains(ctx context.Context) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, sf.threads)

	for subdomain := range sf.results {
		wg.Add(1)
		sem <- struct{}{}

		go func(sub string) {
			defer wg.Done()
			defer func() { <-sem }()

			ips, err := net.LookupIP(sub)
			if err == nil {
				sf.mutex.Lock()
				result := sf.results[sub]
				result.Resolved = true
				for _, ip := range ips {
					if ip.To4() != nil {
						result.IPs = append(result.IPs, ip.String())
					}
				}
				sf.mutex.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()
}

func (sf *SubFinder) addResult(subdomain, source string) {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	
	// Validate subdomain
	if !strings.HasSuffix(subdomain, sf.domain) {
		return
	}
	if strings.HasPrefix(subdomain, ".") || strings.HasPrefix(subdomain, "-") {
		return
	}

	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	if _, exists := sf.results[subdomain]; !exists {
		sf.results[subdomain] = &SubdomainResult{
			Domain:    subdomain,
			Source:    source,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		fmt.Printf("[+] %s (%s)\n", subdomain, source)
	}
}

func (sf *SubFinder) Run(ctx context.Context, wordlistPath string) {
	fmt.Println(BANNER)
	fmt.Printf("\n[*] Target: %s\n", sf.domain)
	fmt.Printf("[*] Threads: %d\n", sf.threads)
	fmt.Println()

	startTime := time.Now()

	// Passive enumeration
	var wg sync.WaitGroup

	// crt.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[*] Querying crt.sh...")
		sf.queryCrtSh(ctx)
	}()

	// Web Archive
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("[*] Querying Wayback Machine...")
		sf.queryWebArchive(ctx)
	}()

	wg.Wait()

	// DNS Bruteforce if wordlist provided
	if wordlistPath != "" {
		fmt.Printf("[*] Loading wordlist: %s\n", wordlistPath)
		wordlist := loadWordlist(wordlistPath)
		if len(wordlist) > 0 {
			fmt.Printf("[*] Starting bruteforce with %d words...\n", len(wordlist))
			sf.bruteforce(ctx, wordlist)
		}
	}

	// Resolve if requested
	if sf.resolve {
		fmt.Println("[*] Resolving subdomains...")
		sf.resolveSubdomains(ctx)
	}

	elapsed := time.Since(startTime)

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("[+] Enumeration completed in %v\n", elapsed)
	fmt.Printf("[+] Total subdomains found: %d\n", len(sf.results))
}

func (sf *SubFinder) GetResults() []SubdomainResult {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	results := make([]SubdomainResult, 0, len(sf.results))
	for _, r := range sf.results {
		results = append(results, *r)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})

	return results
}

func (sf *SubFinder) SaveResults(outputPath string, jsonFormat bool) error {
	results := sf.GetResults()

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if jsonFormat {
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	}

	for _, r := range results {
		line := r.Domain
		if len(r.IPs) > 0 {
			line += " [" + strings.Join(r.IPs, ", ") + "]"
		}
		fmt.Fprintln(file, line)
	}

	return nil
}

func loadWordlist(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("[!] Error loading wordlist: %v\n", err)
		return nil
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words
}

func main() {
	domain := flag.String("d", "", "Target domain")
	wordlist := flag.String("w", "", "Wordlist for bruteforce")
	threads := flag.Int("t", 50, "Number of threads")
	timeout := flag.Int("timeout", 5, "Timeout in seconds")
	output := flag.String("o", "", "Output file")
	jsonOut := flag.Bool("json", false, "JSON output format")
	resolve := flag.Bool("r", false, "Resolve subdomains to IPs")
	version := flag.Bool("v", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Printf("SubFinder v%s\n", VERSION)
		fmt.Println("github.com/bad-antics | x.com/AnonAntics")
		return
	}

	if *domain == "" {
		fmt.Println(BANNER)
		fmt.Println("\nUsage: subfinder -d <domain> [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  -d string     Target domain (required)")
		fmt.Println("  -w string     Wordlist for bruteforce")
		fmt.Println("  -t int        Number of threads (default: 50)")
		fmt.Println("  -timeout int  Timeout in seconds (default: 5)")
		fmt.Println("  -o string     Output file")
		fmt.Println("  -json         JSON output format")
		fmt.Println("  -r            Resolve subdomains to IPs")
		fmt.Println("\nExamples:")
		fmt.Println("  subfinder -d example.com")
		fmt.Println("  subfinder -d example.com -w subdomains.txt -o results.txt")
		fmt.Println("  subfinder -d example.com -r -json -o results.json")
		fmt.Println("\nGet premium at x.com/AnonAntics")
		return
	}

	sf := NewSubFinder(*domain, *threads, time.Duration(*timeout)*time.Second)
	sf.resolve = *resolve
	sf.jsonOutput = *jsonOut

	ctx := context.Background()
	sf.Run(ctx, *wordlist)

	if *output != "" {
		if err := sf.SaveResults(*output, *jsonOut); err != nil {
			fmt.Printf("[!] Error saving results: %v\n", err)
		} else {
			fmt.Printf("[+] Results saved to %s\n", *output)
		}
	}
}
