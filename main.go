package main

// SUBMON v1.0 — Subdomain Takeover Monitor
// Fast parallel DNS/HTTP fingerprinting + AWS-native EB/S3 verification.
//   - Goroutine worker pool (50 default workers, replaces serial baddns loop)
//   - Built-in CNAME fingerprinting for 25+ services
//   - AWS EB: check-dns-availability CLI verification
//   - AWS S3: head-bucket CLI + HTTP NoSuchBucket probe
//   - HTML / JSON / text reports
//   - Telegram & Discord alerts with first-run interactive setup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const version = "1.0"

// ─── Config ──────────────────────────────────────────────────────────────────

type Config struct {
	Target       string
	DomainList   string
	ListMode     bool
	Workers      int
	Concurrency  int
	Depth        int
	OutputFormat string // all | json | html | text
	Confidence   string // all | confirmed | probable
	ScanMode     string // builtin | baddns | all
	Timeout      int    // seconds per subdomain
	VPSInterval  int    // hours, 0 = disabled
	Quiet        bool
	AWSRegion    string

	// Notifications (from env)
	TelegramEnabled bool
	TelegramToken   string
	TelegramChatID  string
	DiscordEnabled  bool
	DiscordWebhook  string
}

// ─── Finding ─────────────────────────────────────────────────────────────────

type Finding struct {
	Target      string    `json:"target"`
	CNAME       string    `json:"cname,omitempty"`
	Confidence  string    `json:"confidence"`
	Module      string    `json:"module"`
	Service     string    `json:"service"`
	Signature   string    `json:"signature"`
	Description string    `json:"description"`
	AWSVerified bool      `json:"aws_verified,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

type ScanResult struct {
	Domain        string
	Timestamp     time.Time
	SubdomainFile string
	TotalSubs     int
	Findings      []Finding
	OutputDir     string
}

// ─── Fingerprints ────────────────────────────────────────────────────────────

type Fingerprint struct {
	Service    string
	CNAMERe    *regexp.Regexp
	HTTPBody   string // substring to match in response body
	StatusCode int    // 0 = any
	Confidence string
	IsAWSEB    bool
	IsAWSS3    bool
	IsAWSCF    bool
}

var fingerprints = []*Fingerprint{
	// AWS ──────────────────────────────────────────────────────────────────────
	{
		Service:    "AWS Elastic Beanstalk",
		CNAMERe:    regexp.MustCompile(`(?i)\.elasticbeanstalk\.com\.?$`),
		Confidence: "PROBABLE",
		IsAWSEB:    true,
	},
	{
		Service:    "AWS S3",
		CNAMERe:    regexp.MustCompile(`(?i)(\.s3[.-][a-z0-9-]+\.amazonaws\.com|\.s3\.amazonaws\.com)\.?$`),
		HTTPBody:   "NoSuchBucket",
		StatusCode: 404,
		Confidence: "CONFIRMED",
		IsAWSS3:    true,
	},
	{
		Service:    "AWS S3 Website",
		CNAMERe:    regexp.MustCompile(`(?i)\.s3-website[.-][a-z0-9-]+\.amazonaws\.com\.?$`),
		HTTPBody:   "NoSuchBucket",
		StatusCode: 404,
		Confidence: "CONFIRMED",
		IsAWSS3:    true,
	},
	{
		Service:    "AWS CloudFront",
		CNAMERe:    regexp.MustCompile(`(?i)\.cloudfront\.net\.?$`),
		HTTPBody:   "Bad request",
		StatusCode: 400,
		Confidence: "PROBABLE",
		IsAWSCF:    true,
	},
	// GitHub / Git hosting ─────────────────────────────────────────────────────
	{
		Service:    "GitHub Pages",
		CNAMERe:    regexp.MustCompile(`(?i)\.github\.io\.?$`),
		HTTPBody:   "There isn't a GitHub Pages site here",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Bitbucket",
		CNAMERe:    regexp.MustCompile(`(?i)\.bitbucket\.io\.?$`),
		HTTPBody:   "Repository not found",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	// PaaS ─────────────────────────────────────────────────────────────────────
	{
		Service:    "Heroku",
		CNAMERe:    regexp.MustCompile(`(?i)(\.herokudns\.com|\.herokuapp\.com)\.?$`),
		HTTPBody:   "No such app",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Azure App Service",
		CNAMERe:    regexp.MustCompile(`(?i)\.azurewebsites\.net\.?$`),
		HTTPBody:   "404 Web Site not found",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Fastly",
		CNAMERe:    regexp.MustCompile(`(?i)\.fastly\.net\.?$`),
		HTTPBody:   "Fastly error: unknown domain",
		StatusCode: 500,
		Confidence: "CONFIRMED",
	},
	// CMS / Website builders ───────────────────────────────────────────────────
	{
		Service:    "Shopify",
		CNAMERe:    regexp.MustCompile(`(?i)\.myshopify\.com\.?$`),
		HTTPBody:   "Sorry, this shop is currently unavailable",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Tumblr",
		CNAMERe:    regexp.MustCompile(`(?i)\.tumblr\.com\.?$`),
		HTTPBody:   "Whatever you were looking for doesn't currently exist",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Ghost",
		CNAMERe:    regexp.MustCompile(`(?i)\.ghost\.io\.?$`),
		HTTPBody:   "The thing you were looking for is no longer here",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Webflow",
		CNAMERe:    regexp.MustCompile(`(?i)\.webflow\.io\.?$`),
		HTTPBody:   "The page you are looking for doesn't exist",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Surge.sh",
		CNAMERe:    regexp.MustCompile(`(?i)\.surge\.sh\.?$`),
		HTTPBody:   "project not found",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Strikingly",
		CNAMERe:    regexp.MustCompile(`(?i)\.strikinglydns\.com\.?$`),
		HTTPBody:   "But if you're looking to build your own website",
		Confidence: "CONFIRMED",
	},
	// SaaS Help / Support ──────────────────────────────────────────────────────
	{
		Service:    "Zendesk",
		CNAMERe:    regexp.MustCompile(`(?i)\.zendesk\.com\.?$`),
		HTTPBody:   "Help Center Closed",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "UserVoice",
		CNAMERe:    regexp.MustCompile(`(?i)\.uservoice\.com\.?$`),
		HTTPBody:   "This UserVoice subdomain is currently available",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Intercom Help",
		CNAMERe:    regexp.MustCompile(`(?i)\.intercom\.help\.?$`),
		HTTPBody:   "Uh oh. That page doesn't exist",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "HelpJuice",
		CNAMERe:    regexp.MustCompile(`(?i)\.helpjuice\.com\.?$`),
		HTTPBody:   "We could not find what you're looking for",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "HelpScout",
		CNAMERe:    regexp.MustCompile(`(?i)\.helpscoutdocs\.com\.?$`),
		HTTPBody:   "No settings were found",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Readme.io",
		CNAMERe:    regexp.MustCompile(`(?i)\.readme\.io\.?$`),
		HTTPBody:   "Project doesnt exist",
		Confidence: "CONFIRMED",
	},
	// Monitoring ───────────────────────────────────────────────────────────────
	{
		Service:    "Pingdom",
		CNAMERe:    regexp.MustCompile(`(?i)\.pingdom\.com\.?$`),
		HTTPBody:   "This public status page is not activated",
		Confidence: "CONFIRMED",
	},
	// E-commerce ───────────────────────────────────────────────────────────────
	{
		Service:    "BigCartel",
		CNAMERe:    regexp.MustCompile(`(?i)\.bigcartel\.com\.?$`),
		HTTPBody:   "An error occurred while loading this store",
		Confidence: "CONFIRMED",
	},
	// Misc hosting ─────────────────────────────────────────────────────────────
	{
		Service:    "Pantheon",
		CNAMERe:    regexp.MustCompile(`(?i)\.pantheonsite\.io\.?$`),
		HTTPBody:   "The gods are wise",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Launchrock",
		CNAMERe:    regexp.MustCompile(`(?i)\.launchrock\.com\.?$`),
		HTTPBody:   "It looks like you may have taken a wrong turn",
		Confidence: "CONFIRMED",
	},
	{
		Service:    "Kajabi",
		CNAMERe:    regexp.MustCompile(`(?i)\.kajabi\.com\.?$`),
		HTTPBody:   "The page you were looking for doesn't exist",
		StatusCode: 404,
		Confidence: "CONFIRMED",
	},
}

// ─── Persisted notification config ───────────────────────────────────────────

type AppConfig struct {
	TelegramEnabled bool   `json:"telegram_enabled"`
	TelegramToken   string `json:"telegram_token"`
	TelegramChatID  string `json:"telegram_chat_id"`
	DiscordEnabled  bool   `json:"discord_enabled"`
	DiscordWebhook  string `json:"discord_webhook"`
}

func configFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".submon.json"
	}
	return filepath.Join(home, ".config", "submon", "config.json")
}

func loadAppConfig() (AppConfig, bool) {
	data, err := os.ReadFile(configFilePath())
	if err != nil {
		return AppConfig{}, false
	}
	var c AppConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return AppConfig{}, false
	}
	return c, true
}

func saveAppConfig(c AppConfig) {
	p := configFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(p, data, 0600)
}

// isTerminal returns true when stdout is an interactive TTY.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptLine(label string) string {
	fmt.Print(label)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

// firstRunSetup interactively asks for Telegram / Discord credentials,
// saves them to ~/.config/submon/config.json, and returns the config.
func firstRunSetup() AppConfig {
	const (
		cyan  = "\033[0;36m"
		green = "\033[0;32m"
		dim   = "\033[2m"
		reset = "\033[0m"
		bold  = "\033[1m"
	)

	fmt.Printf("\n%s%s┌─────────────────────────────────────────────────────┐%s\n", bold, cyan, reset)
	fmt.Printf("%s%s│  FIRST RUN — Notification Setup                     │%s\n", bold, cyan, reset)
	fmt.Printf("%s%s│  Configure Telegram & Discord alerts (or press Enter │%s\n", bold, cyan, reset)
	fmt.Printf("%s%s│  to skip — you can re-run setup by deleting:         │%s\n", bold, cyan, reset)
	fmt.Printf("%s%s│  %s%-51s%s%s│%s\n", bold, cyan, dim, configFilePath(), reset+bold, cyan, reset)
	fmt.Printf("%s%s└─────────────────────────────────────────────────────┘%s\n\n", bold, cyan, reset)

	var c AppConfig

	// ── Telegram ──────────────────────────────────────────────────────────────
	fmt.Printf("  %sTelegram%s\n", bold, reset)
	token := promptLine("    Bot token  (Enter to skip): ")
	if token != "" {
		chatID := promptLine("    Chat ID    (Enter to skip): ")
		if chatID != "" {
			c.TelegramToken = token
			c.TelegramChatID = chatID
			c.TelegramEnabled = true
			fmt.Printf("  %s✓ Telegram enabled%s\n\n", green, reset)
		} else {
			fmt.Printf("  %s– Telegram skipped (no chat ID)%s\n\n", dim, reset)
		}
	} else {
		fmt.Printf("  %s– Telegram skipped%s\n\n", dim, reset)
	}

	// ── Discord ───────────────────────────────────────────────────────────────
	fmt.Printf("  %sDiscord%s\n", bold, reset)
	webhook := promptLine("    Webhook URL (Enter to skip): ")
	if webhook != "" {
		c.DiscordWebhook = webhook
		c.DiscordEnabled = true
		fmt.Printf("  %s✓ Discord enabled%s\n\n", green, reset)
	} else {
		fmt.Printf("  %s– Discord skipped%s\n\n", dim, reset)
	}

	saveAppConfig(c)
	fmt.Printf("  %sConfig saved → %s%s\n\n", dim, configFilePath(), reset)
	return c
}

// applyAppConfig merges saved config into cfg; env vars always win.
func applyAppConfig(ac AppConfig) {
	if cfg.TelegramToken == "" {
		cfg.TelegramToken = ac.TelegramToken
		cfg.TelegramChatID = ac.TelegramChatID
		cfg.TelegramEnabled = ac.TelegramEnabled
	}
	if cfg.DiscordWebhook == "" {
		cfg.DiscordWebhook = ac.DiscordWebhook
		cfg.DiscordEnabled = ac.DiscordEnabled
	}
}

// ─── Globals ─────────────────────────────────────────────────────────────────

var cfg Config
var httpClient *http.Client

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.StringVar(&cfg.Target, "d", "", "Target domain to scan")
	flag.StringVar(&cfg.DomainList, "l", "", "File with one domain per line")
	flag.IntVar(&cfg.Workers, "w", 50, "Parallel workers for subdomain scanning")
	flag.IntVar(&cfg.Concurrency, "c", 1, "Concurrent domain scans (when using -l)")
	flag.IntVar(&cfg.Depth, "depth", 1, "Subdomain depth (0=all, 1=*.domain, 2=*.*.domain)")
	flag.StringVar(&cfg.OutputFormat, "o", "all", "Output format: all|json|html|text")
	flag.StringVar(&cfg.Confidence, "confidence", "all", "Confidence filter: all|confirmed|probable")
	flag.StringVar(&cfg.ScanMode, "scan-mode", "builtin", "Scanner: builtin|baddns|all")
	flag.IntVar(&cfg.Timeout, "timeout", 10, "Per-subdomain HTTP/DNS timeout (seconds)")
	flag.IntVar(&cfg.VPSInterval, "vps", 0, "Daemon interval in hours (0=run once)")
	flag.BoolVar(&cfg.Quiet, "q", false, "Suppress progress output")
	flag.StringVar(&cfg.AWSRegion, "aws-region", "us-east-1", "Default AWS region for EB checks")
	helpFull := flag.Bool("help-full", false, "Show extended help")
	flag.Parse()

	if *helpFull {
		printHelpFull()
		os.Exit(0)
	}

	if cfg.DomainList != "" {
		cfg.ListMode = true
	}

	showBanner()

	// ── Notification config: env vars → saved config → first-run prompt ───────
	// Env vars are applied first so they always override saved config.
	cfg.TelegramToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.TelegramChatID = os.Getenv("TELEGRAM_CHAT_ID")
	if os.Getenv("TELEGRAM_ENABLED") == "true" && cfg.TelegramToken != "" {
		cfg.TelegramEnabled = true
	}
	cfg.DiscordWebhook = os.Getenv("DISCORD_WEBHOOK_URL")
	if os.Getenv("DISCORD_ENABLED") == "true" && cfg.DiscordWebhook != "" {
		cfg.DiscordEnabled = true
	}

	if ac, found := loadAppConfig(); found {
		applyAppConfig(ac) // fills in anything not already set by env
	} else if isTerminal() && !cfg.Quiet {
		// No saved config + interactive TTY → run first-run setup
		ac := firstRunSetup()
		applyAppConfig(ac)
	}

	// HTTP client with connection pooling and timeout
	httpClient = &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 10,
			DisableKeepAlives:   false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	checkDeps()

	if cfg.VPSInterval > 0 {
		logMsg("INFO", fmt.Sprintf("Daemon mode: interval %dh", cfg.VPSInterval))
		for {
			runAll()
			logMsg("INFO", fmt.Sprintf("Cycle complete. Sleeping %dh...", cfg.VPSInterval))
			time.Sleep(time.Duration(cfg.VPSInterval) * time.Hour)
		}
	} else {
		runAll()
	}
}

// ─── Entry Points ────────────────────────────────────────────────────────────

func runAll() {
	if cfg.ListMode {
		runListScan()
	} else if cfg.Target != "" {
		runScan(cfg.Target)
	} else {
		fmt.Fprintln(os.Stderr, "  [!] No target specified. Use -d <domain> or -l <file>")
		flag.Usage()
		os.Exit(1)
	}
}

func runListScan() {
	f, err := os.Open(cfg.DomainList)
	if err != nil {
		logMsg("ERROR", fmt.Sprintf("Cannot open domain list: %v", err))
		os.Exit(1)
	}
	defer f.Close()

	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	logMsg("INFO", fmt.Sprintf("Scanning %d domains from %s", len(domains), cfg.DomainList))

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, domain := range domains {
		sem <- struct{}{}
		wg.Add(1)
		go func(d string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			logMsg("INFO", fmt.Sprintf("[%d/%d] Starting: %s", idx+1, len(domains), d))
			runScan(d)
			logMsg("INFO", fmt.Sprintf("[%d/%d] Completed: %s", idx+1, len(domains), d))
		}(domain, i)
	}
	wg.Wait()
	logMsg("INFO", "All scans completed")
}

// ─── Core Scan ───────────────────────────────────────────────────────────────

func runScan(domain string) {
	ts := time.Now()
	outDir := filepath.Join("results", domain, ts.Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0755); err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: cannot create output dir: %v", domain, err))
		return
	}

	result := ScanResult{
		Domain:    domain,
		Timestamp: ts,
		OutputDir: outDir,
	}

	// 1. Enumerate subdomains
	logMsg("INFO", fmt.Sprintf("%s: Enumerating subdomains (subfinder)", domain))
	allSubsFile := filepath.Join(outDir, "all_subdomains.txt")
	subsFile := filepath.Join(outDir, "subdomains.txt")

	if err := runSubfinder(domain, allSubsFile); err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: subfinder failed: %v", domain, err))
		return
	}

	// 2. Filter by depth
	if err := filterByDepth(allSubsFile, subsFile, domain, cfg.Depth); err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: depth filter failed: %v", domain, err))
		return
	}

	subs, err := readLines(subsFile)
	if err != nil || len(subs) == 0 {
		logMsg("INFO", fmt.Sprintf("%s: no subdomains found", domain))
		return
	}
	result.TotalSubs = len(subs)
	result.SubdomainFile = subsFile
	logMsg("INFO", fmt.Sprintf("%s: Found %d subdomains (depth=%d)", domain, len(subs), cfg.Depth))

	// 3. Fingerprint dangling records
	logMsg("INFO", fmt.Sprintf("%s: Checking fingerprints on dangling records (%d workers)", domain, cfg.Workers))
	result.Findings = parallelScan(subs, domain)

	// 4. Reports
	logMsg("INFO", fmt.Sprintf("%s: Generating reports", domain))
	writeReports(result)

	// 5. Summary
	c, p, pos := countFindings(result.Findings)

	const (
		red   = "\033[0;31m"
		orange = "\033[0;33m"
		green = "\033[0;32m"
		cyan  = "\033[0;36m"
		dim   = "\033[2m"
		bold  = "\033[1m"
		reset = "\033[0m"
	)

	absOut, _ := filepath.Abs(outDir)
	fmt.Printf("\n  %s%s┌─────────────────────────────────────────────────────┐%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s│  Scan complete: %-36s│%s\n", bold, cyan, domain, reset)
	fmt.Printf("  %s%s├─────────────────────────────────────────────────────┤%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s│%s  %s🔴 Confirmed%s  %-5d  %s🟠 Probable%s  %-5d  %s🟡 Possible%s  %-5d%s%s│%s\n",
		bold, cyan, reset,
		red, reset, c,
		orange, reset, p-c,
		"\033[0;33m", reset, pos-p,
		bold, cyan, reset)
	fmt.Printf("  %s%s├─────────────────────────────────────────────────────┤%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s│%s  📁 %s%-49s%s%s│%s\n", bold, cyan, reset, dim, absOut+"/", reset, bold+cyan, reset)
	fmt.Printf("  %s%s│%s  📄 report.html  📋 report.json  📝 summary.txt    %s│%s\n", bold, cyan, reset, bold+cyan, reset)
	if cfg.TelegramEnabled || cfg.DiscordEnabled {
		services := ""
		if cfg.TelegramEnabled {
			services += "Telegram "
		}
		if cfg.DiscordEnabled {
			services += "Discord"
		}
		fmt.Printf("  %s%s│%s  🔔 Alerts → %-40s%s│%s\n", bold, cyan, reset, strings.TrimSpace(services), bold+cyan, reset)
	}
	fmt.Printf("  %s%s└─────────────────────────────────────────────────────┘%s\n\n", bold, cyan, reset)

	// Append to global history
	appendHistory(domain, c, p-c, pos-p)

	// 6. Notify
	sendAlerts(result)
}

// ─── Subfinder ───────────────────────────────────────────────────────────────

func runSubfinder(domain, outFile string) error {
	cmd := exec.Command("subfinder", "-d", domain, "-all", "--recursive", "-silent", "-nc", "-o", outFile)
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func filterByDepth(src, dst, domain string, depth int) error {
	lines, err := readLines(src)
	if err != nil {
		return err
	}

	var patterns []*regexp.Regexp
	escaped := regexp.QuoteMeta(domain)
	switch depth {
	case 0:
		// all
	case 1:
		patterns = append(patterns, regexp.MustCompile(`(?i)^[^.]+\.`+escaped+`$`))
	case 2:
		patterns = append(patterns, regexp.MustCompile(`(?i)^[^.]+\.`+escaped+`$`))
		patterns = append(patterns, regexp.MustCompile(`(?i)^[^.]+\.[^.]+\.`+escaped+`$`))
	default:
		// all
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	for _, line := range lines {
		if depth == 0 || len(patterns) == 0 {
			fmt.Fprintln(w, line)
			continue
		}
		for _, re := range patterns {
			if re.MatchString(line) {
				fmt.Fprintln(w, line)
				break
			}
		}
	}
	return w.Flush()
}

// ─── Parallel Scan ───────────────────────────────────────────────────────────

func parallelScan(subdomains []string, domain string) []Finding {
	total := int64(len(subdomains))
	var completed int64

	jobs := make(chan string, cfg.Workers*2)
	results := make(chan []Finding, len(subdomains))
	var wg sync.WaitGroup

	// Spawn workers
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				findings := checkSubdomain(sub)
				results <- findings
				done := atomic.AddInt64(&completed, 1)
				if !cfg.Quiet {
					pct := done * 100 / total
					fmt.Printf("\r\033[0;32m[%s]\033[0m \033[0;36m[INFO]\033[0m %s: Scanning... [%d/%d] %d%%",
						time.Now().Format("2006-01-02 15:04:05"), domain, done, total, pct)
				}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []Finding
	for batch := range results {
		allFindings = append(allFindings, batch...)
	}

	if !cfg.Quiet {
		fmt.Printf("\r%80s\r\n", "")
	}
	return allFindings
}

// ─── Subdomain Check ─────────────────────────────────────────────────────────

func checkSubdomain(subdomain string) []Finding {
	var findings []Finding

	// Use built-in scanner
	if cfg.ScanMode == "builtin" || cfg.ScanMode == "all" {
		findings = append(findings, checkBuiltin(subdomain)...)
	}

	// Also run baddns if requested
	if cfg.ScanMode == "baddns" || cfg.ScanMode == "all" {
		findings = append(findings, checkBaddns(subdomain)...)
	}

	return dedupeFindings(findings)
}

// checkBuiltin does DNS CNAME resolution + HTTP fingerprinting.
func checkBuiltin(subdomain string) []Finding {
	cnames, nxdomain := resolveCNAMEChain(subdomain)
	if len(cnames) == 0 {
		return nil
	}

	finalCNAME := cnames[len(cnames)-1]
	var findings []Finding

	for _, fp := range fingerprints {
		if !fp.CNAMERe.MatchString(finalCNAME) {
			continue
		}

		f := Finding{
			Target:    subdomain,
			CNAME:     finalCNAME,
			Service:   fp.Service,
			Module:    "CNAME",
			Timestamp: time.Now(),
		}

		switch {
		case fp.IsAWSEB:
			// Always run EB CLI check — even when NXDOMAIN, the prefix may still
			// be claimable and the CLI gives an authoritative answer.
			logMsg("INFO", fmt.Sprintf("  [AWS-EB] checking CNAME availability: %s", finalCNAME))
			cliConfirmed, desc := checkAWSElasticBeanstalk(finalCNAME, cfg.AWSRegion)
			switch {
			case cliConfirmed:
				f.Confidence = "CONFIRMED"
				f.AWSVerified = true
				f.Signature = "EB CNAME available (aws CLI)"
				f.Description = desc
			case nxdomain:
				// CLI couldn't confirm but DNS is already dead — still very likely
				f.Confidence = "CONFIRMED"
				f.Signature = "NXDOMAIN on EB CNAME target"
				f.Description = fmt.Sprintf("CNAME %s is NXDOMAIN. %s", finalCNAME, desc)
			default:
				f.Confidence = "PROBABLE"
				f.Signature = "CNAME → elasticbeanstalk.com"
				f.Description = desc
			}

		case fp.IsAWSS3:
			// Always run S3 check — CLI + HTTP probe.
			logMsg("INFO", fmt.Sprintf("  [AWS-S3] checking bucket: %s (cname: %s)", subdomain, finalCNAME))
			s3Confirmed, desc := checkAWSS3(subdomain, finalCNAME)
			switch {
			case s3Confirmed:
				f.Confidence = "CONFIRMED"
				f.AWSVerified = true
				f.Signature = "S3 NoSuchBucket"
				f.Description = desc
			case nxdomain:
				f.Confidence = "CONFIRMED"
				f.Signature = "NXDOMAIN on S3 CNAME target"
				f.Description = fmt.Sprintf("CNAME %s is NXDOMAIN. %s", finalCNAME, desc)
			default:
				f.Confidence = fp.Confidence
				f.Signature = "CNAME → s3.amazonaws.com"
				f.Description = desc
			}

		case nxdomain:
			// Generic NXDOMAIN for non-AWS services
			f.Confidence = "CONFIRMED"
			f.Signature = "NXDOMAIN on CNAME target"
			f.Description = fmt.Sprintf("CNAME %s resolves to NXDOMAIN — dangling record", finalCNAME)

		case fp.HTTPBody != "":
			// HTTP fingerprint check
			ok, status, body := httpCheck(subdomain)
			if ok && strings.Contains(body, fp.HTTPBody) && (fp.StatusCode == 0 || status == fp.StatusCode) {
				f.Confidence = fp.Confidence
				f.Signature = fp.HTTPBody
				f.Description = fmt.Sprintf("HTTP response contains '%s'", fp.HTTPBody)
			} else {
				f.Confidence = "PROBABLE"
				f.Signature = "CNAME match, HTTP unconfirmed"
				f.Description = fmt.Sprintf("CNAME → %s (HTTP check inconclusive)", fp.Service)
			}

		default:
			f.Confidence = fp.Confidence
			f.Signature = "CNAME match"
			f.Description = fmt.Sprintf("CNAME points to %s", fp.Service)
		}

		findings = append(findings, f)
		break // first matching fingerprint wins
	}

	return findings
}

// resolveCNAMEChain returns the full CNAME chain and whether the final target is NXDOMAIN.
func resolveCNAMEChain(host string) (chain []string, nxdomain bool) {
	visited := map[string]bool{}
	current := host

	for i := 0; i < 10; i++ {
		if visited[current] {
			break
		}
		visited[current] = true

		// Use package-level LookupCNAME (default resolver, no context needed).
		// Do NOT use net.Resolver{}.LookupCNAME(nil, ...) — passing nil context
		// causes a SIGSEGV in the CGO DNS path on Linux.
		cname, err := net.LookupCNAME(current)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				nxdomain = true
			}
			break
		}
		// LookupCNAME returns "host." (with trailing dot) when no CNAME exists
		if cname == current+"." || cname == current {
			break
		}
		clean := strings.TrimSuffix(cname, ".")
		chain = append(chain, clean)
		current = clean
	}

	return chain, nxdomain
}

// httpCheck performs a GET and returns (success, statusCode, body).
func httpCheck(host string) (bool, int, string) {
	for _, u := range []string{"http://" + host, "https://" + host} {
		resp, err := httpClient.Get(u)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close() // explicit close — defer inside a loop leaks until function return
		return true, resp.StatusCode, string(bodyBytes)
	}
	return false, 0, ""
}

// ─── AWS Elastic Beanstalk Check ─────────────────────────────────────────────

// checkAWSElasticBeanstalk calls `aws elasticbeanstalk check-dns-availability`
// on the extracted CNAME prefix.
// Returns (takeover_confirmed, description).
func checkAWSElasticBeanstalk(cname, defaultRegion string) (bool, string) {
	// cname looks like: myapp.us-east-1.elasticbeanstalk.com
	// or: myapp.elasticbeanstalk.com (older style, no region prefix)
	parts := strings.Split(cname, ".")
	if len(parts) < 3 {
		return false, "could not parse EB CNAME"
	}

	prefix := parts[0]
	region := defaultRegion

	// Detect region from CNAME: PREFIX.REGION.elasticbeanstalk.com
	if len(parts) >= 4 {
		maybeRegion := parts[1]
		// Basic heuristic: region names look like us-east-1, eu-west-2, ap-southeast-1, etc.
		regionRe := regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d+$`)
		if regionRe.MatchString(maybeRegion) {
			region = maybeRegion
		}
	}

	out, err := exec.Command(
		"aws", "elasticbeanstalk", "check-dns-availability",
		"--region", region,
		"--cname-prefix", prefix,
	).Output()
	if err != nil {
		return false, fmt.Sprintf("aws CLI error: %v", err)
	}

	var result struct {
		Available           bool   `json:"Available"`
		FullyQualifiedCNAME string `json:"FullyQualifiedCNAME"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return false, fmt.Sprintf("aws CLI parse error: %v", err)
	}

	if result.Available {
		return true, fmt.Sprintf("EB CNAME prefix '%s' is AVAILABLE in %s — takeover possible", prefix, region)
	}
	return false, fmt.Sprintf("EB CNAME prefix '%s' is in use (not available) in %s", prefix, region)
}

// ─── AWS S3 Check ────────────────────────────────────────────────────────────

// checkAWSS3 checks whether the S3 bucket is unclaimed.
// Returns (takeover_confirmed, description).
func checkAWSS3(subdomain, cname string) (bool, string) {
	// Extract bucket name: may be the subdomain itself or from the CNAME
	buckets := extractS3BucketNames(subdomain, cname)

	for _, bucket := range buckets {
		// First try: aws s3api head-bucket
		if awsOk, desc := checkS3ViaCLI(bucket); awsOk {
			return true, desc
		}

		// Fallback: HTTP probe
		if confirmed, desc := checkS3ViaHTTP(bucket); confirmed {
			return true, desc
		}
	}

	return false, "S3 bucket exists or check inconclusive"
}

func extractS3BucketNames(subdomain, cname string) []string {
	seen := map[string]bool{}
	var buckets []string

	add := func(b string) {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" && !seen[b] {
			seen[b] = true
			buckets = append(buckets, b)
		}
	}

	// subdomain itself might be the bucket name
	add(subdomain)

	// strip common S3 CNAME patterns:
	// BUCKET.s3.amazonaws.com
	// BUCKET.s3-us-east-1.amazonaws.com
	// BUCKET.s3.us-east-1.amazonaws.com
	s3Re := regexp.MustCompile(`(?i)^([^.]+)\.s3[.-]`)
	if m := s3Re.FindStringSubmatch(cname); len(m) > 1 {
		add(m[1])
	}

	return buckets
}

func checkS3ViaCLI(bucket string) (bool, string) {
	out, err := exec.Command("aws", "s3api", "head-bucket", "--bucket", bucket).CombinedOutput()
	if err != nil {
		combined := string(out)
		if strings.Contains(combined, "NoSuchBucket") || strings.Contains(combined, "404") {
			return true, fmt.Sprintf("S3 bucket '%s' does not exist — takeover possible", bucket)
		}
		if strings.Contains(combined, "403") {
			return false, fmt.Sprintf("S3 bucket '%s' exists (403 forbidden)", bucket)
		}
	}
	return false, ""
}

func checkS3ViaHTTP(bucket string) (bool, string) {
	for _, u := range []string{
		fmt.Sprintf("http://%s.s3.amazonaws.com/", bucket),
		fmt.Sprintf("http://s3.amazonaws.com/%s/", bucket),
	} {
		resp, err := httpClient.Get(u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close() // explicit close — defer inside a loop leaks until function return
		if strings.Contains(string(body), "NoSuchBucket") {
			return true, fmt.Sprintf("S3 bucket '%s' returns NoSuchBucket", bucket)
		}
	}
	return false, ""
}

// ─── baddns integration ──────────────────────────────────────────────────────

func checkBaddns(subdomain string) []Finding {
	args := []string{"-s", subdomain}
	if cfg.ScanMode != "baddns" && cfg.ScanMode != "all" {
		args = append([]string{"-m", cfg.ScanMode}, args...)
	}
	cmd := exec.Command("baddns", args...)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}

	var findings []Finding
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		f := Finding{
			Target:    getString(raw, "target"),
			CNAME:     getString(raw, "trigger"),
			Confidence: strings.ToUpper(getString(raw, "confidence")),
			Module:    getString(raw, "module"),
			Service:   getString(raw, "signature"),
			Signature: getString(raw, "signature"),
			Description: getString(raw, "description"),
			Timestamp: time.Now(),
		}
		if f.Target == "" {
			f.Target = subdomain
		}
		findings = append(findings, f)
	}
	return findings
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ─── Reports ─────────────────────────────────────────────────────────────────

func writeReports(result ScanResult) {
	// Always write raw JSON
	rawPath := filepath.Join(result.OutputDir, "findings.json")
	writeJSON(rawPath, result.Findings)

	// Confidence-filtered text files
	writeFilteredText(result.OutputDir, result.Findings)

	if cfg.OutputFormat == "all" || cfg.OutputFormat == "json" {
		writeJSONReport(result)
	}
	if cfg.OutputFormat == "all" || cfg.OutputFormat == "html" {
		writeHTMLReport(result)
	}
	if cfg.OutputFormat == "all" || cfg.OutputFormat == "text" {
		writeTextReport(result)
	}
}

func writeFilteredText(dir string, findings []Finding) {
	type filter struct{ name, level string }
	for _, f := range []filter{
		{"vulnerable_confirmed.txt", "CONFIRMED"},
		{"vulnerable_probable.txt", "PROBABLE_OR_ABOVE"},
		{"vulnerable_all.txt", "all"},
	} {
		out, _ := os.Create(filepath.Join(dir, f.name))
		w := bufio.NewWriter(out)
		for _, finding := range findings {
			switch f.level {
			case "CONFIRMED":
				if finding.Confidence == "CONFIRMED" {
					fmt.Fprintln(w, finding.Target)
				}
			case "PROBABLE_OR_ABOVE":
				if finding.Confidence == "CONFIRMED" || finding.Confidence == "PROBABLE" {
					fmt.Fprintln(w, finding.Target)
				}
			default:
				fmt.Fprintln(w, finding.Target)
			}
		}
		w.Flush()
		out.Close()
	}
}

func writeJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

type jsonReport struct {
	ScanTime   time.Time         `json:"scan_time"`
	Tool       string            `json:"tool"`
	Version    string            `json:"version"`
	Domain     string            `json:"domain"`
	ScanMode   string            `json:"scan_mode"`
	Subdomains int               `json:"total_subdomains"`
	Summary    map[string]int    `json:"vulnerabilities"`
	Findings   []Finding         `json:"findings"`
}

func writeJSONReport(result ScanResult) {
	c, p, pos := countFindings(result.Findings)
	report := jsonReport{
		ScanTime:   result.Timestamp,
		Tool:       "SUBMON",
		Version:    version,
		Domain:     result.Domain,
		ScanMode:   cfg.ScanMode,
		Subdomains: result.TotalSubs,
		Summary: map[string]int{
			"confirmed": c,
			"probable":  p - c,
			"possible":  pos - p,
			"total":     pos,
		},
		Findings: result.Findings,
	}
	writeJSON(filepath.Join(result.OutputDir, "report.json"), report)
}

func writeTextReport(result ScanResult) {
	c, p, pos := countFindings(result.Findings)
	f, err := os.Create(filepath.Join(result.OutputDir, "summary.txt"))
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "==========================================")
	fmt.Fprintln(f, "  SUBMON v"+version+" - Scan Results")
	fmt.Fprintln(f, "==========================================")
	fmt.Fprintf(f, "Scan Time  : %s\n", result.Timestamp.Format(time.RFC1123))
	fmt.Fprintf(f, "Domain     : %s\n", result.Domain)
	fmt.Fprintf(f, "Scan Mode  : %s\n", cfg.ScanMode)
	fmt.Fprintf(f, "Subdomains : %d\n\n", result.TotalSubs)
	fmt.Fprintln(f, "VULNERABILITY SUMMARY")
	fmt.Fprintln(f, "------------------------------------------")
	fmt.Fprintf(f, "  %-12s : %d\n", "CONFIRMED", c)
	fmt.Fprintf(f, "  %-12s : %d\n", "PROBABLE", p-c)
	fmt.Fprintf(f, "  %-12s : %d\n", "POSSIBLE", pos-p)
	fmt.Fprintf(f, "  %-12s : %d\n\n", "TOTAL", pos)

	if len(result.Findings) > 0 {
		fmt.Fprintln(f, "FINDING DETAILS")
		fmt.Fprintln(f, "------------------------------------------")
		for i, finding := range result.Findings {
			fmt.Fprintf(f, "\n[%d] %s\n", i+1, finding.Target)
			fmt.Fprintf(f, "  %-14s : %s\n", "Confidence", finding.Confidence)
			fmt.Fprintf(f, "  %-14s : %s\n", "CNAME", finding.CNAME)
			fmt.Fprintf(f, "  %-14s : %s\n", "Service", finding.Service)
			fmt.Fprintf(f, "  %-14s : %s\n", "Signature", finding.Signature)
			fmt.Fprintf(f, "  %-14s : %s\n", "Description", finding.Description)
			if finding.AWSVerified {
				fmt.Fprintf(f, "  %-14s : YES\n", "AWS Verified")
			}
		}
	}
	fmt.Fprintln(f, "\n==========================================")
}

// ─── HTML Report ─────────────────────────────────────────────────────────────

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SUBMON Report - {{.Domain}}</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --blue: #58a6ff; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; }
  a { color: var(--blue); }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }

  /* Header */
  .header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }
  .header h1 { font-size: 28px; font-weight: 700; color: var(--red); letter-spacing: -0.5px; }
  .header h1 span { color: var(--text); }
  .meta { margin-top: 8px; color: var(--muted); font-size: 13px; display: flex; gap: 24px; flex-wrap: wrap; }
  .meta strong { color: var(--text); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge-mode { background: #1f2937; border: 1px solid var(--border); color: var(--muted); }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .card .num { font-size: 40px; font-weight: 700; line-height: 1; }
  .card .label { font-size: 12px; color: var(--muted); margin-top: 6px; text-transform: uppercase; letter-spacing: 1px; }
  .card.confirmed { border-color: var(--red); }
  .card.confirmed .num { color: var(--red); }
  .card.probable { border-color: var(--orange); }
  .card.probable .num { color: var(--orange); }
  .card.possible { border-color: var(--yellow); }
  .card.possible .num { color: var(--yellow); }
  .card.total { border-color: var(--border); }
  .card.total .num { color: var(--text); }
  .card.subdomains { border-color: var(--blue); }
  .card.subdomains .num { color: var(--blue); }

  /* Findings table */
  .section-title { font-size: 18px; font-weight: 600; margin-bottom: 16px; color: var(--text); display: flex; align-items: center; gap: 8px; }
  .count-pill { background: var(--bg3); border: 1px solid var(--border); border-radius: 20px; padding: 2px 10px; font-size: 12px; color: var(--muted); }

  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { background: var(--bg2); border: 1px solid var(--border); color: var(--muted); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--blue); color: var(--blue); background: rgba(88,166,255,0.08); }

  .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; }
  thead { background: var(--bg3); }
  th { padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); white-space: nowrap; }
  td { padding: 10px 14px; border-top: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: rgba(255,255,255,0.02); }

  .conf-badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap; }
  .conf-CONFIRMED { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
  .conf-PROBABLE  { background: rgba(210,153,34,0.15); color: var(--orange); border: 1px solid rgba(210,153,34,0.3); }
  .conf-POSSIBLE  { background: rgba(227,179,65,0.12); color: var(--yellow); border: 1px solid rgba(227,179,65,0.25); }

  .target-cell { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; color: var(--text); }
  .cname-cell  { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; color: var(--muted); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .service-cell { color: var(--blue); font-size: 13px; }
  .desc-cell { color: var(--muted); font-size: 12px; max-width: 320px; }
  .aws-badge { background: rgba(255,153,0,0.15); color: #ff9900; border: 1px solid rgba(255,153,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-left: 6px; }

  .no-findings { text-align: center; padding: 48px; color: var(--muted); }
  .no-findings .icon { font-size: 40px; margin-bottom: 8px; }

  /* Footer */
  .footer { margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1>SUBMON <span>v{{.Version}}</span></h1>
    <div class="meta">
      <div><strong>Target:</strong> {{.Domain}}</div>
      <div><strong>Scan Time:</strong> {{.ScanTime}}</div>
      <div><strong>Mode:</strong> <span class="badge badge-mode">{{.ScanMode}}</span></div>
    </div>
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card confirmed">
      <div class="num">{{.Confirmed}}</div>
      <div class="label">Confirmed</div>
    </div>
    <div class="card probable">
      <div class="num">{{.Probable}}</div>
      <div class="label">Probable</div>
    </div>
    <div class="card possible">
      <div class="num">{{.Possible}}</div>
      <div class="label">Possible</div>
    </div>
    <div class="card total">
      <div class="num">{{.Total}}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card subdomains">
      <div class="num">{{.Subdomains}}</div>
      <div class="label">Subdomains</div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section-title">
    Findings <span class="count-pill">{{.Total}}</span>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterTable('all', this)">All</button>
    <button class="filter-btn" onclick="filterTable('CONFIRMED', this)">Confirmed</button>
    <button class="filter-btn" onclick="filterTable('PROBABLE', this)">Probable</button>
    <button class="filter-btn" onclick="filterTable('POSSIBLE', this)">Possible</button>
  </div>

  <div class="table-wrap">
    {{if .Findings}}
    <table id="findings-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Confidence</th>
          <th>Target Subdomain</th>
          <th>CNAME</th>
          <th>Service</th>
          <th>Signature</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {{range $i, $f := .Findings}}
        <tr data-confidence="{{$f.Confidence}}">
          <td style="color:var(--muted);font-size:12px;">{{inc $i}}</td>
          <td><span class="conf-badge conf-{{$f.Confidence}}">{{$f.Confidence}}</span></td>
          <td class="target-cell">{{$f.Target}}{{if $f.AWSVerified}}<span class="aws-badge">AWS ✓</span>{{end}}</td>
          <td class="cname-cell" title="{{$f.CNAME}}">{{$f.CNAME}}</td>
          <td class="service-cell">{{$f.Service}}</td>
          <td style="font-size:12px;color:var(--muted);">{{$f.Signature}}</td>
          <td class="desc-cell">{{$f.Description}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="no-findings">
      <div class="icon">✓</div>
      <div>No takeover vulnerabilities found</div>
    </div>
    {{end}}
  </div>

  <div class="footer">
    <span>SUBMON v{{.Version}} - Subdomain Takeover Monitor</span>
    <span>Generated {{.ScanTime}}</span>
  </div>
</div>

<script>
function filterTable(conf, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {
    const c = row.getAttribute('data-confidence');
    row.style.display = (conf === 'all' || c === conf) ? '' : 'none';
  });
}
</script>
</body>
</html>`

type htmlData struct {
	Domain    string
	Version   string
	ScanTime  string
	ScanMode  string
	Confirmed int
	Probable  int
	Possible  int
	Total     int
	Subdomains int
	Findings  []Finding
}

func writeHTMLReport(result ScanResult) {
	c, p, pos := countFindings(result.Findings)
	data := htmlData{
		Domain:     result.Domain,
		Version:    version,
		ScanTime:   result.Timestamp.Format("2006-01-02 15:04:05 MST"),
		ScanMode:   cfg.ScanMode,
		Confirmed:  c,
		Probable:   p - c,
		Possible:   pos - p,
		Total:      pos,
		Subdomains: result.TotalSubs,
		Findings:   applyConfidenceFilter(result.Findings, cfg.Confidence),
	}

	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTmpl)
	if err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: HTML template parse failed: %v", result.Domain, err))
		return
	}

	htmlPath := filepath.Join(result.OutputDir, "report.html")
	f, err := os.Create(htmlPath)
	if err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: HTML report create failed: %v", result.Domain, err))
		return
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		logMsg("ERROR", fmt.Sprintf("%s: HTML render failed: %v", result.Domain, err))
		return
	}
	logMsg("INFO", fmt.Sprintf("%s: HTML report → %s", result.Domain, htmlPath))
}

// ─── Notifications ───────────────────────────────────────────────────────────

func sendAlerts(result ScanResult) {
	c, p, pos := countFindings(result.Findings)
	if c+p+pos == 0 {
		return
	}
	if cfg.TelegramEnabled {
		sendTelegram(result, c, p-c, pos-p)
	}
	if cfg.DiscordEnabled {
		sendDiscord(result, c, p-c, pos-p)
	}
}

func sendTelegram(result ScanResult, confirmed, probable, possible int) {
	msg := fmt.Sprintf(
		"🐾 *SUBMON ALERT*\n"+
			"━━━━━━━━━━━━━━━━━━━━━━\n"+
			"📅 Date   : `%s`\n"+
			"🎯 Target : `%s`\n\n"+
			"📊 *SUMMARY*\n"+
			"🔴 Confirmed : %d\n"+
			"🟠 Probable  : %d\n"+
			"🟡 Possible  : %d\n"+
			"━━━━━━━━━━━━━━━━━━━━━━\n"+
			"📁 Report: results/%s/\n"+
			"🔧 submon v%s",
		result.Timestamp.Format("2006-01-02 15:04:05"),
		result.Domain, confirmed, probable, possible,
		result.Domain, version,
	)

	for _, finding := range result.Findings {
		if finding.Confidence == "CONFIRMED" || finding.Confidence == "PROBABLE" {
			emoji := "🟠"
			if finding.Confidence == "CONFIRMED" {
				emoji = "🔴"
			}
			awsMark := ""
			if finding.AWSVerified {
				awsMark = " [AWS✓]"
			}
			msg += fmt.Sprintf("\n\n%s `%s`%s\n```\n  CNAME: %s\n  Service: %s\n```",
				emoji, finding.Target, awsMark, finding.CNAME, finding.Service)
		}
	}

	if len(msg) > 4000 {
		msg = msg[:3900] + "\n\n_...truncated_"
	}

	apiURL := "https://api.telegram.org/bot" + cfg.TelegramToken + "/sendMessage"
	data := map[string]string{
		"chat_id":    cfg.TelegramChatID,
		"text":       msg,
		"parse_mode": "Markdown",
	}
	body, _ := json.Marshal(data)
	resp, err := httpClient.Post(apiURL, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
		logMsg("INFO", "Telegram alert sent for "+result.Domain)
	}
}

func sendDiscord(result ScanResult, confirmed, probable, possible int) {
	color := 16776960 // yellow
	if probable > 0 {
		color = 16744272 // orange
	}
	if confirmed > 0 {
		color = 16711680 // red
	}

	desc := fmt.Sprintf(
		"**Target:** `%s`\n**Scan Time:** `%s`\n\n🔴 Confirmed: **%d**\n🟠 Probable: **%d**\n🟡 Possible: **%d**",
		result.Domain,
		result.Timestamp.Format("2006-01-02 15:04:05"),
		confirmed, probable, possible,
	)

	payload := map[string]interface{}{
		"username": "submon",
		"embeds": []map[string]interface{}{{
			"title":       "🐾 SUBMON — Subdomain Takeover Alert",
			"description": desc,
			"color":       color,
			"footer":      map[string]string{"text": "submon v" + version},
			"timestamp":   result.Timestamp.UTC().Format(time.RFC3339),
		}},
	}

	body, _ := json.Marshal(payload)
	resp, err := httpClient.Post(cfg.DiscordWebhook, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
		logMsg("INFO", "Discord alert sent for "+result.Domain)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func countFindings(findings []Finding) (confirmed, probable, possible int) {
	for _, f := range findings {
		switch f.Confidence {
		case "CONFIRMED":
			confirmed++
			probable++
			possible++
		case "PROBABLE":
			probable++
			possible++
		default:
			possible++
		}
	}
	return
}

func applyConfidenceFilter(findings []Finding, level string) []Finding {
	switch level {
	case "confirmed":
		var out []Finding
		for _, f := range findings {
			if f.Confidence == "CONFIRMED" {
				out = append(out, f)
			}
		}
		return out
	case "probable":
		var out []Finding
		for _, f := range findings {
			if f.Confidence == "CONFIRMED" || f.Confidence == "PROBABLE" {
				out = append(out, f)
			}
		}
		return out
	default:
		return findings
	}
}

func dedupeFindings(findings []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range findings {
		key := f.Target + "|" + f.CNAME + "|" + f.Service
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func appendHistory(domain string, confirmed, probable, possible int) {
	f, err := os.OpenFile("scan_history.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s | %s | C:%d P:%d L:%d\n",
		time.Now().Format("2006-01-02 15:04:05"), domain, confirmed, probable, possible)
}

func checkDeps() {
	missing := false
	if _, err := exec.LookPath("subfinder"); err != nil {
		logMsg("ERROR", "subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		missing = true
	}
	if cfg.ScanMode == "baddns" || cfg.ScanMode == "all" {
		if _, err := exec.LookPath("baddns"); err != nil {
			logMsg("WARN", "baddns not found (required for scan-mode baddns/all). Install: pip install baddns")
		}
	}
	if missing {
		os.Exit(1)
	}
}

func logMsg(level, msg string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	switch level {
	case "INFO":
		fmt.Printf("\033[0;32m[%s]\033[0m \033[0;36m[INFO]\033[0m %s\n", ts, msg)
	case "WARN":
		fmt.Fprintf(os.Stderr, "\033[1;33m[%s] [WARN] %s\033[0m\n", ts, msg)
	case "ERROR":
		fmt.Fprintf(os.Stderr, "\033[0;31m[%s] [ERROR] %s\033[0m\n", ts, msg)
	}
}

func showBanner() {
	const (
		red   = "\033[0;31m"
		bold  = "\033[1m"
		cyan  = "\033[0;36m"
		dim   = "\033[2m"
		green = "\033[0;32m"
		mag   = "\033[0;35m"
		reset = "\033[0m"
	)

	// figlet "chunky" font — rectangular bordered block letters, width 48.
	fmt.Println()
	fmt.Print(red + bold + ` _______ _______ ______ _______ _______ _______` + reset + "\n")
	fmt.Print(red + bold + `|     __|   |   |   __ \   |   |       |    |  |` + reset + "\n")
	fmt.Print(red + bold + `|__     |   |   |   __ <       |   -   |       |` + reset + "\n")
	fmt.Print(red + bold + `|_______|_______|______/__|_|__|_______|__|____|` + reset +
		"  " + cyan + bold + "v" + version + reset + "\n")

	// Centered within 48-char art width:
	//   "Subdomain Takeover Monitor" (26 chars) → 11 leading spaces
	//   "Developed by claude"         (19 chars) → 14 leading spaces
	fmt.Println()
	fmt.Printf("           %sSubdomain Takeover Monitor%s\n", dim, reset)
	fmt.Printf("              %sDeveloped by claude%s\n", mag, reset)
	fmt.Println()

	fmt.Printf("  %smode%s  %s%-10s%s  %sworkers%s  %s%-4d%s  %stimeout%s  %s%ds%s\n\n",
		dim, reset, green, strings.ToUpper(cfg.ScanMode), reset,
		dim, reset, cyan, cfg.Workers, reset,
		dim, reset, cyan, cfg.Timeout, reset)
}

func printHelpFull() {
	fmt.Printf(`
  SUBMON v%s - Subdomain Takeover Monitor (Go)

USAGE:
    submon -d <domain> [options]
    submon -l <file>   [options]

OPTIONS:
    -d <domain>         Target domain
    -l <file>           Domain list (one per line)
    -w <n>              Workers (default 50, increase for speed)
    -c <n>              Concurrent domain scans when using -l
    -depth <n>          Subdomain depth: 0=all, 1=*.domain, 2=*.*.domain
    -o <format>         Output: all|json|html|text (default: all)
    -confidence <lvl>   Filter: all|confirmed|probable
    -scan-mode <mode>   builtin|baddns|all (default: builtin)
    -timeout <sec>      Per-subdomain timeout (default: 10)
    -aws-region <r>     Default AWS region for EB checks (default: us-east-1)
    -vps <hours>        Daemon mode, repeat every N hours
    -q                  Quiet mode
    -help-full          This help

SCAN MODES:
    builtin   Built-in DNS+HTTP fingerprinting (fast, no baddns needed)
    baddns    Use baddns tool (requires: pip install baddns)
    all       Both builtin + baddns

AWS CHECKS:
    Elastic Beanstalk:
      CNAME *.elasticbeanstalk.com → runs:
        aws elasticbeanstalk check-dns-availability --region REGION --cname-prefix PREFIX
      If Available=true → CONFIRMED takeover

    S3:
      CNAME *.s3*.amazonaws.com → runs:
        aws s3api head-bucket --bucket BUCKET
      NoSuchBucket response → CONFIRMED takeover

NOTIFICATIONS (via env vars):
    TELEGRAM_ENABLED=true TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...
    DISCORD_ENABLED=true  DISCORD_WEBHOOK_URL=...

EXAMPLES:
    submon -d example.com                       # full scan
    submon -d example.com -w 100                # 100 parallel workers
    submon -d example.com -scan-mode all        # builtin + baddns
    submon -l domains.txt -c 5 -w 50            # list scan, 5 parallel domains
    submon -d example.com -o html               # HTML report only
    submon -d example.com -aws-region eu-west-1 # EB checks in EU
`, version)
}
