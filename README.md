# SUBMON v1.0

```
 _______ _______ ______ _______ _______ _______
|     __|   |   |   __ \   |   |       |    |  |
|__     |   |   |   __ <       |   -   |       |
|_______|_______|______/__|_|__|_______|__|____|

           Subdomain Takeover Monitor
              Developed by r0h1th
```

A fast subdomain takeover monitor written in Go. Uses a goroutine worker pool for parallel DNS/HTTP fingerprinting and AWS-native verification for Elastic Beanstalk and S3.

---

## Features

- Goroutine worker pool - 50 workers by default, replaces slow serial scanning
- Built-in CNAME fingerprinting for 25+ services (GitHub Pages, Heroku, Azure, S3, Fastly, Shopify, Zendesk, and more)
- AWS Elastic Beanstalk - uses `aws elasticbeanstalk check-dns-availability` to confirm if a CNAME prefix is claimable
- AWS S3 - uses `aws s3api head-bucket` + HTTP `NoSuchBucket` probe
- NXDOMAIN detection on dangling CNAME targets
- HTML report with dark theme, filterable findings table, confidence badges
- JSON + text reports
- Telegram and Discord alerts
- First-run interactive setup for notifications

---

## Installation

```bash
git clone https://github.com/unluckyhacker/submon
cd submon
go build -o submon .
```

### Dependencies

| Tool | Required | Install |
|------|----------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Yes | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| AWS CLI | Optional | For EB/S3 native checks |
| [baddns](https://github.com/blacklanternsecurity/baddns) | Optional | `pip install baddns` (for `--scan-mode baddns`) |

---

## Usage

```bash
# Basic scan
./submon -d example.com

# Fast scan with more workers
./submon -d example.com -w 100

# Scan a list of domains
./submon -l domains.txt -c 5

# Use baddns alongside built-in checks
./submon -d example.com --scan-mode all

# HTML report only
./submon -d example.com -o html

# Only show confirmed findings
./submon -d example.com --confidence confirmed

# AWS checks in a specific region
./submon -d example.com --aws-region eu-west-1

# Daemon mode - repeat every 24 hours
./submon -d example.com --vps 24
```

---

## Options

```
-d <domain>         Target domain
-l <file>           Domain list (one per line)
-w <n>              Workers (default 50)
-c <n>              Concurrent domain scans when using -l (default 1)
-depth <n>          Subdomain depth - 0=all, 1=*.domain, 2=*.*.domain (default 1)
-o <format>         Output format - all, json, html, text (default all)
-confidence <lvl>   Filter findings - all, confirmed, probable (default all)
-scan-mode <mode>   Scanner - builtin, baddns, all (default builtin)
-timeout <sec>      Per-subdomain timeout in seconds (default 10)
-aws-region <r>     AWS region for Elastic Beanstalk checks (default us-east-1)
-vps <hours>        Daemon mode interval in hours
-q                  Quiet mode
```

---

## Notifications

On first run, SUBMON will prompt you to configure Telegram and Discord alerts. Credentials are saved to `~/.config/submon/config.json`.

To reconfigure, delete the config file and run again:
```bash
rm ~/.config/submon/config.json
./submon -d example.com
```

You can also set credentials via environment variables (these override the saved config):

```bash
export TELEGRAM_ENABLED=true
export TELEGRAM_BOT_TOKEN=your_token
export TELEGRAM_CHAT_ID=your_chat_id

export DISCORD_ENABLED=true
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## Output

Results are saved to `results/<domain>/<timestamp>/`:

```
results/example.com/20250403_120000/
├── report.html           - HTML report (dark theme, filterable)
├── report.json           - Machine-readable JSON
├── summary.txt           - Text summary
├── findings.json         - Raw findings
├── vulnerable_confirmed.txt
├── vulnerable_probable.txt
├── vulnerable_all.txt
└── subdomains.txt
```

---

## Supported Services

AWS Elastic Beanstalk, AWS S3, AWS CloudFront, GitHub Pages, Heroku, Azure App Service, Fastly, Shopify, Tumblr, Ghost, Webflow, Surge.sh, Bitbucket, Zendesk, UserVoice, Intercom, HelpJuice, HelpScout, Readme.io, Pingdom, BigCartel, Pantheon, Launchrock, Kajabi, Strikingly

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `builtin` | Built-in DNS + HTTP fingerprinting (default, no extra tools needed) |
| `baddns` | Use baddns tool only |
| `all` | Both builtin and baddns |

---

## AWS Checks

**Elastic Beanstalk** - When a CNAME pointing to `*.elasticbeanstalk.com` is found, SUBMON runs:
```bash
aws elasticbeanstalk check-dns-availability --region REGION --cname-prefix PREFIX
```
If `Available: true` is returned, the finding is marked as `CONFIRMED` with `AWS Verified`.

**S3** - When a CNAME pointing to `*.s3.amazonaws.com` is found, SUBMON runs:
```bash
aws s3api head-bucket --bucket BUCKET
```
A `NoSuchBucket` response confirms the bucket is available for takeover.

---

## License

MIT
