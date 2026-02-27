<!-- 
SEO Keywords: NullSec Recon, reconnaissance tools, OSINT tools, subdomain finder,
asset discovery, information gathering, bug bounty recon, web recon, DNS enumeration,
bad-antics, NullSec Framework, subdomain enumeration, security reconnaissance
-->

<div align="center">

# 🔍 NullSec Recon

### Advanced Reconnaissance & OSINT Toolkit

[![X/Twitter](https://img.shields.io/badge/🔑_GET_KEYS-x.com/AnonAntics-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://x.com/AnonAntics)
[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-NREC--XXX-red?style=for-the-badge)](LICENSE)

[![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)]()
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)]()

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
     ░    ░    ░   ░   ░         ░            ░   ░   ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░░░ R E C O N ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

### 🔓 **[Join x.com/AnonAntics](https://x.com/AnonAntics)** for premium features!

</div>

---

## 🎯 Features

| Tool | Language | Description | Free | Premium |
|------|----------|-------------|------|---------|
| **subfinder** | Go | Fast subdomain discovery | ✅ | 🔥 |
| **dnsrecon** | Go | DNS enumeration & zone transfer | ✅ | 🔥 |
| **wayback** | Python | Wayback Machine scraper | ✅ | 🔥 |
| **gitscan** | Go | GitHub/GitLab secret scanner | ❌ | 🔥 |
| **emailhunter** | Python | Email address harvester | ✅ | 🔥 |
| **techdetect** | Go | Technology stack detector | ✅ | 🔥 |

---

## 📁 Structure

```
nullsec-recon/
├── go/
│   ├── subfinder/       # Subdomain enumeration
│   ├── dnsrecon/        # DNS reconnaissance
│   ├── techdetect/      # Tech stack detection
│   └── gitscan/         # Git repository scanner
├── python/
│   ├── wayback.py       # Wayback Machine scraper
│   ├── emailhunter.py   # Email harvester
│   ├── whois_lookup.py  # WHOIS information
│   └── shodan_search.py # Shodan integration
└── scripts/
    ├── full_recon.sh    # Complete recon automation
    └── report_gen.py    # Report generator
```

---

## 🚀 Quick Start

```bash
# Subdomain enumeration
./subfinder -d example.com -o subdomains.txt

# DNS reconnaissance
./dnsrecon -d example.com --all

# Wayback URLs
python3 wayback.py -d example.com -o urls.txt

# Full automated recon
./scripts/full_recon.sh example.com
```

---

## 🔧 Tool Details

### subfinder (Go) - Subdomain Discovery

Sources:
- Certificate Transparency (crt.sh)
- DNS bruteforce
- Search engines (Google, Bing, Yahoo)
- VirusTotal, SecurityTrails
- Web archives

```bash
# Basic enumeration
./subfinder -d target.com

# With custom wordlist
./subfinder -d target.com -w subdomains.txt

# Multiple sources
./subfinder -d target.com --all -o results.txt

# JSON output
./subfinder -d target.com -json | jq
```

### techdetect (Go) - Technology Detection

Detects:
- Web frameworks (React, Angular, Vue)
- CMS (WordPress, Drupal, Joomla)
- Web servers (nginx, Apache, IIS)
- Programming languages
- CDN providers
- Analytics/tracking

```bash
# Scan single URL
./techdetect -u https://example.com

# Scan list of URLs
./techdetect -l urls.txt -o tech_report.json
```

---

## ⚠️ Legal Disclaimer

**For authorized security testing only.** Only perform reconnaissance on systems you have permission to test.

---

<div align="center">

**NullSec Framework** | [GitHub](https://github.com/bad-antics) | [X/Twitter](https://x.com/AnonAntics)

</div>
