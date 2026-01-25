# NullSec Recon Techniques

## Passive Reconnaissance

### OSINT
```bash
# Domain information
nullsec-recon --osint --domain target.com

# Email enumeration
nullsec-recon --osint --email "*@target.com"

# Social media
nullsec-recon --osint --username targetuser --platforms all
```

### DNS Enumeration
```bash
# Subdomain discovery
nullsec-recon --dns --subdomains target.com --wordlist subdomains.txt

# DNS zone transfer
nullsec-recon --dns --zonetransfer target.com

# Reverse DNS
nullsec-recon --dns --reverse 192.168.1.0/24
```

### Certificate Transparency
```bash
nullsec-recon --certs --domain target.com --sources crtsh,censys,facebook
```

## Active Reconnaissance

### Port Scanning
```bash
# TCP SYN scan
nullsec-recon --scan --target 192.168.1.100 --ports 1-65535 --type syn

# Service version detection
nullsec-recon --scan --target 192.168.1.100 --version

# OS fingerprinting
nullsec-recon --scan --target 192.168.1.100 --os-detect
```

### Web Reconnaissance
```bash
# Directory brute force
nullsec-recon --web --dirbrute https://target.com --wordlist dirs.txt

# Technology detection
nullsec-recon --web --tech https://target.com

# Virtual host discovery
nullsec-recon --web --vhosts 192.168.1.100 --wordlist vhosts.txt
```

### Network Mapping
```bash
# Host discovery
nullsec-recon --network --discover 192.168.1.0/24

# Traceroute
nullsec-recon --network --trace target.com

# ARP scan (local)
nullsec-recon --network --arp 192.168.1.0/24
```

## Cloud Reconnaissance

```bash
# AWS S3 bucket enumeration
nullsec-recon --cloud --s3 --keyword company

# Azure blob enumeration
nullsec-recon --cloud --azure --keyword company

# GCP bucket enumeration
nullsec-recon --cloud --gcp --keyword company
```

## Output Formats

```bash
# JSON output
nullsec-recon --scan --target 192.168.1.100 --output json -o results.json

# XML output
nullsec-recon --scan --target 192.168.1.100 --output xml -o results.xml

# HTML report
nullsec-recon --scan --target 192.168.1.100 --output html -o report.html
```
