# 🔍 OSINT Footprinting Automation Framework

![Python](https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Cost](https://img.shields.io/badge/Cost-Free-brightgreen?style=flat-square)
![Tools](https://img.shields.io/badge/Tools-Nmap%20%7C%20Subfinder%20%7C%20Shodan%20%7C%20h8mail-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

> Automated OSINT reconnaissance framework that performs full target
> footprinting from a single command — subdomains, ports, CVEs,
> email breaches, tech stack, and exposed files — generating a
> professional PDF report and live web dashboard.

Built on **Kali Linux** using **100% free tools**. Zero cost.
Built as a real-world internship portfolio project.

---

## 📸 Real Scan Results

| Target | Subdomains | Live | Total Findings | Exposed Files |
|---|---|---|---|---|
| `rockstargames.com` | 534 | 155 | 207 (14 Critical) | 51 |
| `nmap.org` | 17 | 16 | 903 (872 Critical CVEs) | 2 |
| `bugcrowd.com` | 47 | 30 | 42 | 42 |
| `google.com` | — | — | 1 (WHOIS) | — |

---

## 🏗 Architecture

```
Target Domain
      │
      ▼
┌──────────────────────────────────────────┐
│              Orchestrator                │
│       (parallel ThreadPoolExecutor)      │
└──┬─────────┬──────┬──────┬──────────────┘
   │         │      │      │        │
   ▼         ▼      ▼      ▼        ▼
Subdomains  Ports  WHOIS  Emails  TechStack
   │         │      │      │        │
   └─────────┴──────┴──────┴────────┘
                    │
                    ▼
             SQLite Database
                    │
           ┌────────┴────────┐
           ▼                 ▼
      PDF Report      Streamlit Dashboard
      (ReportLab)     (localhost:8501)
```

---

## ⚡ Features

| Module | Tool | What it finds |
|---|---|---|
| Subdomain Enumeration | Subfinder + dnspython | All subdomains + live IPs |
| Port Scanning | Nmap + Shodan | Open ports, services, CVEs |
| WHOIS + DNS History | python-whois + ViewDNS.info | Registrar, org, old IPs |
| Email Harvesting | theHarvester | Employee emails from Google/Bing/DuckDuckGo |
| Breach Detection | h8mail + Scylla.sh | Leaked credentials — zero cost |
| Tech Fingerprinting | httpx + Wappalyzer signatures | Frameworks, WAF, server versions |
| Exposed Files | httpx path probe | .env, .git, admin panels, backups |
| PDF Report | ReportLab | Professional multi-page dossier |
| Web Dashboard | Streamlit | Live results at localhost:8501 |

---

## 🚀 Installation

### Prerequisites

- Kali Linux (recommended) or Ubuntu
- Python 3.9+
- Go 1.19+ (for Subfinder)

### 1 — Clone the repository

```bash
git clone https://github.com/vikash88-star/osint-footprinting-framework.git
cd osint-footprinting-framework
```

### 2 — Install Python dependencies

```bash
pip3 install python-nmap dnspython python-whois httpx requests \
             beautifulsoup4 shodan reportlab matplotlib \
             streamlit pyyaml rich colorama tabulate aiohttp h8mail \
             --break-system-packages
```

### 3 — Install external tools

```bash
# Nmap + theHarvester — pre-installed on Kali
sudo apt install nmap theharvester golang-go -y

# Subfinder — subdomain enumeration engine
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc

# Verify all tools installed
python3 --version && nmap --version && subfinder --version
```

### 4 — Configure API keys

```bash
cp config/settings.yaml.example config/settings.yaml
nano config/settings.yaml
```

Get your **free** API keys — no payment required:

| API | Where to get it | Free limit |
|---|---|---|
| Shodan | [shodan.io](https://shodan.io) → free account | 100 queries/month |
| VirusTotal | [virustotal.com](https://virustotal.com) → API key | 500 req/day |

---

## 🎯 Usage

### Full scan — all modules at once

```bash
python3 osint.py --target example.com
```

### Specific modules only

```bash
# Subdomains + WHOIS only (fastest — 1-2 mins)
python3 osint.py --target example.com --modules subdomains whois

# Skip ports for speed (3-5 mins)
python3 osint.py --target example.com --modules subdomains whois emails techstack

# Port scan only on already-scanned target
python3 osint.py --target example.com --modules ports

# Full explicit scan (all modules)
python3 osint.py --target example.com --modules subdomains ports whois emails techstack
```

### Launch the web dashboard

```bash
streamlit run dashboard/app.py
```

Open browser at **http://localhost:8501** — select any scanned target from the sidebar dropdown.

### View the PDF report

```bash
xdg-open report.pdf        # Linux
```

---

## 📊 Sample Terminal Output

```
  OSINT Footprinting Framework
  Kali Linux Edition — 100% Free Tools
  Built for internship portfolio

  Target    rockstargames.com
  Modules   subdomains, ports, whois, emails, techstack
  Output    report.pdf

[+] Database ready at output/rockstargames_com.db
[*] Starting scan — this may take 2-5 minutes...

[ Subdomain Enumeration ]
[+] Subfinder found 534 subdomains
[+] Live subdomains  : 155
[*] Dead/unresolved  : 379
  ✓ api.rockstargames.com          104.18.5.130
  ✓ cdn.rockstargames.com          104.18.5.130
  ✓ support.rockstargames.com      52.223.7.86

[ Port Scanning + CVE Matching ]
[1/10] Scanning 104.18.5.130...
[+] 104.18.5.130 — 2 open ports found
    Port  80   tcp  http   Apache httpd
    Port  443  tcp  https  Cloudflare
    Org: Amazon Technologies Inc. | Country: United States

[ Tech Stack + Exposed Files ]
[+] Subdomains scanned   : 15
[+] Exposed files found  : 51  ← check immediately
[+] CRITICAL findings    : 14

[+] All modules finished in 467s
[+] PDF saved → report.pdf
[+] Findings: 207 | Critical: 14 | High: 15 | Medium: 6 | Info: 172
[+] Scan complete!
```

---

## 📁 Project Structure

```
osint-footprinting-framework/
├── osint.py                      # CLI entry point — run this
├── config/
│   ├── settings.yaml             # API keys — gitignored, never uploaded
│   └── settings.yaml.example     # Template — copy this and fill in keys
├── modules/
│   ├── __init__.py
│   ├── subdomains.py             # Subfinder + DNS resolution
│   ├── ports.py                  # Nmap + Shodan CVE matching
│   ├── whois_dns.py              # WHOIS + ViewDNS.info DNS history
│   ├── emails.py                 # theHarvester + h8mail + Scylla.sh
│   └── techstack.py              # HTTP fingerprinting + path probing
├── core/
│   ├── __init__.py
│   ├── orchestrator.py           # Parallel module dispatcher
│   ├── database.py               # SQLite connection + table creation
│   └── aggregator.py             # Findings aggregator + severity scoring
├── report/
│   └── generator.py              # ReportLab PDF builder (multi-page)
├── dashboard/
│   └── app.py                    # Streamlit web dashboard
├── output/                       # Scan results — gitignored
├── .gitignore
└── README.md
```

---

## 🔍 PDF Report Structure

Every scan auto-generates a professional PDF containing:

- **Page 1 — Cover page** — target domain, date, colour-coded severity boxes (Critical / High / Medium / Info counts)
- **Page 2+ — Findings table** — every finding sorted Critical → High → Medium → Info with host and detail
- **Subdomains section** — full list with resolved IPs and live/dead status
- **Ports section** — open ports, service names, versions, CVE count per IP
- **WHOIS section** — registrar, organisation, creation date, expiry, nameservers

---

## 🛡 Severity Scoring

| Severity | Colour | Triggered by |
|---|---|---|
| CRITICAL | 🔴 Red | Active CVEs matched, exposed `.env`/`.git`, 3+ credential breaches |
| HIGH | 🟠 Orange | Admin panels exposed, SSH/DB ports open, 1-2 breaches |
| MEDIUM | 🟡 Amber | Outdated software versions, `.htaccess` accessible |
| INFO | 🔵 Blue | Subdomains discovered, WHOIS data, tech stack identified |

---

## ⚠️ Legal Disclaimer

This tool is for **educational purposes and authorised security testing only**.

Only scan domains you:
- **Own**
- Have **explicit written permission** to test
- Are listed in a **public bug bounty program**

Recommended legal test targets:
- [HackerOne Bug Bounty Programs](https://hackerone.com/bug-bounty-programs)
- [Bugcrowd Programs](https://bugcrowd.com/programs)
- `scanme.nmap.org` — Nmap's official legal scan target

**The author is not responsible for any misuse of this tool.**

---

## 🛠 Full Tech Stack

| Category | Tools / Libraries |
|---|---|
| Language | Python 3.13 |
| Subdomain recon | Subfinder (ProjectDiscovery), dnspython |
| Port scanning | Nmap 7.99, python-nmap |
| Exposure intel | Shodan API (free tier) |
| Email recon | theHarvester |
| Breach detection | h8mail, Scylla.sh |
| HTTP analysis | httpx, BeautifulSoup4, Wappalyzer signatures |
| Database | SQLite3 |
| PDF generation | ReportLab |
| Web dashboard | Streamlit |
| CLI | argparse, rich |
| OS | Kali Linux |

---

## 🤝 Contributing

Pull requests are welcome. For major changes please open an issue first.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/new-module`
3. Commit your changes: `git commit -m "Add new module"`
4. Push to the branch: `git push origin feature/new-module`
5. Open a Pull Request

---

## 👤 Author

**Vikash** — Cybersecurity Student

- 🐙 GitHub: [@vikash88-star](https://github.com/vikash88-star)
- 🔐 Interests: OSINT · Ethical Hacking · Penetration Testing · Python
- 📁 Built from scratch as a real-world internship portfolio project

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

```
MIT License

Copyright (c) 2026 Vikash

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

*If this project helped you, please give it a ⭐ on GitHub — it helps others find it.*
