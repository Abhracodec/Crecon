# crecon

Automated recon toolkit for Kali Linux. One command. Full recon. AI-powered attack paths.

## What It Does

- **Port scan** → open port 80? auto-triggers directory brute-forcing
- **Port scan** → open port 22? auto-tests default SSH credentials
- **CVE lookup** → automatically queries NVD for every detected service version
- **Nuclei** → validates CVEs against discovered services
- **Web crawl** → extracts emails, phones, tech stack
- **AI analysis** → builds complete attack chains from all findings *(optional)*

## What Makes It Different

Most recon tools make you run everything manually. crecon chains them automatically. Then feeds everything to AI for actual attack paths, not just a summary.

| Provider | Cost | Model |
|---|---|---|
| GitHub Models | Free (student) | DeepSeek-R1-0528 |
| Groq | Free | Llama 3.3 70B |
| Gemini | Free | Gemini 1.5 Flash |
| OpenAI | Paid | GPT-4o Mini |
| Anthropic | Paid | Claude Haiku |

## Install
```bash
git clone https://github.com/Abhracodec/Crecon.git
cd Crecon
pip3 install -r requirements.txt --break-system-packages
pip3 install -e . --break-system-packages
sudo apt install nmap nuclei
```

Tested on Kali Linux with Python 3.13.

## Usage
```bash
# Full auto recon
crecon auto <target> --ports 1-1024 --wordlist /usr/share/wordlists/dirb/common.txt

# Port scan with banner grabbing
crecon scan <target> --start 1 --end 1000 --banners

# Web crawl and contact extraction
crecon recon --url https://target.com --output results.csv

# Directory brute-force
crecon enum dirs --url http://target.com --wordlist /usr/share/wordlists/dirb/common.txt

# Subdomain enumeration
crecon enum subs --domain target.com --wordlist /usr/share/wordlists/dnsmap.txt
```

Add `--ai` to any command for AI-powered attack chain analysis *(requires API key — see Setup AI below)*.

## How The Chain Works
```
crecon auto target
    |
    |-- Nmap scan (ports, versions, banners)
    |-- NVD CVE lookup (automatic, no flag needed)
    |
    |-- Port 80/443 found?
    |       |-- Directory brute-force
    |       |-- Web crawl (emails, phones, tech stack)
    |       |-- Nuclei CVE validation
    |
    |-- Port 22 found?
    |       |-- SSH credential testing (paramiko)
    |
    |-- (optional) AI analysis
            |-- Full attack chain with exact commands
```

## Setup AI 
```bash
# Free options (recommended)
crecon config --add-key github_pat_xxx --provider github
crecon config --add-key gsk_xxxx --provider groq
crecon config --add-key AIzaxxxx --provider gemini

# Paid options
crecon config --add-key sk-xxxx --provider openai
crecon config --add-key sk-ant-xxxx --provider anthropic

# View saved keys
crecon config --list-keys
```

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Nmap (`sudo apt install nmap`)
- Nuclei (`sudo apt install nuclei`)

## Legal

For authorized testing and educational use only. Only scan systems you have explicit permission to test.