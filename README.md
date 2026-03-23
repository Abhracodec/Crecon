# crecon

Automated recon toolkit for Kali Linux. One command. Full recon. AI-powered attack paths.

## What It Does

Chains everything together automatically based on what it finds:

- **Port scan** -> open port 80? auto-triggers directory brute-forcing
- **Port scan** -> open port 22? auto-tests default SSH credentials
- **CVE lookup** -> automatically queries NVD for every detected service version
- **Nuclei** -> validates CVEs against discovered services
- **Web crawl** -> extracts emails, phones, tech stack
- **AI analysis** -> builds complete attack chains from all findings

## What Makes It Different

Most recon tools make you run everything manually. crecon chains them automatically. Then feeds everything to AI for actual attack paths, not just a summary.

| Provider | Cost | Model |
|----------|------|-------|
| GitHub Models | Free (student) | DeepSeek-R1-0528 |
| Groq | Free | Llama 3.3 70B |
| Gemini | Free | Gemini 1.5 Flash |
| OpenAI | Paid | GPT-4o Mini |
| Anthropic | Paid | Claude Haiku |

## Install

git clone https://github.com/Abhracodec/Tools.git
cd Tools/crecon
pip3 install -r requirements.txt --break-system-packages
pip3 install -e . --break-system-packages
sudo apt install nmap nuclei

Tested on Kali Linux with Python 3.13.

## Setup AI (one time)

crecon config --add-key github_pat_xxx  --provider github
crecon config --add-key gsk_xxxx        --provider groq
crecon config --add-key AIzaxxxx        --provider gemini
crecon config --add-key sk-xxxx         --provider openai
crecon config --add-key sk-ant-xxxx     --provider anthropic
crecon config --list-keys

## Usage

crecon auto <target> --ports 1-1024 --wordlist /usr/share/wordlists/dirb/common.txt --ai
crecon scan <target> --start 1 --end 1000 --banners --ai
crecon recon --url https://target.com --output results.csv --ai
crecon enum dirs --url http://target.com --wordlist /usr/share/wordlists/dirb/common.txt --ai
crecon enum subs --domain target.com --wordlist /usr/share/wordlists/dnsmap.txt --ai

## How The Chain Works

crecon auto target
    |
    |-- Nmap scan (ports, versions, banners)
    |       -- NVD CVE lookup (automatic, no flag needed)
    |
    |-- Port 80/443 found
    |       |-- Directory brute-force
    |       |-- Web crawl (emails, phones, tech stack)
    |       -- Nuclei CVE validation
    |
    |-- Port 22 found
    |       -- SSH credential testing (paramiko)
    |
    -- AI analysis (DeepSeek-R1)
            -- Full attack chain with exact commands

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Nmap (sudo apt install nmap)
- Nuclei (sudo apt install nuclei)

## Legal

For authorized testing and educational use only. Only scan systems you have explicit permission to test.
