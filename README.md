# EnumerX 🚀

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Category-Reconnaissance-red?style=flat-square)
![Maintenance](https://img.shields.io/badge/Maintained-Yes-blue?style=flat-square)

**EnumerX** is a comprehensive, modular, and "fail-fast" subdomain enumeration wrapper designed for offensive security professionals and bug bounty hunters.

Unlike simple wrappers that blindly pipe tools into each other, EnumerX uses a **Waterfall Logic** with intermediate validation steps. It aggregates passive data, validates it, and *only then* performs expensive active reconnaissance (permutations/bruteforce) on the **verified** dataset. This saves time, reduces CPU load, and eliminates "garbage-in-garbage-out" results.

## 🔥 Key Features

* **Waterfall Methodology:** Passive → Resolution → Active → Permutation → Final Validation.
* **Fail-Fast Architecture:** Intermediate resolution step using `puredns` prevents generating permutations for non-existent domains.
* **Multi-Source Passive Recon:** Integrates Subfinder, Assetfinder, Amass, GitHub, Shodan, VirusTotal, and more.
* **Smart Permutations:** Uses `alterx` and `dnsgen` seeded *only* by validated subdomains.
* **Heavy Active Recon:** Includes BBOT, Cloud Recon (AWS/Azure), and Reverse DNS walking.
* **Bulk Mode:** Multi-threaded processing for list-based scanning with progress tracking and consolidated reporting.
* **Resumable:** Built-in checkpoint system to resume scans if interrupted.
* **Resource Management:** Configurable timeouts and thread limits to prevent burning out your VPS.

## 🛠️ Logic Workflow

1. **Passive Gathering:** Scrapes 15+ sources (APIs, archives, CT logs).
2. **Intermediate Resolution:** Validating passive results immediately using `puredns`.
3. **Active Recon:** Cloud extraction, Zone transfers, and Bruteforce (MassDNS/Shuffledns).
4. **Smart Permutation:** Generates mutations based **only** on the validated passive list.
5. **Final Validation:** Resolves all active findings and extracts IPs/CNAMEs.

## 📦 Installation

EnumerX is a Bash wrapper that relies on the best tools in the industry. You must have the following installed and in your `$PATH`:

### 1. Essentials
```bash
sudo apt update
sudo apt install curl jq dig git libpcap-dev
```
### 2. Go Tools (The Powerhouse)

Ensure you have Go installed, then run:
Bash

go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
go install -v [github.com/projectdiscovery/dnsx/cmd/dnsx@latest](https://github.com/projectdiscovery/dnsx/cmd/dnsx@latest)
go install -v [github.com/tomnomnom/assetfinder@latest](https://github.com/tomnomnom/assetfinder@latest)
go install -v [github.com/lc/gau/v2/cmd/gau@latest](https://github.com/lc/gau/v2/cmd/gau@latest)
go install -v [github.com/d3mondev/puredns/v2@latest](https://github.com/d3mondev/puredns/v2@latest)
go install -v [github.com/projectdiscovery/alterx/cmd/alterx@latest](https://github.com/projectdiscovery/alterx/cmd/alterx@latest)
go install -v [github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest](https://github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest)

### 3. Other Tools

    MassDNS: Installation Guide

    BBOT: pip install bbot

    Subdominator: Installation Guide

    DNSGen: pip install dnsgen

### 4. Clone EnumerX
Bash

git clone [https://github.com/MrRockettt/EnumerX.git](https://github.com/MrRockettt/EnumerX.git)
cd EnumerX
chmod +x enumerx.sh

⚙️ Configuration

Before running, open enumerx.sh and configure your API keys at the top of the file. This is critical for deep enumeration.
Bash

export VIRUSTOTAL_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export GITHUB_TOKEN="your_key"
# ... add other keys

Ensure your paths to wordlists and resolvers are correct:
Bash

export RESOLVERS_PATH="/path/to/resolvers.txt"
export WORDLIST_PATH="/path/to/best-dns-wordlist.txt"

🚀 Usage
Single Domain Mode

Best for deep-diving into a single target.
Bash

./enumerx.sh subenum target.com [threads] [output_dir]

Example:
Bash

./enumerx.sh subenum tesla.com 100 tesla_scan

Bulk Mode

Best for processing large lists of domains (e.g., Bug Bounty programs). It runs multiple domains in parallel.
Bash

./enumerx.sh sublist <domains.txt> [parallel_jobs] [threads_per_job]

Example:
Bash

### Runs 5 domains at a time, using 50 threads per domain
./enumerx.sh sublist targets.txt 5 50

📂 Output Structure

The script creates a structured output directory:
Plaintext
```
results/
├── passive/       # Raw files from individual tools (Subfinder, Amass, etc.)
├── active/        # Bruteforce, Cloud, and Permutation results
├── resolved/      # Validated domain lists (Intermediate steps)
├── final/         # The Gold Mine
│   ├── target.com_final_resolved.txt  # ALL valid subdomains
│   ├── target.com_ips.txt             # Unique IP addresses
│   └── target.com_cnames.txt          # CNAME records
└── SUMMARY_target.com.txt             # Scan statistics and metrics
```
### 🤝 Contributing

Contributions, issues, and feature requests are welcome!

    Fork the project.

    Create your feature branch (git checkout -b feature/AmazingFeature).

    Commit your changes (git commit -m 'Add some AmazingFeature').

    Push to the branch (git push origin feature/AmazingFeature).

    Open a Pull Request.

### ⚠️ Disclaimer

This tool is created for educational purposes and authorized security assessments only. The author is not responsible for any misuse of this tool. Always ensure you have permission to scan the target infrastructure.
📜 License

Distributed under the MIT License. See LICENSE for more information.

Author: Salmon Kumar / 0xSalm0n
