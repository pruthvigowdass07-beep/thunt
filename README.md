# thunt — unified terminal threat-hunting tool

One command to enrich an **IP, domain, URL, or file hash** from many free threat-intel
sources at once, in a single color-coded terminal view. Built for SOC/DFIR triage when
you *don't* want to pay for API access.

```
thunt 171.25.193.25
thunt evil-domain.com
thunt 44d88612fea8a8f36de82e1278abb02f
```

- 🔴 **Malicious** / 🟡 **Suspicious** / 🟢 **Clean** / ⚪ **Unknown** — one aggregated verdict
  plus a per-source breakdown.
- **Works with zero API keys** using genuinely free, no-signup sources. Optional
  **free-tier** keys unlock more.
- Answers the triage questions directly: *when was it created / first seen*, *what does
  AbuseIPDB say*, *what does Talos say*, *what's in MalwareBazaar for this hash*, *what
  does the VirusTotal community say*, *is this a VPN / Tor node and whose*.
- Runs anywhere Python does — **Windows, macOS, Linux** — and ships as a single binary too.

---

## 🚀 Installation

### Option 1: Install via pip (recommended)
```bash
pip install thunt
```

### Option 2: Install via pipx (isolated environment)
```bash
pipx install thunt
```

### Option 3: Install from source
```bash
git clone https://github.com/pruthvigowdass07-beep/thunt.git
cd thunt
pip install -e .
```

### Option 4: Install with scraping support (for Talos when no API key)
```bash
pip install "thunt[scrape]"
```

---

## 🔑 Configuration

thunt works with zero API keys using free sources. For enhanced results, you can configure optional free-tier API keys:

### Get your free API keys:
- **VirusTotal**: https://www.virustotal.com/gui/user/<your_username>/apikey
- **AbuseIPDB**: https://www.abuseipdb.com/account/api
- **OTX**: https://otx.alienvault.com/api
- **Abuse.ch** (MalwareBazaar/URLhaus/ThreatFox): https://abuse.ch/api/
- **GreyNoise**: https://greynoise.io/account
- **Shodan**: https://account.shodan.io/
- **ProxyCheck**: https://proxycheck.io/products/api (optional, keyless tier available)

### Set API keys:
```bash
thunt config set virustotal_key <your_virustotal_key>
thunt config set abuseipdb_key <your_abuseipdb_key>
thunt config set otx_key <your_otx_key>
thunt config set abusech_key <your_abusech_key>
thunt config set greynoise_key <your_greynoise_key>
thunt config set shodan_key <your_shodan_key>
thunt config set proxycheck_key <your_proxycheck_key>
```

### View current configuration:
```bash
thunt config show
```

Configuration is stored in:
- **Windows**: `%APPDATA%\thunt\config.toml`
- **macOS/Linux**: `~/.config/thunt/config.toml`

---

## 💻 Usage Examples

### Basic enrichment:
```bash
thunt 8.8.8.8                    # IP address
thunt google.com                 # Domain
thunt https://malicious-site.com/payload.exe  # URL
thunt 44d88612fea8a8f36de82e1278abb02f      # MD5 hash
```

### Advanced options:
```bash
thunt 1.2.3.4 --json             # Output as JSON
thunt 1.2.3.4 --scrape           # Enable best-effort scraping (Talos)
thunt 1.2.3.4 --only virustotal,abuseipdb  # Query specific sources only
thunt 1.2.3.4 --timeout 30       # Increase timeout to 30 seconds
thunt 1.2.3.4 --no-color         # Disable colored output
```

### Batch processing:
```bash
# From a file containing indicators (one per line)
cat indicators.txt | xargs -n 1 thunt --json
```

---

## 📦 Building Standalone Binaries

Create a single executable that runs on any machine of the same OS/architecture (no Python required):

```bash
# Install PyInstaller first
pip install pyinstaller

# Build the binary
python build_binary.py

# Output: dist/thunt (or dist/thunt.exe on Windows)
```

The resulting binary can be copied to any Windows/macOS/Linux machine and run directly.

---

## 🎯 Output Explanation

Each source shows:
- **Verdict**: 🔴 Malicious / 🟡 Suspicious / 🟢 Clean / ⚪ Unknown
- **Key findings**: Relevant intel from that source
- **Overall verdict**: Aggregated result at the top

The tool prioritizes actionable intelligence for SOC/DFIR triage:
- Creation/first seen dates
- Geolocation and network ownership
- Reputation and threat scores
- Associated malware and campaign information
- VPN/Tor/proxy detection

---

## Sources

| Source | Indicators | Cost | What it gives |
|--------|-----------|------|---------------|
| **RDAP / whois** | domain, IP | free, no key | **creation date**, registrar, allocation, owner |
| **DNS** (Cloudflare DoH) | domain | free, no key | A/AAAA/NS/MX resolution |
| **ip-api** | IP | free, no key | geo, ISP, ASN, hosting/proxy flags |
| **Shodan InternetDB** | IP | free, no key | open ports, CVEs, tags |
| **crt.sh** | domain | free, no key | earliest cert (age proxy), subdomains |
| **proxycheck.io** | IP | free (keyless ~100/day) | **VPN / proxy / Tor + provider name**, risk score |
| **Tor** (onionoo) | IP | free, no key | authoritative Tor exit/relay + nickname + first seen |
| **GreyNoise** (community) | IP | free, no key | internet-scanner noise, RIOT benign classification |
| **AbuseIPDB** | IP | **free key** (1000/day) | abuse confidence score, reports, usage type |
| **VirusTotal** | all | **free key** (4/min) | AV detection ratio, reputation, **community comments** |
| **AlienVault OTX** | all | **free key** | community threat "pulses", malware families |
| **MalwareBazaar** | hash | **free key** | signature/family, file type, tags, **linked sandbox reports** |
| **URLhaus** | domain, IP, hash | **free key** | malicious URLs hosted / payload info |
| **ThreatFox** | IP, domain, hash | **free key** | known-IOC → malware family mapping |
| **Cisco Talos** | IP | scrape (`--scrape`) | email/web reputation (no public API — Playwright) |

"free key" = no cost, one signup. abuse.ch (MalwareBazaar / URLhaus / ThreatFox) share a
single free Auth-Key from <https://auth.abuse.ch>.

---

## Install

### Recommended: pipx (isolated, on PATH)

```bash
pipx install thunt
# or from source:
pipx install .
```

Requires Python 3.9+. Works on macOS, Linux, and Windows.

To enable Talos scraping (optional, heavy):

```bash
pipx install "thunt[scrape]"
python -m playwright install chromium
```

### Plain pip / virtualenv

```bash
python -m pip install .
```

### Single binary (no Python on the target box)

Build a standalone executable you can `scp` to any machine:

```bash
python -m pip install ".[dev]" pyinstaller
python build_binary.py          # produces dist/thunt (or dist/thunt.exe on Windows)
```

Copy `dist/thunt` to any Linux/macOS host and run it — no Python required. (The
single-binary build does not include the optional Playwright scraper.)

---

## Configure free keys (optional)

Everything works with no keys. To unlock the key-gated sources:

```bash
thunt config set abusech_key     <KEY>   # MalwareBazaar + URLhaus + ThreatFox
thunt config set virustotal_key  <KEY>
thunt config set abuseipdb_key   <KEY>
thunt config set otx_key         <KEY>
thunt config set proxycheck_key  <KEY>   # optional; keyless tier already works
thunt config show
```

Keys are stored in `~/.config/thunt/config.toml` (`%APPDATA%\thunt\config.toml` on
Windows), or supply them via environment variables (`VT_API_KEY`, `ABUSEIPDB_API_KEY`,
`OTX_API_KEY`, `ABUSECH_API_KEY`, `PROXYCHECK_API_KEY`, …).

Where to get them (all free): VirusTotal `virustotal.com/gui/join-us` · AbuseIPDB
`abuseipdb.com/register` · OTX `otx.alienvault.com` · abuse.ch `auth.abuse.ch` ·
proxycheck.io `proxycheck.io`.

---

## Usage

```
thunt <indicator> [options]

  --json            machine-readable JSON output
  --scrape          enable best-effort Playwright scraping (Talos)
  --only A,B        query only these sources (see --list-sources)
  --timeout N       per-source timeout in seconds (default 20)
  --no-color        plain output
  --list-sources    list every source and its requirement
  thunt config      show / set / path
```

**Exit codes** (handy for automation): `0` clean/unknown, `1` suspicious, `2` malicious.

```bash
# pipe a list of IOCs through it
while read ioc; do thunt "$ioc" --json; done < iocs.txt > enriched.jsonl
```

Defanged indicators (`evil[.]com`, `hxxp://…`) are accepted as-is.

---

## Notes & honesty

- VirusTotal, AbuseIPDB, and Talos are behind Cloudflare/reCAPTCHA. thunt uses their
  **free API** where one exists (VT, AbuseIPDB) and best-effort scraping only for Talos.
  Scraping is inherently fragile and may break when the site changes.
- No indicator you query is stored or sent anywhere except the intel source being queried.
- MIT licensed.
