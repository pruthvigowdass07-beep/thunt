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
