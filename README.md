BugFalcon is a free, open-source tool for authorised bug bounty recon on Linux. Give it a target in your scope and it checks the tech, searches public CVE data, runs Nuclei, searchsploit and subfinder if you have them installed, and writes a clean Markdown report. It never runs an exploit by itself.

# BugFalcon 🦅

**Automated Bug Bounty Recon + CVE Hunter for Linux**

BugFalcon runs a full automated pipeline for authorised bug bounty testing, then saves a clean report. It searches public vulnerability data — it does **not** auto-exploit a target and never runs an Exploit-DB payload by itself.

```
 ____              _____     _
|  _ \            |  ___|   | |
| |_) |_   _  __ _| |_ __ _| | ___ ___  _ __
|  _ <| | | |/ _` |  _/ _` | |/ __/ _ \| '_ \
| |_) | |_| | (_| | | | (_| | | (_| (_) | | | |
|____/ \__,_|\__, |_|  \__,_|_|\___\___/|_| |_|
               __/ |
              |___/
```

## What `auto` does, in order

1. **Scope check** — target must be in `scope.txt`, or you confirm permission interactively. Out-of-scope = stops, no request sent.
2. **Tech detection** — headers only (Server, X-Powered-By, X-Generator)
3. **NVD CVE search** — public CVEs for the detected tech
4. **Advanced scanners, if YOU installed them** — Nuclei (detection templates), searchsploit, subfinder
5. **Auto report** — Markdown file in `reports/<target>-<date>.md`

Auto results are leads, not proof. Always verify by hand — NVD keyword search can return related-but-irrelevant CVEs.

## Install (Linux)

```bash
chmod +x bugfalcon.py
python3 bugfalcon.py --help
```

Optional advanced tools (install only if you want those steps):

```bash
sudo apt install exploitdb   # searchsploit
# Nuclei, subfinder, httpx — install from ProjectDiscovery releases / Go:
#   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Use

```bash
# 1. Add ONLY targets you own or that are in your written bug-bounty scope
cp scope.example.txt scope.txt
python3 bugfalcon.py scope add example.com
python3 bugfalcon.py scope list

# 2. Full automated run + report
python3 bugfalcon.py auto example.com

# Dry run — shows the steps, sends no request
python3 bugfalcon.py auto example.com --dry-run

# 3. Single commands
python3 bugfalcon.py search wordpress
python3 bugfalcon.py search apache --limit 5
python3 bugfalcon.py cve CVE-2024-12345
python3 bugfalcon.py check example.com
python3 bugfalcon.py exploit CVE-2024-12345

# 4. Interactive mode
python3 bugfalcon.py interactive
# bugfalcon> auto example.com
# bugfalcon> search nginx
# bugfalcon> exit
```

## Safety rule

- `search` and `cve` use only public NVD data — no target involved.
- `check` and `auto` stop unless the target is in scope or you confirm written permission.
- No payload is run automatically, no data is deleted, no brute-force, no out-of-scope testing.
- Never test a target you don't own or that isn't in a written bug-bounty scope. Unauthorised access is illegal, including in the UAE.

## Author

Uzair Ul Haq — [@uzair-haq](https://github.com/uzair-haq)

## License

MIT — see [LICENSE](LICENSE).
