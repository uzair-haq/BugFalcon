#!/usr/bin/env python3
"""
BugFalcon — Automated Bug Bounty Hunter for Linux
Searches PUBLIC vulnerability databases, then helps with guided,
authorised testing — it does NOT auto-exploit a target.

What it does:
  search <keyword>   Search NVD (National Vulnerability Database) for CVEs
  cve <CVE-YYYY-NNNN>  Show details, CVSS score, CWE and public references
  check <url>        Light header check (only with permission) + CVE search
                     for the tech it can see in headers
  exploit <CVE-ID>   Guided, non-destructive testing checklist + public
                     references. It never runs a payload by itself.
  scope add <domain> Add a domain to scope.txt (your written scope)
  scope list         List domains in scope.txt
  auto <url>         FULL AUTOMATED PIPELINE, scope-gated:
                     1) scope check  2) header/tech detection
                     3) NVD CVE search for detected tech
                     4) Nuclei (if installed) + searchsploit (if installed)
                     5) auto Markdown report in reports/
  interactive        Type commands in a loop: search / cve / check / exploit / auto

Safety rule built in:
  - 'search' and 'cve' are public data — no target needed, always allowed.
  - 'check' and 'auto' require the target to be in scope.txt OR an
    interactive permission confirmation. If neither, they stop before
    touching the target.
  - 'auto' runs only detection / template scans (Nuclei templates are
    mostly non-destructive). It never runs an Exploit-DB payload, never
    deletes data, never brute-forces, and never tests out-of-scope targets.
  - Never use this on a site you do not have permission for.
    Unauthorised access is illegal, including in the UAE.

No dependencies for the core — Python 3 standard library only.
Advanced tools, used only if YOU install them on Linux:
  nuclei (ProjectDiscovery), searchsploit (Exploit-DB),
  subfinder + httpx for subdomain/URL discovery (auto uses them if present).
Install examples:
  sudo apt install exploitdb
  # nuclei / subfinder / httpx: see README.md
Run:  python3 bugfalcon.py --help
      python3 bugfalcon.py scope add example.com
      python3 bugfalcon.py auto example.com
      python3 bugfalcon.py interactive
"""

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BANNER = r"""
 ____              _____     _               
|  _ \            |  ___|   | |              
| |_) |_   _  __ _| |_ __ _| | ___ ___  _ __ 
|  _ <| | | |/ _` |  _/ _` | |/ __/ _ \| '_ \
| |_) | |_| | (_| | | | (_| | | (_| (_) | | | |
|____/ \__,_|\__, |_|  \__,_|_|\___\___/|_| |_|
               __/ |                           
              |___/                            
  Automated Bug Bounty Recon + CVE Hunter  |  v2.0  |  by uzair-haq
  Authorised scope only — scope.txt gate, no auto payloads, no out-of-scope testing
"""

NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "BugFalcon/2.0 (authorised security research)"


def fetch_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print("NVD blocked the request (403). Wait a bit — NVD rate-limits "
                  "requests without an API key — then try again.")
        elif e.code == 429:
            print("NVD rate limit hit (429). Wait 30 seconds and retry, "
                  "or get a free NVD API key and add it later.")
        else:
            print(f"NVD request failed: HTTP {e.code}")
        return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None


def cvss_score(cve):
    try:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data = metrics[key][0]["cvssData"]
                return data.get("baseScore"), data.get("baseSeverity"), data.get("vectorString")
    except Exception:
        pass
    return None, None, None


def description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def show_cve_summary(cve):
    cid = cve.get("id", "?")
    score, sev, _vec = cvss_score(cve)
    desc = description(cve)
    if len(desc) > 280:
        desc = desc[:277] + "..."
    print(f"\n{cid}  |  CVSS: {score} ({sev})" if score and sev else (f"\n{cid}  |  CVSS: {score}" if score else f"\n{cid}"))
    print(f"  Published: {cve.get('published', '?')}")
    print(f"  {desc}")
    refs = cve.get("references", [])
    if refs:
        print(f"  References ({len(refs)}): {refs[0].get('url', '')}")


def cmd_search(keyword, limit=10):
    print(f"Searching NVD for: {keyword}")
    url = (f"{NVD_SEARCH}?keywordSearch={urllib.parse.quote(keyword)}"
           f"&resultsPerPage={limit}")
    data = fetch_json(url)
    if not data:
        return
    vulns = data.get("vulnerabilities", [])
    print(f"Found {data.get('totalResults', len(vulns))} total, showing {len(vulns)}")
    if not vulns:
        print("No public CVE found for that keyword. Try a broader word, "
              "e.g. 'wordpress' instead of a plugin version.")
        return
    for v in vulns:
        show_cve_summary(v["cve"])

    # Optional local Exploit-DB index, if the user has it installed.
    if shutil.which("searchsploit"):
        print("\n[searchsploit found locally — public Exploit-DB matches:]")
        try:
            out = subprocess.run(["searchsploit", "--disable-colour", keyword],
                                 capture_output=True, text=True, timeout=30)
            lines = [l for l in out.stdout.splitlines() if l.strip()][:15]
            print("\n".join(lines) if lines else "  (no local Exploit-DB match)")
        except Exception as e:
            print(f"  searchsploit check skipped: {e}")
    else:
        print("\nTip: install exploitdb (searchsploit) on Linux to also search "
              "public Exploit-DB entries offline: sudo apt install exploitdb")


def cmd_cve(cve_id):
    cve_id = cve_id.strip().upper()
    url = f"{NVD_SEARCH}?cveId={urllib.parse.quote(cve_id)}"
    data = fetch_json(url)
    if not data or not data.get("vulnerabilities"):
        print(f"No NVD record for {cve_id}. Check the ID spelling.")
        return
    cve = data["vulnerabilities"][0]["cve"]
    score, sev, vec = cvss_score(cve)
    print(f"\n{cve_id}")
    print(f"Published: {cve.get('published', '?')}  |  Last modified: {cve.get('lastModified', '?')}")
    if score:
        print(f"CVSS: {score} ({sev})  {vec or ''}")
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        cwes = [d.get("value") for w in weaknesses for d in w.get("description", [])]
        print(f"CWE: {', '.join(cwes)}")
    print(f"\n{description(cve)}")
    refs = cve.get("references", [])
    print(f"\nPublic references ({len(refs)}):")
    for r in refs[:12]:
        print(f"  - {r.get('url', '')}")


def confirm_permission(target):
    print(f"\nTarget: {target}")
    print("Only continue if you OWN this target or it is in a written")
    print("bug-bounty / pentest scope for you. Unauthorised testing is illegal.")
    ans = input("Do you have written permission for this target? [y/N]: ").strip().lower()
    return ans in ("y", "yes")


def cmd_check(url, assume_yes=False):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not assume_yes and not confirm_permission(url):
        print("Stopped. No request was sent to the target.")
        return
    print(f"Fetching headers only (no scan, no payload) from {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = dict(resp.headers)
            print(f"Status: {resp.status}")
    except Exception as e:
        print(f"Could not reach target: {e}")
        return
    interesting = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
    seen = []
    for k in interesting:
        if k in headers:
            print(f"  {k}: {headers[k]}")
            seen.append(headers[k])
    if not seen:
        print("  No tech-identifying header found. Try: search <tech you know, "
              "e.g. wordpress, apache, nginx>")
        return
    print("\nSearching NVD for CVEs matching what the headers show...")
    for value in seen:
        # Use the first word as the search keyword, e.g. 'Apache' from 'Apache/2.4'
        keyword = value.split("/")[0].split()[0]
        print(f"\n--- {keyword} ---")
        cmd_search(keyword, limit=5)


def cmd_exploit(cve_id):
    """Guided help only — never executes a payload."""
    print("\n=== GUIDED TESTING HELP (no payload is run by this tool) ===")
    cmd_cve(cve_id)
    print("""
Before you test anything, confirm all of these:
  [ ] Target is in your written scope / you own it
  [ ] You are testing in a lab copy first if possible
  [ ] Test is non-destructive: read-only proof first, no data deletion,
      no DoS, no changing other users' data
  [ ] You will report it through the program's channel, with steps,
      impact, and a fix suggestion — not post the exploit publicly first

Next steps you do manually (outside this tool):
  1. Read the public references above and the vendor advisory.
  2. If Exploit-DB / searchsploit has a PoC, read it fully first —
     never run a downloaded exploit blind.
  3. Reproduce in your lab, capture evidence (request/response, screenshot).
  4. If it works on the in-scope target, stop, document, and report.

If you do not have permission, stop here. This tool will not help
you run it against that target.
""")


SCOPE_FILE = "scope.txt"


def _domain_of(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
    return host


def load_scope():
    if not os.path.exists(SCOPE_FILE):
        return []
    with open(SCOPE_FILE) as f:
        return [l.strip().lower() for l in f if l.strip() and not l.strip().startswith("#")]


def in_scope(url):
    host = _domain_of(url)
    for entry in load_scope():
        if host == entry or host.endswith("." + entry):
            return True
    return False


def cmd_scope_add(domain):
    domain = _domain_of(domain)
    existing = load_scope()
    if domain in existing:
        print(f"{domain} is already in {SCOPE_FILE}.")
        return
    with open(SCOPE_FILE, "a") as f:
        f.write(domain + "\n")
    print(f"Added {domain} to {SCOPE_FILE}. Only add targets you own or that are in your written bug-bounty scope.")


def cmd_scope_list():
    scopes = load_scope()
    if not scopes:
        print(f"No scope yet. Add one with: python3 bugfalcon.py scope add <domain>")
        return
    print(f"Scope ({SCOPE_FILE}):")
    for s in scopes:
        print(f"  - {s}")


def run_tool_if_present(name, args, timeout=180):
    """Run an optional advanced tool if installed; otherwise skip with a tip."""
    if not shutil.which(name):
        print(f"  [{name} not installed — skipped]")
        return ""
    print(f"  [running {name} ...]")
    try:
        out = subprocess.run([name] + args, capture_output=True, text=True, timeout=timeout)
        return (out.stdout or "") + (out.stderr or "")
    except Exception as e:
        print(f"  [{name} failed: {e}]")
        return ""


def search_cves_return(keyword, limit=5):
    url = (f"{NVD_SEARCH}?keywordSearch={urllib.parse.quote(keyword)}"
           f"&resultsPerPage={limit}")
    data = fetch_json(url)
    if not data:
        return []
    return [v["cve"] for v in data.get("vulnerabilities", [])]


def cmd_auto(url, assume_yes=False, dry_run=False):
    """Automated pipeline: scope -> tech -> NVD -> nuclei/searchsploit -> report."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = _domain_of(url)
    print(f"\n=== AUTO PIPELINE: {url} ===")
    if dry_run:
        print("[dry-run] No request will be sent. Showing the steps that would run:")
        print("  1. Scope check  2. Header/tech detection  3. NVD CVE search")
        print("  4. Nuclei + searchsploit (if installed)  5. Markdown report")
        print(f"  In scope? {in_scope(url)}  (scope.txt: {load_scope() or 'empty'})")
        return
    if not in_scope(url):
        print(f"{host} is NOT in {SCOPE_FILE}.")
        if not assume_yes and not confirm_permission(url):
            print("Stopped. Add it first only if it is in your written scope:")
            print(f"  python3 bugfalcon.py scope add {host}")
            return
    print("[1/5] Scope: OK")

    # Step 2: header / tech detection
    print("[2/5] Tech detection (headers only)...")
    techs = []
    headers = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = dict(resp.headers)
            print(f"  Status: {resp.status}")
    except Exception as e:
        print(f"  Could not reach target: {e}")
    for k in ("Server", "X-Powered-By", "X-Generator"):
        if k in headers:
            print(f"  {k}: {headers[k]}")
            techs.append(headers[k].split("/")[0].split()[0])
    techs = sorted(set(t for t in techs if t))
    if not techs:
        print("  No tech header found — NVD step will use 'web' as a fallback keyword.")

    # Optional subdomain discovery (only if subfinder installed, in-scope root only)
    subdomains = run_tool_if_present("subfinder", ["-d", host, "-silent"])
    if subdomains:
        print(f"  Subdomains found: {len(subdomains.splitlines())}")

    # Step 3: NVD search
    print("[3/5] NVD CVE search...")
    cve_lines = []
    for kw in (techs or ["web"]):
        print(f"  --- {kw} ---")
        cves = search_cves_return(kw, limit=5)
        for cve in cves:
            score, sev, _ = cvss_score(cve)
            line = f"{cve.get('id')} | CVSS {score} ({sev}) | {description(cve)[:160]}"
            print(f"    {line}")
            cve_lines.append(line)

    # Step 4: advanced scanners, if installed (detection templates only)
    print("[4/5] Advanced scanners (installed tools only)...")
    nuclei_out = run_tool_if_present(
        "nuclei", ["-u", url, "-severity", "critical,high,medium", "-silent"])
    if nuclei_out:
        print("\n".join(nuclei_out.splitlines()[:30]))
    ss_out = ""
    if techs:
        ss_out = run_tool_if_present("searchsploit", ["--disable-colour"] + techs[:1])
        if ss_out:
            print("\n".join(ss_out.splitlines()[:15]))

    # Step 5: report
    print("[5/5] Writing report...")
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "_", host)
    report_path = f"reports/{safe_host}-{stamp}.md"
    with open(report_path, "w") as f:
        f.write(f"# BugFalcon Auto Report — {url}\n\n")
        f.write(f"Date: {datetime.datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Scope file: {SCOPE_FILE} (target confirmed in scope)\n\n")
        f.write("## Tech detected (headers)\n\n")
        for k, v in headers.items():
            if k in ("Server", "X-Powered-By", "X-Generator", "Content-Type"):
                f.write(f"- {k}: {v}\n")
        if subdomains:
            f.write("\n## Subdomains (subfinder)\n\n```\n" + subdomains + "\n```\n")
        f.write("\n## Public CVEs found (NVD)\n\n")
        for line in cve_lines or ["No CVE returned for detected tech."]:
            f.write(f"- {line}\n")
        if nuclei_out:
            f.write("\n## Nuclei findings\n\n```\n" + nuclei_out[:4000] + "\n```\n")
        if ss_out:
            f.write("\n## Exploit-DB matches (searchsploit, references only)\n\n```\n" + ss_out[:2000] + "\n```\n")
        f.write("\n## Next steps (manual, in scope only)\n\n")
        f.write("1. Verify each finding by hand — scanners give false positives.\n")
        f.write("2. Test non-destructively first, in a lab copy if possible.\n")
        f.write("3. Report through the program's channel with steps, impact and fix.\n")
        f.write("4. This tool never ran an Exploit-DB payload automatically.\n")
    print(f"Report saved: {report_path}")
    print("Done. Verify findings by hand before reporting — auto results are leads, not proof.")


def interactive():
    print("BugFalcon interactive mode. Commands: search <word> | cve <ID> | "
          "check <url> | exploit <ID> | auto <url> | scope list | help | exit")
    while True:
        try:
            line = input("\nbugfalcon> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if not line:
            continue
        if line in ("exit", "quit"):
            print("Bye.")
            break
        if line == "help":
            print("  search <keyword>   — search public CVEs on NVD")
            print("  cve <CVE-ID>       — show one CVE in detail")
            print("  check <url>        — header check + CVE search (permission asked)")
            print("  exploit <CVE-ID>   — guided testing checklist, no payload run")
            print("  auto <url>         — full automated pipeline (scope-gated) + report")
            print("  scope list         — show scope.txt")
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            print("Could not parse that command.")
            continue
        run_command(parts)


def run_command(parts):
    cmd = parts[0]
    if cmd == "search" and len(parts) >= 2:
        cmd_search(" ".join(parts[1:]))
    elif cmd == "cve" and len(parts) == 2:
        cmd_cve(parts[1])
    elif cmd == "check" and len(parts) == 2:
        cmd_check(parts[1])
    elif cmd == "exploit" and len(parts) == 2:
        cmd_exploit(parts[1])
    elif cmd == "auto" and len(parts) == 2:
        cmd_auto(parts[1])
    elif cmd == "scope" and len(parts) == 2 and parts[1] == "list":
        cmd_scope_list()
    elif cmd == "interactive":
        interactive()
    else:
        print("Usage: search <keyword> | cve <CVE-ID> | check <url> | "
              "exploit <CVE-ID> | auto <url> | scope list | interactive")


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="BugFalcon — public CVE search + guided authorised testing")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("search", help="Search NVD for CVEs")
    s.add_argument("keyword", nargs="+")
    s.add_argument("--limit", type=int, default=10)
    c = sub.add_parser("cve", help="Show one CVE")
    c.add_argument("cve_id")
    k = sub.add_parser("check", help="Header check + CVE search (permission asked)")
    k.add_argument("url")
    k.add_argument("--i-have-permission", action="store_true")
    e = sub.add_parser("exploit", help="Guided testing help for a CVE (no payload run)")
    e.add_argument("cve_id")
    sc = sub.add_parser("scope", help="Manage scope.txt")
    sc.add_argument("action", choices=["add", "list"])
    sc.add_argument("domain", nargs="?")
    a = sub.add_parser("auto", help="Full automated pipeline (scope-gated) + report")
    a.add_argument("url")
    a.add_argument("--i-have-permission", action="store_true")
    a.add_argument("--dry-run", action="store_true")
    sub.add_parser("interactive", help="Interactive command loop")
    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return
    if args.cmd == "search":
        cmd_search(" ".join(args.keyword), limit=args.limit)
    elif args.cmd == "cve":
        cmd_cve(args.cve_id)
    elif args.cmd == "check":
        cmd_check(args.url, assume_yes=args.i_have_permission)
    elif args.cmd == "exploit":
        cmd_exploit(args.cve_id)
    elif args.cmd == "scope":
        if args.action == "add" and args.domain:
            cmd_scope_add(args.domain)
        else:
            cmd_scope_list()
    elif args.cmd == "auto":
        cmd_auto(args.url, assume_yes=args.i_have_permission, dry_run=args.dry_run)
    elif args.cmd == "interactive":
        interactive()


if __name__ == "__main__":
    main()
