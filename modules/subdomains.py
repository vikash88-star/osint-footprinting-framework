# modules/subdomains.py
# PURPOSE: Find every subdomain attached to the target domain.
#
# HOW IT WORKS:
# 1. Subfinder queries certificate transparency logs, DNS brute force,
#    and passive sources (VirusTotal free, crt.sh, etc.) — all free
# 2. For each subdomain found, we do a DNS A-record lookup
#    to get the IP address and confirm it is live
# 3. Results are saved to the "subdomains" table in SQLite
#
# WHY THIS MATTERS:
# Companies have hundreds of subdomains. dev.company.com,
# staging.company.com, api-old.company.com — these forgotten
# servers are often unpatched and exposed. Finding them is
# step 1 of every real penetration test.

import subprocess
import json
import dns.resolver
import sqlite3
import time
from rich.console import Console
from rich.progress import track

console = Console()


def run_subfinder(target):
    """
    Runs Subfinder as a subprocess and collects subdomain results.
    Subfinder outputs one JSON object per line — we parse each line.

    Returns: list of subdomain strings
    """
    console.print(f"[*] Running Subfinder on {target}...")

    try:
        result = subprocess.run(
            [
                "subfinder",
                "-d", target,        # target domain
                "-silent",           # no banner/noise
                "-json",             # output as JSON lines
                "-t", "50",          # 50 concurrent threads
                "-timeout", "30",    # 30 second timeout per source
            ],
            capture_output=True,
            text=True,
            timeout=180             # max 3 minutes total
        )

        subdomains = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                # Each line is a JSON object like: {"host": "api.example.com", ...}
                data = json.loads(line)
                host = data.get("host", "").strip()
                if host and target in host:
                    subdomains.append(host)
            except json.JSONDecodeError:
                # Some lines are plain text — accept those too
                if "." in line and target in line:
                    subdomains.append(line)

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in subdomains:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        console.print(f"[green][+] Subfinder found {len(unique)} subdomains[/green]")
        return unique

    except FileNotFoundError:
        console.print("[red][!] subfinder not found — install it first (Phase 0)[/red]")
        return []
    except subprocess.TimeoutExpired:
        console.print("[yellow][!] Subfinder timed out — using partial results[/yellow]")
        return []


def resolve_ip(subdomain):
    """
    Does a DNS A-record lookup for the subdomain.
    Returns the IP address string if live, or None if dead/unresolvable.

    Example:
        resolve_ip("api.example.com") → "93.184.216.34"
        resolve_ip("dead.example.com") → None
    """
    try:
        # Set a short timeout so dead subdomains don't slow us down
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3  # 3 second timeout

        answers = resolver.resolve(subdomain, "A")
        # Return the first IP address found
        return str(answers[0])
    except Exception:
        # NXDOMAIN, timeout, no answer — subdomain is dead
        return None


def save_to_db(conn, subdomain, ip, status):
    """
    Saves one subdomain result to the SQLite database.
    INSERT OR IGNORE means if we already have it, skip — no duplicates.
    """
    try:
        conn.execute(
            """INSERT OR IGNORE INTO subdomains
               (subdomain, ip, status) VALUES (?, ?, ?)""",
            (subdomain, ip, status)
        )
        conn.commit()
    except sqlite3.Error as e:
        console.print(f"[red][!] DB error saving {subdomain}: {e}[/red]")


def run(target, conn):
    """
    Main entry point called by orchestrator.
    Runs the full subdomain enumeration pipeline.

    Pipeline:
    subfinder → list of subdomains
    → DNS resolve each one → get IP
    → classify as live or dead
    → save all to SQLite
    """
    console.print(f"\n[bold cyan][ Subdomain Enumeration ][/bold cyan]")
    console.print(f"[*] Target: {target}\n")

    # Step 1 — find subdomains using Subfinder
    subdomains = run_subfinder(target)

    if not subdomains:
        console.print("[yellow][!] No subdomains found. Try a larger domain.[/yellow]")
        return []

    # Step 2 — resolve each subdomain to an IP
    console.print(f"[*] Resolving {len(subdomains)} subdomains to IPs...")

    results   = []
    live_count = 0
    dead_count = 0

    for subdomain in track(subdomains, description="Resolving..."):
        ip     = resolve_ip(subdomain)
        status = "live" if ip else "dead"

        if status == "live":
            live_count += 1
        else:
            dead_count += 1

        # Save immediately — don't wait until the end
        save_to_db(conn, subdomain, ip, status)

        results.append({
            "subdomain": subdomain,
            "ip":        ip,
            "status":    status
        })

        # Small delay — be polite to DNS servers
        time.sleep(0.1)

    # Step 3 — print summary
    console.print()
    console.print(f"[green][+] Live subdomains  : {live_count}[/green]")
    console.print(f"[dim][*] Dead/unresolved : {dead_count}[/dim]")
    console.print(f"[green][+] Total saved to DB: {len(results)}[/green]")

    # Print the live ones so you can see results immediately
    console.print("\n[bold]Live subdomains found:[/bold]")
    for r in results:
        if r["status"] == "live":
            console.print(f"  [green]✓[/green] {r['subdomain']:<40} {r['ip']}")

    return results
