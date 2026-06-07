# modules/emails.py
# PURPOSE: Find employee emails and check them against breach databases.
#
# HOW IT WORKS:
# 1. theHarvester scrapes Google, Bing, DuckDuckGo for emails
#    associated with the target domain — all free, no keys
# 2. h8mail checks each email against free breach sources
#    (paste sites, COMB dataset, IntelligenceX free tier)
# 3. Scylla.sh as a backup breach checker — free public API
# 4. Results saved to emails table with severity rating
#
# WHY THIS MATTERS:
# A breached employee email + reused password = full account takeover.
# This is how 80%+ of real corporate breaches begin.
# Finding "john.smith@company.com appeared in LinkedIn2021 breach"
# is a critical finding in any pen test report.

import subprocess
import requests
import sqlite3
import json
import re
import time
import os
from rich.console import Console
from rich.table   import Table

console = Console()


def get_db_path(target):
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"


def harvest_emails(target):
    """
    Run theHarvester to collect email addresses associated
    with the target domain from public search engines.

    Sources used (all free):
    - google   : Google search results
    - bing     : Bing search results
    - duckduckgo: DuckDuckGo results

    Returns list of email strings.
    """
    console.print(f"[*] Running theHarvester on {target}...")

    try:
        result = subprocess.run(
            [
                "theHarvester",
                "-d", target,
                "-b", "google,bing,duckduckgo",
                "-l", "200"          # limit to 200 results
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        emails = set()
        output = result.stdout + result.stderr

        # Extract emails using regex
        # Pattern matches standard email format
        pattern = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        )

        for match in pattern.findall(output):
            email = match.lower().strip()
            # Only keep emails that belong to the target domain
            domain_base = target.split(".")[0]
            if target in email or domain_base in email:
                emails.add(email)

        found = list(emails)
        console.print(f"[green][+] theHarvester found {len(found)} emails[/green]")
        return found

    except FileNotFoundError:
        console.print("[yellow][!] theHarvester not found — trying fallback[/yellow]")
        return []
    except subprocess.TimeoutExpired:
        console.print("[yellow][!] theHarvester timed out[/yellow]")
        return []


def check_breach_h8mail(email):
    """
    Use h8mail to check if this email appears in known breaches.
    h8mail is free and queries multiple public breach sources.

    Returns list of breach source names, or empty list if clean.
    """
    output_file = f"/tmp/h8mail_{email.replace('@','_').replace('.','_')}.json"

    try:
        subprocess.run(
            ["h8mail", "-t", email, "--json", output_file],
            capture_output=True,
            text=True,
            timeout=60
        )

        if not os.path.exists(output_file):
            return []

        with open(output_file) as f:
            data = json.load(f)

        breaches = []
        for entry in data:
            sources = entry.get("sources", [])
            for src in sources:
                name = src.get("origin", "Unknown")
                if name and name not in breaches:
                    breaches.append(name)

        # Clean up temp file
        os.remove(output_file)
        return breaches

    except FileNotFoundError:
        console.print("[dim][*] h8mail not installed — using Scylla fallback[/dim]")
        return []
    except (json.JSONDecodeError, KeyError):
        return []
    except Exception:
        return []


def check_breach_scylla(email):
    """
    Backup breach check using Scylla.sh public API.
    Completely free, no signup or API key needed.
    Scylla indexes billions of leaked credential records.

    Rate limit: ~1 request per second — we handle this with sleep.
    Returns list of domain/source names where email was found.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    }

    try:
        url = f"https://scylla.sh/search?q=email:{email}&size=5"
        r   = requests.get(url, headers=headers, timeout=10)
        time.sleep(1.2)  # respect rate limit

        if r.status_code == 200:
            data = r.json()
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                sources = list(set(
                    h.get("_source", {}).get("Domain", "Unknown breach")
                    for h in hits
                ))
                return [s for s in sources if s]
        return []

    except requests.RequestException:
        return []
    except (json.JSONDecodeError, KeyError):
        return []


def assign_severity(breach_count):
    """
    Assign severity based on number of breaches found.
    This mirrors real pen test report severity ratings.

    0 breaches  → INFO     (clean)
    1-2 breaches→ HIGH     (exposed — needs password reset)
    3+ breaches → CRITICAL (serial reuse — immediate risk)
    """
    if breach_count >= 3:
        return "CRITICAL"
    elif breach_count >= 1:
        return "HIGH"
    else:
        return "INFO"


def save_email_to_db(conn, email, breaches, breach_count):
    """Save email + breach data to emails table."""
    try:
        conn.execute(
            """INSERT OR IGNORE INTO emails
               (email, breaches, breach_count)
               VALUES (?, ?, ?)""",
            (email, json.dumps(breaches), breach_count)
        )
        conn.commit()
    except sqlite3.Error as e:
        console.print(f"[red][!] DB error saving email {email}: {e}[/red]")


def print_email_results(results):
    """Print email breach results as a colour-coded table."""
    if not results:
        console.print("[dim][*] No emails to display[/dim]")
        return

    table = Table(title="Email Breach Analysis", show_lines=True)
    table.add_column("Email",        style="cyan",  width=35)
    table.add_column("Severity",     style="white", width=10)
    table.add_column("Breaches",     style="white", width=8)
    table.add_column("Sources",      style="dim",   width=35)

    for r in results:
        # Colour code severity
        sev = r["severity"]
        if sev == "CRITICAL":
            sev_display = "[bold red]CRITICAL[/bold red]"
        elif sev == "HIGH":
            sev_display = "[yellow]HIGH[/yellow]"
        else:
            sev_display = "[dim]INFO[/dim]"

        sources_str = ", ".join(r["breaches"][:3]) if r["breaches"] else "None"

        table.add_row(
            r["email"],
            sev_display,
            str(r["breach_count"]),
            sources_str
        )

    console.print(table)


def run(target):
    """
    Main entry point called by orchestrator.
    Opens its own thread-safe SQLite connection.
    """
    # Thread-safe: open own connection
    db_path = get_db_path(target)
    conn    = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    console.print(f"\n[bold cyan][ Email Harvesting + Breach Detection ][/bold cyan]")
    console.print(f"[*] Target: {target}\n")

    # Step 1 — harvest emails from search engines
    emails = harvest_emails(target)

    if not emails:
        console.print(
            "[yellow][!] No emails found — "
            "try a larger domain with more public exposure[/yellow]"
        )
        conn.close()
        return []

    # Step 2 — check each email for breaches
    console.print(f"\n[*] Checking {len(emails)} emails for breach exposure...")
    console.print("[dim][*] Using h8mail (primary) + Scylla.sh (backup) — both free[/dim]\n")

    results        = []
    critical_count = 0
    high_count     = 0

    for i, email in enumerate(emails, 1):
        console.print(f"[dim][{i}/{len(emails)}] Checking {email}...[/dim]")

        # Try h8mail first
        breaches = check_breach_h8mail(email)

        # If h8mail found nothing, try Scylla as backup
        if not breaches:
            breaches = check_breach_scylla(email)

        breach_count = len(breaches)
        severity     = assign_severity(breach_count)

        if severity == "CRITICAL": critical_count += 1
        if severity == "HIGH":     high_count     += 1

        save_email_to_db(conn, email, breaches, breach_count)

        results.append({
            "email":        email,
            "breaches":     breaches,
            "breach_count": breach_count,
            "severity":     severity
        })

        time.sleep(0.5)

    # Step 3 — print results table
    console.print()
    print_email_results(results)

    # Step 4 — summary
    console.print()
    console.print(f"[bold green][+] Email analysis complete[/bold green]")
    console.print(f"[green]    Total emails found    : {len(results)}[/green]")
    console.print(f"[{'red' if critical_count > 0 else 'dim'}]    CRITICAL (3+ breaches) : {critical_count}[/{'red' if critical_count > 0 else 'dim'}]")
    console.print(f"[{'yellow' if high_count > 0 else 'dim'}]    HIGH (1-2 breaches)    : {high_count}[/{'yellow' if high_count > 0 else 'dim'}]")

    conn.close()
    return results
