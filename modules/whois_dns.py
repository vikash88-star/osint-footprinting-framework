# modules/whois_dns.py
# PURPOSE: Collect domain registration data and DNS history.
#
# HOW IT WORKS:
# 1. WHOIS lookup — who registered this domain, when, expiry date
# 2. ViewDNS.info — free scrape of historical DNS records
#    (old IPs the domain used to point to — often forgotten + unpatched)
# 3. All results saved to whois_data and dns_history tables
#
# ALL FREE — no API keys needed for either source.
#
# WHY THIS MATTERS:
# WHOIS tells you: org name, registrar, creation date, expiry
# DNS history tells you: old IPs — legacy servers often have
# no WAF, no updates, and full access to the same application.
# This is how bug bounty hunters find hidden attack surfaces.

import whois
import requests
import sqlite3
import time
import json
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table   import Table

console = Console()


def get_db_path(target):
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"


def get_whois_data(target):
    """
    Fetch WHOIS registration data for the target domain.

    Returns a dict with:
    - registrar     : who manages the domain registration
    - creation_date : when was this domain first registered
    - expiration_date: when does it expire (near expiry = takeover risk)
    - name_servers  : which DNS provider
    - org           : organisation name
    - emails        : contact emails in WHOIS record
    """
    console.print(f"[*] Running WHOIS lookup on {target}...")
    try:
        w = whois.whois(target)

        # Dates can be lists — take the first one
        creation   = w.creation_date
        expiration = w.expiration_date
        if isinstance(creation,   list): creation   = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]

        result = {
            "registrar":       str(w.registrar       or "Unknown"),
            "creation_date":   str(creation          or "Unknown"),
            "expiration_date": str(expiration        or "Unknown"),
            "name_servers":    str(w.name_servers    or "Unknown"),
            "org":             str(w.org             or "Unknown"),
            "whois_emails":    str(w.emails          or "None")
        }

        console.print(f"[green][+] WHOIS data retrieved[/green]")
        return result

    except Exception as e:
        console.print(f"[yellow][!] WHOIS error: {e}[/yellow]")
        return {
            "registrar":       "Error",
            "creation_date":   "Error",
            "expiration_date": "Error",
            "name_servers":    "Error",
            "org":             "Error",
            "whois_emails":    "Error"
        }


def get_dns_history(target):
    """
    Scrape ViewDNS.info for historical DNS A records.
    This is completely free — no API key needed.
    ViewDNS keeps records of every IP a domain has ever pointed to.

    Why this matters: old IPs are often:
    - Not behind the current WAF/CDN
    - Running outdated software
    - Still serving the same application directly

    Returns list of dicts: [{old_ip, first_seen, last_seen}]
    """
    console.print(f"[*] Fetching DNS history from ViewDNS.info...")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    url = f"https://viewdns.info/iphistory/?domain={target}"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        time.sleep(1)  # be polite

        if r.status_code != 200:
            console.print(f"[yellow][!] ViewDNS returned {r.status_code}[/yellow]")
            return []

        soup    = BeautifulSoup(r.text, "html.parser")
        records = []

        # ViewDNS results are in an HTML table
        # We find all tables and look for the one with IP history data
        tables = soup.find_all("table")

        for table in tables:
            rows = table.find_all("tr")
            for row in rows[1:]:  # skip header row
                cols = row.find_all("td")
                if len(cols) >= 3:
                    ip         = cols[0].get_text(strip=True)
                    location   = cols[1].get_text(strip=True)
                    first_seen = cols[2].get_text(strip=True)
                    last_seen  = cols[3].get_text(strip=True) if len(cols) > 3 else "Unknown"

                    # Only save valid IP addresses
                    if ip and "." in ip and ip[0].isdigit():
                        records.append({
                            "old_ip":     ip,
                            "location":   location,
                            "first_seen": first_seen,
                            "last_seen":  last_seen
                        })

        console.print(f"[green][+] DNS history: {len(records)} historical IPs found[/green]")
        return records

    except requests.RequestException as e:
        console.print(f"[yellow][!] ViewDNS error: {e}[/yellow]")
        return []


def save_whois_to_db(conn, data):
    """Save WHOIS data to whois_data table."""
    try:
        conn.execute(
            """INSERT INTO whois_data
               (registrar, creation_date, expiration_date, name_servers, org)
               VALUES (?, ?, ?, ?, ?)""",
            (
                data["registrar"],
                data["creation_date"],
                data["expiration_date"],
                data["name_servers"],
                data["org"]
            )
        )
        conn.commit()
    except sqlite3.Error as e:
        console.print(f"[red][!] DB error saving WHOIS: {e}[/red]")


def save_dns_history_to_db(conn, records):
    """Save DNS history records to dns_history table."""
    for r in records:
        try:
            conn.execute(
                """INSERT INTO dns_history
                   (old_ip, first_seen, last_seen)
                   VALUES (?, ?, ?)""",
                (r["old_ip"], r["first_seen"], r["last_seen"])
            )
        except sqlite3.Error as e:
            console.print(f"[red][!] DB error saving DNS history: {e}[/red]")
    conn.commit()


def print_whois_table(data):
    """Print WHOIS results as a neat table."""
    table = Table(title="WHOIS Registration Data", show_lines=True)
    table.add_column("Field",  style="cyan",  width=20)
    table.add_column("Value",  style="white", width=50)

    table.add_row("Registrar",       data["registrar"])
    table.add_row("Organisation",    data["org"])
    table.add_row("Created",         data["creation_date"])
    table.add_row("Expires",         data["expiration_date"])
    table.add_row("Name Servers",    data["name_servers"][:60])
    table.add_row("WHOIS Emails",    data["whois_emails"])

    console.print(table)


def print_dns_history_table(records):
    """Print DNS history as a neat table."""
    if not records:
        console.print("[dim][*] No DNS history records found[/dim]")
        return

    table = Table(title="DNS History (old IPs)", show_lines=True)
    table.add_column("Old IP",      style="yellow", width=18)
    table.add_column("First Seen",  style="dim",    width=15)
    table.add_column("Last Seen",   style="dim",    width=15)

    for r in records:
        table.add_row(r["old_ip"], r["first_seen"], r["last_seen"])

    console.print(table)
    console.print(
        "[yellow][!] Old IPs may bypass current WAF/CDN — "
        "worth investigating manually[/yellow]"
    )


def run(target):
    """
    Main entry point called by orchestrator.
    Opens its own thread-safe SQLite connection.
    """
    # Thread-safe: open own connection
    db_path = get_db_path(target)
    conn    = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    console.print(f"\n[bold cyan][ WHOIS + DNS History ][/bold cyan]")
    console.print(f"[*] Target: {target}\n")

    # Step 1 — WHOIS lookup
    whois_data = get_whois_data(target)
    print_whois_table(whois_data)
    save_whois_to_db(conn, whois_data)

    console.print()

    # Step 2 — DNS history
    dns_records = get_dns_history(target)
    print_dns_history_table(dns_records)
    save_dns_history_to_db(conn, dns_records)

    console.print(f"\n[bold green][+] WHOIS + DNS history complete[/bold green]")
    conn.close()
