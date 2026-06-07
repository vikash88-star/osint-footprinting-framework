# modules/ports.py
# PURPOSE: Scan open ports on all live IPs discovered by subdomains.py
#
# HOW IT WORKS:
# 1. Read live IPs from the subdomains SQLite table
# 2. Run Nmap on each IP — detects open ports + service versions
# 3. Query Shodan free tier for additional intel and CVE matches
# 4. Save everything to the ports table
#
# WHY PORT SCANNING MATTERS:
# Port 22  open = SSH login panel exposed
# Port 3306 open = MySQL database on public internet (very bad)
# Port 8080 open = dev server accidentally left running
# Port 443  open = HTTPS (normal, but version matters)
# Each open port with an outdated service = potential CVE match

import nmap
import shodan
import time
import sqlite3
import json
from rich.console import Console
from rich.table import Table

# Thread-safe DB connection helper
def get_db_path(target):
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"

console = Console()
MAX_IPS_TO_SCAN = 10

def get_live_ips(conn):
    """
    Read the live IPs that subdomains.py already discovered.
    We only scan IPs that successfully resolved — no point
    scanning dead subdomains.

    Returns list of unique IPs (deduplicated — multiple subdomains
    can share the same IP, we scan each IP only once).
    """
    cursor = conn.execute(
        "SELECT DISTINCT ip FROM subdomains WHERE status = 'live' AND ip IS NOT NULL"
    )
    rows = cursor.fetchall()
    ips  = [row[0] for row in rows if row[0]]
    console.print(f"[*] Found {len(ips)} unique live IPs to scan")
    return ips


def scan_with_nmap(ip):
    """
    Run Nmap service version scan on a single IP.

    Flags used:
    -sV        = detect service versions (what software + version on each port)
    --top-ports 1000 = scan the 1000 most common ports (faster than all 65535)
    -T4        = aggressive timing (faster, fine for CTF/lab targets)
    --open     = only show open ports (skip filtered/closed)
    -Pn        = skip ping check (some hosts block ping but still have open ports)

    Returns list of dicts — one per open port found.
    """
    console.print(f"[dim][*] Nmap scanning {ip}...[/dim]")
    scanner = nmap.PortScanner()

    try:
        scanner.scan(
            hosts=ip,
            arguments="-sV --top-ports 1000 -T4 --open -Pn",
            timeout=120
        )
    except Exception as e:
        console.print(f"[red][!] Nmap error on {ip}: {e}[/red]")
        return []

    open_ports = []

    if ip not in scanner.all_hosts():
        return []

    for proto in scanner[ip].all_protocols():
        port_list = scanner[ip][proto].keys()
        for port in port_list:
            port_data = scanner[ip][proto][port]

            # Only save open ports
            if port_data["state"] != "open":
                continue

            service = port_data.get("name",    "unknown")
            version = port_data.get("version", "")
            product = port_data.get("product", "")

            # Combine product + version for display
            full_version = f"{product} {version}".strip()

            open_ports.append({
                "ip":       ip,
                "port":     port,
                "protocol": proto,
                "service":  service,
                "version":  full_version
            })

    console.print(f"[green][+] {ip} — {len(open_ports)} open ports found[/green]")
    return open_ports


def query_shodan(ip, api_key):
    """
    Query Shodan for additional intelligence on this IP.
    Shodan has already scanned the entire internet — we just
    look up what it knows about this specific IP.

    Free tier gives us:
    - Organisation that owns the IP
    - ISP / hosting provider
    - Country
    - Known CVEs (this is the gold — pre-matched vulnerabilities)
    - Additional open ports Shodan has seen historically

    Returns dict of extra data, or empty dict if API key missing/invalid.
    """
    if not api_key or api_key == "YOUR_FREE_SHODAN_KEY":
        console.print("[dim][*] No Shodan key — skipping Shodan lookup[/dim]")
        return {}

    try:
        api  = shodan.Shodan(api_key)
        host = api.host(ip)

        # Extract CVE list — each entry looks like "CVE-2021-44228"
        vulns = list(host.get("vulns", []))

        return {
            "org":       host.get("org",          "Unknown"),
            "isp":       host.get("isp",          "Unknown"),
            "country":   host.get("country_name", "Unknown"),
            "vulns":     vulns,
            "hostnames": host.get("hostnames",    [])
        }

    except shodan.APIError as e:
        if "No information available" in str(e):
            # Shodan just doesn't have data on this IP — not an error
            return {}
        console.print(f"[yellow][!] Shodan error for {ip}: {e}[/yellow]")
        return {}
    except Exception as e:
        console.print(f"[yellow][!] Shodan unexpected error: {e}[/yellow]")
        return {}


def save_ports_to_db(conn, ports_data, shodan_data):
    """
    Save port scan results to SQLite ports table.
    Merges Nmap findings with Shodan CVE data.
    """
    vulns_str = json.dumps(shodan_data.get("vulns", []))

    for p in ports_data:
        try:
            conn.execute(
                """INSERT INTO ports
                   (ip, port, protocol, service, version, vulns)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    p["ip"],
                    p["port"],
                    p["protocol"],
                    p["service"],
                    p["version"],
                    vulns_str
                )
            )
        except sqlite3.Error as e:
            console.print(f"[red][!] DB error saving port {p['port']}: {e}[/red]")

    conn.commit()


def print_ports_table(ip, ports, shodan_info):
    """
    Print a neat table of results in the terminal
    so you can see findings in real time.
    """
    if not ports:
        return

    table = Table(title=f"Open ports on {ip}", show_lines=True)
    table.add_column("Port",     style="cyan",  width=8)
    table.add_column("Protocol", style="dim",   width=10)
    table.add_column("Service",  style="green", width=12)
    table.add_column("Version",  style="white", width=30)

    for p in ports:
        table.add_row(
            str(p["port"]),
            p["protocol"],
            p["service"],
            p["version"] or "—"
        )

    console.print(table)

    # Print CVEs if Shodan found any — these are critical findings
    vulns = shodan_info.get("vulns", [])
    if vulns:
        console.print(f"[bold red]  ⚠ CVEs found on {ip}:[/bold red]")
        for cve in vulns:
            console.print(f"    [red]• {cve}[/red]")
    else:
        console.print(f"[dim]  No CVEs matched by Shodan for {ip}[/dim]")

    # Print Shodan org info
    if shodan_info.get("org"):
        console.print(
            f"  [dim]Org: {shodan_info.get('org')} | "
            f"ISP: {shodan_info.get('isp')} | "
            f"Country: {shodan_info.get('country')}[/dim]"
        )
    console.print()


def run(target, config):
    """
    Main entry point called by orchestrator.
    Opens its OWN SQLite connection — thread safe.
    """
    # Each thread must open its own connection
    db_path = get_db_path(target)
    conn    = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    console.print(f"\n[bold cyan][ Port Scanning + CVE Matching ][/bold cyan]")
    console.print(f"[*] Target: {target}\n")

    # Step 1 — get live IPs from database
    all_ips = get_live_ips(conn)

    if not all_ips:
        console.print("[yellow][!] No live IPs found — run subdomains module first[/yellow]")
        conn.close()
        return

    # Limit IPs scanned
    ips_to_scan = all_ips[:MAX_IPS_TO_SCAN]
    if len(all_ips) > MAX_IPS_TO_SCAN:
        console.print(
            f"[yellow][*] Limiting to {MAX_IPS_TO_SCAN} IPs "
            f"(found {len(all_ips)} — change MAX_IPS_TO_SCAN to scan more)[/yellow]"
        )

    shodan_api_key = config.get("shodan_api_key", "")
    total_ports    = 0
    total_cves     = 0

    # Step 2 — scan each IP
    for i, ip in enumerate(ips_to_scan, 1):
        console.print(f"[cyan][{i}/{len(ips_to_scan)}] Scanning {ip}...[/cyan]")

        open_ports  = scan_with_nmap(ip)
        shodan_info = query_shodan(ip, shodan_api_key)

        print_ports_table(ip, open_ports, shodan_info)
        save_ports_to_db(conn, open_ports, shodan_info)

        total_ports += len(open_ports)
        total_cves  += len(shodan_info.get("vulns", []))

        time.sleep(2)

    # Step 3 — summary
    console.print(f"[bold green][+] Port scan complete[/bold green]")
    console.print(f"[green]    Open ports found : {total_ports}[/green]")
    console.print(
        f"[{'red' if total_cves > 0 else 'dim'}]"
        f"    CVEs matched    : {total_cves}"
        f"[/{'red' if total_cves > 0 else 'dim'}]"
    )

    conn.close()
