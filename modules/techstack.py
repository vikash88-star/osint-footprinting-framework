# modules/techstack.py
# PURPOSE: Fingerprint web technologies and find exposed sensitive files.
#
# HOW IT WORKS:
# 1. Read live subdomains from SQLite (found by subdomains.py)
# 2. Send HTTP HEAD/GET request to each subdomain
# 3. Parse response headers to identify:
#    - Web server (Apache, Nginx, IIS)
#    - Backend language (PHP, Python, Node.js)
#    - Frameworks (WordPress, Django, Laravel)
#    - CDN/WAF (Cloudflare, Akamai, Fastly)
# 4. Probe sensitive paths on each subdomain:
#    /.env          → contains DB passwords, API keys (CRITICAL)
#    /.git/HEAD     → exposes full source code (CRITICAL)
#    /wp-admin/     → WordPress admin panel exposed (HIGH)
#    /phpmyadmin/   → database admin panel (HIGH)
#    /admin/        → generic admin panel (HIGH)
#    /api/docs      → API documentation exposed (MEDIUM)
#    /robots.txt    → reveals hidden paths (INFO)
# 5. Save all findings with severity ratings to SQLite
#
# ALL FREE — uses only httpx (HTTP library), no APIs needed.
#
# WHY THIS MATTERS:
# An exposed .env file contains database passwords in plaintext.
# This single misconfiguration has caused billion-dollar breaches.
# Tech stack info tells you which CVEs to check next.

import httpx
import sqlite3
import json
import time
from rich.console import Console
from rich.table   import Table

console = Console()


def get_db_path(target):
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"


def get_live_subdomains(conn):
    """
    Read live subdomains from the database.
    Only process subdomains that actually resolved to an IP.
    """
    cursor = conn.execute(
        "SELECT subdomain, ip FROM subdomains WHERE status = 'live'"
    )
    return [{"subdomain": row[0], "ip": row[1]} for row in cursor.fetchall()]


def detect_technologies(headers, body_preview):
    """
    Identify technologies from HTTP response headers and HTML body.

    Headers that reveal tech stack:
    Server: Apache/2.4.41        → Apache version
    X-Powered-By: PHP/7.4.3      → PHP version (huge info leak)
    X-Generator: WordPress 6.0   → WordPress
    Set-Cookie: laravel_session  → Laravel framework
    Set-Cookie: PHPSESSID        → PHP backend

    Returns list of detected technology strings.
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    body_lower    = body_preview.lower() if body_preview else ""

    # --- Server header ---
    server = headers_lower.get("server", "")
    if server:
        if "apache"  in server: detected.append(f"Apache ({server})")
        elif "nginx" in server: detected.append(f"Nginx ({server})")
        elif "iis"   in server: detected.append(f"Microsoft IIS ({server})")
        elif "caddy" in server: detected.append("Caddy")
        else:                   detected.append(f"Server: {server[:30]}")

    # --- X-Powered-By header (biggest info leak) ---
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        detected.append(f"X-Powered-By: {powered_by[:40]}")

    # --- Framework detection from cookies ---
    cookies = headers_lower.get("set-cookie", "")
    if "laravel_session" in cookies:  detected.append("Laravel (PHP)")
    if "phpsessid"       in cookies:  detected.append("PHP Session")
    if "asp.net_session" in cookies:  detected.append("ASP.NET")
    if "django"          in cookies:  detected.append("Django (Python)")
    if "rack.session"    in cookies:  detected.append("Ruby on Rails")

    # --- CDN/WAF detection ---
    if "cf-ray"              in headers_lower: detected.append("WAF: Cloudflare")
    if "x-fastly-request-id" in headers_lower: detected.append("CDN: Fastly")
    if "x-amz-cf-id"         in headers_lower: detected.append("CDN: AWS CloudFront")
    if "x-akamai-transformed" in headers_lower: detected.append("WAF: Akamai")
    if "x-sucuri-id"          in headers_lower: detected.append("WAF: Sucuri")

    # --- Body-based detection ---
    if "wp-content"   in body_lower: detected.append("WordPress")
    if "joomla"       in body_lower: detected.append("Joomla")
    if "drupal"       in body_lower: detected.append("Drupal")
    if "shopify"      in body_lower: detected.append("Shopify")
    if "__next"       in body_lower: detected.append("Next.js")
    if "react"        in body_lower: detected.append("React")
    if "angular"      in body_lower: detected.append("Angular")

    return detected


def detect_waf(headers):
    """
    Check if a WAF (Web Application Firewall) is protecting the site.
    WAFs make exploitation much harder — important info for pen test.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    if "cf-ray"               in headers_lower: return "Cloudflare"
    if "x-sucuri-id"          in headers_lower: return "Sucuri"
    if "x-akamai-transformed" in headers_lower: return "Akamai"
    if "x-fastly-request-id"  in headers_lower: return "Fastly"
    if "x-amz-cf-id"          in headers_lower: return "AWS CloudFront"
    return "None detected"


# Sensitive paths to probe on every subdomain
# Severity rating:
# CRITICAL = contains secrets or gives code access
# HIGH     = admin panels, DB managers
# MEDIUM   = API docs, config files
# INFO     = robots.txt, sitemaps (harmless but informative)

SENSITIVE_PATHS = [
    {"path": "/.env",              "severity": "CRITICAL",
     "desc": "Environment file — may contain DB passwords and API keys"},
    {"path": "/.git/HEAD",         "severity": "CRITICAL",
     "desc": "Git repository exposed — source code downloadable"},
    {"path": "/.git/config",       "severity": "CRITICAL",
     "desc": "Git config exposed"},
    {"path": "/wp-admin/",         "severity": "HIGH",
     "desc": "WordPress admin panel"},
    {"path": "/phpmyadmin/",       "severity": "HIGH",
     "desc": "phpMyAdmin database manager exposed"},
    {"path": "/admin/",            "severity": "HIGH",
     "desc": "Admin panel exposed"},
    {"path": "/administrator/",    "severity": "HIGH",
     "desc": "Joomla admin panel"},
    {"path": "/api/docs",          "severity": "MEDIUM",
     "desc": "API documentation publicly accessible"},
    {"path": "/api/swagger.json",  "severity": "MEDIUM",
     "desc": "Swagger API spec exposed"},
    {"path": "/.htaccess",         "severity": "MEDIUM",
     "desc": "Apache config file accessible"},
    {"path": "/config.php.bak",    "severity": "HIGH",
     "desc": "PHP config backup file"},
    {"path": "/backup.zip",        "severity": "CRITICAL",
     "desc": "Site backup archive accessible"},
    {"path": "/robots.txt",        "severity": "INFO",
     "desc": "Robots.txt — may reveal hidden paths"},
    {"path": "/sitemap.xml",       "severity": "INFO",
     "desc": "Sitemap — enumerates all pages"},
    {"path": "/.DS_Store",         "severity": "MEDIUM",
     "desc": "macOS metadata — reveals directory structure"},
]


def check_exposed_files(base_url):
    """
    Probe each sensitive path on the target subdomain.

    Logic:
    - HTTP 200 = file exists and is readable → EXPOSED
    - HTTP 403 = file exists but access denied → EXISTS (still interesting)
    - HTTP 301/302 = redirect → note it
    - HTTP 404 = not found → skip

    Returns list of exposed path findings.
    """
    exposed = []

    for item in SENSITIVE_PATHS:
        path     = item["path"]
        severity = item["severity"]
        desc     = item["desc"]
        url      = f"{base_url}{path}"

        try:
            r = httpx.get(
                url,
                timeout=5,
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            )

            if r.status_code in [200, 403]:
                status_label = "EXPOSED" if r.status_code == 200 else "EXISTS (403)"
                exposed.append({
                    "path":     path,
                    "status":   r.status_code,
                    "label":    status_label,
                    "severity": severity,
                    "desc":     desc,
                    "size":     len(r.content)
                })

                # Print critical findings immediately — don't wait
                if severity == "CRITICAL":
                    console.print(
                        f"  [bold red]⚠ CRITICAL: {base_url}{path} "
                        f"(HTTP {r.status_code}) — {desc}[/bold red]"
                    )
                elif severity == "HIGH":
                    console.print(
                        f"  [red]! HIGH: {base_url}{path} "
                        f"(HTTP {r.status_code})[/red]"
                    )

        except httpx.TimeoutException:
            pass  # path doesn't exist or too slow — skip
        except httpx.RequestError:
            pass  # connection refused, DNS fail — skip

        time.sleep(0.3)  # small delay between requests

    return exposed


def scan_subdomain(subdomain):
    """
    Full tech fingerprint + exposed file scan for one subdomain.
    Tries HTTPS first, falls back to HTTP if HTTPS fails.

    Returns dict with all findings, or None if subdomain unreachable.
    """
    # Try HTTPS first, then HTTP
    for scheme in ["https", "http"]:
        base_url = f"{scheme}://{subdomain}"
        try:
            r = httpx.get(
                base_url,
                timeout=8,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            )

            # Get a preview of the body for tech detection
            body_preview = r.text[:3000] if r.text else ""

            # Detect technologies from headers + body
            technologies = detect_technologies(dict(r.headers), body_preview)

            # Detect WAF
            waf = detect_waf(dict(r.headers))

            # Check for exposed sensitive files
            exposed = check_exposed_files(base_url)

            return {
                "subdomain":    subdomain,
                "base_url":     base_url,
                "status_code":  r.status_code,
                "technologies": technologies,
                "waf":          waf,
                "exposed":      exposed
            }

        except httpx.TimeoutException:
            continue  # try next scheme
        except httpx.RequestError:
            continue  # try next scheme

    return None  # both HTTPS and HTTP failed


def save_to_db(conn, result):
    """Save techstack findings to SQLite."""
    if not result:
        return
    try:
        conn.execute(
            """INSERT INTO techstack
               (subdomain, technologies, exposed_files, waf)
               VALUES (?, ?, ?, ?)""",
            (
                result["subdomain"],
                json.dumps(result["technologies"]),
                json.dumps(result["exposed"]),
                result["waf"]
            )
        )
        conn.commit()
    except sqlite3.Error as e:
        console.print(f"[red][!] DB error: {e}[/red]")


def print_results_table(results):
    """Print a summary table of all techstack findings."""
    if not results:
        return

    table = Table(title="Tech Stack Fingerprinting Results", show_lines=True)
    table.add_column("Subdomain",   style="cyan",   width=35)
    table.add_column("Technologies",style="white",  width=30)
    table.add_column("WAF",         style="yellow", width=15)
    table.add_column("Exposed",     style="red",    width=8)

    for r in results:
        techs   = ", ".join(r["technologies"][:2]) if r["technologies"] else "Unknown"
        exposed = str(len(r["exposed"])) if r["exposed"] else "0"
        table.add_row(
            r["subdomain"][:35],
            techs[:30],
            r["waf"],
            f"[red]{exposed}[/red]" if int(exposed) > 0 else exposed
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

    console.print(f"\n[bold cyan][ Tech Stack + Exposed Files ][/bold cyan]")
    console.print(f"[*] Target: {target}\n")

    # Step 1 — get live subdomains from DB
    subdomains = get_live_subdomains(conn)

    if not subdomains:
        console.print("[yellow][!] No live subdomains — run subdomains module first[/yellow]")
        conn.close()
        return

    # Limit to 15 subdomains to keep scan time reasonable
    to_scan = subdomains[:15]
    if len(subdomains) > 15:
        console.print(
            f"[yellow][*] Scanning first 15 of {len(subdomains)} subdomains[/yellow]"
        )

    results        = []
    exposed_count  = 0
    critical_count = 0

    # Step 2 — scan each subdomain
    for i, sub in enumerate(to_scan, 1):
        subdomain = sub["subdomain"]
        console.print(f"[dim][{i}/{len(to_scan)}] Scanning {subdomain}...[/dim]")

        result = scan_subdomain(subdomain)

        if result:
            save_to_db(conn, result)
            results.append(result)

            # Count exposed files
            for f in result["exposed"]:
                exposed_count += 1
                if f["severity"] == "CRITICAL":
                    critical_count += 1
        else:
            console.print(f"[dim]  {subdomain} — unreachable[/dim]")

        time.sleep(0.5)

    # Step 3 — print summary table
    console.print()
    print_results_table(results)

    # Step 4 — print all exposed files found
    all_exposed = [
        (r["subdomain"], f)
        for r in results
        for f in r["exposed"]
    ]

    if all_exposed:
        console.print()
        exposed_table = Table(title="⚠ Exposed Sensitive Files", show_lines=True)
        exposed_table.add_column("Severity", style="red",   width=10)
        exposed_table.add_column("URL",      style="cyan",  width=45)
        exposed_table.add_column("Status",   style="white", width=10)
        exposed_table.add_column("Description", style="dim", width=35)

        for subdomain, f in sorted(
            all_exposed,
            key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x[1]["severity"])
        ):
            sev = f["severity"]
            colour = "bold red" if sev=="CRITICAL" else "red" if sev=="HIGH" else "yellow"
            exposed_table.add_row(
                f"[{colour}]{sev}[/{colour}]",
                f"{subdomain}{f['path']}",
                str(f["status"]),
                f["desc"][:35]
            )
        console.print(exposed_table)

    # Step 5 — final summary
    console.print()
    console.print(f"[bold green][+] Tech stack scan complete[/bold green]")
    console.print(f"[green]    Subdomains scanned  : {len(results)}[/green]")
    console.print(f"[{'red' if exposed_count > 0 else 'dim'}]    Exposed files found : {exposed_count}[/{'red' if exposed_count > 0 else 'dim'}]")
    console.print(f"[{'bold red' if critical_count > 0 else 'dim'}]    CRITICAL findings   : {critical_count}[/{'bold red' if critical_count > 0 else 'dim'}]")

    conn.close()
    return results
