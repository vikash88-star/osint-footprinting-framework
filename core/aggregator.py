# core/aggregator.py
# PURPOSE: Read all module results from SQLite, deduplicate,
# assign severity scores, and return a structured findings dict
# that the PDF generator and dashboard both use.
#
# SEVERITY SCORING:
# CRITICAL (score 4) = active CVE, exposed .env/.git, 3+ breaches
# HIGH     (score 3) = admin panels, 1-2 breaches, open DB port
# MEDIUM   (score 2) = outdated software, .htaccess exposed
# INFO     (score 1) = WHOIS data, subdomains, tech stack info

import sqlite3
import json
from datetime import datetime


def get_db_path(target):
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"


SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "INFO": 1}


def aggregate(target):
    """
    Main function — reads every table and returns a structured
    report dict ready for PDF generation and dashboard display.
    """
    db_path = get_db_path(target)
    conn    = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    report = {
        "target":       target,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings":     [],
        "subdomains":   [],
        "ports":        [],
        "emails":       [],
        "whois":        {},
        "techstack":    [],
        "dns_history":  [],
        "summary": {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "info":     0,
            "total":    0
        }
    }

    # ── Subdomains ────────────────────────────────────────────────
    try:
        rows = conn.execute(
            "SELECT subdomain, ip, status FROM subdomains"
        ).fetchall()
        for row in rows:
            report["subdomains"].append(dict(row))
            if row["status"] == "live":
                report["findings"].append({
                    "severity":    "INFO",
                    "category":    "Subdomain",
                    "host":        row["subdomain"],
                    "detail":      f"Live subdomain → IP: {row['ip']}",
                    "score":       1
                })
    except Exception as e:
        print(f"[!] Subdomains read error: {e}")

    # ── Ports + CVEs ──────────────────────────────────────────────
    try:
        rows = conn.execute(
            "SELECT ip, port, service, version, vulns FROM ports"
        ).fetchall()
        for row in rows:
            report["ports"].append(dict(row))
            vulns = json.loads(row["vulns"]) if row["vulns"] else []

            # Open sensitive ports = HIGH finding
            sensitive_ports = {
                22: "SSH exposed",
                23: "Telnet exposed (CRITICAL — unencrypted)",
                3306: "MySQL DB exposed to internet",
                5432: "PostgreSQL exposed to internet",
                27017: "MongoDB exposed (no auth by default)",
                6379: "Redis exposed (no auth by default)",
                9200: "Elasticsearch exposed",
                21: "FTP exposed"
            }

            if row["port"] in sensitive_ports:
                sev = "CRITICAL" if row["port"] in [23, 27017, 6379] else "HIGH"
                report["findings"].append({
                    "severity": sev,
                    "category": "Exposed Port",
                    "host":     f"{row['ip']}:{row['port']}",
                    "detail":   f"{sensitive_ports[row['port']]} — {row['service']} {row['version']}",
                    "score":    SEVERITY_SCORE[sev]
                })

            # CVEs = CRITICAL findings
            for cve in vulns:
                report["findings"].append({
                    "severity": "CRITICAL",
                    "category": "CVE Match",
                    "host":     f"{row['ip']}:{row['port']}",
                    "detail":   f"{cve} on {row['service']} {row['version']}",
                    "score":    4
                })
    except Exception as e:
        print(f"[!] Ports read error: {e}")

    # ── Emails + Breaches ─────────────────────────────────────────
    try:
        rows = conn.execute(
            "SELECT email, breaches, breach_count FROM emails"
        ).fetchall()
        for row in rows:
            report["emails"].append(dict(row))
            if row["breach_count"] and row["breach_count"] > 0:
                sev = "CRITICAL" if row["breach_count"] >= 3 else "HIGH"
                breaches = json.loads(row["breaches"]) if row["breaches"] else []
                report["findings"].append({
                    "severity": sev,
                    "category": "Credential Breach",
                    "host":     row["email"],
                    "detail":   f"Found in {row['breach_count']} breach(es): {', '.join(breaches[:3])}",
                    "score":    SEVERITY_SCORE[sev]
                })
    except Exception as e:
        print(f"[!] Emails read error: {e}")

    # ── WHOIS ─────────────────────────────────────────────────────
    try:
        row = conn.execute(
            "SELECT * FROM whois_data LIMIT 1"
        ).fetchone()
        if row:
            report["whois"] = dict(row)
            report["findings"].append({
                "severity": "INFO",
                "category": "WHOIS",
                "host":     target,
                "detail":   f"Registrar: {row['registrar']} | Org: {row['org']} | Expires: {row['expiration_date']}",
                "score":    1
            })
    except Exception as e:
        print(f"[!] WHOIS read error: {e}")

    # ── Tech Stack + Exposed Files ────────────────────────────────
    try:
        rows = conn.execute(
            "SELECT subdomain, technologies, exposed_files, waf FROM techstack"
        ).fetchall()
        for row in rows:
            report["techstack"].append(dict(row))
            exposed = json.loads(row["exposed_files"]) if row["exposed_files"] else []
            for f in exposed:
                sev = f.get("severity", "MEDIUM")
                report["findings"].append({
                    "severity": sev,
                    "category": "Exposed File",
                    "host":     row["subdomain"],
                    "detail":   f"{f['path']} (HTTP {f['status']}) — {f.get('desc','')}",
                    "score":    SEVERITY_SCORE.get(sev, 2)
                })
    except Exception as e:
        print(f"[!] Techstack read error: {e}")

    # ── DNS History ───────────────────────────────────────────────
    try:
        rows = conn.execute(
            "SELECT old_ip, first_seen, last_seen FROM dns_history"
        ).fetchall()
        for row in rows:
            report["dns_history"].append(dict(row))
            report["findings"].append({
                "severity": "INFO",
                "category": "DNS History",
                "host":     target,
                "detail":   f"Old IP: {row['old_ip']} (seen: {row['first_seen']} → {row['last_seen']})",
                "score":    1
            })
    except Exception as e:
        print(f"[!] DNS history read error: {e}")

    # ── Sort findings by severity score (highest first) ───────────
    report["findings"].sort(key=lambda x: x["score"], reverse=True)

    # ── Count by severity ─────────────────────────────────────────
    for f in report["findings"]:
        sev = f["severity"]
        if   sev == "CRITICAL": report["summary"]["critical"] += 1
        elif sev == "HIGH":     report["summary"]["high"]     += 1
        elif sev == "MEDIUM":   report["summary"]["medium"]   += 1
        else:                   report["summary"]["info"]     += 1
    report["summary"]["total"] = len(report["findings"])

    conn.close()
    return report
