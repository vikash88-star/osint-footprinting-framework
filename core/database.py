# core/database.py
# PURPOSE: Creates the SQLite database and all tables.
# Every module (subdomains, ports, emails etc.) writes
# its results here. The report engine reads from here.

import sqlite3
import os

def init_db(target):
    """
    Called once at startup.
    Creates a .db file named after the target domain.
    Example: example_com.db inside the output/ folder.
    """
    # Replace dots and dashes so filename is safe
    safe_name = target.replace(".", "_").replace("-", "_")
    db_path   = f"output/{safe_name}.db"

    # Create output folder if it doesn't exist
    os.makedirs("output", exist_ok=True)

    # Connect (creates the file if it doesn't exist)
    conn = sqlite3.connect(db_path)

    # This makes rows behave like dictionaries — easier to read
    conn.row_factory = sqlite3.Row

    # Create all tables
    _create_tables(conn)

    print(f"[+] Database ready at {db_path}")
    return conn


def _create_tables(conn):
    """
    Creates all 6 tables — one per module.
    IF NOT EXISTS means running twice won't break anything.
    """
    conn.executescript("""

        -- Table 1: subdomains found by Subfinder
        CREATE TABLE IF NOT EXISTS subdomains (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain     TEXT UNIQUE,
            ip            TEXT,
            status        TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Table 2: open ports found by Nmap + Shodan
        CREATE TABLE IF NOT EXISTS ports (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ip       TEXT,
            port     INTEGER,
            protocol TEXT,
            service  TEXT,
            version  TEXT,
            vulns    TEXT
        );

        -- Table 3: employee emails + breach check results
        CREATE TABLE IF NOT EXISTS emails (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email        TEXT UNIQUE,
            breaches     TEXT,
            breach_count INTEGER DEFAULT 0
        );

        -- Table 4: WHOIS registration data
        CREATE TABLE IF NOT EXISTS whois_data (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            registrar       TEXT,
            creation_date   TEXT,
            expiration_date TEXT,
            name_servers    TEXT,
            org             TEXT
        );

        -- Table 5: tech stack + exposed files per subdomain
        CREATE TABLE IF NOT EXISTS techstack (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain     TEXT,
            technologies  TEXT,
            exposed_files TEXT,
            waf           TEXT
        );

        -- Table 6: DNS history from ViewDNS.info
        CREATE TABLE IF NOT EXISTS dns_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            old_ip     TEXT,
            first_seen TEXT,
            last_seen  TEXT
        );

    """)
    conn.commit()


def get_live_subdomains(conn):
    """
    Helper used by ports.py and techstack.py.
    Returns only subdomains that resolved to a live IP.
    """
    cursor = conn.execute(
        "SELECT subdomain, ip FROM subdomains WHERE status = 'live'"
    )
    return [dict(row) for row in cursor.fetchall()]


def get_all_emails(conn):
    """
    Helper used by aggregator to build the report.
    Returns all emails with breach data.
    """
    cursor = conn.execute("SELECT * FROM emails")
    return [dict(row) for row in cursor.fetchall()]


def get_all_findings(conn):
    """
    Helper used by report generator.
    Returns every row from every table as a dict.
    """
    data = {}
    tables = ["subdomains", "ports", "emails",
              "whois_data", "techstack", "dns_history"]
    for table in tables:
        try:
            cursor = conn.execute(f"SELECT * FROM {table}")
            data[table] = [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            data[table] = []
            print(f"[!] Could not read table {table}: {e}")
    return data

def get_db_path(target):
    """
    Returns the database file path for a target.
    Used by modules that need their own thread-safe connection.
    """
    safe_name = target.replace(".", "_").replace("-", "_")
    return f"output/{safe_name}.db"
