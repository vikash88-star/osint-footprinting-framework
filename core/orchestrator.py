# core/orchestrator.py
# PURPOSE: The "brain" that controls which modules run and in what order.
#
# WHY THIS ORDER?
# Subdomains MUST run first — ports.py and techstack.py need
# the list of live IPs that subdomains.py discovers.
# After subdomains finishes, all other modules run in parallel
# using ThreadPoolExecutor so we don't wait for one to finish
# before starting the next.

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console

console = Console()


def run_all(target, conn, config, modules):
    """
    Main entry point called by osint.py.
    Runs all selected modules in the correct order.
    """

    start_time = time.time()

    # ----------------------------------------------------------------
    # STAGE 1 — Subdomains (must run first, everything depends on it)
    # ----------------------------------------------------------------
    if "subdomains" in modules:
        console.print("[cyan][*] Stage 1: Subdomain enumeration...[/cyan]")
        try:
            from modules.subdomains import run as run_subdomains
            run_subdomains(target, conn)
        except Exception as e:
            console.print(f"[red][!] Subdomains module error: {e}[/red]")
    else:
        console.print("[dim][*] Skipping subdomains module[/dim]")

    # ----------------------------------------------------------------
    # STAGE 2 — All other modules run in parallel using threads
    # Each module is independent at this point — they all just
    # read from the subdomains table and write to their own table
    # ----------------------------------------------------------------
    console.print("[cyan][*] Stage 2: Running remaining modules in parallel...[/cyan]")

    # Build list of (module_name, function) pairs to run
    tasks = []

# NOTE: We pass `target` instead of `conn` to threaded modules.
    # Each module opens its own SQLite connection inside its thread.
    # This avoids the "SQLite objects created in a thread" error.

    if "ports" in modules:
        try:
            from modules.ports import run as run_ports
            tasks.append(("ports", run_ports, [target, config]))
        except ImportError:
            console.print("[dim][*] ports module not built yet[/dim]")

    if "whois" in modules:
        try:
            from modules.whois_dns import run as run_whois
            tasks.append(("whois", run_whois, [target]))
        except ImportError:
            console.print("[dim][*] whois module not built yet[/dim]")

    if "emails" in modules:
        try:
            from modules.emails import run as run_emails
            tasks.append(("emails", run_emails, [target]))
        except ImportError:
            console.print("[dim][*] emails module not built yet[/dim]")

    if "techstack" in modules:
        try:
            from modules.techstack import run as run_techstack
            tasks.append(("techstack", run_techstack, [target]))
        except ImportError:
            console.print("[dim][*] techstack module not built yet[/dim]")

    # Run all tasks in parallel — max 4 threads at once
    if tasks:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(_run_task, name, fn, args): name
                for name, fn, args in tasks
            }
            for future in as_completed(futures):
                module_name = futures[future]
                try:
                    future.result()
                    console.print(f"[green][+] {module_name} module complete[/green]")
                except Exception as e:
                    console.print(f"[red][!] {module_name} module failed: {e}[/red]")

    # ----------------------------------------------------------------
    # DONE
    # ----------------------------------------------------------------
    elapsed = round(time.time() - start_time, 2)
    console.print()
    console.print(f"[bold green][+] All modules finished in {elapsed}s[/bold green]")


def _run_task(name, fn, args):
    """
    Wrapper that runs a single module function safely.
    Any error inside a module is caught here so one
    failing module doesn't crash the entire scan.
    """
    console.print(f"[dim][*] Starting {name}...[/dim]")
    fn(*args)
