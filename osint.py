# osint.py
# PURPOSE: Main entry point. Run this file to start a scan.
# Usage: python3 osint.py --target example.com
# Optional: python3 osint.py --target example.com --output myreport.pdf

import argparse
import yaml
import os
import sys

from core.database import init_db
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table

console = Console()


def load_config():
    """
    Reads config/settings.yaml into a Python dictionary.
    All API keys and settings come from here — never hardcoded.
    """
    config_path = "config/settings.yaml"
    if not os.path.exists(config_path):
        console.print("[red][!] config/settings.yaml not found![/red]")
        console.print("[yellow]    Create it first — see Phase 0 Step 0.6[/yellow]")
        sys.exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f)


def print_banner():
    """Prints the tool banner on startup."""
    banner = (
        "[bold cyan]  OSINT Footprinting Framework[/bold cyan]\n"
        "[dim]  Kali Linux Edition — 100% Free Tools[/dim]\n"
        "[dim]  Built for internship portfolio[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))
    console.print()


def print_summary_table(target, modules, output):
    """Prints a neat summary of what is about to run."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("[green]Target[/green]",   f"[bold]{target}[/bold]")
    table.add_row("[green]Modules[/green]",  ", ".join(modules))
    table.add_row("[green]Output[/green]",   output)
    table.add_row("[green]OS[/green]",       "Kali Linux")
    console.print(table)
    console.print()


def main():
    print_banner()

    # --- Argument parser ---
    # This is what lets you type --target, --output, --modules
    parser = argparse.ArgumentParser(
        description="OSINT Footprinting Automation Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target domain to scan\nExample: example.com"
    )
    parser.add_argument(
        "--output",
        default="report.pdf",
        help="PDF report filename (default: report.pdf)"
    )
    parser.add_argument(
        "--modules",
        nargs="+",
        default=["subdomains", "ports", "whois", "emails", "techstack"],
        choices=["subdomains", "ports", "whois", "emails", "techstack"],
        help=(
            "Which modules to run (default: all)\n"
            "Example: --modules subdomains ports"
        )
    )
    args = parser.parse_args()

    # --- Load config ---
    config = load_config()

    # --- Print what we are about to do ---
    print_summary_table(args.target, args.modules, args.output)

    # --- Initialise database ---
    # Creates output/example_com.db with all 6 empty tables
    conn = init_db(args.target)
    console.print()

    # --- Run all modules via orchestrator ---
    # (We build orchestrator.py in Phase 2)
    console.print("[yellow][*] Starting scan — this may take 2-5 minutes...[/yellow]")
    console.print()

    try:
        from core.orchestrator import run_all
        run_all(args.target, conn, config, args.modules)
    except ImportError:
        console.print("[red][!] orchestrator.py not built yet — complete Phase 2[/red]")
        conn.close()
        sys.exit(0)

    # --- Generate PDF report ---
    # (We build generator.py in Phase 6)
    console.print()
    console.print("[yellow][*] Generating PDF report...[/yellow]")
    try:
        from report.generator import generate_pdf
        generate_pdf(args.target, conn, args.output)
        console.print(f"[bold green][+] Report saved → {args.output}[/bold green]")
    except ImportError:
        console.print("[dim][*] Report generator not built yet — complete Phase 6[/dim]")

    conn.close()
    console.print()
    console.print("[bold green][+] Scan complete![/bold green]")


if __name__ == "__main__":
    # Always run from the project root directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
