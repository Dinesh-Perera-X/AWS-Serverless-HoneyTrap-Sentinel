import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.token_manager import HoneyTokenManager
from generators.seeder import TrapSeeder
from detectors.canary_detector import CanaryDetector

console = Console()

def display_banner():
    banner = (
        "[bold cyan]AWS Serverless HoneyTrap Sentinel 🍯⚡[/bold cyan]\n"
        "[dim]Active Defense, Canary Token Generation & Deception Engine[/dim]"
    )
    console.print(Panel.fit(banner, border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="AWS HoneyToken & Active Defense Trapper.")
    parser.add_argument("--list-tokens", action="store_true", help="List all currently armed honeytokens and traps")
    parser.add_argument("--seed", action="store_true", help="Seed default decoy credentials and S3 traps")
    parser.add_argument("--scan-trail", help="Path to CloudTrail JSON log file to audit for canary triggers", default="data/sample_cloudtrail.json")
    args = parser.parse_args()

    display_banner()

    if args.seed:
        TrapSeeder.seed_initial_traps()
        console.print("[bold green]✔ Initial enterprise decoy traps seeded successfully into registry.[/bold green]\n")

    registry = HoneyTokenManager.load_registry()
    tokens = registry.get("tokens", [])

    if args.scan_trail:
        if not os.path.exists(args.scan_trail):
            console.print(f"[red][!] CloudTrail log file not found: {args.scan_trail}[/red]")
            sys.exit(1)

        console.print(f"[*] Ingesting CloudTrail audit stream from: [cyan]{args.scan_trail}[/cyan]\n")
        alerts = CanaryDetector.scan_cloudtrail_log(args.scan_trail, tokens)

        table = Table(title="[bold red]🚨 HoneyToken Trip-Wire Detections & Intrusion Alerts[/bold red]", border_style="red")
        table.add_column("Alert ID", justify="center", style="dim")
        table.add_column("Trigger Mechanism", justify="center", style="magenta")
        table.add_column("Compromised Asset / Key", style="yellow")
        table.add_column("AWS Action", justify="center", style="cyan")
        table.add_column("Attacker IP", justify="center", style="white")
        table.add_column("User Agent / Tooling", style="dim white")
        table.add_column("Severity", justify="center")

        if not alerts:
            table.add_row("-", "CLEAN", "No canary triggers detected.", "-", "-", "-", "[bold green]INFORMATIONAL[/bold green]")
        else:
            for a in alerts:
                sev_color = "bold red" if a["severity"] == "CRITICAL" else "bold yellow"
                table.add_row(
                    a["alert_id"],
                    a["trigger_type"],
                    a["compromised_key"],
                    a["event_name"],
                    a["source_ip"],
                    a["user_agent"][:30] + "..." if len(a["user_agent"]) > 30 else a["user_agent"],
                    f"[{sev_color}]{a['severity']}[/{sev_color}]"
                )
        console.print(table)
        console.print(f"\n[bold green]✔ Day 2 Complete:[/bold green] Detected [bold red]{len(alerts)}[/bold red] canary trip-wire triggers.")
        return

    table = Table(title="[bold cyan]🍯 Active AWS HoneyToken & Canary Decoy Inventory[/bold cyan]", border_style="cyan")
    table.add_column("Token ID", justify="center", style="dim")
    table.add_column("Canary Type", justify="center", style="magenta")
    table.add_column("Tracked Resource / Canary Key", style="white")
    table.add_column("Deployment Location (Bait)", style="yellow")
    table.add_column("Status", justify="center")

    for t in tokens:
        ident = t["access_key_id"] if t["access_key_id"] else t["resource_identifier"]
        table.add_row(t["token_id"], t["type"], ident, t["deployment_location"], f"[bold green]{t['status']}[/bold green]")
    console.print(table)

if __name__ == "__main__":
    main()
