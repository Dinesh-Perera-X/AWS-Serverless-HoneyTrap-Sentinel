import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.token_manager import HoneyTokenManager
from generators.seeder import TrapSeeder

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
    parser.add_argument("--generate", choices=["IAM_KEY", "S3_TRAP"], help="Generate a new specific canary decoy")
    parser.add_argument("--target", help="Resource name or identifier for new canary")
    parser.add_argument("--location", help="Deployment location notes", default="Internal repo")
    args = parser.parse_args()

    display_banner()

    if args.seed:
        TrapSeeder.seed_initial_traps()
        console.print("[bold green]✔ Initial enterprise decoy traps seeded successfully into registry.[/bold green]\n")

    if args.generate:
        t_type = "IAM_ACCESS_KEY" if args.generate == "IAM_KEY" else "DECOY_S3_BUCKET"
        target_name = args.target or ("canary-key-user" if t_type == "IAM_ACCESS_KEY" else "decoy-data-bucket")
        new_token = HoneyTokenManager.register_token(t_type, target_name, args.location)
        console.print(f"[bold green]✔ Successfully Armed New Canary Token:[/bold green] [cyan]{new_token['token_id']}[/cyan]")
        if new_token["access_key_id"]:
            console.print(f"  • Canary Access Key: [bold yellow]{new_token['access_key_id']}[/bold yellow]")
        console.print()

    registry = HoneyTokenManager.load_registry()
    tokens = registry.get("tokens", [])

    table = Table(title="[bold cyan]🍯 Active AWS HoneyToken & Canary Decoy Inventory[/bold cyan]", border_style="cyan")
    table.add_column("Token ID", justify="center", style="dim")
    table.add_column("Canary Type", justify="center", style="magenta")
    table.add_column("Tracked Resource / Canary Key", style="white")
    table.add_column("Deployment Location (Bait)", style="yellow")
    table.add_column("Status", justify="center")

    if not tokens:
        table.add_row("-", "-", "No active traps armed. Run with --seed to populate.", "-", "[dim]EMPTY[/dim]")
    else:
        for t in tokens:
            ident = t["access_key_id"] if t["access_key_id"] else t["resource_identifier"]
            table.add_row(
                t["token_id"],
                t["type"],
                ident,
                t["deployment_location"],
                f"[bold green]{t['status']}[/bold green]"
            )

    console.print(table)
    console.print(f"\n[bold green]✔ Day 1 Complete:[/bold green] Honeytoken registry operational ({len(tokens)} armed decoys).")

if __name__ == "__main__":
    main()
