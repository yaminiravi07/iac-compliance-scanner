"""Entry point: python scan.py <file-or-folder>"""
import sys

from rich.console import Console
from rich.table import Table

from scanner.parser import load_resources
from scanner.rules import run_rules

SEVERITY_COLOUR = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def main():
    console = Console()
    if len(sys.argv) != 2:
        console.print("Usage: python scan.py <terraform file or folder>")
        sys.exit(1)

    resources = load_resources(sys.argv[1])
    findings = run_rules(resources)

    console.print(f"\nScanned [bold]{len(resources)}[/bold] resources, "
                  f"found [bold red]{len(findings)}[/bold red] issues\n")

    if not findings:
        console.print("[bold green]No issues found.[/bold green]")
        sys.exit(0)

    table = Table(show_lines=True)
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Resource")
    table.add_column("Problem")
    table.add_column("ISO 27001")
    table.add_column("BSI")
    for f in findings:
        colour = SEVERITY_COLOUR[f.severity]
        table.add_row(f"[{colour}]{f.severity}[/{colour}]", f.rule_id, f.resource,
                      f.message, f.iso27001, f.bsi)
    console.print(table)

    counts = {sev: sum(f.severity == sev for f in findings) for sev in SEVERITY_COLOUR}
    console.print(f"[red]HIGH: {counts['HIGH']}[/red]   [yellow]MEDIUM: {counts['MEDIUM']}[/yellow]   "
                  f"[cyan]LOW: {counts['LOW']}[/cyan]\n")

    # Exit code 1 means "issues found", so a CI pipeline can fail the build.
    sys.exit(1)


if __name__ == "__main__":
    main()