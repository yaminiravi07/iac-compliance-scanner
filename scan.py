"""Scan Terraform for security misconfigurations mapped to ISO 27001 and BSI.

Usage:
    python scan.py examples/insecure.tf
    python scan.py examples/ --html report.html --json report.json
"""
import argparse
import sys

from rich.console import Console
from rich.table import Table

from scanner.parser import load_resources
from scanner.report import summarise, write_html, write_json
from scanner.rules import run_rules

SEVERITY_COLOUR = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def parse_args():
    parser = argparse.ArgumentParser(description="IaC compliance scanner for Terraform")
    parser.add_argument("target", help="Terraform file or folder to scan")
    parser.add_argument("--html", metavar="FILE", help="also write an HTML report")
    parser.add_argument("--json", metavar="FILE", help="also write a JSON report")
    return parser.parse_args()


def print_table(console, findings):
    table = Table(show_lines=True)
    for column in ("Severity", "Rule", "Resource", "Problem", "ISO 27001", "BSI"):
        table.add_column(column)
    for f in findings:
        colour = SEVERITY_COLOUR[f.severity]
        table.add_row(f"[{colour}]{f.severity}[/{colour}]", f.rule_id, f.resource,
                      f.message, f.iso27001, f.bsi)
    console.print(table)


def main():
    args = parse_args()
    console = Console()

    resources = load_resources(args.target)
    findings = run_rules(resources)

    console.print(f"\nScanned [bold]{len(resources)}[/bold] resources, "
                  f"found [bold red]{len(findings)}[/bold red] issues\n")

    if findings:
        print_table(console, findings)
        counts = summarise(findings)
        console.print(f"[red]HIGH: {counts['HIGH']}[/red]   [yellow]MEDIUM: {counts['MEDIUM']}[/yellow]   "
                      f"[cyan]LOW: {counts['LOW']}[/cyan]\n")
    else:
        console.print("[bold green]No issues found.[/bold green]")

    if args.json:
        write_json(findings, args.target, len(resources), args.json)
        console.print(f"JSON report written to [bold]{args.json}[/bold]")
    if args.html:
        write_html(findings, args.target, len(resources), args.html)
        console.print(f"HTML report written to [bold]{args.html}[/bold]")

    # Exit code 1 means "issues found", so a CI pipeline can fail the build.
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()