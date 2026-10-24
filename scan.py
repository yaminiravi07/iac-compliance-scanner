"""Entry point: python scan.py <file-or-folder>"""
import sys

from rich import print

from scanner.parser import load_resources


def main():
    if len(sys.argv) != 2:
        print("Usage: python scan.py <terraform file or folder>")
        sys.exit(1)

    resources = load_resources(sys.argv[1])
    print(f"[bold]Found {len(resources)} resources[/bold]\n")
    for r in resources:
        print(f"[cyan]{r['type']}[/cyan].{r['name']}  ({r['file']})")
        print(r["config"])
        print()


if __name__ == "__main__":
    main()