#!/usr/bin/env python3
import os
import sys
import re
import argparse
from rich.console import Console
from rich.tree import Tree
from rich.table import Table
from rich.panel import Panel

console = Console()

class SentinelScanner:
    def __init__(self):
        # Advanced Regex Patterns
        self.rules = [
            {
                "id": "CWE-601",
                "type": "Open Redirect",
                "severity": "HIGH",
                # Matches redirects using request inputs without validation
                "pattern": r"(?:res\.redirect|window\.location|location\.href|window\.open)\s*\(\s*(?:req\.(?:query|params|body)|url|target|dest|to|path|redirect_uri).*?\)",
                "negative_lookahead": r"whitelist|safe|isValid|validateUrl|checkOrigin",
                "description": "Unvalidated user-controlled input is used as a redirection target.",
                "remediation": "Implement an allow-list of approved URLs or use relative paths only."
            },
            {
                "id": "CWE-639",
                "type": "IDOR (Insecure Direct Object Reference)",
                "severity": "CRITICAL",
                # Matches DB lookups using request IDs without session context
                "pattern": r"(?:findById|select|db\.query|findOne|collection\(.*?\)\.doc)\s*\(\s*(?:req\.(?:params|query|body)\.(?:id|uid|user_id|uuid)).*?\)",
                "negative_lookahead": r"req\.user|session|owner|tenant|auth|permission",
                "description": "Sensitive resource accessed via user-controlled ID without ownership verification.",
                "remediation": "Validate that the authenticated user has permission to access the requested resource ID."
            },
            {
                "id": "CWE-639", # Corrected from CWE-434 to CWE-639 (Insecure Direct Object Reference / IDOR) or CWE-472
                "type": "Parameter Tampering",
                "severity": "HIGH",
                # Matches critical fields being assigned directly from request
                "pattern": r"(?:price|amount|quantity|role|admin|permission|is_admin|status)\s*=\s*req\.(?:body|query|params)\.(?:price|amount|quantity|role|admin|permission|is_admin|status)",
                "negative_lookahead": r"verifyPrice|db\.lookup|config\.get|calculate|validate",
                "description": "Critical business logic parameters are accepted directly from client-side requests.",
                "remediation": "Retrieve critical values (like prices or roles) from a trusted server-side source or database."
            }
        ]

    def scan_content(self, content):
        issues = []
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            line_num = idx + 1
            for rule in self.rules:
                if re.search(rule["pattern"], line):
                    # Check for security controls (negative lookahead)
                    if not re.search(rule["negative_lookahead"], line, re.IGNORECASE):
                        issues.append({
                            "cwe": rule["id"],
                            "type": rule["type"],
                            "severity": rule["severity"],
                            "line": line_num,
                            "snippet": line.strip(),
                            "description": rule["description"],
                            "remediation": rule["remediation"]
                        })
        return issues

    def scan_file(self, filepath):
        if not os.path.isfile(filepath):
            console.print(f"[bold red]Error:[/bold red] File not found: {filepath}")
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.scan_content(content)
        except Exception as e:
            console.print(f"[bold red]Error reading {filepath}:[/bold red] {str(e)}")
            return None

    def scan_directory(self, dirpath):
        results = {}
        for root, _, files in os.walk(dirpath):
            if any(x in root for x in ["node_modules", ".git", "dist", "venv", "__pycache__"]):
                continue
            for file in files:
                if file.endswith(('.ts', '.js', '.tsx', '.jsx', '.py')):
                    path = os.path.join(root, file)
                    issues = self.scan_file(path)
                    if issues:
                        results[path] = issues
        return results

def main():
    parser = argparse.ArgumentParser(description="Sentinel™ Real-Time Code Analyzer CLI")
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    args = parser.parse_args()

    scanner = SentinelScanner()
    target = args.target

    console.print(Panel.fit("[bold cyan]Sentinel™ Security Engine v2.5[/bold cyan]\n[dim]Advanced Regex-Based Static Analysis[/dim]", border_style="blue"))

    if os.path.isfile(target):
        issues = scanner.scan_file(target)
        all_results = {target: issues} if issues else {}
    else:
        all_results = scanner.scan_directory(target)

    if not all_results:
        console.print("[bold green]✔ No vulnerabilities detected by heuristic engine.[/bold green]")
        return

    for path, issues in all_results.items():
        tree = Tree(f"[bold white]{path}[/bold white] [red]({len(issues)} issues found)[/red]")
        for iss in issues:
            severity_color = "red" if iss["severity"] in ["CRITICAL", "HIGH"] else "yellow"
            node = tree.add(f"[{severity_color}]{iss['severity']}[/{severity_color}] [bold]{iss['type']}[/bold] ([dim]{iss['cwe']}[/dim]) at Line {iss['line']}")
            node.add(f"Snippet: [italic]{iss['snippet'][:100]}[/italic]")
            node.add(f"Description: {iss['description']}")
            node.add(f"Remediation: [green]{iss['remediation']}[/green]")
        console.print(tree)
        console.print("-" * 80)

if __name__ == "__main__":
    main()
