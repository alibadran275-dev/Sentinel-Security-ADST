#!/usr/bin/env python3
"""
Sentinel: Application Security Code Sandbox & Attack Simulation Tree (ADST)
A comprehensive security training lab for vulnerability analysis and remediation.
"""

import os
import sys
import urllib.parse
from typing import Dict, Any, List

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.console import Console
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.table import Table
except ImportError:
    print("Error: Please install required dependencies: pip install rich requests")
    sys.exit(1)

console = Console()
TARGET_DIR = "./target_code"

VULNERABLE_CODE_TEMPLATES = {
    "auth.ts": """/**
 * Authentication Handler - Vulnerable Implementation
 * Training Lab: OWASP Top 10 Security Issues
 */

interface UserProfile {
  id: string;
  username: string;
  email: string;
  role: string;
}

const USER_DATABASE: Record<string, UserProfile> = {
  "user_1001": { id: "user_1001", username: "alice", email: "alice@company.com", role: "standard" },
  "user_1002": { id: "user_1002", username: "bob", email: "bob@company.com", role: "standard" },
  "admin_9999": { id: "admin_9999", username: "admin", email: "admin@company.com", role: "administrator" },
};

export class AuthController {
  
  /**
   * VULNERABILITY: Insecure Direct Object Reference (IDOR)
   * CWE-639: Authorization Bypass Through User-Controlled Key
   */
  async getUserProfile(req: any, res: any) {
    const { userId } = req.query;
    
    if (!userId) {
      return res.status(400).json({ error: "Missing userId parameter" });
    }
    
    const profile = USER_DATABASE[userId];
    if (!profile) {
      return res.status(404).json({ error: "User profile not found" });
    }
    
    return res.json({ status: "success", data: profile });
  }

  /**
   * VULNERABILITY: Open Redirect
   * CWE-601: URL Redirection to Untrusted Site
   */
  async handleLogout(req: any, res: any) {
    const { redirectTo } = req.query;
    
    console.log("Session destroyed.");
    
    if (redirectTo) {
      return res.redirect(redirectTo);
    }
    
    return res.redirect("/dashboard");
  }
}
""",
    "payments.ts": """/**
 * Checkout Handler - Vulnerable Implementation
 * Training Lab: Client-Side Validation Bypass
 */

export class CheckoutController {
  
  /**
   * VULNERABILITY: Parameter Tampering - Price Manipulation
   * CWE-434: Unrestricted Upload of File with Dangerous Type
   */
  async processCheckout(req: any, res: any) {
    const { itemId, quantity, singleUnitPrice, currency } = req.body;
    
    const totalAmount = quantity * singleUnitPrice;
    
    console.log(`Charged: ${totalAmount} ${currency} for item ${itemId}`);
    return res.json({ success: true, total: totalAmount });
  }
}
"""
}

VULNERABILITY_DATABASE = {
    "IDOR": {
        "name": "Insecure Direct Object Reference",
        "severity": "CRITICAL",
        "score": "9.1/10",
        "description": "User profile queries based on unvalidated client input without session verification",
        "attack_steps": [
            "Attacker logs in as user_1002",
            "Attacker modifies URL parameter from user_1002 to admin_9999",
            "System returns admin profile without authorization check",
            "Attacker gains full administrative access"
        ],
        "remediation": "Validate userId against req.session.userId before database queries"
    },
    "OPEN_REDIRECT": {
        "name": "Open Redirection Vulnerability",
        "severity": "HIGH",
        "score": "7.4/10",
        "description": "Server redirects to user-supplied URLs without domain validation",
        "attack_steps": [
            "Attacker crafts phishing email with redirect link",
            "Link redirects victim to malicious domain clone",
            "User enters credentials on fake login page",
            "Attacker captures credentials"
        ],
        "remediation": "Implement whitelist of allowed redirect domains"
    },
    "PRICE_TAMPERING": {
        "name": "Parameter Tampering - Price Manipulation",
        "severity": "CRITICAL",
        "score": "9.3/10",
        "description": "System trusts client-side price values without server-side verification",
        "attack_steps": [
            "Attacker modifies HTML form price field to $0.01",
            "System processes tampered price on checkout",
            "Payment gateway charges minimal amount",
            "Attacker completes fraud transaction"
        ],
        "remediation": "Fetch actual prices from server-side database, never trust client input"
    }
}


def initialize_sandbox():
    """Create sandbox environment and generate vulnerable code files."""
    console.print("\n[bold cyan]Initializing Sentinel sandbox workspace...[/bold cyan]")
    
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)
        console.print(f"[green]✓ Created sandbox directory: {TARGET_DIR}[/green]")
    else:
        console.print(f"[yellow]ℹ Sandbox directory already exists[/yellow]")

    for filename, code_content in VULNERABLE_CODE_TEMPLATES.items():
        file_path = os.path.join(TARGET_DIR, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code_content)
        console.print(f"[green]✓ Generated: {file_path}[/green]")


def download_remote_file(url: str, output_path: str) -> bool:
    """Download remote files to sandbox with progress tracking."""
    console.print(f"\n[cyan]Downloading from URL:[/cyan]")
    console.print(f"  [blue]{url}[/blue]")
    console.print(f"  [dim]Destination: {output_path}[/dim]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Downloading...", total=100)
            
            if requests:
                response = requests.get(url, stream=True, timeout=15)
                response.raise_for_status()
                total_size = int(response.headers.get('content-length', 0))
                
                written_size = 0
                with open(output_path, 'wb') as file:
                    for chunk in response.iter_content(chunk_size=4096):
                        if chunk:
                            file.write(chunk)
                            written_size += len(chunk)
                            if total_size > 0:
                                percent = int((written_size / total_size) * 100)
                                progress.update(task, completed=percent)
            else:
                import urllib.request
                urllib.request.urlretrieve(url, output_path)
                progress.update(task, completed=100)

        console.print(f"[green]✓ Download complete: {output_path}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/red]")
        return False


def analyze_code_file(file_path: str) -> Dict[str, Any]:
    """Scan code file for known vulnerabilities."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    findings = {
        "filename": os.path.basename(file_path),
        "vulnerabilities": []
    }

    if "userId" in content and "USER_DATABASE" in content:
        findings["vulnerabilities"].append("IDOR")
    
    if "redirectTo" in content or "redirect(" in content:
        findings["vulnerabilities"].append("OPEN_REDIRECT")
    
    if "singleUnitPrice" in content and "totalAmount" in content:
        findings["vulnerabilities"].append("PRICE_TAMPERING")

    return findings


def display_attack_simulation_tree():
    """Display comprehensive Attack Simulation Tree (ADST)."""
    console.print("\n" + "="*80)
    console.print("[bold cyan]SENTINEL ATTACK SIMULATION TREE (ADST)[/bold cyan]")
    console.print("="*80)

    if not os.path.exists(TARGET_DIR):
        console.print("[red]✗ Sandbox directory not found[/red]")
        return

    root_tree = Tree("[cyan bold]Sentinel Workspace[/cyan bold]")
    
    files_list = [f for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]
    
    for filename in files_list:
        file_path = os.path.join(TARGET_DIR, filename)
        file_size = round(os.path.getsize(file_path) / 1024, 2)
        file_node = root_tree.add(f"[bold white]📄 {filename}[/bold white] ({file_size} KB)")

        audit_report = analyze_code_file(file_path)
        
        if not audit_report["vulnerabilities"]:
            file_node.add("[green]✓ No known vulnerabilities detected[/green]")
        else:
            vulns_node = file_node.add("[bold red]⚠ VULNERABILITIES DETECTED[/bold red]")
            
            for vuln_key in audit_report["vulnerabilities"]:
                if vuln_key in VULNERABILITY_DATABASE:
                    vuln = VULNERABILITY_DATABASE[vuln_key]
                    vuln_item = vulns_node.add(
                        f"[bold yellow]{vuln['name']} ({vuln['severity']})[/bold yellow]"
                    )
                    vuln_item.add(f"[dim]{vuln['description']}[/dim]")
                    
                    attack_tree = vuln_item.add("[bold red]Attack Path[/bold red]")
                    for step in vuln["attack_steps"]:
                        attack_tree.add(f"[red]{step}[/red]")
                    
                    fix_tree = vuln_item.add("[bold green]Remediation[/bold green]")
                    fix_tree.add(f"[green]{vuln['remediation']}[/green]")

    console.print(root_tree)
    console.print("="*80)


def display_source_code(file_path: str):
    """Display source code with syntax highlighting."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()
        syntax = Syntax(code, "typescript", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title=f"Source: {os.path.basename(file_path)}", expand=False))
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")


def main():
    """Main CLI interface."""
    console.print(Panel(
        "[bold cyan]SENTINEL[/bold cyan]\n"
        "[dim]Application Security Code Sandbox & Attack Simulation Tree[/dim]",
        border_style="cyan"
    ))

    initialize_sandbox()
    display_attack_simulation_tree()

    while True:
        console.print("\n[bold]Menu:[/bold]")
        console.print("  [1] Refresh vulnerability analysis")
        console.print("  [2] Download external file")
        console.print("  [3] View source code")
        console.print("  [4] Exit")
        
        choice = input("\nSelect option [1-4]: ").strip()
        
        if choice == "1":
            display_attack_simulation_tree()
        elif choice == "2":
            url = input("Enter file URL: ").strip()
            if not url:
                continue
            default_name = os.path.basename(urllib.parse.urlparse(url).path) or "downloaded_file.ts"
            filename = input(f"Output filename [{default_name}]: ").strip() or default_name
            output_dest = os.path.join(TARGET_DIR, filename)
            download_remote_file(url, output_dest)
            display_attack_simulation_tree()
        elif choice == "3":
            files_list = os.listdir(TARGET_DIR)
            if not files_list:
                console.print("[yellow]No files in sandbox[/yellow]")
                continue
            console.print("\nSelect file:")
            for idx, f in enumerate(files_list):
                console.print(f"  [{idx}] {f}")
            try:
                sel_idx = int(input("Enter index: "))
                selected_file = files_list[sel_idx]
                display_source_code(os.path.join(TARGET_DIR, selected_file))
            except Exception as ex:
                console.print(f"[red]Invalid selection: {ex}[/red]")
        elif choice == "4" or choice.lower() == "q":
            console.print("[cyan]Exiting Sentinel. Stay secure![/cyan]")
            break
        else:
            console.print("[red]Invalid option[/red]")


if __name__ == "__main__":
    main()
