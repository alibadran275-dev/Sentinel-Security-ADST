import os
import sys
import re

print("==========================================================================")
print(" Sentinel™ Real-Time CLI Code Analyzer Init Check")
print("==========================================================================")

class RichMock:
    class Console:
        def print(self, *args, **kwargs):
            import builtins
            builtins.print(*args, **kwargs)

try:
    from rich.console import Console
    from rich.tree import Tree
    from rich import print as rprint
except ImportError:
    # Handle environment where Rich library is not immediately available natively on client
    # fallback elegantly to simple formatted terminal trees
    class Tree:
        def __init__(self, label):
            self.label = label
            self.children = []
        def add(self, label):
            node = Tree(label)
            self.children.append(node)
            return node
    
    def rprint(text):
        print(text)
    
    Console = RichMock.Console

console = Console()

def run_local_heuristics(filepath):
    issues = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            lt = line.strip()
            
            # Open Redirect detection
            if ("redirect" in lt or "window.location" in lt or "location.href" in lt) and \
               ("query" in lt or "params" in lt or "url" in lt or "target" in lt) and \
               not any(w in lt for w in ["whitelist", "safe", "isValid"]):
                issues.append({
                    "type": "Open Redirect",
                    "severity": "[bold red]HIGH[/bold red]",
                    "line": line_num,
                    "snippet": lt,
                    "desc": "Unvalidated redirect target using request values"
                })
                
            # IDOR detection
            if any(k in lt for k in ["findById", "select", "db.query", "findOne"]) and \
               any(p in lt for p in ["params.id", "query.id", "body.id"]) and \
               not any(s in lt for s in ["session", "owner", "tenant", "req.user"]):
                issues.append({
                    "type": "IDOR",
                    "severity": "[bold red]CRITICAL[/bold red]",
                    "line": line_num,
                    "snippet": lt,
                    "desc": "Critical Direct database lookup with dynamic input parameter without current user checks"
                })
                
            # Parameter Tampering detection
            if any(p in lt for p in ["price", "amount", "quantity", "role", "admin"]) and \
               any(r in lt for r in ["req.body", "req.query", "req.params"]) and \
               not any(v in lt for v in ["verifyPrice", "db."]):
                issues.append({
                    "type": "Parameter Tampering",
                    "severity": "[bold yellow]MEDIUM[/bold yellow]",
                    "line": line_num,
                    "snippet": lt,
                    "desc": "Critical parameter states (role/payment values) mapped straight from query variables"
                })
    except Exception as e:
        rprint(f"[red]Error analyzing {filepath}: {str(e)}[/red]")
    return issues

def scan_directory(path_target):
    rprint(f"\n[bold cyan]Starting Sentinel™ Fast Scan for: {path_target}[/bold cyan]")
    if not os.path.exists(path_target):
        rprint("[bold red]Error: Path target does not exist.[/bold red]")
        return
        
    all_issues = {}
    if os.path.isfile(path_target):
        issues = run_local_heuristics(path_target)
        if issues:
            all_issues[path_target] = issues
    else:
        for root, dirs, files in os.walk(path_target):
            # Skip noise folders
            if any(exclude in root for exclude in ["node_modules", ".git", "dist", "env", "venv"]):
                continue
            for file in files:
                if file.endswith(('.ts', '.js', '.tsx', '.jsx', '.py', '.rb', '.go', '.java')):
                    fullpath = os.path.join(root, file)
                    issues = run_local_heuristics(fullpath)
                    if issues:
                        all_issues[fullpath] = issues

    if not all_issues:
        rprint("[bold green]✔ Scan complete. Sentinel™ detected 0 fast-heuristic code threats![/bold green]\n")
        return

    rprint(f"[bold red]Found vulnerabilities across {len(all_issues)} file(s). Rendering ADST Security Trees:[/bold red]\n")
    
    for filepath, issues in all_issues.items():
        tree = Tree(f"[bold white]{os.path.basename(filepath)}[/bold white] ({len(issues)} flaws)")
        for iss in issues:
            child = tree.add(f"[{iss['severity']}] {iss['type']} at Line {iss['line']}")
            child.add(f"Snippet: [dim]{iss['snippet'][:60]}[/dim]")
            child.add(f"Flaw explanation: {iss['desc']}")
        
        # Rendering
        if hasattr(tree, 'children') and not isinstance(Console(), RichMock.Console):
            # If using actual Tree print class
            console.print(tree)
        else:
            # Elegant text-fallback tree representation manually
            print(f"└── {tree.label}")
            for node in tree.children:
                print(f"    ├── {node.label}")
                for sub in node.children:
                    print(f"    │   └── {sub.label}")
        print("-" * 50)

if __name__ == "__main__":
    target = "." if len(sys.argv) < 2 else sys.argv[1]
    scan_directory(target)
