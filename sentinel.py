#!/usr/bin/env python3
import os
import sys
import re
import argparse
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel

console = Console()

class HardenedSentinelEngine:
    def __init__(self):
        self.CWE_MAP = {
            "OPEN_REDIRECT": "CWE-601",
            "IDOR": "CWE-639",
            "PARAM_TAMPERING": "CWE-472"
        }
        self.SINKS = {
            "REDIRECT": r"(?:res\.redirect|window\.location|location\.href|window\.open)",
            "DATABASE": r"(?:findById|select|db\.query|findOne|collection\(.*?\)\.doc|db\.\w+)",
        }
        self.TAMPER_KEYS = ["price", "amount", "amt", "quantity", "qty", "role", "admin", "is_admin", "permission", "status"]

    def strip_comments(self, line):
        """Remove single-line and inline comments for analysis."""
        return re.sub(r"//.*$|/\*.*?\*/", "", line)

    def extract_variables(self, content):
        vars_found = {"redirect": set(), "id": set(), "tamper": set()}
        # Clean content for variable extraction
        clean_content = "\n".join([self.strip_comments(l) for l in content.splitlines()])
        
        # Standard: const x = req.query.y;
        for match in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|params|body)\.(\w+)", clean_content):
            self._categorize_var(match.group(1), match.group(2), vars_found)
            
        # Destructuring: const { x, y } = req.body;
        for match in re.finditer(r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(?:query|params|body)", clean_content):
            for item in match.group(1).split(","):
                item = item.strip()
                if ":" in item:
                    src, local = item.split(":")
                    self._categorize_var(local.strip(), src.strip(), vars_found)
                else:
                    self._categorize_var(item, item, vars_found)
        return vars_found

    def _categorize_var(self, var_name, source_key, vars_found):
        sk, vn = source_key.lower(), var_name.lower()
        if any(k in sk or k in vn for k in ["url", "target", "dest", "to", "path", "redirect"]):
            vars_found["redirect"].add(var_name)
        if any(k in sk or k in vn for k in ["id", "uid", "uuid", "user_id"]):
            vars_found["id"].add(var_name)
        if any(k in sk or k in vn for k in self.TAMPER_KEYS):
            vars_found["tamper"].add(var_name)

    def scan_content(self, content):
        issues = []
        raw_lines = content.splitlines()
        # Pre-clean lines to ignore comments during sink detection
        clean_lines = [self.strip_comments(l) for l in raw_lines]
        vars_map = self.extract_variables(content)
        
        for idx, line in enumerate(clean_lines):
            if not line.strip(): continue
            line_num = idx + 1
            context = "\n".join(clean_lines[max(0, idx-5):idx])
            
            # Open Redirect
            for v in vars_map["redirect"]:
                if re.search(self.SINKS["REDIRECT"] + r"\s*\(.*?\b" + re.escape(v) + r"\b", line):
                    if not self._is_validated(context, line, v):
                        issues.append(self._create_issue("OPEN_REDIRECT", "Open Redirect", "HIGH", line_num, raw_lines[idx], f"Unvalidated '{v}' used in redirect."))

            # IDOR
            for v in vars_map["id"]:
                if re.search(self.SINKS["DATABASE"] + r"\s*\(.*?\b" + re.escape(v) + r"\b", line):
                    if not self._is_validated(context, line, v, auth_check=True):
                        issues.append(self._create_issue("IDOR", "IDOR / Access Control Bypass", "CRITICAL", line_num, raw_lines[idx], f"DB query using user-controlled ID '{v}'."))

            # Parameter Tampering
            for v in vars_map["tamper"]:
                if re.search(r"\b(?:price|amount|amt|role|admin|status|permission)\b\s*[:=]\s*.*?\b" + re.escape(v) + r"\b", line, re.IGNORECASE):
                    if not self._is_validated(context, line, v):
                        issues.append(self._create_issue("PARAM_TAMPERING", "Parameter Tampering", "HIGH", line_num, raw_lines[idx], f"Critical field assigned from '{v}'."))

        return issues

    def _is_validated(self, context, line, var_name, auth_check=False):
        full = (context + "\n" + line).lower()
        # Use word boundaries to avoid matching "checkout" as "check"
        checks = [r"\bwhitelist\b", r"\bisvalid\b", r"\bsafe\b", r"\bvalidate\b", r"\bcheck\b", r"\bincludes\b", r"\bindexof\b", r"\ballowed\b", r"\bverify\b", r"\bauth\b", r"\bpermission\b"]
        if auth_check: 
            checks.extend([r"\breq\.user\b", r"\bsession\b", r"\bowner\b", r"\btenant\b", r"\bdb\.user\b"])
        return any(re.search(p, full) for p in checks)

    def _create_issue(self, k, n, s, l, sn, d):
        rem = {"OPEN_REDIRECT": "Use allow-list.", "IDOR": "Check ownership.", "PARAM_TAMPERING": "Fetch from DB."}
        return {"cwe": self.CWE_MAP[k], "type": n, "severity": s, "line": l, "snippet": sn.strip(), "description": d, "remediation": rem[k]}

    def scan_file(self, f):
        if not os.path.isfile(f): return None
        with open(f, 'r', encoding='utf-8', errors='ignore') as f: return self.scan_content(f.read())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default=".")
    args = parser.parse_args()
    engine = HardenedSentinelEngine()
    console.print(Panel.fit("[bold red]Sentinel™ Hardened Security Core v3.0[/bold red]", border_style="red"))
    target = args.target
    results = {}
    if os.path.isfile(target):
        iss = engine.scan_file(target)
        if iss: results[target] = iss
    else:
        for root, _, files in os.walk(target):
            if "node_modules" in root: continue
            for file in files:
                if file.endswith(('.ts', '.js')):
                    p = os.path.join(root, file)
                    iss = engine.scan_file(p)
                    if iss: results[p] = iss
    for path, issues in results.items():
        tree = Tree(f"[bold white]{path}[/bold white] [red]({len(issues)} flaws)[/red]")
        for iss in issues:
            node = tree.add(f"[bold red]{iss['severity']}[/bold red] {iss['type']} ({iss['cwe']}) @ Line {iss['line']}")
            node.add(f"Sink: {iss['snippet']}")
        console.print(tree)

if __name__ == "__main__": main()
