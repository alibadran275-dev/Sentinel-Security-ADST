#!/usr/bin/env python3
import os
import sys
import re
import argparse
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel

console = Console()

class SentinelDataFlowEngine:
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
        self.TAMPER_KEYS = ["cost", "unitcost", "fee", "discount", "balance", "total", "price", "amt", "quantity", "qty", "role", "admin", "rate"]
        self.TRUST_PATTERNS = [r"db\.lookup", r"await\s+db\.", r"config\.get", r"fetchfromdatabase", r"getpricefromdb"]

    def strip_comments(self, line):
        return re.sub(r"//.*$|/\*.*?\*/", "", line)

    def analyze_data_flow(self, content):
        tainted_vars = {"redirect": set(), "id": set(), "tamper": set()}
        secure_vars = set()
        
        lines = [self.strip_comments(l) for l in content.splitlines()]
        
        # 1. Initial Taint Sources
        for line in lines:
            m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|params|body)\.(\w+)", line)
            if m:
                var_name, source_key = m.groups()
                self._categorize_var(var_name, source_key, tainted_vars)
            
            m = re.search(r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(?:query|params|body)", line)
            if m:
                items = m.group(1).split(",")
                for item in items:
                    item = item.strip()
                    if ":" in item:
                        src, local = item.split(":")
                        self._categorize_var(local.strip(), src.strip(), tainted_vars)
                    else:
                        self._categorize_var(item, item, tainted_vars)

        # 2. Trust Boundary Initial Detection
        for line in lines:
            for pattern in self.TRUST_PATTERNS:
                m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*.*?" + pattern, line, re.IGNORECASE)
                if m: secure_vars.add(m.group(1))

        # 3. Data-Flow Propagation (Iterative)
        changed = True
        while changed:
            changed = False
            for line in lines:
                m = re.search(r"(?:const|let|var|)\s*(\w+)\s*=\s*([^;]+)", line)
                if not m: continue
                target, expression = m.groups()
                target = target.strip()
                
                # Trust propagation
                if any(re.search(r"\b" + re.escape(s) + r"\b", expression) for s in secure_vars):
                    if target not in secure_vars:
                        secure_vars.add(target)
                        changed = True
                    continue
                
                if target in secure_vars: continue

                # Taint propagation
                for cat in tainted_vars:
                    if any(re.search(r"\b" + re.escape(t) + r"\b", expression) for t in tainted_vars[cat]):
                        if target not in tainted_vars[cat]:
                            tainted_vars[cat].add(target)
                            changed = True
        
        return tainted_vars, secure_vars

    def _categorize_var(self, var_name, source_key, vars_found):
        sk, vn = source_key.lower(), var_name.lower()
        if any(k in sk or k in vn for k in ["url", "target", "dest", "to", "path", "redirect"]): vars_found["redirect"].add(var_name)
        if any(k in sk or k in vn for k in ["id", "uid", "uuid", "user_id", "invoiceid"]): vars_found["id"].add(var_name)
        if any(k in sk or k in vn for k in self.TAMPER_KEYS): vars_found["tamper"].add(var_name)

    def scan_content(self, content):
        issues = []
        raw_lines = content.splitlines()
        clean_lines = [self.strip_comments(l) for l in raw_lines]
        tainted_vars, secure_vars = self.analyze_data_flow(content)
        
        for idx, line in enumerate(clean_lines):
            if not line.strip(): continue
            if any(re.search(p, line, re.IGNORECASE) for p in self.TRUST_PATTERNS): continue
            
            line_num = idx + 1
            context = "\n".join(clean_lines[max(0, idx-5):idx])
            
            for cat, cwe_key in [("redirect", "OPEN_REDIRECT"), ("id", "IDOR"), ("tamper", "PARAM_TAMPERING")]:
                for v in tainted_vars[cat]:
                    if v in secure_vars: continue
                    
                    is_sink = False
                    if cat == "redirect" and re.search(self.SINKS["REDIRECT"] + r"\s*\(.*?\b" + re.escape(v) + r"\b", line): is_sink = True
                    elif cat == "id" and re.search(self.SINKS["DATABASE"] + r"\s*\(.*?\b" + re.escape(v) + r"\b", line): is_sink = True
                    elif cat == "tamper" and re.search(r"\b(?:" + "|".join(self.TAMPER_KEYS) + r")\b\s*[:=]\s*.*?\b" + re.escape(v) + r"\b", line, re.IGNORECASE): is_sink = True
                    
                    if is_sink and not self._is_validated(context, line, v, auth_check=(cat=="id")):
                        issues.append(self._create_issue(cwe_key, self._get_name(cwe_key), self._get_sev(cwe_key), line_num, raw_lines[idx], f"Tainted variable '{v}' used in sink."))
        return issues

    def _is_validated(self, context, line, var_name, auth_check=False):
        full = (context + "\n" + line).lower()
        checks = [r"\bwhitelist\b", r"\bisvalid\b", r"\bsafe\b", r"\bvalidate\b", r"\bcheck\b", r"\bincludes\b", r"\bindexof\b", r"\ballowed\b", r"\bverify\b", r"\bauth\b", r"\bpermission\b"]
        if auth_check: checks.extend([r"\breq\.user\b", r"\bsession\b", r"\bowner\b", r"\btenant\b", r"\bdb\.user\b"])
        return any(re.search(p, full) for p in checks)

    def _get_name(self, k): return {"OPEN_REDIRECT": "Open Redirect", "IDOR": "IDOR / Access Control Bypass", "PARAM_TAMPERING": "Parameter Tampering"}[k]
    def _get_sev(self, k): return {"OPEN_REDIRECT": "HIGH", "IDOR": "CRITICAL", "PARAM_TAMPERING": "HIGH"}[k]
    def _create_issue(self, k, n, s, l, sn, d):
        rem = {"OPEN_REDIRECT": "Use allow-list.", "IDOR": "Check ownership.", "PARAM_TAMPERING": "Fetch authoritative values from server-side database."}
        return {"cwe": self.CWE_MAP[k], "type": n, "severity": s, "line": l, "snippet": sn.strip(), "description": d, "remediation": rem[k]}

    def scan_file(self, f):
        if not os.path.isfile(f): return None
        with open(f, 'r', encoding='utf-8', errors='ignore') as f: return self.scan_content(f.read())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", default=".")
    args = parser.parse_args()
    engine = SentinelDataFlowEngine()
    console.print(Panel.fit("[bold red]Sentinel™ Ironclad Data-Flow Engine v4.0[/bold red]", border_style="red"))
    results = {}
    if os.path.isfile(args.target):
        iss = engine.scan_file(args.target)
        if iss: results[args.target] = iss
    else:
        for root, _, files in os.walk(args.target):
            if "node_modules" in root: continue
            for file in files:
                if file.endswith(('.ts', '.js')):
                    p = os.path.join(root, file)
                    iss = engine.scan_file(p)
                    if iss: results[p] = iss
    if not results: console.print("[bold green]✔ Zero vulnerabilities detected.[/bold green]"); return
    for path, issues in results.items():
        tree = Tree(f"[bold white]{path}[/bold white] [red]({len(issues)} flaws)[/red]")
        for iss in issues: tree.add(f"[bold red]{iss['severity']}[/bold red] {iss['type']} ({iss['cwe']}) @ Line {iss['line']}").add(f"Sink: {iss['snippet']}")
        console.print(tree)

if __name__ == "__main__": main()
