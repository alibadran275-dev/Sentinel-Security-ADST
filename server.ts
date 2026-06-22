import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// --- Ironclad Data-Flow Engine ---

interface Issue {
  id: string;
  cwe: string;
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

const CWE_MAP = {
  OPEN_REDIRECT: "CWE-601",
  IDOR: "CWE-639",
  PARAM_TAMPERING: "CWE-472"
};

const TAMPER_KEYS = ["cost", "unitcost", "fee", "discount", "balance", "total", "price", "amt", "quantity", "qty", "role", "admin"];
const TRUST_PATTERNS = [/db\.lookup/i, /await\s+db\./i, /config\.get/i, /fetchfromdatabase/i, /getpricefromdb/i];

function runIroncladScan(code: string): Issue[] {
  const issues: Issue[] = [];
  const rawLines = code.split("\n");
  const cleanLines = rawLines.map(l => l.replace(/\/\/.*$|\/\*.*?\*\//g, ""));
  
  const taintedVars: Record<string, Set<string>> = {
    redirect: new Set(),
    id: new Set(),
    tamper: new Set()
  };
  const secureVars = new Set<string>();

  // 1. Initial Taint Sources
  cleanLines.forEach(line => {
    const stdMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|params|body)\.(\w+)/);
    if (stdMatch) {
      const [_, varName, sourceKey] = stdMatch;
      categorizeVar(varName, sourceKey, taintedVars);
    }

    const destructMatch = line.match(/(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(?:query|params|body)/);
    if (destructMatch) {
      destructMatch[1].split(",").forEach(item => {
        const [src, local] = item.includes(":") ? item.split(":").map(i => i.trim()) : [item.trim(), item.trim()];
        categorizeVar(local, src, taintedVars);
      });
    }

    TRUST_PATTERNS.forEach(pattern => {
      const trustMatch = line.match(new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*=\\s*.*?${pattern.source}`, "i"));
      if (trustMatch) secureVars.add(trustMatch[1]);
    });
  });

  function categorizeVar(name: string, key: string, map: any) {
    const sk = key.toLowerCase();
    const vn = name.toLowerCase();
    if (["url", "target", "dest", "to", "path", "redirect"].some(k => sk.includes(k) || vn.includes(k))) map.redirect.add(name);
    if (["id", "uid", "uuid", "user_id", "invoiceid"].some(k => sk.includes(k) || vn.includes(k))) map.id.add(name);
    if (TAMPER_KEYS.some(k => sk.includes(k) || vn.includes(k))) map.tamper.add(name);
  }

  // 2. Transitive Propagation
  let changed = true;
  while (changed) {
    changed = false;
    cleanLines.forEach(line => {
      const assignMatch = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(\w+)(?:\s*;|\s*$)/);
      if (assignMatch) {
        const [_, target, source] = assignMatch;
        if (secureVars.has(source) && !secureVars.has(target)) {
          secureVars.add(target);
          changed = true;
        }
        Object.keys(taintedVars).forEach(cat => {
          if (taintedVars[cat].has(source) && !taintedVars[cat].has(target) && !secureVars.has(target)) {
            taintedVars[cat].add(target);
            changed = true;
          }
        });
      }
    });
  }

  // 3. Sink Detection
  cleanLines.forEach((line, index) => {
    const lineNum = index + 1;
    const context = cleanLines.slice(Math.max(0, index - 5), index).join("\n").toLowerCase();
    const fullContext = (context + "\n" + line).toLowerCase();
    
    const isValidated = (auth = false) => {
      const patterns = [/\bwhitelist\b/, /\bisvalid\b/, /\bsafe\b/, /\bvalidate\b/, /\bcheck\b/, /\bincludes\b/, /\bindexof\b/, /\ballowed\b/, /\bverify\b/, /\bauth\b/, /\bpermission\b/];
      if (auth) patterns.push(...[/\breq\.user\b/, /\bsession\b/, /\bowner\b/, /\btenant\b/, /\bdb\.user\b/]);
      return patterns.some(p => p.test(fullContext));
    };

    taintedVars.redirect.forEach(v => {
      if (secureVars.has(v)) return;
      if (new RegExp(`(?:res\\.redirect|window\\.location|location\\.href|window\\.open)\\s*\\(.*?\\b${v}\\b`).test(line) && !isValidated()) {
        issues.push(createIssue("OPEN_REDIRECT", "Open Redirect", "HIGH", lineNum, rawLines[index], `Tainted variable '${v}' used in redirect.`));
      }
    });

    taintedVars.id.forEach(v => {
      if (secureVars.has(v)) return;
      if (new RegExp(`(?:findById|select|db\\.query|findOne|collection\\(.*?\\)\\.doc|db\\.\\w+)\\s*\\(.*?\\b${v}\\b`).test(line) && !isValidated(true)) {
        issues.push(createIssue("IDOR", "IDOR / Access Control Bypass", "CRITICAL", lineNum, rawLines[index], `Tainted ID '${v}' used in DB query.`));
      }
    });

    taintedVars.tamper.forEach(v => {
      if (secureVars.has(v)) return;
      const tamperPattern = new RegExp(`\\b(?:${TAMPER_KEYS.join("|")})\\b\\s*[:=]\\s*.*?\\b${v}\\b`, "i");
      if (tamperPattern.test(line) && !isValidated()) {
        issues.push(createIssue("PARAM_TAMPERING", "Parameter Tampering", "HIGH", lineNum, rawLines[index], `Critical field assigned from tainted variable '${v}'.`));
      }
    });
  });

  return issues;
}

function createIssue(typeKey: string, typeName: string, severity: any, line: number, snippet: string, desc: string): Issue {
  const remediations: any = {
    OPEN_REDIRECT: "Use allow-list.",
    IDOR: "Check ownership.",
    PARAM_TAMPERING: "Fetch authoritative values from server-side database."
  };
  return {
    id: `${CWE_MAP[typeKey as keyof typeof CWE_MAP]}-${line}`,
    cwe: CWE_MAP[typeKey as keyof typeof CWE_MAP],
    type: typeName,
    severity,
    line,
    snippet: snippet.trim(),
    description: desc,
    remediation: remediations[typeKey]
  };
}

// --- API Endpoints ---

app.post("/api/scan", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const issues = runIroncladScan(code);
  res.json({ success: true, issues });
});

app.post("/api/scan-deep", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const localIssues = runIroncladScan(code);
  const key = process.env.GEMINI_API_KEY;

  if (!key) {
    return res.json({
      success: true,
      analysis: {
        summary: "Ironclad heuristic scan complete.",
        issues: localIssues,
        adst: {
          nodeName: "Data-Flow Analysis Root",
          description: "Multi-hop taint tracking results",
          children: localIssues.map(i => ({ nodeName: i.type, description: i.description }))
        }
      }
    });
  }

  try {
    const genAI = new GoogleGenAI(key);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    const prompt = `Perform a deep security audit. Return JSON only.
    Code:
    ${code}`;
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const jsonMatch = response.text().match(/\{[\s\S]*\}/);
    const analysis = JSON.parse(jsonMatch ? jsonMatch[0] : response.text());
    res.json({ success: true, analysis });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/project-files", (req, res) => {
  const files = ["server.ts", "sentinel.py", "package.json", "src/App.tsx", "README.md"];
  const result: Record<string, string> = {};
  files.forEach(f => {
    const p = path.join(process.cwd(), f);
    if (fs.existsSync(p)) result[f] = fs.readFileSync(p, "utf8");
  });
  res.json({ success: true, files: result });
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get("*", (req, res) => res.sendFile(path.join(distPath, "index.html")));
    }
  }
  app.listen(PORT, "0.0.0.0", () => console.log(`Sentinel™ Tactical Backend on http://localhost:${PORT}`));
}

startServer();
