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

// --- Tactical Detection Engine (Hardened) ---

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

const TAMPER_KEYS = ["price", "amount", "amt", "quantity", "qty", "role", "admin", "is_admin", "permission", "status"];

function runTacticalScan(code: string): Issue[] {
  const issues: Issue[] = [];
  const lines = code.split("\n");
  
  // 1. Extract Variables (Tracking Sources)
  const varsFound = {
    redirect: new Set<string>(),
    id: new Set<string>(),
    tamper: new Set<string>()
  };

  // Standard Assignment Tracking
  const stdRegex = /(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|params|body)\.(\w+)/g;
  let match;
  while ((match = stdRegex.exec(code)) !== null) {
    const [_, varName, sourceKey] = match;
    categorizeVar(varName, sourceKey, varsFound);
  }

  // ES6 Destructuring Tracking
  const destructRegex = /(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(?:query|params|body)/g;
  while ((match = destructRegex.exec(code)) !== null) {
    const items = match[1].split(",").map(i => i.trim().split(":")[0].trim());
    items.forEach(item => categorizeVar(item, item, varsFound));
  }

  function categorizeVar(name: string, key: string, map: any) {
    const sk = key.toLowerCase();
    if (["url", "target", "dest", "to", "path", "redirect"].some(k => sk.includes(k))) map.redirect.add(name);
    if (["id", "uid", "uuid", "user_id"].some(k => sk.includes(k))) map.id.add(name);
    if (TAMPER_KEYS.some(k => sk.includes(k))) map.tamper.add(name);
  }

  // 2. Scan for Sinks with Contextual Lookback
  lines.forEach((line, index) => {
    const lineNum = index + 1;
    const context = lines.slice(Math.max(0, index - 5), index).join("\n").toLowerCase();
    const fullContext = (context + "\n" + line).toLowerCase();
    
    const isValidated = (v: string, auth = false) => {
      const patterns = ["whitelist", "isvalid", "safe", "validate", "check", "includes", "indexof", "allowed", "verify", "auth", "permission"];
      if (auth) patterns.push(...["req.user", "session", "owner", "tenant", "db.user"]);
      return patterns.some(p => fullContext.includes(p));
    };

    // Open Redirect (CWE-601)
    varsFound.redirect.forEach(v => {
      const sinkRegex = new RegExp(`(?:res\\.redirect|window\\.location|location\\.href|window\\.open)\\s*\\(.*?${v}.*?\\)`);
      if (sinkRegex.test(line) && !isValidated(v)) {
        issues.push(createIssue("OPEN_REDIRECT", "Open Redirect", "HIGH", lineNum, line, `Unvalidated variable '${v}' used in redirection.`));
      }
    });

    // IDOR (CWE-639)
    varsFound.id.forEach(v => {
      const sinkRegex = new RegExp(`(?:findById|select|db\\.query|findOne|collection\\(.*?\\)\\.doc|db\\..*?\\(.*?\\))\\s*\\(.*?${v}.*?\\)`);
      if (sinkRegex.test(line) && !isValidated(v, true)) {
        issues.push(createIssue("IDOR", "IDOR / Access Control Bypass", "CRITICAL", lineNum, line, `DB query using ID '${v}' without ownership check.`));
      }
    });

    // Parameter Tampering (CWE-472)
    varsFound.tamper.forEach(v => {
      const sinkRegex = new RegExp(`(?:price|amount|role|admin|status|permission)\\s*=\\s*.*?${v}`);
      if (sinkRegex.test(line) && !isValidated(v)) {
        issues.push(createIssue("PARAM_TAMPERING", "Parameter Tampering", "HIGH", lineNum, line, `Critical field assigned from user-controlled variable '${v}'.`));
      }
    });
  });

  return issues;
}

function createIssue(typeKey: string, typeName: string, severity: any, line: number, snippet: string, desc: string): Issue {
  const remediations: any = {
    OPEN_REDIRECT: "Use an allow-list of safe domains or relative paths.",
    IDOR: "Verify resource ownership against req.user.id before DB access.",
    PARAM_TAMPERING: "Retrieve authoritative values (price/role) from server-side database."
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
  const issues = runTacticalScan(code);
  res.json({ success: true, issues });
});

app.post("/api/scan-deep", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const localIssues = runTacticalScan(code);
  const key = process.env.GEMINI_API_KEY;

  if (!key) {
    return res.json({
      success: true,
      analysis: {
        summary: "Tactical heuristic scan complete. Deep AI Audit requires API Key.",
        issues: localIssues,
        adst: {
          nodeName: "Tactical Analysis Root",
          description: "Variable tracking and contextual analysis results",
          children: localIssues.map(i => ({ nodeName: i.type, description: i.description }))
        }
      }
    });
  }

  try {
    const genAI = new GoogleGenAI(key);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    const prompt = `Perform a military-grade security audit. Return JSON only.
    Schema: { "summary": string, "issues": Issue[], "remediationPatch": string, "adst": Node }
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
