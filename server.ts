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

// --- Detection Logic Engine ---

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

const RULES = [
  {
    cwe: "CWE-601",
    type: "Open Redirect",
    severity: "HIGH",
    pattern: /(?:res\.redirect|window\.location|location\.href|window\.open)\s*\(\s*(?:req\.(?:query|params|body)|url|target|dest|to|path|redirect_uri).*?\)/,
    negative: /whitelist|safe|isValid|validateUrl|checkOrigin/i,
    description: "Unvalidated user-controlled input is used as a redirection target, potentially enabling phishing.",
    remediation: "Implement an allow-list of approved URLs or use relative paths only."
  },
  {
    cwe: "CWE-639",
    type: "IDOR",
    severity: "CRITICAL",
    pattern: /(?:findById|select|db\.query|findOne|collection\(.*?\)\.doc)\s*\(\s*(?:req\.(?:params|query|body)\.(?:id|uid|user_id|uuid)).*?\)/,
    negative: /req\.user|session|owner|tenant|auth|permission/i,
    description: "Sensitive resource accessed via user-controlled ID without ownership or permission verification.",
    remediation: "Validate that the authenticated user has permission to access the requested resource ID."
  },
  {
    cwe: "CWE-639",
    type: "Parameter Tampering",
    severity: "HIGH",
    pattern: /(?:price|amount|quantity|role|admin|permission|is_admin|status)\s*=\s*req\.(?:body|query|params)\.(?:price|amount|quantity|role|admin|permission|is_admin|status)/,
    negative: /verifyPrice|db\.lookup|config\.get|calculate|validate/i,
    description: "Critical business logic parameters are accepted directly from client-side requests.",
    remediation: "Retrieve critical values (like prices or roles) from a trusted server-side source or database."
  }
];

function runHeuristicScan(code: string): Issue[] {
  const issues: Issue[] = [];
  const lines = code.split("\n");

  lines.forEach((line, index) => {
    const lineNum = index + 1;
    RULES.forEach(rule => {
      if (rule.pattern.test(line)) {
        if (!rule.negative.test(line)) {
          issues.push({
            id: `${rule.cwe}-${lineNum}`,
            cwe: rule.cwe,
            type: rule.type,
            severity: rule.severity as any,
            line: lineNum,
            snippet: line.trim(),
            description: rule.description,
            remediation: rule.remediation
          });
        }
      }
    });
  });

  return issues;
}

// --- API Endpoints ---

app.post("/api/scan", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });
  const issues = runHeuristicScan(code);
  res.json({ success: true, issues });
});

app.post("/api/scan-deep", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "No code provided" });

  const localIssues = runHeuristicScan(code);
  const key = process.env.GEMINI_API_KEY;

  if (!key) {
    // Fallback if no API key
    return res.json({
      success: true,
      analysis: {
        summary: "Heuristic scan completed. Deep AI Audit requires a GEMINI_API_KEY.",
        issues: localIssues,
        adst: {
          nodeName: "Code Entry",
          description: "Source code received for analysis",
          children: localIssues.map(i => ({
            nodeName: `Exploit ${i.type}`,
            description: i.description
          }))
        }
      }
    });
  }

  try {
    const genAI = new GoogleGenAI(key);
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
    const prompt = `Perform a deep security audit on this code. Return JSON only.
    Schema: { "summary": string, "issues": Issue[], "remediationPatch": string, "adst": Node }
    Code:
    ${code}`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    // Basic JSON extraction from markdown if needed
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const analysis = JSON.parse(jsonMatch ? jsonMatch[0] : text);
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

// --- Static File Serving & Routing ---

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    // Corrected production path
    const distPath = path.join(process.cwd(), "dist");
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get("*", (req, res) => {
        res.sendFile(path.join(distPath, "index.html"));
      });
    } else {
      // Fallback for development/testing if dist doesn't exist yet
      app.get("/", (req, res) => {
        res.send("Sentinel Backend Running. Build frontend to see UI.");
      });
    }
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Sentinel™ Backend standing guard on http://localhost:${PORT}`);
  });
}

startServer();
