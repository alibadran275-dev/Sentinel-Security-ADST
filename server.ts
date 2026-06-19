import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

// Initialize Express
const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini SDK lazily if key exists
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI {
  if (!aiClient) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) {
      throw new Error("GEMINI_API_KEY environment variable is not configured. Please add it via the Secrets panel.");
    }
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// Interfaces for response
interface Issue {
  id: string;
  type: "Open Redirect" | "IDOR" | "Parameter Tampering" | "Injection / Low-Severity Case";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

// Fast heuristic/regex static code analysis
function runHeuristicScan(code: string): Issue[] {
  const issues: Issue[] = [];
  const lines = code.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const num = i + 1;
    const lineText = lines[i];

    // 1. Open Redirect
    // Target patterns: redirecting, res.redirect, loc.href, window.location, window.open using a variable query/param
    if (
      (lineText.includes("res.redirect") || lineText.includes("window.location") || lineText.includes("location.href") || lineText.match(/redirect\(/)) &&
      (lineText.includes("req.query") || lineText.includes("req.params") || lineText.includes("url") || lineText.includes("target") || lineText.includes("dest")) &&
      !lineText.includes("whitelist") && !lineText.includes("safe") && !lineText.includes("isValid")
    ) {
      issues.push({
        id: `OR-${num}`,
        type: "Open Redirect",
        severity: "HIGH",
        line: num,
        snippet: lineText.trim(),
        description: "Unvalidated redirection target detected. Uncontrolled input is directly supplied to a redirect function, allowing attackers to perform phishing attacks via redirection to external malicious websites.",
        remediation: "Implement strict allow-listing of relative path targets, or parse and validate the host address before redirecting. Avoid passing dynamic input parameters directly to dynamic redirections.",
      });
    }

    // 2. IDOR (Insecure Direct Object Reference)
    // Target patterns: database operations directly executing query with user-provided IDs without session controls or owner verification checks
    if (
      (lineText.includes("findById") || lineText.includes("select") || lineText.includes("db.query") || lineText.includes("findOne") || lineText.includes("collection(")) &&
      (lineText.includes("req.params.id") || lineText.includes("req.query.id") || lineText.includes("req.body.id")) &&
      !lineText.includes("req.user.id") && !lineText.includes("session") && !lineText.includes("owner") && !lineText.includes("tenant")
    ) {
      issues.push({
        id: `IDOR-${num}`,
        type: "IDOR",
        severity: "CRITICAL",
        line: num,
        snippet: lineText.trim(),
        description: "Potential Insecure Direct Object Reference (IDOR). The application retrieves objects using user-controlled parameters with no validation check regarding whether the current session's user owns or has authorization to access the specific resource.",
        remediation: "Verify that the authenticated user (typically fetched from session JWT or helper middlewares) possesses owner rights over the target ID before initiating data retrieval/updates.",
      });
    }

    // 3. Parameter Tampering
    // Target patterns: reading prices, quantities, amounts directly from req.body or req.query during sensitive workflows, e.g., product payments, checkouts, or rights elevations.
    if (
      (lineText.includes("price") || lineText.includes("amount") || lineText.includes("quantity") || lineText.includes("role") || lineText.includes("admin")) &&
      (lineText.includes("req.body") || lineText.includes("req.query") || lineText.includes("req.params")) &&
      (lineText.includes("checkout") || lineText.includes("pay") || lineText.includes("purchase") || lineText.includes("update") || lineText.includes("config")) &&
      !lineText.includes("const price = db") && !lineText.includes("verifyPrice")
    ) {
      issues.push({
        id: `PT-${num}`,
        type: "Parameter Tampering",
        severity: "HIGH",
        line: num,
        snippet: lineText.trim(),
        description: "Potential raw parameter tampering risk. Critical application attributes (like prices, roles, or quantities) appear to be loaded or updated directly targetable from request structures. Malicious users can alter these values before submission.",
        remediation: "Never trust raw pricing or critical structural states supplied from client parameters. Retrieve baseline facts (like element pricing) directly from a trusted database or secure server state, using incoming values only as item references.",
      });
    }
  }

  // If no vulnerabilities found locally but user is sending non-empty text, provide a clean response.
  return issues;
}

// 1. API: Quick scanner (local heuristics tool)
app.post("/api/scan", (req, res) => {
  try {
    const { code } = req.body;
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Please input some code to scan." });
    }
    const issues = runHeuristicScan(code);
    return res.json({ success: true, issues });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "An error occurred during quick analysis." });
  }
});

// 2. API: Deep AI Audit (integrating gemini-3.5-flash)
app.post("/api/scan-deep", async (req, res) => {
  try {
    const { code } = req.body;
    if (typeof code !== "string" || !code.trim()) {
      return res.status(400).json({ error: "Please input some code to analyze." });
    }

    // Compile local quick heuristic results first
    const localIssues = runHeuristicScan(code);

    let aiAnalysis: any = null;

    try {
      const ai = getGeminiClient();
      const prompt = `Analyze the typical patterns of vulnerabilities in this user's source code:
---
${code}
---
If there are any logical flaws regarding Open Redirect, IDOR, or Parameter Tampering, document them.
Please yield a valid JSON output matching this strict schema:
{
  "summary": "High-level visual summary of the source code safety",
  "issues": [
    {
      "id": "A UNIQUE ID string starting with AI-",
      "type": "Open Redirect" | "IDOR" | "Parameter Tampering",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "line": 12, // accurate line number
      "snippet": "exact snippet of unsafe code",
      "description": "Clear step-by-step security explanation",
      "remediation": "Immediate code remediation strategies"
    }
  ],
  "remediationPatch": "Fully refactored safe code block replacing the vulnerabilities with secure, validated patterns.",
  "adst": {
    "nodeName": "Attack Vector / Entry Point (e.g., Unauthenticated POST route)",
    "description": "Entry mechanism description",
    "children": [
      {
        "nodeName": "Action / Exploit Attempt (e.g., Target field tampering)",
        "description": "How the attack is operationalized",
        "children": [
          {
            "nodeName": "Impact / Outcome (e.g., Data exfiltration or phishing redirection)",
            "description": "What happens upon successful breach"
          }
        ]
      }
    ]
  }
}`;

      const aiResponse = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              remediationPatch: { type: Type.STRING },
              issues: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    id: { type: Type.STRING },
                    type: { type: Type.STRING },
                    severity: { type: Type.STRING },
                    line: { type: Type.INTEGER },
                    snippet: { type: Type.STRING },
                    description: { type: Type.STRING },
                    remediation: { type: Type.STRING },
                  },
                  required: ["id", "type", "severity", "line", "snippet", "description", "remediation"],
                },
              },
              adst: {
                type: Type.OBJECT,
                properties: {
                  nodeName: { type: Type.STRING },
                  description: { type: Type.STRING },
                  children: { type: Type.ARRAY },
                },
                required: ["nodeName", "description"],
              },
            },
            required: ["summary", "issues", "remediationPatch", "adst"],
          },
        },
      });

      const responseText = aiResponse.text;
      if (responseText) {
        aiAnalysis = JSON.parse(responseText.trim());
      }
    } catch (apiError: any) {
      console.error("Gemini API request failed:", apiError);
      // Fallback on local heuristic results with simulated ADST tree to avoid UI breakage of missing keys
      aiAnalysis = {
        summary: `Fell back to Offline Heuristic Engine: ${localIssues.length > 0 ? `${localIssues.length} issues found` : "No issues discovered immediately by heuristic regex filters"}. For deep AI audits, make sure your GEMINI_API_KEY is supplied in the Settings panel.`,
        issues: localIssues,
        remediationPatch: `// Quick secure guideline update:\n// Validate every URI to lock Open Redirect\n// Verify req.user session properties prior to DB queries\n// Obtain absolute item configs (pricing, roles, permissions) directly in Server variables`,
        adst: {
          nodeName: "Client Code Upload",
          description: "Source code read by heuristic engines",
          children: localIssues.map((issue) => ({
            nodeName: `Attempt Exploit of ${issue.type}`,
            description: `Manipulate line ${issue.line}: '${issue.snippet.slice(0, 40)}'`,
            children: [
              {
                nodeName: `Achieve target results of type: ${issue.type}`,
                description: "Security state breached due to missing access context checks"
              }
            ]
          }))
        }
      };
    }

    return res.json({ success: true, analysis: aiAnalysis });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "An error occurred during deep security audit." });
  }
});

// 3. API: Get project files to download as ZIP
app.get("/api/project-files", (req, res) => {
  try {
    const filesToInclude = [
      "server.ts",
      "sentinel.py",
      "setup_project.py",
      "package.json",
      "index.html",
      "metadata.json",
      "tsconfig.json",
      "vite.config.ts",
      ".env.example",
      ".gitignore",
      "src/main.tsx",
      "src/index.css",
      "src/App.tsx",
    ];

    const result: Record<string, string> = {};

    for (const f of filesToInclude) {
      const fullPath = path.join(process.cwd(), f);
      if (fs.existsSync(fullPath)) {
        result[f] = fs.readFileSync(fullPath, "utf8");
      }
    }

    return res.json({ success: true, files: result });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to read project files." });
  }
});

// Setup Vite dev server or static distribution build serving
async function setupViteOrStatic() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Sentinel™ Backend standing guard on http://localhost:${PORT}`);
  });
}

setupViteOrStatic();
