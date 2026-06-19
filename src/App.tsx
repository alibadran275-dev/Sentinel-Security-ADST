import React, { useState } from "react";
import { 
  Shield, 
  Terminal, 
  CheckCircle, 
  Copy, 
  Download, 
  Cpu, 
  RefreshCw, 
  AlertTriangle, 
  Code2, 
  Zap, 
  Bug,
  Lock,
  ChevronDown
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import JSZip from "jszip";

// --- Types ---

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

interface ADSTNode {
  nodeName: string;
  description: string;
  children?: ADSTNode[];
}

interface ScanAnalysis {
  summary: string;
  issues: Issue[];
  remediationPatch?: string;
  adst: ADSTNode;
}

// --- Components ---

const SeverityBadge = ({ severity }: { severity: Issue["severity"] }) => {
  const styles = {
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/20",
    HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    MEDIUM: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    LOW: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border uppercase tracking-wider ${styles[severity]}`}>
      {severity}
    </span>
  );
};

const ADSTTreeNode = ({ node }: { node: ADSTNode }) => {
  const [isOpen, setIsOpen] = useState(true);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div className="ml-4 border-l border-slate-800/50 pl-4 my-2">
      <div 
        className={`group flex items-start gap-3 p-2 rounded-lg transition-colors ${hasChildren ? 'cursor-pointer hover:bg-slate-900/40' : ''}`}
        onClick={() => hasChildren && setIsOpen(!isOpen)}
      >
        <div className="mt-1">
          {hasChildren ? (
            <motion.div animate={{ rotate: isOpen ? 0 : -90 }}>
              <ChevronDown className="w-3.5 h-3.5 text-emerald-500" />
            </motion.div>
          ) : (
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500/40 mt-1" />
          )}
        </div>
        <div className="space-y-1">
          <h4 className="text-xs font-bold text-slate-200 group-hover:text-emerald-400 transition-colors">
            {node.nodeName}
          </h4>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            {node.description}
          </p>
        </div>
      </div>
      {hasChildren && isOpen && (
        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}>
          {node.children?.map((child, idx) => (
            <ADSTTreeNode key={idx} node={child} />
          ))}
        </motion.div>
      )}
    </div>
  );
};

export default function App() {
  const [code, setCode] = useState(`// Sentinel™ Code Analyzer - Input Area
const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // This will trigger an Open Redirect alert
  res.redirect(target);
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // This will trigger an IDOR alert
  db.query("SELECT * FROM users WHERE id = " + userId);
});`);

  const [isScanning, setIsScanning] = useState(false);
  const [analysis, setAnalysis] = useState<ScanAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (type: "quick" | "deep") => {
    setIsScanning(true);
    setError(null);
    try {
      const endpoint = type === "quick" ? "/api/scan" : "/api/scan-deep";
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await response.json();
      
      if (data.success) {
        if (type === "quick") {
          setAnalysis({
            summary: `Heuristic scan identified ${data.issues.length} potential vulnerabilities.`,
            issues: data.issues,
            adst: {
              nodeName: "Heuristic Scan Root",
              description: "Static analysis triggered via regex patterns",
              children: data.issues.map((i: Issue) => ({
                nodeName: `${i.type} detected`,
                description: i.description
              }))
            }
          });
        } else {
          setAnalysis(data.analysis);
        }
      } else {
        setError(data.error || "Scan failed.");
      }
    } catch (err) {
      setError("Security engine offline or unreachable.");
    } finally {
      setIsScanning(false);
    }
  };

  const downloadCLI = async () => {
    try {
      const response = await fetch("/api/project-files");
      const data = await response.json();
      if (data.success) {
        const zip = new JSZip();
        Object.entries(data.files).forEach(([f, c]) => zip.file(f, c as string));
        const blob = await zip.generateAsync({ type: "blob" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "Sentinel_CLI.zip";
        a.click();
      }
    } catch (e) { console.error(e); }
  };

  return (
    <div className="min-h-screen bg-[#060810] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200 antialiased">
      {/* Header */}
      <header className="border-b border-slate-900/60 bg-slate-950/60 backdrop-blur-md sticky top-0 z-50 px-4 py-3 md:px-8">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-emerald-400" />
            <span className="font-bold text-lg tracking-tight text-white">Sentinel<span className="text-emerald-400">™</span></span>
          </div>
          <button onClick={downloadCLI} className="bg-slate-900 hover:bg-slate-800 text-xs font-bold px-4 py-2 rounded-xl border border-slate-800 flex items-center gap-2">
            <Download className="w-3.5 h-3.5" /> Download CLI
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 relative z-10">
        
        {/* Editor Area */}
        <div className="lg:col-span-7 flex flex-col gap-4">
          <div className="bg-slate-950/50 border border-slate-900 rounded-2xl overflow-hidden flex flex-col flex-1 shadow-2xl">
            <div className="bg-slate-900/40 px-4 py-2 border-b border-slate-900 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-emerald-400" />
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Source Code Editor</span>
              </div>
            </div>
            <textarea
              id="code-input"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className="flex-1 w-full bg-transparent p-6 font-mono text-sm text-slate-300 resize-none focus:outline-none min-h-[400px]"
              spellCheck={false}
            />
            <div className="p-4 bg-slate-950 border-t border-slate-900 flex gap-3">
              <button onClick={() => handleScan("quick")} disabled={isScanning} className="flex-1 bg-slate-900 hover:bg-slate-800 text-slate-200 py-3 rounded-xl text-sm font-bold border border-slate-800 flex items-center justify-center gap-2">
                {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4 text-yellow-400" />} Quick Scan
              </button>
              <button onClick={() => handleScan("deep")} disabled={isScanning} className="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white py-3 rounded-xl text-sm font-bold flex items-center justify-center gap-2">
                <Cpu className="w-4 h-4" /> Deep AI Audit
              </button>
            </div>
          </div>
        </div>

        {/* Results Area */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          <div className="bg-slate-950/50 border border-slate-900 rounded-2xl p-6 shadow-xl">
            {error && <div className="text-red-400 text-xs mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">{error}</div>}
            
            {!analysis && !isScanning && (
              <div className="text-center py-20 text-slate-600">
                <Terminal className="w-10 h-10 mx-auto mb-4 opacity-20" />
                <p className="text-xs uppercase tracking-widest font-bold">Waiting for Scan...</p>
              </div>
            )}

            {isScanning && (
              <div className="text-center py-20">
                <RefreshCw className="w-10 h-10 mx-auto mb-4 animate-spin text-emerald-500" />
                <p className="text-xs text-slate-400">Analyzing Attack Vectors...</p>
              </div>
            )}

            {analysis && !isScanning && (
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-slate-900 pb-4">
                  <h3 className="font-bold text-white flex items-center gap-2"><CheckCircle className="w-4 h-4 text-emerald-400" /> Audit Results</h3>
                  <span className="text-[10px] font-mono bg-slate-900 px-2 py-1 rounded text-slate-400">{analysis.issues.length} Flaws</span>
                </div>
                
                <p className="text-xs text-slate-400 italic">"{analysis.summary}"</p>

                <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2">
                  {analysis.issues.map((issue, idx) => (
                    <div key={idx} className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-3">
                      <div className="flex justify-between items-start">
                        <div className="flex items-center gap-2">
                          <Bug className="w-3.5 h-3.5 text-slate-500" />
                          <span className="text-xs font-bold text-slate-200">{issue.type}</span>
                        </div>
                        <SeverityBadge severity={issue.severity} />
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 bg-black/40 p-2 rounded">Line {issue.line}: {issue.snippet}</div>
                      <p className="text-[11px] text-slate-400">{issue.description}</p>
                      <div className="pt-2 border-t border-slate-800 flex items-center gap-2 text-[10px] text-emerald-400 font-bold">
                        <Lock className="w-3 h-3" /> {issue.remediation}
                      </div>
                    </div>
                  ))}
                </div>

                {analysis.adst && (
                  <div className="mt-6 border-t border-slate-900 pt-6">
                    <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Attack Simulation Tree (ADST)</h4>
                    <ADSTTreeNode node={analysis.adst} />
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
