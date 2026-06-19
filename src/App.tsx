import React, { useState, useEffect } from "react";
import { 
  Shield, 
  Terminal, 
  CheckCircle, 
  Copy, 
  Download, 
  Cpu, 
  RefreshCw, 
  Eye, 
  AlertTriangle, 
  ChevronRight, 
  Code2, 
  Zap, 
  Search,
  Bug,
  Lock,
  ExternalLink,
  ChevronDown,
  LayoutDashboard
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import JSZip from "jszip";

// --- Types ---

interface Issue {
  id: string;
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

const ADSTTreeNode = ({ node, depth = 0 }: { node: ADSTNode; depth?: number }) => {
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
        <motion.div 
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
        >
          {node.children?.map((child, idx) => (
            <ADSTTreeNode key={idx} node={child} depth={depth + 1} />
          ))}
        </motion.div>
      )}
    </div>
  );
};

export default function App() {
  const [code, setCode] = useState(`// Paste your sensitive code here for real-time analysis
const express = require('express');
const app = express();

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // VULNERABLE: Open Redirect
  res.redirect(target);
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABLE: IDOR
  const user = db.query("SELECT * FROM users WHERE id = " + userId);
  res.json(user);
});`);

  const [isScanning, setIsScanning] = useState(false);
  const [scanType, setScanType] = useState<"quick" | "deep" | null>(null);
  const [analysis, setAnalysis] = useState<ScanAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [zipLoading, setZipLoading] = useState(false);

  const handleScan = async (type: "quick" | "deep") => {
    setIsScanning(true);
    setScanType(type);
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
          // Wrap quick scan issues into the ScanAnalysis structure
          setAnalysis({
            summary: `Quick Heuristic Scan complete. Found ${data.issues.length} potential issues.`,
            issues: data.issues,
            adst: {
              nodeName: "Heuristic Entry Point",
              description: "Pattern-based matching triggered on code structure",
              children: data.issues.map((i: Issue) => ({
                nodeName: `Pattern Match: ${i.type}`,
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
      setError("Connection to security engine failed.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleDownloadZip = async () => {
    setZipLoading(true);
    try {
      const response = await fetch("/api/project-files");
      const data = await response.json();
      if (data.success && data.files) {
        const zip = new JSZip();
        Object.entries(data.files).forEach(([filename, content]) => {
          zip.file(filename, content as string);
        });
        const blob = await zip.generateAsync({ type: "blob" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "Sentinel_CLI_Toolsuite.zip";
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setZipLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#060810] text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200 antialiased">
      {/* Background decoration */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#111422_1px,transparent_1px),linear-gradient(to_bottom,#111422_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none z-0" />
      
      {/* Header */}
      <header className="border-b border-slate-900/60 bg-slate-950/60 backdrop-blur-md sticky top-0 z-50 px-4 py-3 md:px-8">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-emerald-500/10 border border-emerald-500/20 p-2 rounded-xl text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.1)]">
              <Shield className="w-5 h-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">Sentinel<span className="text-emerald-400">™</span></span>
                <span className="text-[10px] uppercase font-mono tracking-widest bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded-full">Production v2.4</span>
              </div>
            </div>
          </div>
          
          <div className="hidden md:flex items-center gap-6">
            <nav className="flex items-center gap-4 text-sm font-medium text-slate-400">
              <a href="#" className="text-white hover:text-emerald-400 transition-colors">Dashboard</a>
              <a href="#" className="hover:text-emerald-400 transition-colors">Audit History</a>
              <a href="#" className="hover:text-emerald-400 transition-colors">Documentation</a>
            </nav>
            <button 
              onClick={handleDownloadZip}
              disabled={zipLoading}
              className="bg-slate-900 hover:bg-slate-800 text-slate-200 px-4 py-2 rounded-xl text-xs font-bold border border-slate-800 transition-all flex items-center gap-2"
            >
              {zipLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              CLI Tool
            </button>
          </div>
          
          <button className="md:hidden p-2 text-slate-400">
            <LayoutDashboard className="w-6 h-6" />
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 relative z-10">
        
        {/* Left Column: Input & Controls */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          <div className="bg-slate-950/50 border border-slate-900 rounded-2xl overflow-hidden flex flex-col flex-1 shadow-2xl">
            <div className="bg-slate-900/40 px-4 py-3 border-b border-slate-900 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code2 className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Source Code Analyzer</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-red-500/40" />
                <div className="w-2 h-2 rounded-full bg-yellow-500/40" />
                <div className="w-2 h-2 rounded-full bg-green-500/40" />
              </div>
            </div>
            
            <div className="flex-1 relative min-h-[400px]">
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="absolute inset-0 w-full h-full bg-transparent p-6 font-mono text-sm text-slate-300 resize-none focus:outline-none selection:bg-emerald-500/20"
                spellCheck={false}
              />
            </div>
            
            <div className="p-4 bg-slate-950 border-t border-slate-900 flex flex-col sm:flex-row gap-3">
              <button
                onClick={() => handleScan("quick")}
                disabled={isScanning}
                className="flex-1 bg-slate-900 hover:bg-slate-800 text-slate-200 py-3 px-4 rounded-xl text-sm font-bold border border-slate-800 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isScanning && scanType === "quick" ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4 text-yellow-400" />}
                Quick Heuristic Scan
              </button>
              <button
                onClick={() => handleScan("deep")}
                disabled={isScanning}
                className="flex-1 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white py-3 px-4 rounded-xl text-sm font-bold shadow-[0_0_20px_rgba(16,185,129,0.2)] transition-all flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isScanning && scanType === "deep" ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Cpu className="w-4 h-4" />}
                Deep AI Audit
              </button>
            </div>
          </div>

          {/* Remediation Patch (If available) */}
          <AnimatePresence>
            {analysis?.remediationPatch && (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-emerald-950/10 border border-emerald-500/20 rounded-2xl overflow-hidden shadow-xl"
              >
                <div className="bg-emerald-500/10 px-4 py-3 border-b border-emerald-500/20 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <Lock className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-wider">AI Security Patch (Suggested)</span>
                  </div>
                  <button 
                    onClick={() => navigator.clipboard.writeText(analysis.remediationPatch!)}
                    className="text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
                <pre className="p-6 font-mono text-xs text-emerald-200/80 overflow-x-auto leading-relaxed">
                  {analysis.remediationPatch}
                </pre>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right Column: Results & ADST */}
        <div className="lg:col-span-5 flex flex-col gap-6">
          
          {/* Summary / Status */}
          <div className="bg-slate-950/50 border border-slate-900 rounded-2xl p-6 shadow-xl relative overflow-hidden">
            {!analysis && !isScanning && !error && (
              <div className="flex flex-col items-center justify-center py-10 text-center space-y-4">
                <div className="w-16 h-16 bg-slate-900 rounded-2xl flex items-center justify-center text-slate-600">
                  <Search className="w-8 h-8" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-white font-bold">Ready for Analysis</h3>
                  <p className="text-xs text-slate-500 max-w-[240px]">Paste your code and select a scan method to begin the security audit.</p>
                </div>
              </div>
            )}

            {isScanning && (
              <div className="flex flex-col items-center justify-center py-10 text-center space-y-6">
                <div className="relative">
                  <div className="w-16 h-16 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Shield className="w-6 h-6 text-emerald-500 animate-pulse" />
                  </div>
                </div>
                <div className="space-y-2">
                  <h3 className="text-white font-bold animate-pulse">
                    {scanType === "deep" ? "Executing Neural Security Audit..." : "Running Heuristic Analysis..."}
                  </h3>
                  <p className="text-xs text-slate-500">Sentinel is analyzing attack vectors and logical flaws.</p>
                </div>
              </div>
            )}

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-red-400">Security Engine Error</h4>
                  <p className="text-xs text-red-400/70">{error}</p>
                </div>
              </div>
            )}

            {analysis && !isScanning && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-white font-bold flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-emerald-400" />
                    Scan Results
                  </h3>
                  <div className="text-[10px] font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded">
                    {analysis.issues.length} Flaws Found
                  </div>
                </div>
                
                <p className="text-xs text-slate-400 leading-relaxed border-l-2 border-emerald-500/30 pl-4 italic">
                  "{analysis.summary}"
                </p>

                {/* Issues List */}
                <div className="space-y-4">
                  {analysis.issues.map((issue, idx) => (
                    <motion.div 
                      key={issue.id}
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="group bg-slate-900/40 border border-slate-800 hover:border-slate-700 rounded-xl overflow-hidden transition-all"
                    >
                      <div className="p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Bug className="w-4 h-4 text-slate-500" />
                            <span className="text-xs font-bold text-slate-200">{issue.type}</span>
                          </div>
                          <SeverityBadge severity={issue.severity} />
                        </div>
                        
                        <div className="bg-slate-950/60 p-2 rounded-lg border border-slate-800/50 font-mono text-[10px] text-slate-400">
                          <span className="text-slate-600 mr-2">{issue.line} |</span>
                          {issue.snippet}
                        </div>
                        
                        <p className="text-[11px] text-slate-500 leading-relaxed">
                          {issue.description}
                        </p>

                        <div className="pt-2 border-t border-slate-800/50">
                          <div className="flex items-center gap-1.5 text-emerald-400 mb-1">
                            <Lock className="w-3 h-3" />
                            <span className="text-[10px] font-bold uppercase tracking-wider">Remediation</span>
                          </div>
                          <p className="text-[11px] text-emerald-400/70 leading-relaxed">
                            {issue.remediation}
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ADST Visualization */}
          <AnimatePresence>
            {analysis?.adst && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-slate-950/50 border border-slate-900 rounded-2xl overflow-hidden shadow-xl"
              >
                <div className="bg-slate-900/40 px-4 py-3 border-b border-slate-900 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <RefreshCw className="w-4 h-4 text-emerald-400" />
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Attack Simulation Tree (ADST)</span>
                  </div>
                </div>
                <div className="p-4 max-h-[400px] overflow-y-auto">
                  <ADSTTreeNode node={analysis.adst} />
                </div>
              </motion.div>
            )}
          </AnimatePresence>

        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900/60 bg-slate-950/60 py-6 px-4 md:px-8 relative z-10">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
            <Terminal className="w-3 h-3" />
            <span>© 2026 Sentinel™ Security Engine. All rights reserved.</span>
          </div>
          <div className="flex items-center gap-6 text-[11px] font-mono text-slate-500">
            <a href="#" className="hover:text-emerald-400 transition-colors">Privacy Protocol</a>
            <a href="#" className="hover:text-emerald-400 transition-colors">System Status</a>
            <a href="#" className="flex items-center gap-1 hover:text-emerald-400 transition-colors">
              Github <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
