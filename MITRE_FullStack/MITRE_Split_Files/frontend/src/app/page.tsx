'use client';

import { useState, useRef } from 'react';
import Link from 'next/link';
import {
  Shield, Upload, FileText, Download, Loader2, CheckCircle, AlertCircle,
  Target, Clock, Activity, ChevronRight, X, ExternalLink, BookOpen,
  ScanSearch, GitBranch, Gauge,
} from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

const ALL_TACTICS = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];

interface MitreTechnique {
  id: string;
  tactic: string;
  name: string;
  count: number;
}

interface Event {
  id: number;
  timestamp: string;
  source: string;
  description: string;
  mitre_tactic: string;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  confidence: number;
}

interface AnalysisResult {
  incident_id: string;
  events_parsed: number;
  mitre_techniques: MitreTechnique[];
  events: Event[];
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access': 'bg-red-100 text-red-800 border-red-200',
  'Execution': 'bg-orange-100 text-orange-800 border-orange-200',
  'Persistence': 'bg-amber-100 text-amber-800 border-amber-200',
  'Privilege Escalation': 'bg-yellow-100 text-yellow-800 border-yellow-200',
  'Defense Evasion': 'bg-purple-100 text-purple-800 border-purple-200',
  'Credential Access': 'bg-pink-100 text-pink-800 border-pink-200',
  'Discovery': 'bg-blue-100 text-blue-800 border-blue-200',
  'Lateral Movement': 'bg-cyan-100 text-cyan-800 border-cyan-200',
  'Collection': 'bg-teal-100 text-teal-800 border-teal-200',
  'Exfiltration': 'bg-rose-100 text-rose-800 border-rose-200',
  'Command and Control': 'bg-indigo-100 text-indigo-800 border-indigo-200',
  'Impact': 'bg-red-100 text-red-800 border-red-200',
  'Unknown': 'bg-slate-100 text-slate-600 border-slate-200',
};

export default function Home() {
  const [inputMode, setInputMode] = useState<'file' | 'paste'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [pasteText, setPasteText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = (selectedFile: File) => {
    const validTypes = ['.csv', '.json', '.txt', '.log'];
    const ext = '.' + selectedFile.name.split('.').pop()?.toLowerCase();
    if (!validTypes.includes(ext)) {
      setError(`Invalid file type. Use: ${validTypes.join(', ')}`);
      return;
    }
    if (selectedFile.size > 15 * 1024 * 1024) {
      setError('File too large. Maximum size is 15 MB.');
      return;
    }
    setFile(selectedFile);
    setError(null);
    setResult(null);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const analyze = async () => {
    setLoading(true);
    setError(null);
    try {
      let res: Response;
      if (inputMode === 'paste') {
        if (!pasteText.trim()) return;
        res = await fetch(`${API_URL}/api/integrations/raw`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ logs: pasteText, format: 'auto' }),
        });
      } else {
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        res = await fetch(`${API_URL}/api/analyze`, { method: 'POST', body: formData });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Analysis failed');
      setResult(data);
    } catch (e: any) {
      setError(e.message || 'Failed to connect to API. Make sure backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = (format: string) => {
    if (!result) return;
    window.open(`${API_URL}/api/download/${result.incident_id}/${format}`, '_blank');
  };

  const reset = () => {
    setFile(null);
    setPasteText('');
    setResult(null);
    setError(null);
  };

  const canAnalyze = inputMode === 'file' ? !!file : pasteText.trim().length > 0;

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-slate-900">MITRE ATT&CK Mapper</h1>
              <p className="text-xs text-slate-500">Incident Timeline Analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/integrations"
              className="text-sm text-slate-600 hover:text-slate-900 font-medium"
            >
              Integrations
            </Link>
            <Link
              href="/docs"
              className="text-sm text-slate-600 hover:text-slate-900 font-medium"
            >
              API Docs
            </Link>
            <a
              href="https://github.com/soham7998/MITRE_Incident_Mapper"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-slate-600 hover:text-slate-900 flex items-center gap-1.5 font-medium"
            >
              GitHub <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        {/* Hero */}
        {!result && (
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold text-slate-900 mb-4 text-balance">
              Convert security logs to <span className="text-blue-600">MITRE timelines</span>
            </h2>
            <p className="text-lg text-slate-600 max-w-2xl mx-auto">
              Upload your incident logs and get automatic MITRE ATT&CK technique mapping,
              interactive timelines, and compliance-ready PDF reports.
            </p>
          </div>
        )}

        {/* Upload Section */}
        {!result && (
          <div className="max-w-2xl mx-auto">
            {/* Mode tabs */}
            <div className="flex gap-1 mb-4 bg-slate-100 rounded-lg p-1 w-fit">
              {([['file', 'Upload File'], ['paste', 'Paste Events']] as const).map(([mode, label]) => (
                <button
                  key={mode}
                  onClick={() => { setInputMode(mode); setError(null); }}
                  className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    inputMode === mode ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-900'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {inputMode === 'file' ? (
              <div
                onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
                onDragLeave={() => setDragActive(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
                  dragActive ? 'border-blue-500 bg-blue-50'
                  : file ? 'border-green-500 bg-green-50'
                  : 'border-slate-300 bg-white hover:border-blue-400 hover:bg-blue-50/50'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.json,.txt,.log"
                  onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
                  className="hidden"
                />
                {file ? (
                  <div className="flex items-center justify-center gap-3">
                    <CheckCircle className="w-8 h-8 text-green-600" />
                    <div className="text-left">
                      <p className="font-medium text-slate-900">{file.name}</p>
                      <p className="text-sm text-slate-500">{(file.size / 1024).toFixed(1)} KB</p>
                    </div>
                  </div>
                ) : (
                  <>
                    <Upload className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                    <p className="text-lg font-medium text-slate-900 mb-1">Drop your log file here</p>
                    <p className="text-sm text-slate-500">or click to browse — CSV, JSON, TXT, LOG · max 15 MB</p>
                  </>
                )}
              </div>
            ) : (
              <div className="border border-slate-200 rounded-xl bg-white overflow-hidden">
                <textarea
                  value={pasteText}
                  onChange={(e) => setPasteText(e.target.value)}
                  rows={12}
                  placeholder={`Paste log events here — one per line.\n\nExamples:\nJan 15 09:00:01 server sshd[1234]: Failed password for root from 192.168.1.1\nJan 15 09:01:23 server sudo: admin : COMMAND=/bin/bash\nCEF:0|Microsoft|Defender|1.0|1001|Malware Detected|8|src=10.0.0.5\n2025-01-15T09:02:00Z,endpoint.log,powershell.exe -enc base64encodedpayload`}
                  className="w-full px-4 py-3 text-sm font-mono text-slate-800 placeholder-slate-400 resize-none focus:outline-none leading-relaxed"
                />
                {pasteText.trim() && (
                  <div className="px-4 py-2 border-t border-slate-100 bg-slate-50 text-xs text-slate-400">
                    {pasteText.trim().split('\n').filter(l => l.trim()).length} lines · supports syslog, CEF, CSV, plain text
                  </div>
                )}
              </div>
            )}

            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-800">{error}</p>
              </div>
            )}

            {canAnalyze && (
              <button
                onClick={analyze}
                disabled={loading}
                className="mt-4 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
              >
                {loading ? (
                  <><Loader2 className="w-5 h-5 animate-spin" />Analyzing...</>
                ) : (
                  <><Target className="w-5 h-5" />Analyze with MITRE ATT&CK</>
                )}
              </button>
            )}

            {/* Feature cards */}
            <div className="mt-12 grid grid-cols-3 gap-4">
              {[
                { icon: Target, label: 'Auto Mapping', desc: '120+ MITRE patterns' },
                { icon: Activity, label: 'Timeline', desc: 'Visual kill chain' },
                { icon: FileText, label: 'PDF Reports', desc: 'Compliance-ready' },
              ].map((f, i) => (
                <div key={i} className="bg-white border border-slate-200 rounded-lg p-4 text-center">
                  <f.icon className="w-6 h-6 text-blue-600 mx-auto mb-2" />
                  <p className="font-medium text-sm text-slate-900">{f.label}</p>
                  <p className="text-xs text-slate-500 mt-1">{f.desc}</p>
                </div>
              ))}
            </div>

            {/* How mapping works */}
            <div className="mt-6 border border-slate-200 rounded-xl bg-white overflow-hidden">
              <div className="px-5 py-3.5 border-b border-slate-100 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-semibold text-slate-900">How MITRE Mapping Works</span>
                </div>
              </div>
              <div className="grid grid-cols-4 divide-x divide-slate-100">
                {[
                  {
                    icon: Upload,
                    step: '01',
                    title: 'Parse',
                    body: 'Raw logs (syslog, CEF, CSV, JSON) are ingested line-by-line and normalised into structured events with a timestamp, source, and description.',
                  },
                  {
                    icon: ScanSearch,
                    step: '02',
                    title: 'Match',
                    body: '120+ compiled regex patterns are tested against each event description. Patterns cover keywords like powershell, mimikatz, psexec, and more.',
                  },
                  {
                    icon: GitBranch,
                    step: '03',
                    title: 'Assign',
                    body: 'A matched pattern carries the ATT&CK technique ID (e.g. T1059), subtechnique, and tactic (e.g. Execution) — all assigned directly to that event.',
                  },
                  {
                    icon: Gauge,
                    step: '04',
                    title: 'Score',
                    body: 'Confidence is weighted by tactic severity — Initial Access and Credential Access score highest (1.0 / 0.95), Discovery lowest (0.85).',
                  },
                ].map(({ icon: Icon, step, title, body }) => (
                  <div key={step} className="px-4 py-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-mono font-bold text-slate-300">{step}</span>
                      <Icon className="w-4 h-4 text-blue-600" />
                      <span className="text-sm font-semibold text-slate-800">{title}</span>
                    </div>
                    <p className="text-xs text-slate-500 leading-relaxed">{body}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <ResultsView result={result} onReset={reset} onDownload={downloadReport} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 mt-20 bg-white">
        <div className="max-w-6xl mx-auto px-6 py-6 text-center text-sm text-slate-500">
          Built by{' '}
          <a href="https://linkedin.com/in/shahsoham2003" className="text-blue-600 hover:underline">
            Soham Shah
          </a>
          {' • '}
          <a href="https://github.com/soham7998/MITRE_Incident_Mapper" className="text-blue-600 hover:underline">
            Open Source
          </a>
        </div>
      </footer>
    </div>
  );
}

function AttackHeatmap({ techniques }: { techniques: MitreTechnique[] }) {
  const byTactic: Record<string, MitreTechnique[]> = {};
  ALL_TACTICS.forEach(t => { byTactic[t] = []; });
  techniques.forEach(t => { if (byTactic[t.tactic]) byTactic[t.tactic].push(t); });
  const covered = ALL_TACTICS.filter(t => byTactic[t].length > 0).length;

  return (
    <div>
      <p className="text-sm text-slate-500 mb-3">{covered} of {ALL_TACTICS.length} tactics covered in this incident</p>
      <div className="overflow-x-auto pb-2">
        <div className="flex gap-3 min-w-max">
          {ALL_TACTICS.map(tactic => {
            const hits = byTactic[tactic];
            const active = hits.length > 0;
            return (
              <div key={tactic} className={`w-44 rounded-xl border-2 p-3 transition-all duration-200 ${active ? 'bg-gradient-to-b from-red-50 to-red-100 border-red-300 shadow-md shadow-red-100' : 'bg-slate-50 border-slate-200 opacity-60'}`}>
                <div className="flex items-center justify-between mb-2.5">
                  <p className={`text-sm font-bold uppercase tracking-wide leading-tight ${active ? 'text-red-700' : 'text-slate-400'}`}>
                    {tactic}
                  </p>
                  {active && (
                    <span className="bg-red-600 text-white text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center shrink-0 ml-1">
                      {hits.length}
                    </span>
                  )}
                </div>
                {hits.length === 0 && <p className="text-xs text-slate-300 italic">No activity</p>}
                {hits.map(t => (
                  <div key={t.id} className="bg-red-600 rounded-lg px-2 py-1.5 mb-1.5 shadow-sm">
                    <p className="text-xs font-mono font-bold text-white">{t.id}</p>
                    <p className="text-xs text-red-100 truncate">{t.name}</p>
                    <p className="text-xs text-red-300 mt-0.5">{t.count} event{t.count !== 1 ? 's' : ''}</p>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function ResultsView({ result, onReset, onDownload }: { result: AnalysisResult; onReset: () => void; onDownload: (f: string) => void }) {
  const [tab, setTab] = useState<'heatmap' | 'techniques' | 'timeline'>('heatmap');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900">Analysis Results</h2>
          <p className="text-sm text-slate-500 mt-1 font-mono">{result.incident_id}</p>
        </div>
        <button onClick={onReset} className="text-sm text-slate-600 hover:text-slate-900 flex items-center gap-1">
          <X className="w-4 h-4" /> Analyze another
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <StatCard icon={FileText} label="Events Parsed"    value={result.events_parsed}                                   color="blue" />
        <StatCard icon={Target}   label="Techniques Found" value={result.mitre_techniques.length}                         color="purple" />
        <StatCard icon={Clock}    label="Tactics Covered"  value={new Set(result.mitre_techniques.map(t => t.tactic)).size} color="green" />
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Export Report</h3>
        <div className="grid grid-cols-3 gap-3">
          {[
            { format: 'pdf', label: 'PDF Report', desc: 'Compliance-ready' },
            { format: 'json', label: 'JSON Data',  desc: 'For automation' },
            { format: 'csv', label: 'CSV Export',  desc: 'Open in Excel' },
          ].map(d => (
            <button key={d.format} onClick={() => onDownload(d.format)}
              className="border border-slate-200 hover:border-blue-400 hover:bg-blue-50 rounded-lg p-4 text-left transition-all group">
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-sm text-slate-900">{d.label}</span>
                <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600" />
              </div>
              <span className="text-xs text-slate-500">{d.desc}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="flex border-b border-slate-200">
          {([
            { id: 'heatmap',    label: 'ATT&CK Heatmap' },
            { id: 'techniques', label: 'Techniques' },
            { id: 'timeline',   label: 'Event Timeline' },
          ] as const).map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
                tab === t.id ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}>
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-6">
          {tab === 'heatmap' && <AttackHeatmap techniques={result.mitre_techniques} />}

          {tab === 'techniques' && (
            <div className="space-y-2">
              {result.mitre_techniques.map(t => (
                <div key={t.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium border ${TACTIC_COLORS[t.tactic] || TACTIC_COLORS.Unknown}`}>
                      {t.id}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-slate-900">{t.name}</p>
                      <p className="text-xs text-slate-500">{t.tactic}</p>
                    </div>
                  </div>
                  <span className="text-sm font-medium text-slate-700">{t.count} events</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'timeline' && (
            <div className="space-y-3 max-h-[600px] overflow-y-auto">
              {result.events.map((event, idx) => (
                <div key={event.id} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full bg-blue-600 mt-1" />
                    {idx < result.events.length - 1 && <div className="w-0.5 flex-1 bg-slate-200 my-1" />}
                  </div>
                  <div className="flex-1 pb-4">
                    <p className="text-sm text-slate-900 mb-1">{event.description}</p>
                    <div className="flex items-center gap-2 flex-wrap text-xs text-slate-500">
                      <span>{event.timestamp}</span>
                      <span>·</span>
                      <span className="font-mono">{event.source}</span>
                      {event.mitre_technique_id && (
                        <>
                          <span>·</span>
                          <span className={`px-1.5 py-0.5 rounded font-mono font-medium border ${TACTIC_COLORS[event.mitre_tactic] || TACTIC_COLORS.Unknown}`}>
                            {event.mitre_technique_id}
                          </span>
                        </>
                      )}
                      {event.confidence > 0 && (
                        <span className="bg-slate-100 px-2 py-0.5 rounded text-slate-600">{event.confidence}%</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }: any) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-600',
    purple: 'bg-purple-50 text-purple-600',
    green: 'bg-green-50 text-green-600',
  };
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${colors[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <p className="text-2xl font-bold text-slate-900">{value}</p>
      <p className="text-sm text-slate-500 mt-1">{label}</p>
    </div>
  );
}
