'use client';

import { useState, useRef } from 'react';
import Link from 'next/link';
import {
  Shield, Upload, FileText, Download, Loader2, CheckCircle, AlertCircle,
  Target, Clock, Activity, ChevronRight, X, ExternalLink
} from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

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
  const [file, setFile] = useState<File | null>(null);
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
    if (selectedFile.size > 10 * 1024 * 1024) {
      setError('File too large. Maximum size is 10 MB.');
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
    if (!file) return;
    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        body: formData,
      });
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
    setResult(null);
    setError(null);
  };

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
            <div
              onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
                dragActive
                  ? 'border-blue-500 bg-blue-50'
                  : file
                  ? 'border-green-500 bg-green-50'
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
                  <p className="text-sm text-slate-500">or click to browse — CSV, JSON, TXT, LOG · max 10 MB</p>
                </>
              )}
            </div>

            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-800">{error}</p>
              </div>
            )}

            {file && (
              <button
                onClick={analyze}
                disabled={loading}
                className="mt-6 w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-semibold py-3 px-6 rounded-lg flex items-center justify-center gap-2 transition-colors"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Target className="w-5 h-5" />
                    Analyze with MITRE ATT&CK
                  </>
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
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Header with reset */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-slate-900">Analysis Results</h2>
                <p className="text-sm text-slate-500 mt-1">Incident ID: {result.incident_id}</p>
              </div>
              <button
                onClick={reset}
                className="text-sm text-slate-600 hover:text-slate-900 flex items-center gap-1"
              >
                <X className="w-4 h-4" /> Analyze another
              </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-4">
              <StatCard icon={FileText} label="Events Parsed" value={result.events_parsed} color="blue" />
              <StatCard icon={Target} label="Techniques Found" value={result.mitre_techniques.length} color="purple" />
              <StatCard icon={Clock} label="Tactics Covered" value={new Set(result.mitre_techniques.map(t => t.tactic)).size} color="green" />
            </div>

            {/* Downloads */}
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <h3 className="font-semibold text-slate-900 mb-4">Export Report</h3>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { format: 'pdf', label: 'PDF Report', desc: 'Compliance-ready' },
                  { format: 'json', label: 'JSON Data', desc: 'For automation' },
                  { format: 'csv', label: 'CSV Export', desc: 'Open in Excel' },
                ].map((d) => (
                  <button
                    key={d.format}
                    onClick={() => downloadReport(d.format)}
                    className="border border-slate-200 hover:border-blue-400 hover:bg-blue-50 rounded-lg p-4 text-left transition-all group"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-sm text-slate-900">{d.label}</span>
                      <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-600" />
                    </div>
                    <span className="text-xs text-slate-500">{d.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* MITRE Techniques */}
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <h3 className="font-semibold text-slate-900 mb-4">MITRE ATT&CK Techniques Detected</h3>
              <div className="space-y-2">
                {result.mitre_techniques.map((t) => (
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
            </div>

            {/* Events Timeline */}
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <h3 className="font-semibold text-slate-900 mb-4">Event Timeline</h3>
              <div className="space-y-3 max-h-[600px] overflow-y-auto">
                {result.events.map((event, idx) => (
                  <div key={event.id} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="w-2 h-2 rounded-full bg-blue-600"></div>
                      {idx < result.events.length - 1 && (
                        <div className="w-0.5 flex-1 bg-slate-200 my-1"></div>
                      )}
                    </div>
                    <div className="flex-1 pb-4">
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-slate-900 mb-1">{event.description}</p>
                          <div className="flex items-center gap-2 flex-wrap text-xs text-slate-500">
                            <span>{event.timestamp}</span>
                            <span>•</span>
                            <span className="font-mono">{event.source}</span>
                            {event.mitre_technique_id && (
                              <>
                                <span>•</span>
                                <span className={`px-1.5 py-0.5 rounded font-mono font-medium border ${TACTIC_COLORS[event.mitre_tactic] || TACTIC_COLORS.Unknown}`}>
                                  {event.mitre_technique_id}
                                </span>
                              </>
                            )}
                          </div>
                        </div>
                        {event.confidence > 0 && (
                          <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
                            {event.confidence}%
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
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
