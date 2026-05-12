'use client';

import { useState } from 'react';
import Link from 'next/link';
import {
  Shield, ArrowLeft, Loader2, AlertCircle, CheckCircle,
  Target, FileText, Clock, Activity, Download, X, ChevronRight,
} from 'lucide-react';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

// ── shared types ──────────────────────────────────────────────────────────────

interface MitreTechnique { id: string; tactic: string; name: string; count: number }
interface Event {
  id: number; timestamp: string; source: string; description: string;
  mitre_tactic: string; mitre_technique_id: string | null;
  mitre_technique_name: string | null; confidence: number;
}
interface AnalysisResult {
  incident_id: string; events_parsed: number;
  mitre_techniques: MitreTechnique[]; events: Event[];
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access':        'bg-red-100 text-red-800 border-red-200',
  'Execution':             'bg-orange-100 text-orange-800 border-orange-200',
  'Persistence':           'bg-amber-100 text-amber-800 border-amber-200',
  'Privilege Escalation':  'bg-yellow-100 text-yellow-800 border-yellow-200',
  'Defense Evasion':       'bg-purple-100 text-purple-800 border-purple-200',
  'Credential Access':     'bg-pink-100 text-pink-800 border-pink-200',
  'Discovery':             'bg-blue-100 text-blue-800 border-blue-200',
  'Lateral Movement':      'bg-cyan-100 text-cyan-800 border-cyan-200',
  'Collection':            'bg-teal-100 text-teal-800 border-teal-200',
  'Exfiltration':          'bg-rose-100 text-rose-800 border-rose-200',
  'Command and Control':   'bg-indigo-100 text-indigo-800 border-indigo-200',
  'Impact':                'bg-red-100 text-red-800 border-red-200',
  'Unknown':               'bg-slate-100 text-slate-600 border-slate-200',
};

const ALL_TACTICS = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];

// ── connector tab types ───────────────────────────────────────────────────────

type Tab = 'splunk' | 'elastic' | 'cloudtrail' | 'dnif' | 'raw';

const TABS: { id: Tab; label: string; badge?: string }[] = [
  { id: 'splunk',      label: 'Splunk' },
  { id: 'elastic',     label: 'Elasticsearch' },
  { id: 'cloudtrail',  label: 'AWS CloudTrail' },
  { id: 'dnif',        label: 'DNIF Hypercloud' },
  { id: 'raw',         label: 'Paste Logs',    badge: 'syslog · CEF' },
];

// ── connector forms ───────────────────────────────────────────────────────────

function SplunkForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [url, setUrl]       = useState('');
  const [token, setToken]   = useState('');
  const [query, setQuery]   = useState('index=* sourcetype=syslog earliest=-1h');
  const [limit, setLimit]   = useState('500');
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState('');

  const run = async () => {
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/api/integrations/splunk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, token, query, limit: parseInt(limit) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      onResult(data);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      <Field label="Splunk URL" hint="e.g. https://splunk.company.com:8089">
        <input value={url} onChange={e => setUrl(e.target.value)}
          placeholder="https://splunk.company.com:8089"
          className="input" />
      </Field>
      <Field label="Bearer Token" hint="Settings → Tokens in Splunk Web">
        <input value={token} onChange={e => setToken(e.target.value)} type="password"
          placeholder="••••••••••••••••"
          className="input" />
      </Field>
      <Field label="SPL Query">
        <input value={query} onChange={e => setQuery(e.target.value)}
          className="input font-mono text-sm" />
      </Field>
      <Field label="Max events">
        <input value={limit} onChange={e => setLimit(e.target.value)} type="number"
          className="input w-32" />
      </Field>
      {error && <ErrorMsg msg={error} />}
      <RunBtn loading={loading} onClick={run} disabled={!url || !token} />
    </div>
  );
}

function ElasticForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [url, setUrl]         = useState('');
  const [apiKey, setApiKey]   = useState('');
  const [user, setUser]       = useState('');
  const [pass, setPass]       = useState('');
  const [index, setIndex]     = useState('logs-*');
  const [query, setQuery]     = useState('');
  const [limit, setLimit]     = useState('500');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const run = async () => {
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/api/integrations/elastic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url, api_key: apiKey, username: user, password: pass,
          index, query, limit: parseInt(limit),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      onResult(data);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      <Field label="Elasticsearch URL">
        <input value={url} onChange={e => setUrl(e.target.value)}
          placeholder="https://my-cluster.es.io:9200"
          className="input" />
      </Field>
      <Field label="API Key" hint="Kibana → Stack Management → API keys (or leave blank for basic auth)">
        <input value={apiKey} onChange={e => setApiKey(e.target.value)} type="password"
          placeholder="base64-encoded API key"
          className="input" />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username (optional)">
          <input value={user} onChange={e => setUser(e.target.value)} className="input" />
        </Field>
        <Field label="Password (optional)">
          <input value={pass} onChange={e => setPass(e.target.value)} type="password" className="input" />
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Index pattern">
          <input value={index} onChange={e => setIndex(e.target.value)} className="input font-mono text-sm" />
        </Field>
        <Field label="Max documents">
          <input value={limit} onChange={e => setLimit(e.target.value)} type="number" className="input w-full" />
        </Field>
      </div>
      <Field label="Lucene query" hint="Leave blank to match all">
        <input value={query} onChange={e => setQuery(e.target.value)}
          placeholder='event.category:process OR event.category:network'
          className="input font-mono text-sm" />
      </Field>
      {error && <ErrorMsg msg={error} />}
      <RunBtn loading={loading} onClick={run} disabled={!url} />
    </div>
  );
}

function CloudTrailForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [text, setText]       = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const run = async () => {
    setLoading(true); setError('');
    try {
      let parsed: any;
      try { parsed = JSON.parse(text); }
      catch { throw new Error('Invalid JSON — paste a CloudTrail file with a Records[] array'); }

      const res = await fetch(`${API_URL}/api/integrations/cloudtrail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: parsed }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      onResult(data);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500">
        Paste the contents of a CloudTrail JSON file — the{' '}
        <code className="bg-slate-100 px-1 rounded text-xs">Records[]</code> format from S3 or CloudTrail Lake export.
        The parser extracts event name, source, user identity, and source IP.
      </p>
      <Field label="CloudTrail JSON">
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={10}
          placeholder={'{\n  "Records": [\n    {\n      "eventTime": "2025-01-15T...",\n      "eventName": "ConsoleLogin",\n      ...\n    }\n  ]\n}'}
          className="input font-mono text-xs leading-relaxed resize-y"
        />
      </Field>
      {error && <ErrorMsg msg={error} />}
      <RunBtn loading={loading} onClick={run} disabled={!text.trim()} />
    </div>
  );
}

function RawForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [text, setText]       = useState('');
  const [fmt, setFmt]         = useState('auto');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const run = async () => {
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/api/integrations/raw`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: text, format: fmt }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      onResult(data);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500">
        Paste logs directly — one event per line. Supports plain syslog, ArcSight CEF, and freeform text.
        No need to save to a file first.
      </p>
      <div className="flex gap-3 items-center">
        <span className="text-sm text-slate-600">Format</span>
        {['auto', 'syslog', 'cef', 'text'].map(f => (
          <button key={f} onClick={() => setFmt(f)}
            className={`px-3 py-1 rounded text-xs font-mono font-medium border transition-colors ${
              fmt === f ? 'bg-slate-900 text-white border-slate-900' : 'bg-white text-slate-600 border-slate-200 hover:border-slate-400'
            }`}>
            {f}
          </button>
        ))}
      </div>
      <Field label="Paste logs here">
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={12}
          placeholder={`Jan 15 09:00:01 server sshd[1234]: Failed password for root from 192.168.1.1 port 22\nJan 15 09:00:45 server sudo: admin : command not allowed ; TTY=pts/0 ; COMMAND=/bin/bash\nCEF:0|Microsoft|Defender|1.0|1001|Malware Detected|8|src=10.0.0.5 fname=malware.exe`}
          className="input font-mono text-xs leading-relaxed resize-y"
        />
      </Field>
      {error && <ErrorMsg msg={error} />}
      <RunBtn loading={loading} onClick={run} disabled={!text.trim()} />
    </div>
  );
}

function DNIFForm({ onResult }: { onResult: (r: AnalysisResult) => void }) {
  const [url, setUrl]         = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [query, setQuery]     = useState('stream=AUTHENTICATION fetch last 1h');
  const [limit, setLimit]     = useState('500');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const run = async () => {
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/api/integrations/dnif`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, username, password, query, limit: parseInt(limit) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      onResult(data);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-500">
        Connect to your DNIF Hypercloud instance using the console URL and credentials.
        Queries use{' '}
        <span className="font-mono text-xs bg-slate-100 px-1 rounded">DQL</span>
        {' '}— DNIF&apos;s native query language.
      </p>
      <Field label="DNIF Console URL" hint="e.g. https://tenant.hypercloud.dnif.in">
        <input value={url} onChange={e => setUrl(e.target.value)}
          placeholder="https://tenant.hypercloud.dnif.in"
          className="input" />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username">
          <input value={username} onChange={e => setUsername(e.target.value)}
            placeholder="admin"
            className="input" />
        </Field>
        <Field label="Password">
          <input value={password} onChange={e => setPassword(e.target.value)} type="password"
            placeholder="••••••••••••••••"
            className="input" />
        </Field>
      </div>
      <Field label="DQL Query" hint="stream · fetch · filter">
        <input value={query} onChange={e => setQuery(e.target.value)}
          className="input font-mono text-sm" />
      </Field>
      <Field label="Max events">
        <input value={limit} onChange={e => setLimit(e.target.value)} type="number"
          className="input w-32" />
      </Field>
      {error && <ErrorMsg msg={error} />}
      <RunBtn loading={loading} onClick={run} disabled={!url || !username || !password} />
    </div>
  );
}

// ── small shared components ───────────────────────────────────────────────────

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 mb-1">
        {label}
        {hint && <span className="font-normal text-slate-400 ml-2 text-xs">{hint}</span>}
      </label>
      {children}
    </div>
  );
}

function ErrorMsg({ msg }: { msg: string }) {
  return (
    <div className="flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg">
      <AlertCircle className="w-4 h-4 text-red-600 mt-0.5 shrink-0" />
      <p className="text-sm text-red-800">{msg}</p>
    </div>
  );
}

function RunBtn({ loading, onClick, disabled }: { loading: boolean; onClick: () => void; disabled: boolean }) {
  return (
    <button onClick={onClick} disabled={loading || disabled}
      className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white font-semibold py-2.5 px-6 rounded-lg flex items-center gap-2 transition-colors text-sm">
      {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing…</> : <><Target className="w-4 h-4" /> Fetch &amp; Analyze</>}
    </button>
  );
}

// ── ATT&CK heatmap ────────────────────────────────────────────────────────────

function AttackHeatmap({ techniques }: { techniques: MitreTechnique[] }) {
  const byTactic: Record<string, MitreTechnique[]> = {};
  ALL_TACTICS.forEach(t => { byTactic[t] = []; });
  techniques.forEach(t => { if (byTactic[t.tactic]) byTactic[t.tactic].push(t); });
  const covered = ALL_TACTICS.filter(t => byTactic[t].length > 0).length;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-slate-500">
          {covered} of {ALL_TACTICS.length} tactics covered
        </p>
      </div>
      <div className="overflow-x-auto pb-2">
        <div className="flex gap-2 min-w-max">
          {ALL_TACTICS.map(tactic => {
            const hits = byTactic[tactic];
            const active = hits.length > 0;
            return (
              <div key={tactic}
                className={`w-36 rounded-lg border p-2.5 transition-colors ${active ? 'bg-red-50 border-red-200' : 'bg-slate-50 border-slate-200'}`}>
                <p className={`text-xs font-semibold mb-2 leading-tight ${active ? 'text-red-700' : 'text-slate-400'}`}>
                  {tactic}
                </p>
                {hits.length === 0 && (
                  <p className="text-xs text-slate-300 italic">—</p>
                )}
                {hits.map(t => (
                  <div key={t.id} className="bg-red-600 rounded px-1.5 py-1 mb-1">
                    <p className="text-xs font-mono font-bold text-white">{t.id}</p>
                    <p className="text-xs text-red-100 truncate">{t.name}</p>
                    <p className="text-xs text-red-200">{t.count} event{t.count !== 1 ? 's' : ''}</p>
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

// ── results ───────────────────────────────────────────────────────────────────

function Results({ result, onReset }: { result: AnalysisResult; onReset: () => void }) {
  const [tab, setTab] = useState<'heatmap' | 'timeline' | 'techniques'>('heatmap');
  const tactics = new Set(result.mitre_techniques.map(t => t.tactic)).size;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Analysis complete</h2>
          <p className="text-sm text-slate-500 mt-0.5 font-mono">{result.incident_id}</p>
        </div>
        <button onClick={onReset} className="text-sm text-slate-500 hover:text-slate-900 flex items-center gap-1">
          <X className="w-4 h-4" /> New analysis
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { icon: FileText,  label: 'Events parsed',    value: result.events_parsed,           color: 'text-blue-600 bg-blue-50' },
          { icon: Target,    label: 'Techniques found',  value: result.mitre_techniques.length, color: 'text-purple-600 bg-purple-50' },
          { icon: Clock,     label: 'Tactics covered',   value: tactics,                        color: 'text-green-600 bg-green-50' },
        ].map(({ icon: Icon, label, value, color }) => (
          <div key={label} className="bg-white border border-slate-200 rounded-xl p-4">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-3 ${color}`}>
              <Icon className="w-4 h-4" />
            </div>
            <p className="text-2xl font-bold text-slate-900">{value}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* Exports */}
      <div className="flex gap-2">
        {(['pdf', 'json', 'csv'] as const).map(fmt => (
          <a key={fmt} href={`${API_URL}/api/download/${result.incident_id}/${fmt}`} target="_blank" rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-2 bg-white border border-slate-200 hover:border-blue-400 rounded-lg text-sm font-medium text-slate-700 hover:text-blue-600 transition-colors">
            <Download className="w-3.5 h-3.5" />
            {fmt.toUpperCase()}
          </a>
        ))}
      </div>

      {/* Tabs */}
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

        <div className="p-5">
          {tab === 'heatmap' && <AttackHeatmap techniques={result.mitre_techniques} />}

          {tab === 'techniques' && (
            <div className="space-y-2">
              {result.mitre_techniques.map(t => (
                <div key={t.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${TACTIC_COLORS[t.tactic] || TACTIC_COLORS.Unknown}`}>
                      {t.id}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-slate-900">{t.name}</p>
                      <p className="text-xs text-slate-500">{t.tactic}</p>
                    </div>
                  </div>
                  <span className="text-sm font-medium text-slate-600">{t.count} events</span>
                </div>
              ))}
            </div>
          )}

          {tab === 'timeline' && (
            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {result.events.map((event, idx) => (
                <div key={event.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                    {idx < result.events.length - 1 && <div className="w-px flex-1 bg-slate-200 my-1" />}
                  </div>
                  <div className="flex-1 pb-3">
                    <p className="text-sm text-slate-900">{event.description}</p>
                    <div className="flex items-center gap-2 mt-1 flex-wrap text-xs text-slate-400">
                      <span>{event.timestamp}</span>
                      <span>·</span>
                      <span className="font-mono">{event.source}</span>
                      {event.mitre_technique_id && (
                        <>
                          <span>·</span>
                          <span className={`px-1.5 py-0.5 rounded font-mono font-bold border ${TACTIC_COLORS[event.mitre_tactic] || TACTIC_COLORS.Unknown}`}>
                            {event.mitre_technique_id}
                          </span>
                        </>
                      )}
                      {event.confidence > 0 && (
                        <span className="bg-slate-100 px-1.5 rounded text-slate-500">{event.confidence}%</span>
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

// ── page ──────────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('splunk');
  const [result, setResult] = useState<AnalysisResult | null>(null);

  if (result) {
    return (
      <div className="min-h-screen bg-white">
        <Header />
        <main className="max-w-5xl mx-auto px-6 py-10">
          <Results result={result} onReset={() => setResult(null)} />
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white">
      <Header />
      <main className="max-w-3xl mx-auto px-6 py-12">
        <div className="mb-10">
          <h1 className="text-2xl font-bold text-slate-900 mb-2">Log Integrations</h1>
          <p className="text-slate-500">
            Pull logs directly from your existing infrastructure — no file exports, no copy-paste from dashboards.
            Connect once, get a full MITRE ATT&CK timeline in seconds.
          </p>
        </div>

        {/* Source tabs */}
        <div className="flex gap-1 mb-6 border-b border-slate-200">
          {TABS.map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2 ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}>
              {tab.label}
              {tab.badge && (
                <span className="text-xs text-slate-400 font-normal font-mono">{tab.badge}</span>
              )}
            </button>
          ))}
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-6">
          {activeTab === 'splunk'     && <SplunkForm      onResult={setResult} />}
          {activeTab === 'elastic'    && <ElasticForm     onResult={setResult} />}
          {activeTab === 'cloudtrail' && <CloudTrailForm  onResult={setResult} />}
          {activeTab === 'dnif'       && <DNIFForm        onResult={setResult} />}
          {activeTab === 'raw'        && <RawForm         onResult={setResult} />}
        </div>

        <p className="mt-5 text-xs text-slate-400">
          Credentials are sent directly to your backend — never stored or logged.
          The backend is{' '}
          <a href="https://github.com/soham7998/MITRE_Incident_Mapper" className="underline hover:text-slate-700">
            open source
          </a>.
        </p>
      </main>
    </div>
  );
}

function Header() {
  return (
    <header className="border-b border-slate-200 bg-white sticky top-0 z-10">
      <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-semibold text-slate-900">MITRE Incident Mapper</span>
          <span className="text-slate-300">/</span>
          <span className="text-slate-500 text-sm">Integrations</span>
        </div>
        <Link href="/" className="flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to app
        </Link>
      </div>
    </header>
  );
}
