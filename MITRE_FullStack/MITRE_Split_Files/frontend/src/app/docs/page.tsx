import type { Metadata } from 'next';
import Link from 'next/link';
import { Shield, ArrowLeft } from 'lucide-react';

export const metadata: Metadata = {
  title: 'API Docs — MITRE Incident Mapper',
  description: 'API reference for the MITRE Incident Mapper backend',
};

const BASE_URL = 'https://mitreincident-product.up.railway.app';

function Method({ type }: { type: string }) {
  const colors: Record<string, string> = {
    GET: 'bg-blue-100 text-blue-700',
    POST: 'bg-green-100 text-green-700',
  };
  return (
    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${colors[type]}`}>
      {type}
    </span>
  );
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <pre className="bg-slate-900 text-slate-100 rounded-lg p-4 text-sm font-mono overflow-x-auto leading-relaxed">
      {children}
    </pre>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2 className="text-lg font-semibold text-slate-900 mb-5 pb-2 border-b border-slate-200">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Endpoint({
  method,
  path,
  description,
  children,
}: {
  method: string;
  path: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-8">
      <div className="flex items-center gap-3 mb-2">
        <Method type={method} />
        <code className="text-sm font-mono text-slate-800">{path}</code>
      </div>
      <p className="text-sm text-slate-600 mb-4">{description}</p>
      {children}
    </div>
  );
}

function Field({ name, type, desc }: { name: string; type: string; desc: string }) {
  return (
    <tr className="border-t border-slate-100">
      <td className="py-2 pr-4 font-mono text-sm text-slate-800">{name}</td>
      <td className="py-2 pr-4 text-xs text-slate-500">{type}</td>
      <td className="py-2 text-sm text-slate-600">{desc}</td>
    </tr>
  );
}

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-white">
      <header className="border-b border-slate-200 bg-white sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-blue-600 to-blue-800 rounded-lg flex items-center justify-center">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="font-semibold text-slate-900">MITRE Incident Mapper</span>
            <span className="text-slate-300">/</span>
            <span className="text-slate-500 text-sm">API Docs</span>
          </div>
          <Link
            href="/"
            className="flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to app
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12">
        <div className="mb-12">
          <h1 className="text-3xl font-bold text-slate-900 mb-3">API Reference</h1>
          <p className="text-slate-500 text-sm">
            Base URL:{' '}
            <code className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700 font-mono">
              {BASE_URL}
            </code>
          </p>
          <p className="text-slate-500 text-sm mt-1">No authentication required.</p>
        </div>

        <Section title="Endpoints">
          {/* Health */}
          <Endpoint method="GET" path="/api/health" description="Check if the API is up.">
            <Code>{`curl ${BASE_URL}/api/health`}</Code>
            <div className="mt-3">
              <Code>{`{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00.000000",
  "incidents_loaded": 3
}`}</Code>
            </div>
          </Endpoint>

          {/* Analyze */}
          <Endpoint
            method="POST"
            path="/api/analyze"
            description="Upload a log file and get MITRE ATT&CK technique mappings back."
          >
            <p className="text-xs text-slate-500 mb-2">
              Accepts <code className="bg-slate-100 px-1 rounded">multipart/form-data</code>.
              Supported formats: <code className="bg-slate-100 px-1 rounded">.csv</code>{' '}
              <code className="bg-slate-100 px-1 rounded">.json</code>{' '}
              <code className="bg-slate-100 px-1 rounded">.txt</code>{' '}
              <code className="bg-slate-100 px-1 rounded">.log</code>.{' '}
              Max file size: <strong>10 MB</strong>.
            </p>
            <Code>{`curl -X POST ${BASE_URL}/api/analyze \\
  -F "file=@incident.csv"`}</Code>

            <div className="mt-4 mb-2 text-xs font-medium text-slate-500 uppercase tracking-wide">
              Response
            </div>
            <Code>{`{
  "incident_id": "INC-20250115103000-a1b2c3d4",
  "events_parsed": 42,
  "mitre_techniques": [
    {
      "id": "T1078",
      "tactic": "Initial Access",
      "name": "Valid Accounts",
      "count": 5
    }
  ],
  "events": [
    {
      "id": 1,
      "timestamp": "2025-01-15T09:00:00",
      "source": "auth.log",
      "description": "Failed login attempt for root",
      "mitre_tactic": "Credential Access",
      "mitre_technique_id": "T1110",
      "mitre_technique_name": "Brute Force",
      "confidence": 87.5
    }
  ]
}`}</Code>

            <div className="mt-4">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-2">
                CSV format
              </p>
              <Code>{`timestamp,source,description
2025-01-15T09:00:00,auth.log,Failed login attempt for root
2025-01-15T09:01:23,syslog,New cron job added by user admin`}</Code>
            </div>
          </Endpoint>

          {/* Get incident */}
          <Endpoint
            method="GET"
            path="/api/incident/:id"
            description="Retrieve a previously analyzed incident by its ID."
          >
            <Code>{`curl ${BASE_URL}/api/incident/INC-20250115103000-a1b2c3d4`}</Code>
            <p className="text-xs text-slate-500 mt-2">
              Returns the same shape as <code className="bg-slate-100 px-1 rounded">/api/analyze</code>, plus{' '}
              <code className="bg-slate-100 px-1 rounded">filename</code> and{' '}
              <code className="bg-slate-100 px-1 rounded">created_at</code>.
              Incidents are held in memory — they disappear on server restart.
            </p>
          </Endpoint>

          {/* Download */}
          <Endpoint
            method="GET"
            path="/api/download/:id/:format"
            description="Download the incident report. Format is pdf, json, or csv."
          >
            <Code>{`# PDF
curl -O ${BASE_URL}/api/download/INC-20250115103000-a1b2c3d4/pdf

# JSON
curl -O ${BASE_URL}/api/download/INC-20250115103000-a1b2c3d4/json

# CSV
curl -O ${BASE_URL}/api/download/INC-20250115103000-a1b2c3d4/csv`}</Code>
          </Endpoint>
        </Section>

        <Section title="Response fields">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th className="pb-2 text-xs font-medium text-slate-400 uppercase tracking-wide">Field</th>
                <th className="pb-2 text-xs font-medium text-slate-400 uppercase tracking-wide">Type</th>
                <th className="pb-2 text-xs font-medium text-slate-400 uppercase tracking-wide">Notes</th>
              </tr>
            </thead>
            <tbody>
              <Field name="incident_id" type="string" desc="Unique ID for this analysis run. Use it to download reports." />
              <Field name="events_parsed" type="number" desc="Total log entries processed." />
              <Field name="mitre_techniques" type="array" desc="Deduplicated list of techniques found, with event counts." />
              <Field name="events" type="array" desc="Every event with its mapping result and confidence score (0–100)." />
              <Field name="confidence" type="number" desc="How closely the log line matched the technique pattern. Above 70 is a solid match." />
            </tbody>
          </table>
        </Section>

        <Section title="Errors">
          <table className="w-full text-left">
            <thead>
              <tr>
                <th className="pb-2 text-xs font-medium text-slate-400 uppercase tracking-wide">Status</th>
                <th className="pb-2 text-xs font-medium text-slate-400 uppercase tracking-wide">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['400', 'Bad request — missing file, wrong format, or unparseable content.'],
                ['404', 'Incident ID not found (or server restarted and lost it).'],
                ['413', 'File too large. Maximum upload size is 10 MB.'],
                ['500', 'Something broke on our end. Try again.'],
              ].map(([code, msg]) => (
                <tr key={code} className="border-t border-slate-100">
                  <td className="py-2 pr-6 font-mono text-sm text-slate-800">{code}</td>
                  <td className="py-2 text-sm text-slate-600">{msg}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-4">
            <Code>{`{ "error": "Could not parse file" }`}</Code>
          </div>
        </Section>

        <Section title="Quick start">
          <Code>{`# 1. Check the API is up
curl ${BASE_URL}/api/health

# 2. Analyze a log file
curl -X POST ${BASE_URL}/api/analyze -F "file=@your_logs.csv"

# 3. Download the PDF report using the incident_id from step 2
curl -O ${BASE_URL}/api/download/<incident_id>/pdf`}</Code>
        </Section>
      </main>

      <footer className="border-t border-slate-200 mt-8">
        <div className="max-w-4xl mx-auto px-6 py-5 text-sm text-slate-400">
          Built by{' '}
          <a href="https://linkedin.com/in/shahsoham2003" className="text-blue-600 hover:underline">
            Soham Shah
          </a>
        </div>
      </footer>
    </div>
  );
}
