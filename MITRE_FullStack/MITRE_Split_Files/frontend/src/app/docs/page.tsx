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
          <div className="flex items-center gap-4">
            <Link href="/integrations" className="text-sm text-slate-500 hover:text-slate-900 transition-colors">
              Integrations
            </Link>
            <Link href="/" className="flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900 transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" />
              Back to app
            </Link>
          </div>
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
              Max file size: <strong>15 MB</strong>.
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

        <Section title="Integrations">
          <p className="text-sm text-slate-600 mb-6">
            All integration endpoints accept <code className="bg-slate-100 px-1 rounded">application/json</code> and return
            the same response shape as <code className="bg-slate-100 px-1 rounded">/api/analyze</code>.
            Credentials are never stored — they are used only for the duration of the request.
          </p>

          <Endpoint method="POST" path="/api/integrations/splunk" description="Query a Splunk search head via its REST API.">
            <Code>{`curl -X POST ${BASE_URL}/api/integrations/splunk \\
  -H "Content-Type: application/json" \\
  -d '{
    "url":   "https://splunk.company.com:8089",
    "token": "your-bearer-token",
    "query": "index=* sourcetype=syslog earliest=-1h",
    "limit": 500
  }'`}</Code>
          </Endpoint>

          <Endpoint method="POST" path="/api/integrations/elastic" description="Search an Elasticsearch or OpenSearch index.">
            <Code>{`curl -X POST ${BASE_URL}/api/integrations/elastic \\
  -H "Content-Type: application/json" \\
  -d '{
    "url":     "https://my-cluster.es.io:9200",
    "api_key": "base64-api-key",
    "index":   "logs-*",
    "query":   "event.category:process",
    "limit":   500
  }'`}</Code>
            <p className="text-xs text-slate-500 mt-2">Use <code className="bg-slate-100 px-1 rounded">username</code> + <code className="bg-slate-100 px-1 rounded">password</code> instead of <code className="bg-slate-100 px-1 rounded">api_key</code> for basic auth.</p>
          </Endpoint>

          <Endpoint method="POST" path="/api/integrations/cloudtrail" description="Analyze AWS CloudTrail Records[] JSON directly.">
            <Code>{`curl -X POST ${BASE_URL}/api/integrations/cloudtrail \\
  -H "Content-Type: application/json" \\
  -d '{ "logs": { "Records": [ ... ] } }'

# or upload a CloudTrail .json file
curl -X POST ${BASE_URL}/api/integrations/cloudtrail \\
  -F "file=@cloudtrail-2025-01-15.json"`}</Code>
          </Endpoint>

          <Endpoint method="POST" path="/api/integrations/raw" description="Paste raw syslog, CEF, LEEF, or plain text logs directly.">
            <Code>{`curl -X POST ${BASE_URL}/api/integrations/raw \\
  -H "Content-Type: application/json" \\
  -d '{
    "format": "syslog",
    "logs": "Jan 15 09:00:01 server sshd[1234]: Failed password for root\\nJan 15 09:01:23 server sudo: COMMAND=/bin/bash"
  }'`}</Code>
            <p className="text-xs text-slate-500 mt-2"><code className="bg-slate-100 px-1 rounded">format</code> accepts <code className="bg-slate-100 px-1 rounded">auto</code>, <code className="bg-slate-100 px-1 rounded">syslog</code>, <code className="bg-slate-100 px-1 rounded">cef</code>, or <code className="bg-slate-100 px-1 rounded">text</code>. CEF lines starting with <code className="bg-slate-100 px-1 rounded">CEF:</code> are auto-detected.</p>
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
                ['413', 'File too large. Maximum upload size is 15 MB.'],
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

      <footer className="border-t border-slate-700 mt-8 bg-slate-900">
        <div className="max-w-4xl mx-auto px-6 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <a
              href="https://linkedin.com/in/shahsoham2003"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-slate-400 hover:text-blue-400 transition-colors text-sm"
            >
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4">
                <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 0 1-2.063-2.065 2.064 2.064 0 1 1 2.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
              </svg>
              LinkedIn
            </a>
            <div className="text-center">
              <p className="text-slate-200 font-semibold tracking-wide text-sm">MITRE Incident Mapper</p>
              <p className="text-slate-500 text-xs mt-0.5">v2.0.0</p>
            </div>
            <a
              href="mailto:soham27@somaiya.edu"
              className="flex items-center gap-2 text-slate-400 hover:text-blue-400 transition-colors text-sm"
            >
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4">
                <path d="M1.5 8.67v8.58a3 3 0 0 0 3 3h15a3 3 0 0 0 3-3V8.67l-8.928 5.493a3 3 0 0 1-3.144 0L1.5 8.67z"/>
                <path d="M22.5 6.908V6.75a3 3 0 0 0-3-3h-15a3 3 0 0 0-3 3v.158l9.714 5.978a1.5 1.5 0 0 0 1.572 0L22.5 6.908z"/>
              </svg>
              soham27@somaiya.edu
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}
