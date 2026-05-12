"""
MITRE ATT&CK Incident Mapper - Backend API
Deployed on Railway.app
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import json
import csv
import re
import requests as req
from datetime import datetime
import time
from io import BytesIO, StringIO
import uuid
from urllib.parse import urlparse

from src.mitre_mapper import MitreMapper
from src.timeline_builder import TimelineBuilder, ReportGenerator

incidents = {}

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 15 * 1024 * 1024  # 15 MB

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "http://localhost:5173",
            "https://*.vercel.app",
            "https://mitre-incident-mapper.vercel.app",
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

mapper = MitreMapper()
timeline_builder = TimelineBuilder()
report_generator = ReportGenerator()

# ============================================================================
# PARSERS
# ============================================================================

def parse_csv(file_content):
    try:
        reader = csv.DictReader(StringIO(file_content.decode('utf-8')))
        return [row for row in reader]
    except Exception:
        return None

def parse_json(file_content):
    try:
        data = json.loads(file_content.decode('utf-8'))
        return data if isinstance(data, list) else [data]
    except Exception:
        return None

def parse_syslog(file_content):
    lines = file_content.decode('utf-8').split('\n')
    return [
        {'timestamp': datetime.now().isoformat(), 'source': 'syslog', 'description': line}
        for line in lines if line.strip()
    ]

def parse_cloudtrail(data):
    """Parse AWS CloudTrail Records[] format."""
    records = data if isinstance(data, list) else data.get('Records', [])
    events = []
    for r in records:
        desc_parts = [r.get('eventName', ''), r.get('eventSource', '')]
        resources = r.get('requestParameters') or {}
        if isinstance(resources, dict):
            desc_parts.append(' '.join(str(v) for v in resources.values() if v))
        error = r.get('errorMessage') or r.get('errorCode', '')
        if error:
            desc_parts.append(error)
        events.append({
            'timestamp': r.get('eventTime', datetime.now().isoformat()),
            'source': r.get('eventSource', 'cloudtrail'),
            'description': ' '.join(p for p in desc_parts if p),
            'user': (r.get('userIdentity') or {}).get('arn', ''),
            'region': r.get('awsRegion', ''),
            'sourceIPAddress': r.get('sourceIPAddress', ''),
        })
    return events

def parse_cef(text):
    """Parse ArcSight CEF format: CEF:version|vendor|product|...|extensions"""
    events = []
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('CEF:'):
            parts = line.split('|', 7)
            name = parts[4] if len(parts) > 4 else line
            ext = parts[7] if len(parts) > 7 else ''
            ts_match = re.search(r'rt=(\d+)', ext)
            ts = datetime.fromtimestamp(int(ts_match.group(1)) / 1000).isoformat() if ts_match else datetime.now().isoformat()
            src = re.search(r'src=([^\s]+)', ext)
            events.append({
                'timestamp': ts,
                'source': src.group(1) if src else (parts[1] if len(parts) > 1 else 'cef'),
                'description': f"{name} {ext}",
            })
        else:
            events.append({
                'timestamp': datetime.now().isoformat(),
                'source': 'log',
                'description': line,
            })
    return events

def extract_timestamp(event):
    for key in ['timestamp', 'time', 'date', 'datetime', '_time', 'Timestamp', 'eventTime', '@timestamp']:
        if key in event:
            return event[key]
    return datetime.now().isoformat()

def extract_description(event):
    for key in ['message', 'description', 'event', 'detail', 'text', 'event_description', 'Message', '_raw', 'log']:
        if key in event and event[key]:
            return str(event[key])
    return ' '.join([str(v) for v in event.values() if v])

# ============================================================================
# CORE PROCESSING
# ============================================================================

def process_events(events, source_label='file', filename=None):
    """Run MITRE mapping on a list of events and return the full analysis result."""
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
    processed_events = []
    mitre_techniques = {}

    for idx, event in enumerate(events):
        timestamp = extract_timestamp(event) if isinstance(event, dict) else datetime.now().isoformat()
        description = extract_description(event) if isinstance(event, dict) else str(event)
        src = event.get('source', source_label) if isinstance(event, dict) else source_label
        match = mapper.find_technique(description)

        processed = {
            'id': idx + 1,
            'timestamp': timestamp,
            'source': src,
            'description': description,
            'mitre_tactic': match.tactic if match else 'Unknown',
            'mitre_technique_id': match.technique_id if match else None,
            'mitre_technique_name': match.technique_name if match else None,
            'mitre_subtechnique': match.subtechnique if match else None,
            'confidence': round(match.confidence * 100, 1) if match else 0,
        }
        processed_events.append(processed)

        if match:
            key = match.technique_id
            if key not in mitre_techniques:
                mitre_techniques[key] = {
                    'id': key, 'tactic': match.tactic,
                    'name': match.technique_name, 'count': 0
                }
            mitre_techniques[key]['count'] += 1

    timeline = timeline_builder.build_timeline(processed_events)

    incidents[incident_id] = {
        'incident_id': incident_id,
        'source': source_label,
        'filename': filename or source_label,
        'created_at': datetime.now().isoformat(),
        'events': processed_events,
        'timeline': timeline,
        'mitre_techniques': list(mitre_techniques.values()),
    }

    return jsonify({
        'incident_id': incident_id,
        'events_parsed': len(processed_events),
        'mitre_techniques': list(mitre_techniques.values()),
        'timeline': timeline,
        'events': processed_events,
    }), 200

# ============================================================================
# CORE ROUTES
# ============================================================================

@app.route('/')
def root():
    return jsonify({
        'service': 'MITRE Incident Mapper API',
        'version': '1.3.0',
        'status': 'running',
        'endpoints': {
            'analyze':            'POST /api/analyze',
            'incident':           'GET  /api/incident/<id>',
            'download':           'GET  /api/download/<id>/<format>',
            'health':             'GET  /api/health',
            'splunk':             'POST /api/integrations/splunk',
            'elasticsearch':      'POST /api/integrations/elastic',
            'cloudtrail':         'POST /api/integrations/cloudtrail',
            'raw':                'POST /api/integrations/raw',
            'dnif':               'POST /api/integrations/dnif',
        },
        'frontend': 'https://mitre-incident-mapper.vercel.app'
    })

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'incidents_in_memory': len(incidents)
    })

@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    if request.method == 'OPTIONS':
        return '', 204

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = file.filename.lower()
    file_content = file.read()

    if filename.endswith('.csv'):
        events = parse_csv(file_content)
    elif filename.endswith('.json'):
        raw = parse_json(file_content)
        # Detect CloudTrail format automatically
        if raw and isinstance(raw, list) and len(raw) == 1 and 'Records' in raw[0]:
            events = parse_cloudtrail(raw[0])
        elif raw and isinstance(raw, dict) and 'Records' in raw:
            events = parse_cloudtrail(raw)
        else:
            events = raw
    elif filename.endswith('.txt') or filename.endswith('.log'):
        events = parse_syslog(file_content)
    else:
        return jsonify({'error': 'Unsupported format. Use .csv, .json, .txt, or .log'}), 400

    if not events:
        return jsonify({'error': 'Could not parse file'}), 400

    return process_events(events, source_label='file', filename=file.filename)

@app.route('/api/incident/<incident_id>')
def get_incident(incident_id):
    doc = incidents.get(incident_id)
    if not doc:
        return jsonify({'error': 'Incident not found'}), 404
    return jsonify(doc), 200

@app.route('/api/download/<incident_id>/<format>')
def download(incident_id, format):
    incident = incidents.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    if format == 'json':
        return send_file(
            BytesIO(json.dumps(incident, indent=2).encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'{incident_id}.json'
        )

    elif format == 'csv':
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=[
            'Timestamp', 'Source', 'Description', 'MITRE Tactic',
            'MITRE Technique ID', 'MITRE Technique', 'Confidence'
        ])
        writer.writeheader()
        for event in incident['events']:
            writer.writerow({
                'Timestamp': event['timestamp'],
                'Source': event['source'],
                'Description': event['description'],
                'MITRE Tactic': event['mitre_tactic'],
                'MITRE Technique ID': event['mitre_technique_id'] or '',
                'MITRE Technique': event['mitre_technique_name'] or '',
                'Confidence': f"{event['confidence']}%",
            })
        return send_file(
            BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'{incident_id}.csv'
        )

    elif format == 'pdf':
        pdf_bytes = report_generator.generate_pdf(incident)
        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'{incident_id}.pdf'
        )

    return jsonify({'error': 'Unsupported format'}), 400

# ============================================================================
# INTEGRATIONS
# ============================================================================

@app.route('/api/integrations/splunk', methods=['POST', 'OPTIONS'])
def integrate_splunk():
    """Query a Splunk instance via its REST API and run MITRE analysis."""
    if request.method == 'OPTIONS':
        return '', 204

    body = request.get_json() or {}
    splunk_url = (body.get('url') or '').rstrip('/')
    token = body.get('token') or ''
    query = body.get('query') or 'index=* earliest=-1h'
    limit = min(int(body.get('limit') or 500), 2000)

    if not splunk_url or not token:
        return jsonify({'error': 'url and token are required'}), 400

    headers = {'Authorization': f'Bearer {token}'}

    try:
        resp = req.post(
            f"{splunk_url}/services/search/jobs/export",
            headers=headers,
            data={
                'search': f'search {query}',
                'output_mode': 'json',
                'count': limit,
            },
            verify=False,
            timeout=30,
            stream=True,
        )

        if resp.status_code == 401:
            return jsonify({'error': 'Splunk authentication failed. Check your token.'}), 401
        if resp.status_code == 403:
            return jsonify({'error': 'Splunk permission denied for this query.'}), 403

        events = []
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                obj = json.loads(line)
                r = obj.get('result')
                if not r:
                    continue
                events.append({
                    'timestamp': r.get('_time', datetime.now().isoformat()),
                    'source': r.get('host', r.get('source', 'splunk')),
                    'description': r.get('_raw', r.get('message', str(r))),
                })
            except Exception:
                continue

        if not events:
            return jsonify({'error': 'No events returned. Check your query and time range.'}), 400

        return process_events(events, source_label='splunk')

    except req.exceptions.ConnectionError:
        return jsonify({'error': f'Could not connect to {splunk_url}. Check the URL and network.'}), 502
    except req.exceptions.Timeout:
        return jsonify({'error': 'Splunk query timed out after 30s.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/integrations/elastic', methods=['POST', 'OPTIONS'])
def integrate_elastic():
    """Query an Elasticsearch / OpenSearch index and run MITRE analysis."""
    if request.method == 'OPTIONS':
        return '', 204

    body = request.get_json() or {}
    es_url = (body.get('url') or '').rstrip('/')
    api_key = body.get('api_key') or ''
    username = body.get('username') or ''
    password = body.get('password') or ''
    index = body.get('index') or '*'
    query_str = body.get('query') or ''
    limit = min(int(body.get('limit') or 500), 2000)

    if not es_url:
        return jsonify({'error': 'url is required'}), 400

    headers = {'Content-Type': 'application/json'}
    auth = None

    if api_key:
        headers['Authorization'] = f'ApiKey {api_key}'
    elif username and password:
        auth = (username, password)

    search_body = {
        'size': limit,
        'sort': [{'@timestamp': {'order': 'asc'}}],
        'query': {'query_string': {'query': query_str}} if query_str else {'match_all': {}},
    }

    try:
        resp = req.get(
            f"{es_url}/{index}/_search",
            headers=headers,
            auth=auth,
            json=search_body,
            verify=False,
            timeout=30,
        )

        if resp.status_code in (401, 403):
            return jsonify({'error': 'Elasticsearch authentication failed.'}), 401

        data = resp.json()
        hits = data.get('hits', {}).get('hits', [])

        if not hits:
            return jsonify({'error': 'No documents matched. Check your index and query.'}), 400

        events = []
        for hit in hits:
            src = hit.get('_source', {})
            message = (
                src.get('message') or
                src.get('log', {}).get('original', '') if isinstance(src.get('log'), dict) else src.get('log') or
                str(src)
            )
            events.append({
                'timestamp': src.get('@timestamp', datetime.now().isoformat()),
                'source': (
                    src.get('agent', {}).get('name', '') if isinstance(src.get('agent'), dict)
                    else src.get('host', {}).get('name', '') if isinstance(src.get('host'), dict)
                    else hit.get('_index', 'elasticsearch')
                ),
                'description': str(message),
            })

        return process_events(events, source_label='elasticsearch')

    except req.exceptions.ConnectionError:
        return jsonify({'error': f'Could not connect to {es_url}.'}), 502
    except req.exceptions.Timeout:
        return jsonify({'error': 'Elasticsearch query timed out.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/integrations/cloudtrail', methods=['POST', 'OPTIONS'])
def integrate_cloudtrail():
    """Analyze AWS CloudTrail JSON (Records[] format)."""
    if request.method == 'OPTIONS':
        return '', 204

    if 'file' in request.files:
        f = request.files['file']
        try:
            data = json.loads(f.read().decode('utf-8'))
        except Exception:
            return jsonify({'error': 'Invalid JSON file'}), 400
    else:
        body = request.get_json() or {}
        data = body.get('logs')
        if not data:
            return jsonify({'error': 'Provide a file upload or a logs JSON body'}), 400
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                return jsonify({'error': 'Invalid JSON in logs field'}), 400

    events = parse_cloudtrail(data)
    if not events:
        return jsonify({'error': 'No CloudTrail records found'}), 400

    return process_events(events, source_label='cloudtrail')


@app.route('/api/integrations/raw', methods=['POST', 'OPTIONS'])
def integrate_raw():
    """Analyze pasted raw logs — syslog, CEF, LEEF, or plain text."""
    if request.method == 'OPTIONS':
        return '', 204

    body = request.get_json() or {}
    text = (body.get('logs') or '').strip()
    fmt = (body.get('format') or 'auto').lower()

    if not text:
        return jsonify({'error': 'logs field is required'}), 400

    if fmt == 'cef' or (fmt == 'auto' and text.startswith('CEF:')):
        events = parse_cef(text)
    else:
        lines = [l for l in text.split('\n') if l.strip()]
        events = [
            {'timestamp': datetime.now().isoformat(), 'source': fmt, 'description': line}
            for line in lines
        ]

    if not events:
        return jsonify({'error': 'Could not parse log text'}), 400

    return process_events(events, source_label=fmt if fmt != 'auto' else 'raw')

@app.route('/api/integrations/dnif', methods=['POST', 'OPTIONS'])
def integrate_dnif():
    """Query DNIF Hypercloud via API token from the system/token page."""
    if request.method == 'OPTIONS':
        return '', 204

    body = request.get_json() or {}
    raw_url   = (body.get('url') or '').strip()
    token     = (body.get('token') or '').strip()
    query     = body.get('query') or 'stream=* | duration 1d'
    limit     = min(int(body.get('limit') or 500), 2000)
    scope_id  = (body.get('scope_id') or 'default').strip()
    tz        = body.get('timezone') or 'UTC'

    if not raw_url or not token:
        return jsonify({'error': 'url and token are required'}), 400

    # Accept full browser URL like https://ap1.dnif.cloud/#/<tenant-uuid>/...
    no_hash  = raw_url.split('#')[0].rstrip('/')
    parsed   = urlparse(no_hash)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    tenant_id = ''
    if '#' in raw_url:
        hash_part  = raw_url.split('#', 1)[1].lstrip('/')
        uuid_match = re.match(
            r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
            hash_part, re.IGNORECASE,
        )
        if uuid_match:
            tenant_id = uuid_match.group(1)

    # Also try to extract scope from URL path if not provided in body
    if scope_id == 'default' and '#' in raw_url:
        hash_part = raw_url.split('#', 1)[1].lstrip('/')
        parts = hash_part.split('/')
        if len(parts) >= 2:
            candidate = parts[1]
            if candidate and not re.match(r'^[0-9a-f-]{36}$', candidate, re.IGNORECASE):
                scope_id = candidate

    if not tenant_id:
        return jsonify({
            'error': (
                'Could not find tenant ID in URL. '
                'Paste the full browser URL including the # fragment, '
                'e.g. https://ap1.dnif.cloud/#/<tenant-uuid>/training/system/token'
            )
        }), 400

    # DNIF Hypercloud uses "Token" header (not SSID) for API token auth
    hdrs = {'Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'}

    try:
        # Step 1: Submit the DQL job
        invoke_resp = req.post(
            f"{base_url}/{tenant_id}/wrk/api/job/invoke",
            headers=hdrs,
            json={
                'query_timezone': tz,
                'scope_id': scope_id,
                'job_type': 'dql',
                'job_execution': 'on-demand',
                'query': query,
            },
            verify=False,
            timeout=30,
        )

        if invoke_resp.status_code in (401, 403):
            return jsonify({'error': 'DNIF token rejected. Regenerate from system → token page.'}), 401
        if not invoke_resp.ok:
            return jsonify({
                'error': f'DNIF invoke failed (HTTP {invoke_resp.status_code}): {invoke_resp.text[:200]}'
            }), 502

        invoke_data = invoke_resp.json()
        if invoke_data.get('status') != 'success':
            return jsonify({
                'error': f'DNIF job submission failed: {invoke_data.get("message", str(invoke_data))}'
            }), 502

        task_items = invoke_data.get('data', [])
        if not task_items:
            return jsonify({'error': 'DNIF returned no task ID.'}), 502
        task_id = task_items[0].get('id') or task_items[0].get('task_id')
        if not task_id:
            return jsonify({'error': 'Could not extract task ID from DNIF response.'}), 502

        # Step 2: Poll task state (up to ~30s)
        state_url  = f"{base_url}/{tenant_id}/wrk/api/dispatcher/task/state/{task_id}"
        result_url = f"{base_url}/{tenant_id}/wrk/api/dispatcher/task/result/{task_id}"
        completed  = False
        for _ in range(10):
            time.sleep(3)
            try:
                state_resp = req.get(state_url, headers=hdrs, verify=False, timeout=15)
                if state_resp.ok:
                    sd = state_resp.json()
                    ts = str(sd.get('task_state', '')).upper()
                    if ts in ('SUCCESS', 'DONE', 'COMPLETED', 'EXECUTED'):
                        completed = True
                        break
                    if ts in ('FAILED', 'ERROR', 'CANCELLED'):
                        return jsonify({'error': f'DNIF job failed with state: {ts}'}), 502
            except Exception:
                pass

        if not completed:
            return jsonify({'error': 'DNIF job timed out after 30s. Try a narrower time range.'}), 504

        # Step 3: Fetch results
        res_resp = req.get(
            result_url,
            headers=hdrs,
            params={'pagesize': limit, 'pageno': 1},
            verify=False,
            timeout=30,
        )
        if not res_resp.ok:
            return jsonify({'error': f'DNIF result fetch failed (HTTP {res_resp.status_code})'}), 502

        res_data = res_resp.json()
        rows = res_data.get('result') or res_data.get('data') or []

        if not rows:
            return jsonify({'error': 'No events returned. Check your token, scope, and DQL query.'}), 400

        events = []
        for row in rows:
            if not isinstance(row, dict):
                continue

            # Timestamp: prefer $CNAMTime (epoch ms), then string fields
            ts_raw = row.get('$CNAMTime') or row.get('$SystemTstamp') or row.get('$Time')
            if ts_raw and str(ts_raw).isdigit() and len(str(ts_raw)) >= 13:
                try:
                    timestamp = datetime.fromtimestamp(int(ts_raw) / 1000).isoformat()
                except Exception:
                    timestamp = datetime.now().isoformat()
            else:
                timestamp = str(ts_raw) if ts_raw else datetime.now().isoformat()

            source = (
                row.get('$DevSrcIP') or row.get('$SrcIP') or
                row.get('$PicoSystemName') or row.get('$Hostname') or 'dnif'
            )

            # Prefer parsed fields; fall back to raw $LogEvent JSON
            description = (
                row.get('$Message') or row.get('$EventName') or
                row.get('$Action') or row.get('$OperationName')
            )
            if not description:
                log_event = row.get('$LogEvent', '')
                if log_event:
                    try:
                        le = json.loads(log_event) if isinstance(log_event, str) else log_event
                        description = (
                            le.get('message') or le.get('event', {}).get('action') or
                            le.get('winlog', {}).get('event_data', {}).get('Description') or
                            str(log_event)[:300]
                        )
                    except Exception:
                        description = str(log_event)[:300]
            if not description:
                description = str(row)[:300]

            events.append({'timestamp': timestamp, 'source': str(source), 'description': str(description)})

        return process_events(events, source_label='dnif')

    except req.exceptions.ConnectionError:
        return jsonify({'error': f'Could not connect to {base_url}. Check the URL.'}), 502
    except req.exceptions.Timeout:
        return jsonify({'error': 'DNIF request timed out.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 15 MB.'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# RUN
# ============================================================================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    env = os.getenv('FLASK_ENV', 'development')
    app.run(host='0.0.0.0', port=port, debug=(env == 'development'))
