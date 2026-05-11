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
from io import BytesIO, StringIO
import uuid
import urllib3

_MONGO_URL = os.getenv('MONGODB_URL') or os.getenv('MONGO_URL') or os.getenv('MONGO_PRIVATE_URL')
_col = None
_mem = {}

def _get_col():
    global _col
    if _col is not None:
        return _col
    if not _MONGO_URL:
        return None
    try:
        from pymongo import MongoClient
        client = MongoClient(_MONGO_URL, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
        col = client['mitre_mapper']['incidents']
        col.create_index('incident_id', unique=True)
        _col = col
        return _col
    except Exception as e:
        print(f'MongoDB connect failed: {e}')
        return None

def _save(doc: dict):
    col = _get_col()
    if col is not None:
        try:
            col.replace_one({'incident_id': doc['incident_id']}, doc, upsert=True)
            return
        except Exception as e:
            print(f'MongoDB write failed: {e}')
    _mem[doc['incident_id']] = doc

def _load(incident_id: str):
    col = _get_col()
    if col is not None:
        try:
            return col.find_one({'incident_id': incident_id}, {'_id': 0})
        except Exception:
            pass
    return _mem.get(incident_id)

def _count():
    col = _get_col()
    if col is not None:
        try:
            return col.count_documents({})
        except Exception:
            pass
    return len(_mem)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    _save({
        'incident_id': incident_id,
        'source': source_label,
        'filename': filename or source_label,
        'created_at': datetime.now().isoformat(),
        'events': processed_events,
        'timeline': timeline,
        'mitre_techniques': list(mitre_techniques.values()),
    })

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
        'storage': 'mongodb' if USE_MONGO else 'memory',
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
        },
        'frontend': 'https://mitre-incident-mapper.vercel.app'
    })

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'storage': 'mongodb' if USE_MONGO else 'memory',
        'incidents_stored': _count()
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
    doc = _load(incident_id)
    if not doc:
        return jsonify({'error': 'Incident not found'}), 404
    return jsonify(doc), 200

@app.route('/api/download/<incident_id>/<format>')
def download(incident_id, format):
    incident = _load(incident_id)
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
