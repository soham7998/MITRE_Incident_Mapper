"""
MITRE ATT&CK Incident Mapper - Backend API
Deployed on Railway.app
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import json
import csv
from datetime import datetime
from io import BytesIO, StringIO
import uuid

from src.mitre_mapper import MitreMapper
from src.timeline_builder import TimelineBuilder, ReportGenerator

app = Flask(__name__)

# Configure CORS for Vercel frontend
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

# Initialize components
mapper = MitreMapper()
timeline_builder = TimelineBuilder()
report_generator = ReportGenerator()

# In-memory storage (use Redis/DB for production scale)
incidents = {}

# ============================================================================
# UTILITY FUNCTIONS
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
        {'timestamp': datetime.now().isoformat(), 'raw': line, 'description': line}
        for line in lines if line.strip()
    ]

def extract_timestamp(event):
    for key in ['timestamp', 'time', 'date', 'datetime', '_time', 'Timestamp']:
        if key in event:
            return event[key]
    return datetime.now().isoformat()

def extract_description(event):
    for key in ['message', 'description', 'event', 'detail', 'text', 'event_description', 'Message']:
        if key in event and event[key]:
            return str(event[key])
    return ' '.join([str(v) for v in event.values() if v])

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def root():
    """Health check / API info."""
    return jsonify({
        'service': 'MITRE Incident Mapper API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'analyze': 'POST /api/analyze',
            'incident': 'GET /api/incident/<id>',
            'download': 'GET /api/download/<id>/<format>',
            'health': 'GET /api/health'
        },
        'frontend': 'https://mitre-incident-mapper.vercel.app'
    })

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'incidents_loaded': len(incidents)
    })

@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    """Upload and analyze incident log."""
    if request.method == 'OPTIONS':
        return '', 204
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = file.filename.lower()
    file_content = file.read()
    
    # Parse based on extension
    if filename.endswith('.csv'):
        events = parse_csv(file_content)
    elif filename.endswith('.json'):
        events = parse_json(file_content)
    elif filename.endswith('.txt') or filename.endswith('.log'):
        events = parse_syslog(file_content)
    else:
        return jsonify({'error': 'Unsupported format. Use .csv, .json, .txt, or .log'}), 400
    
    if not events:
        return jsonify({'error': 'Could not parse file'}), 400
    
    # Create incident
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8]}"
    
    processed_events = []
    mitre_techniques = {}
    
    for idx, event in enumerate(events):
        timestamp = extract_timestamp(event)
        description = extract_description(event)
        match = mapper.find_technique(description)
        
        processed = {
            'id': idx + 1,
            'timestamp': timestamp,
            'source': event.get('source', 'Unknown'),
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
        'filename': file.filename,
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

@app.route('/api/incident/<incident_id>')
def get_incident(incident_id):
    if incident_id not in incidents:
        return jsonify({'error': 'Incident not found'}), 404
    return jsonify(incidents[incident_id]), 200

@app.route('/api/download/<incident_id>/<format>')
def download(incident_id, format):
    if incident_id not in incidents:
        return jsonify({'error': 'Incident not found'}), 404
    
    incident = incidents[incident_id]
    
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
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# RUN
# ============================================================================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    env = os.getenv('FLASK_ENV', 'development')
    print(f"🚀 MITRE API starting on port {port} ({env})")
    app.run(host='0.0.0.0', port=port, debug=(env == 'development'))
