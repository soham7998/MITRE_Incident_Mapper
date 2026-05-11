"""
Timeline Builder & Report Generator
"""

from typing import List, Dict, Any
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from io import BytesIO

class TimelineBuilder:
    """Builds structured timeline from events."""
    
    def build_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build chronological timeline with MITRE tactic grouping."""
        
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda x: x['timestamp'])
        
        # Group by MITRE tactic
        tactics_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Command and Control', 'Impact'
        ]
        
        timeline_phases = {}
        for event in sorted_events:
            tactic = event['mitre_tactic']
            if tactic not in timeline_phases:
                timeline_phases[tactic] = []
            timeline_phases[tactic].append(event)
        
        # Return ordered timeline
        return [
            {
                'tactic': tactic,
                'events': timeline_phases.get(tactic, [])
            }
            for tactic in tactics_order
            if tactic in timeline_phases
        ]


class ReportGenerator:
    """Generates PDF incident reports."""
    
    TACTIC_COLORS = {
        'Initial Access': colors.HexColor('#FF6B6B'),
        'Execution': colors.HexColor('#FFA94D'),
        'Persistence': colors.HexColor('#FFD93D'),
        'Privilege Escalation': colors.HexColor('#F9CA24'),
        'Defense Evasion': colors.HexColor('#6C5CE7'),
        'Credential Access': colors.HexColor('#E17055'),
        'Discovery': colors.HexColor('#74B9FF'),
        'Lateral Movement': colors.HexColor('#81ECEC'),
        'Collection': colors.HexColor('#55EFC4'),
        'Exfiltration': colors.HexColor('#FD79A8'),
        'Command and Control': colors.HexColor('#FDCB6E'),
        'Impact': colors.HexColor('#E84393'),
    }
    
    def generate_pdf(self, incident: Dict[str, Any]) -> bytes:
        """Generate PDF report from incident."""
        
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1A1A1A'),
            spaceAfter=10,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#333333'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
        )
        
        # Build story
        story = []
        
        # Title
        story.append(Paragraph('INCIDENT REPORT', title_style))
        story.append(Paragraph('MITRE ATT&CK Incident Timeline Analysis', styles['Heading3']))
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        incident_id = incident.get('incident_id', 'N/A')
        created_at = incident.get('created_at', 'N/A')
        events_count = len(incident.get('events', []))
        
        metadata_text = f"""
        <b>Incident ID:</b> {incident_id}<br/>
        <b>Generated:</b> {created_at}<br/>
        <b>Total Events:</b> {events_count}<br/>
        <b>Source File:</b> {incident.get('filename', 'Unknown')}<br/>
        """
        story.append(Paragraph(metadata_text, normal_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Attack Chain Summary
        story.append(Paragraph('MITRE ATT&CK Kill Chain', heading_style))
        
        techniques = incident.get('mitre_techniques', [])
        if techniques:
            technique_text = ' → '.join([f"{t['id']}" for t in techniques[:5]])
            if len(techniques) > 5:
                technique_text += f" ... +{len(techniques)-5} more"
            story.append(Paragraph(technique_text, normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Event Timeline
        story.append(Paragraph('Detailed Event Timeline', heading_style))
        
        events = incident.get('events', [])
        if events:
            # Create event table
            event_data = [['#', 'Timestamp', 'Tactic', 'Technique', 'Confidence', 'Event']]
            
            for idx, event in enumerate(events[:20], 1):  # First 20 events
                tactic = event.get('mitre_tactic', 'Unknown')
                technique_id = event.get('mitre_technique_id', 'N/A')
                confidence = f"{event.get('confidence', 0)}%"
                desc = event.get('description', '')[:60] + ('...' if len(event.get('description', '')) > 60 else '')
                
                event_data.append([
                    str(idx),
                    event.get('timestamp', '')[:10],
                    tactic,
                    technique_id,
                    confidence,
                    desc
                ])
            
            event_table = Table(event_data, colWidths=[0.3*inch, 1*inch, 1.2*inch, 0.7*inch, 0.7*inch, 1.5*inch])
            event_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F5F5')]),
            ]))
            story.append(event_table)
        
        story.append(Spacer(1, 0.3*inch))
        
        # Recommendations
        story.append(Paragraph('Recommendations', heading_style))
        recommendations = """
        1. Review all events mapped to high-severity tactics (Execution, Credential Access, Exfiltration)<br/>
        2. Correlate events with asset inventory to identify affected systems<br/>
        3. Collect additional forensic data from systems involved in detected tactics<br/>
        4. Update detection rules to identify similar attack patterns<br/>
        5. Document findings for threat intelligence sharing<br/>
        """
        story.append(Paragraph(recommendations, normal_style))
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
