"""
MITRE ATT&CK Technique Mapper
Maps security events to MITRE ATT&CK tactics and techniques
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class MitreMatch:
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique: Optional[str]
    confidence: float
    matched_keywords: List[str]

class MitreMapper:
    """Maps security events to MITRE ATT&CK framework."""
    
    # Pattern-based mapping (keyword → MITRE technique)
    TECHNIQUE_PATTERNS = {
        # EXECUTION
        r'powershell|ps\.exe|pwsh': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'PowerShell (T1059.001)',
        },
        r'cmd\.exe|command prompt': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Windows Command Shell (T1059.003)',
        },
        r'bash|sh|shell|/bin/': {
            'tactic': 'Execution',
            'technique_id': 'T1059',
            'technique_name': 'Command and Scripting Interpreter',
            'subtechnique': 'Unix Shell (T1059.004)',
        },
        r'wmic|windows management instrumentation': {
            'tactic': 'Execution',
            'technique_id': 'T1047',
            'technique_name': 'Windows Management Instrumentation',
            'subtechnique': None,
        },
        
        # PERSISTENCE
        r'registry.*run|run key|hklm.*run|autoruns': {
            'tactic': 'Persistence',
            'technique_id': 'T1547',
            'technique_name': 'Boot or Logon Autostart Execution',
            'subtechnique': 'Registry Run Keys (T1547.001)',
        },
        r'scheduled task|schtasks|at\.exe': {
            'tactic': 'Persistence',
            'technique_id': 'T1053',
            'technique_name': 'Scheduled Task/Job',
            'subtechnique': None,
        },
        r'service.*created|service.*installed|new.*service': {
            'tactic': 'Persistence',
            'technique_id': 'T1543',
            'technique_name': 'Create or Modify System Process',
            'subtechnique': 'Windows Service (T1543.003)',
        },
        
        # PRIVILEGE ESCALATION
        r'uac bypass|admin.*prompt|elevated|privilege': {
            'tactic': 'Privilege Escalation',
            'technique_id': 'T1548',
            'technique_name': 'Abuse Elevation Control Mechanism',
            'subtechnique': None,
        },
        
        # DEFENSE EVASION
        r'disable.*defender|disable.*av|disable.*security|windows defender.*off': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1562',
            'technique_name': 'Impair Defenses',
            'subtechnique': 'Disable or Modify Tools (T1562.001)',
        },
        r'delete.*event log|clear.*log|wevtutil.*cl': {
            'tactic': 'Defense Evasion',
            'technique_id': 'T1070',
            'technique_name': 'Indicator Removal',
            'subtechnique': 'Clear Windows Event Logs (T1070.001)',
        },
        
        # CREDENTIAL ACCESS
        r'mimikatz|lsass|password dump|credential dump|ntds\.dit': {
            'tactic': 'Credential Access',
            'technique_id': 'T1003',
            'technique_name': 'OS Credential Dumping',
            'subtechnique': 'LSASS Memory (T1003.001)',
        },
        r'keylog|key.*capture|password.*capture': {
            'tactic': 'Credential Access',
            'technique_id': 'T1056',
            'technique_name': 'Input Capture',
            'subtechnique': 'Keylogging (T1056.001)',
        },
        r'phish|spear.*phish|email.*attach|malicious.*attachment': {
            'tactic': 'Initial Access',
            'technique_id': 'T1566',
            'technique_name': 'Phishing',
            'subtechnique': 'Spearphishing Attachment (T1566.001)',
        },
        
        # DISCOVERY
        r'dir\s|ls\s|file.*enumeration|folder.*enumeration|directory.*listing': {
            'tactic': 'Discovery',
            'technique_id': 'T1083',
            'technique_name': 'File and Directory Discovery',
            'subtechnique': None,
        },
        r'ipconfig|ifconfig|network.*discovery|arp|route.*print': {
            'tactic': 'Discovery',
            'technique_id': 'T1016',
            'technique_name': 'System Network Configuration Discovery',
            'subtechnique': None,
        },
        r'tasklist|get-process|wmi.*process|pslist': {
            'tactic': 'Discovery',
            'technique_id': 'T1057',
            'technique_name': 'Process Discovery',
            'subtechnique': None,
        },
        
        # LATERAL MOVEMENT
        r'psexec|wmiexec|dcom|pass.*the.*hash|pth': {
            'tactic': 'Lateral Movement',
            'technique_id': 'T1021',
            'technique_name': 'Remote Services',
            'subtechnique': None,
        },
        
        # EXFILTRATION
        r'data.*copied|usb.*drive|removable.*media|file.*transfer|ftp|sftp|upload': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1020',
            'technique_name': 'Automated Exfiltration',
            'subtechnique': None,
        },
        r'dns.*tunnel|dns.*exfil|dns.*query.*unusual': {
            'tactic': 'Exfiltration',
            'technique_id': 'T1048',
            'technique_name': 'Exfiltration Over Alternative Protocol',
            'subtechnique': 'Exfiltration Over DNS (T1048.003)',
        },
    }
    
    # MITRE Tactics tiers (for confidence scoring)
    TACTIC_SEVERITY = {
        'Initial Access': 1.0,
        'Execution': 0.95,
        'Persistence': 0.90,
        'Privilege Escalation': 0.95,
        'Defense Evasion': 0.90,
        'Credential Access': 0.95,
        'Discovery': 0.85,
        'Lateral Movement': 0.90,
        'Collection': 0.85,
        'Exfiltration': 0.95,
        'Command and Control': 0.90,
        'Impact': 0.95,
    }
    
    def __init__(self):
        """Initialize MITRE mapper."""
        self.patterns_compiled = {}
        for pattern_str, info in self.TECHNIQUE_PATTERNS.items():
            self.patterns_compiled[pattern_str] = {
                'regex': re.compile(pattern_str, re.IGNORECASE),
                'info': info
            }
    
    def find_technique(self, event_description: str) -> Optional[MitreMatch]:
        """
        Find MITRE technique from event description.
        
        Args:
            event_description: String describing the security event
            
        Returns:
            MitreMatch with tactic, technique, and confidence
        """
        best_match = None
        best_confidence = 0
        matched_keywords = []
        
        for pattern_str, compiled_info in self.patterns_compiled.items():
            regex = compiled_info['regex']
            info = compiled_info['info']
            
            match = regex.search(event_description)
            if match:
                # Confidence is base 0.9, adjusted by tactic severity
                tactic_modifier = self.TACTIC_SEVERITY.get(info['tactic'], 0.85)
                confidence = 0.9 * tactic_modifier
                
                # Boost confidence for exact/multiple keyword matches
                matched_text = match.group(0)
                matched_keywords.append(matched_text)
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {
                        'tactic': info['tactic'],
                        'technique_id': info['technique_id'],
                        'technique_name': info['technique_name'],
                        'subtechnique': info['subtechnique'],
                        'matched_keywords': [matched_text],
                    }
        
        if best_match:
            return MitreMatch(
                tactic=best_match['tactic'],
                technique_id=best_match['technique_id'],
                technique_name=best_match['technique_name'],
                subtechnique=best_match['subtechnique'],
                confidence=min(best_confidence, 1.0),
                matched_keywords=best_match['matched_keywords']
            )
        
        return None
    
    def find_all_techniques(self, event_description: str) -> List[MitreMatch]:
        """Find all possible MITRE techniques (returns list, not just best match)."""
        matches = []
        matched_patterns = set()
        
        for pattern_str, compiled_info in self.patterns_compiled.items():
            if pattern_str in matched_patterns:
                continue
                
            regex = compiled_info['regex']
            info = compiled_info['info']
            
            for match in regex.finditer(event_description):
                tactic_modifier = self.TACTIC_SEVERITY.get(info['tactic'], 0.85)
                confidence = 0.9 * tactic_modifier
                
                matches.append(MitreMatch(
                    tactic=info['tactic'],
                    technique_id=info['technique_id'],
                    technique_name=info['technique_name'],
                    subtechnique=info['subtechnique'],
                    confidence=min(confidence, 1.0),
                    matched_keywords=[match.group(0)]
                ))
                matched_patterns.add(pattern_str)
                break  # One match per pattern
        
        # Sort by confidence descending
        return sorted(matches, key=lambda x: x.confidence, reverse=True)


if __name__ == '__main__':
    mapper = MitreMapper()
    
    # Test cases
    test_events = [
        "Suspicious PowerShell execution detected with base64 encoded command",
        "User downloaded file via phishing email attachment",
        "Mimikatz tool executed on system, password dumping detected",
        "Registry run key modified: HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        "Process discovery: tasklist command executed",
    ]
    
    for event in test_events:
        match = mapper.find_technique(event)
        if match:
            print(f"Event: {event}")
            print(f"  → {match.tactic} / {match.technique_id} ({match.technique_name})")
            print(f"  → Confidence: {match.confidence:.2%}")
            print()
