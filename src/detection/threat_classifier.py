"""Unified threat classification.

Every detection, whether from a behaviour rule, the ransomware-like file
monitor or the behaviour-anomaly model, is given:

    classification       what kind of activity the evidence points to
    detection_method     rule | file_behaviour | anomaly
    verification_status  always "unverified": SecureX has no malware-signature
                         database or threat-intelligence feed, so nothing it
                         detects is independently confirmed
    evidence             the observations that led to the classification

Detections are never forced into a malware family. Anomalies that match no
known pattern are reported as "Unknown suspicious activity".
"""

from typing import Any, Dict, List

UNKNOWN = 'Unknown suspicious activity'
UNKNOWN_DETAIL = 'Unknown suspicious activity: insufficient evidence to determine the specific threat type.'

# Rule category (config/rules.json) -> classification. Rule names describe
# behaviour, not confirmed malware, so the labels say "suspicious".
RULE_CATEGORY_CLASSIFICATION = {
    'Malware': 'Suspicious process (malware-like pattern)',
    'Script Attack': 'Suspicious process (script abuse)',
    'Code Injection': 'Suspicious process (code injection)',
    'Privilege Escalation': 'Suspicious process (privilege escalation)',
    'Brute Force': 'Brute-force activity',
    'Network Attack': 'Network anomaly (suspicious port)',
    'Network Scan': 'Network anomaly (scanning or flooding)',
    'Data Theft': 'Network anomaly (possible data exfiltration)',
    'File Tampering': 'Suspicious file activity',
    'Resource Abuse': 'Resource abuse',
}

VERIFICATION_NOTE = ('Heuristic detection, not confirmed: SecureX has no malware-signature '
                     'database or threat-intelligence feed to verify it against.')


def _rule_evidence(threat: Dict[str, Any]) -> List[str]:
    event = threat.get('event_data') or {}
    evidence = []
    if threat.get('description'):
        evidence.append(f"Matched rule {threat.get('rule_matched', '')}: {threat['description']}".strip())
    if event.get('reason'):
        evidence.append(str(event['reason']))
    for key, label in (('process_name', 'Process'), ('pid', 'PID'), ('remote_ip', 'Remote address'),
                       ('remote_port', 'Remote port'), ('connection_count', 'Connections'),
                       ('cpu_percent', 'CPU %'), ('memory_percent', 'Memory %')):
        if event.get(key) not in (None, ''):
            evidence.append(f'{label}: {event[key]}')
    return evidence


def classify(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Add classification fields to a threat dict (in place) and return it."""
    source = threat.get('detection_method') or 'rule'
    if source == 'file_behaviour':
        classification = threat.get('classification') or 'Suspicious bulk file modification'
        evidence = list(threat.get('evidence') or [])
    elif source == 'anomaly':
        classification = UNKNOWN
        evidence = list(threat.get('evidence') or []) + [UNKNOWN_DETAIL]
    else:
        source = 'rule'
        classification = RULE_CATEGORY_CLASSIFICATION.get(threat.get('category'), UNKNOWN)
        evidence = _rule_evidence(threat)
        if classification == UNKNOWN:
            evidence.append(UNKNOWN_DETAIL)

    threat['classification'] = classification
    threat['detection_method'] = source
    threat['verification_status'] = 'unverified'
    threat['evidence'] = evidence + [VERIFICATION_NOTE]
    return threat
