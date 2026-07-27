"""
Rule-Based Detection Engine

This module implements the rule-based threat detection system:
- Loads detection rules from configuration
- Matches events against rules
- Identifies threats based on patterns
- Assigns severity and confidence scores

This is the core of Phase 1 (rule-based detection).
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


class RuleEngine:
    """
    Rule-based threat detection engine.
    
    Explanation:
    - Signature-based detection (like antivirus)
    - Each rule defines conditions to match
    - Rules have severity, confidence, and impact ratings
    - When conditions match, a threat is detected
    
    How it works:
    1. Load rules from rules.json
    2. For each event, check all rules
    3. If event matches rule conditions, create threat alert
    4. Attach metadata for downstream processing
    
    Advantages:
    - Fast and deterministic
    - Low false positives for known threats
    - Easy to understand and explain
    
    Limitations:
    - Can only detect known patterns
    - Requires rule updates for new threats
    - Cannot detect zero-day attacks
    """
    
    def __init__(self, rules_data: Dict[str, Any]):
        """
        Initialize rule engine with detection rules.
        
        Args:
            rules_data: Dictionary containing rules and templates
        """
        self.rules = rules_data.get('rules', [])
        self.advisory_templates = rules_data.get('advisory_templates', {})
        self.logger = logging.getLogger('CyberAdvisor.RuleEngine')
        
        self.logger.info(f"Rule Engine initialized with {len(self.rules)} rules")
    
    def check_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check an event against all rules.
        
        Args:
            event: Event dictionary from monitoring modules
        
        Returns:
            Threat dictionary if rule matched, None otherwise
        """
        for rule in self.rules:
            if self._match_rule(event, rule):
                threat = self._create_threat_from_rule(event, rule)
                return threat
        
        return None
    
    def check_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check multiple events against all rules.
        
        Args:
            events: List of event dictionaries
        
        Returns:
            List of detected threats
        """
        threats = []
        
        for event in events:
            threat = self.check_event(event)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _match_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """
        Check if event matches rule conditions.
        
        Args:
            event: Event to check
            rule: Rule definition
        
        Returns:
            True if event matches rule conditions
        """
        conditions = rule.get('conditions', {})
        
        # Check event type
        if 'event_type' in conditions:
            if event.get('event_type') != conditions['event_type']:
                return False
        
        event_data = event.get('data', {})
        
        # Check process name contains
        if 'process_name_contains' in conditions:
            process_name = event_data.get('process_name', '').lower()
            if not process_name:
                return False
            
            suspicious_names = conditions['process_name_contains']
            if not any(name.lower() in process_name for name in suspicious_names):
                return False
        
        # Check port in list
        if 'port_in' in conditions:
            remote_port = event_data.get('remote_port')
            if remote_port not in conditions['port_in']:
                return False
        
        # Check CPU threshold
        if 'cpu_percent' in conditions:
            cpu = event_data.get('cpu_percent', 0)
            if cpu < conditions['cpu_percent']:
                return False
        
        # Check path contains
        if 'path_contains' in conditions:
            file_path = event_data.get('file_path', '').lower()
            if not file_path:
                return False
            
            path_patterns = conditions['path_contains']
            if not any(pattern.lower() in file_path for pattern in path_patterns):
                return False
        
        # Check file extension
        if 'extension_in' in conditions:
            file_path = event_data.get('file_path', '').lower()
            extensions = conditions['extension_in']
            if not any(file_path.endswith(ext.lower()) for ext in extensions):
                return False
        
        # Check connection count (for correlation-based rules)
        if 'connection_count' in conditions:
            count = event_data.get('connection_count', 0)
            if count < conditions['connection_count']:
                return False
        
        # Check count threshold (for repeated events)
        if 'count' in conditions:
            # This would require correlation/aggregation
            # For now, we'll assume the event already has a count
            event_count = event_data.get('count', 1)
            if event_count < conditions['count']:
                return False
        
        # All conditions matched
        return True
    
    def _create_threat_from_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create threat object from matched rule and event.
        
        Args:
            event: Matched event
            rule: Matched rule
        
        Returns:
            Threat dictionary
        """
        threat = {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'threat_id': rule['id'],
            'threat_name': rule['name'],
            'description': rule.get('description', ''),
            'category': rule.get('category', 'Unknown'),
            'severity': rule['severity'],
            'confidence': rule.get('confidence', 0.5),
            'impact': rule.get('impact', 'unknown'),
            'source': event.get('source', 'unknown'),
            'event_data': event.get('data', {}),
            'rule_matched': rule['id'],
            'advisory_template': rule.get('advisory_template')
        }
        
        self.logger.info(
            f"Threat detected: {rule['name']} (Rule: {rule['id']}, "
            f"Severity: {rule['severity']})"
        )
        
        return threat
    
    def get_advisory_template(self, template_name: str) -> Optional[Dict[str, Any]]:
        """
        Get advisory template by name.
        
        Args:
            template_name: Name of advisory template
        
        Returns:
            Advisory template dictionary or None
        """
        return self.advisory_templates.get(template_name)
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get rule definition by ID.
        
        Args:
            rule_id: Rule ID
        
        Returns:
            Rule dictionary or None
        """
        for rule in self.rules:
            if rule['id'] == rule_id:
                return rule
        return None
    
    def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get all rules in a category.
        
        Args:
            category: Category name
        
        Returns:
            List of matching rules
        """
        return [rule for rule in self.rules if rule.get('category') == category]
    
    def get_rules_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get all rules with specific severity.
        
        Args:
            severity: Severity level (low, medium, high)
        
        Returns:
            List of matching rules
        """
        return [rule for rule in self.rules if rule.get('severity') == severity]
    
    def add_rule(self, rule: Dict[str, Any]):
        """
        Add a new rule to the engine.
        
        Args:
            rule: Rule dictionary
        """
        # Validate required fields
        required_fields = ['id', 'name', 'conditions', 'severity']
        for field in required_fields:
            if field not in rule:
                raise ValueError(f"Rule missing required field: {field}")
        
        # Check for duplicate ID
        if any(r['id'] == rule['id'] for r in self.rules):
            raise ValueError(f"Rule ID {rule['id']} already exists")
        
        self.rules.append(rule)
        self.logger.info(f"Added new rule: {rule['id']} - {rule['name']}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule from the engine.
        
        Args:
            rule_id: ID of rule to remove
        
        Returns:
            True if rule was removed
        """
        original_count = len(self.rules)
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        
        if len(self.rules) < original_count:
            self.logger.info(f"Removed rule: {rule_id}")
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about loaded rules.
        
        Returns:
            Statistics dictionary
        """
        by_severity = {'low': 0, 'medium': 0, 'high': 0}
        by_category = {}
        
        for rule in self.rules:
            # Count by severity
            severity = rule.get('severity', 'unknown')
            if severity in by_severity:
                by_severity[severity] += 1
            
            # Count by category
            category = rule.get('category', 'Unknown')
            by_category[category] = by_category.get(category, 0) + 1
        
        return {
            'total_rules': len(self.rules),
            'by_severity': by_severity,
            'by_category': by_category
        }


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Sample rules
    test_rules = {
        "rules": [
            {
                "id": "TEST_001",
                "name": "Suspicious Process",
                "description": "Test rule",
                "category": "Malware",
                "severity": "high",
                "confidence": 0.9,
                "conditions": {
                    "event_type": "process_start",
                    "process_name_contains": ["mimikatz", "nmap"]
                },
                "impact": "system_control",
                "advisory_template": "suspicious_process"
            }
        ],
        "advisory_templates": {}
    }
    
    engine = RuleEngine(test_rules)
    
    # Test event
    test_event = {
        'timestamp': datetime.now().isoformat(),
        'event_type': 'process_start',
        'source': 'system_monitor',
        'data': {
            'process_name': 'mimikatz.exe',
            'pid': 1234
        }
    }
    
    threat = engine.check_event(test_event)
    if threat:
        print(f"Threat detected: {threat['threat_name']}")
        print(f"Severity: {threat['severity']}")
    else:
        print("No threat detected")
