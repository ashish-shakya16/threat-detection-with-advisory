"""Knowledge base for security information."""

from typing import Dict, Optional


class KnowledgeBase:
    """Manage security knowledge for the AI assistant"""

    def __init__(self, db_manager=None):
        """Initialize knowledge base"""
        self.db_manager = db_manager
        self.threat_definitions = self._load_threat_definitions()

    def _load_threat_definitions(self) -> Dict:
        """Load threat definitions"""
        definitions = {
            'Malware': {
                'description': 'Malicious software designed to harm or exploit your system',
                'risks': ['Data theft', 'System damage', 'Performance degradation'],
                'prevention': ['Use antivirus', 'Keep OS updated', 'Avoid suspicious downloads']
            },
            'Trojan': {
                'description': 'Malware disguised as legitimate software',
                'risks': ['Backdoor access', 'Data theft', 'System takeover'],
                'prevention': ['Download from trusted sources', 'Verify file hashes', 'Use antivirus']
            },
            'Ransomware': {
                'description': 'Software that encrypts your files and demands payment',
                'risks': ['Data loss', 'Business disruption', 'Financial loss'],
                'prevention': ['Regular backups', 'System updates', 'User training']
            },
            'Spyware': {
                'description': 'Software that monitors and steals your information',
                'risks': ['Privacy violation', 'Identity theft', 'Financial fraud'],
                'prevention': ['Antispyware software', 'Browser security', 'Email caution']
            },
            'Phishing': {
                'description': 'Deceptive attempts to steal credentials via email or websites',
                'risks': ['Account compromise', 'Identity theft', 'Credential theft'],
                'prevention': ['Email verification', 'URL checking', 'Multi-factor auth']
            }
        }
        return definitions

    def get_threat_info(self, threat_type: str) -> Optional[Dict]:
        """Get information about a threat type"""
        return self.threat_definitions.get(threat_type)

    def store_conversation(self, user_id: int, query: str, response: str, confidence: float = 1.0) -> None:
        """Store conversation in database"""
        if self.db_manager:
            try:
                self.db_manager.log_conversation(user_id, query, response, confidence)
            except Exception:
                pass

    def get_faq_answer(self, question: str) -> Optional[str]:
        """Get FAQ answer for common questions"""
        faqs = {
            'what is ransomware': 'Ransomware is malicious software that encrypts your files and demands payment to decrypt them.',
            'how do i backup': 'You should backup important files to an external drive or cloud storage regularly.',
            'is my system safe': 'Run a full scan with antivirus software to check for threats.',
            'what is phishing': 'Phishing is a deceptive attempt to trick you into revealing sensitive information via fake emails or websites.',
        }

        question_lower = question.lower()
        for faq_key, answer in faqs.items():
            if faq_key in question_lower:
                return answer

        return None
