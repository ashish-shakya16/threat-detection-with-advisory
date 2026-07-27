"""AI Security Assistant Module."""

import logging
from typing import Dict
from src.assistant.knowledge_base import KnowledgeBase
from src.assistant.prompt_templates import SYSTEM_PROMPT

logger = logging.getLogger('securex')


class AIAssistant:
    """AI-powered security assistant"""

    def __init__(self, db_manager=None, config: Dict = None):
        """Initialize AI Assistant"""
        self.db_manager = db_manager
        self.config = config or {}
        self.knowledge_base = KnowledgeBase(db_manager)

    def explain_threat(self, threat: Dict) -> str:
        """Explain a detected threat"""
        threat_type = threat.get('category', 'Unknown')
        threat_info = self.knowledge_base.get_threat_info(threat_type)

        if threat_info:
            explanation = f"""
Threat: {threat.get('threat_name', 'Unknown')}

What is it?
{threat_info['description']}

Why is it dangerous?
{', '.join(threat_info['risks'])}

What should you do?
{', '.join(threat_info['prevention'])}
"""
            return explanation

        return f"""
Threat Detected: {threat.get('threat_name', 'Unknown')}
Category: {threat.get('category', 'Unknown')}
Risk Level: {threat.get('risk_level', 'Unknown')}

Description: {threat.get('description', 'No additional information available')}

Recommended Action: Run a full system scan and quarantine any infected files.
"""

    def answer_question(self, question: str, user_id: int = None) -> str:
        """Answer a security question"""
        faq_answer = self.knowledge_base.get_faq_answer(question)
        if faq_answer:
            response = str(faq_answer)
        else:
            response = "I don't have enough information to answer this question. Please check the documentation or contact support."

        if user_id and self.db_manager:
            self.knowledge_base.store_conversation(user_id, question, response)

        return response

    def generate_summary(self, threats: list, period: str = 'daily') -> str:
        """Generate threat summary report"""
        critical = sum(1 for t in threats if t.get('risk_level') == 'Critical')
        high = sum(1 for t in threats if t.get('risk_level') == 'High')
        medium = sum(1 for t in threats if t.get('risk_level') == 'Medium')
        low = sum(1 for t in threats if t.get('risk_level') == 'Low')

        summary = f"""
Security Summary Report - {period.capitalize()}

Total Threats Detected: {len(threats)}
  Critical: {critical}
  High: {high}
  Medium: {medium}
  Low: {low}

Key Findings:
"""
        if critical > 0:
            summary += f"- {critical} critical threats require immediate attention\n"
        if high > 0:
            summary += f"- {high} high-risk threats detected\n"

        summary += """
Recommendations:
1. Review and act on critical and high-risk alerts immediately
2. Run full system scans regularly
3. Keep all software and OS patches updated
4. Consider implementing stronger access controls
5. Educate users about cybersecurity best practices
"""
        return summary
