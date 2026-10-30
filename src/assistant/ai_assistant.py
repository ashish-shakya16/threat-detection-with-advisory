"""AI Security Assistant Module.

Answers security questions and explains SecureX detections using
retrieval-augmented generation. The assistant is read-only: it has no tools
and cannot run commands, stop processes, delete or quarantine files.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from src.assistant.knowledge_base import KnowledgeBase
from src.assistant.rag import SecurityRetriever, load_documents
from src.assistant.prompt_templates import (
    FAQ_PROMPT_TEMPLATE,
    REPORT_GENERATION_TEMPLATE,
    SYSTEM_PROMPT,
    THREAT_EXPLANATION_TEMPLATE,
)

logger = logging.getLogger('securex')

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_QUESTION_LENGTH = 2000
MAX_RESPONSE_LENGTH = 8000

PROVIDER_DEFAULT_URLS = {
    'openai-compatible': 'https://api.openai.com/v1/chat/completions',
    'huggingface': 'https://router.huggingface.co/v1/chat/completions',
    'ollama': 'http://localhost:11434/v1/chat/completions',
}

# Questions about the user's own SecureX data rather than general security.
HISTORY_PATTERN = re.compile(
    r'\b(recent|recently|latest|last|today|yesterday|this week|history|scans?|'
    r'alerts?|logs?|detected|detections|flagged|dashboard|'
    r'(?:my|our|this) (?:system|computer|pc|device|machine|threats?|network))\b',
    re.IGNORECASE,
)
# Knowledge sections whose list items are advice rather than description.
ADVICE_SECTION_PATTERN = re.compile(
    r'(what to do|response|prevention|recommended|how to check|investigating)', re.IGNORECASE
)
ACTION_PATTERN = re.compile(
    r'\b(delete|remove|kill|terminate|end|stop|quarantine|block|uninstall|wipe)\b',
    re.IGNORECASE,
)
HEDGE_PATTERN = re.compile(
    r"\b(not sure|uncertain|cannot determine|can't determine|insufficient|unclear|"
    r"no evidence|not enough information)\b",
    re.IGNORECASE,
)
SAFE_THREAT_FIELDS = (
    'id', 'threat_name', 'category', 'risk_level', 'risk_score', 'severity',
    'source', 'description', 'detected_at', 'last_seen_at', 'occurrence_count', 'status',
    'risk_context',
)

ADVISORY_WARNING = 'AI-generated guidance. Check it against the evidence before you act.'
NO_ACTION_NOTE = (
    'The assistant cannot take actions on your system. Containment such as suspending '
    'a process only happens through the response approval workflow in the threat '
    'details, after you have reviewed the evidence.'
)


def _untrusted(label: str, text: str) -> str:
    """Wrap data so the model can tell it apart from instructions."""
    text = str(text).replace('</untrusted_data>', '[/untrusted_data]')
    return f'<untrusted_data label="{label}">\n{text}\n</untrusted_data>'


def _clean_excerpt(text: str, limit: int = 500) -> str:
    # Headings are already shown as the evidence source, so drop them.
    text = re.sub(r'(?m)^#{1,6}\s.*$', '', text).strip()
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text if len(text) <= limit else text[:limit].rsplit(' ', 1)[0] + '...'


def _list_items(text: str) -> List[str]:
    """Pull bullet or numbered list lines out of a knowledge chunk."""
    items = []
    for line in text.splitlines():
        match = re.match(r'\s*(?:[-*]|\d+\.)\s+(.*)', line)
        if match and len(match.group(1)) > 15:
            items.append(match.group(1).strip())
    return items


class AIAssistant:
    """AI-powered security assistant"""

    def __init__(self, db_manager=None, config: Dict = None):
        """Initialize AI assistant"""
        self.db_manager = db_manager
        self.config = config or {}
        self.knowledge_base = KnowledgeBase(db_manager)
        self.ai_config = self.config.get('ai', {}) or {}
        knowledge_dir = Path(self.ai_config.get('knowledge_dir', 'docs/security_knowledge'))
        if not knowledge_dir.is_absolute():
            knowledge_dir = PROJECT_ROOT / knowledge_dir
        documents = load_documents(self.knowledge_base.threat_definitions, str(knowledge_dir))
        self.retriever = SecurityRetriever(self.ai_config, documents)

    # ------------------------------------------------------------------
    # Input validation and provider access
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_question(question: str) -> str:
        """Bound and normalize user input before it reaches a provider."""
        if not isinstance(question, str):
            raise ValueError('Message must be text')
        normalized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', question).strip()
        if not normalized:
            raise ValueError('Message is required')
        if len(normalized) > MAX_QUESTION_LENGTH:
            raise ValueError(f'Message must be {MAX_QUESTION_LENGTH} characters or fewer')
        return normalized

    def _provider(self) -> str:
        return self.ai_config.get('provider', 'openai-compatible')

    def _api_key(self) -> str:
        """Resolve the API key from the environment; it is never stored in config."""
        environment_variable = self.ai_config.get('api_key_env', 'SECUREX_AI_API_KEY')
        return os.environ.get(environment_variable, '')

    def provider_available(self) -> bool:
        if not self.ai_config.get('enabled', False):
            return False
        return bool(self._api_key()) or self._provider() == 'ollama'

    def _generate_response(self, prompt: str, history: Optional[List[Dict[str, str]]] = None) -> str:
        """Generate a response through an OpenAI-compatible chat endpoint.

        Returns an empty string when the provider is disabled, unconfigured or
        fails, so callers can fall back to the local knowledge base.
        """
        if not self.ai_config.get('enabled', False):
            return ''

        api_key = self._api_key()
        if not api_key and self._provider() != 'ollama':
            logger.warning('AI assistant is enabled but no API key was configured')
            return ''

        endpoint = self.ai_config.get('base_url') or PROVIDER_DEFAULT_URLS.get(
            self._provider(), PROVIDER_DEFAULT_URLS['openai-compatible']
        )
        messages = [{'role': 'system', 'content': SYSTEM_PROMPT}]
        messages.extend(history or [])
        messages.append({'role': 'user', 'content': prompt})
        payload = {
            'model': self.ai_config.get('model', 'gpt-4o-mini'),
            'messages': messages,
            'temperature': self.ai_config.get('temperature', 0.2),
            'max_tokens': self.ai_config.get('max_tokens', 600),
        }
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=self.ai_config.get('timeout_seconds', 30),
            )
            response.raise_for_status()
            content = response.json()['choices'][0]['message']['content']
            return content.strip()[:MAX_RESPONSE_LENGTH] if isinstance(content, str) else ''
        except Exception as error:
            # The exception text never contains the key; it is only in headers.
            logger.warning('AI assistant request failed; using local response: %s', type(error).__name__)
            return ''

    # ------------------------------------------------------------------
    # SecureX context
    # ------------------------------------------------------------------

    def _recent_threat_records(self, limit: int = 10, hours: int = 168) -> List[Dict[str, Any]]:
        if not self.db_manager:
            return []
        try:
            rows = self.db_manager.get_recent_threats(limit=limit, hours=hours)
        except Exception as error:
            logger.warning('Could not load threat history for assistant: %s', error)
            return []
        return [{key: row.get(key) for key in SAFE_THREAT_FIELDS if key in row} for row in rows]

    @staticmethod
    def _record_evidence(record: Dict[str, Any]) -> Dict[str, Any]:
        seen = record.get('occurrence_count') or 1
        excerpt = (
            f"{record.get('threat_name')} | risk {record.get('risk_level')} "
            f"(score {record.get('risk_score')}) | category {record.get('category')} | "
            f"source {record.get('source')} | detected {record.get('detected_at')} | "
            f"seen {seen} time(s) | status {record.get('status')}"
        )
        if record.get('description'):
            excerpt += f" | rule: {record['description']}"
        if record.get('risk_context'):
            excerpt += f" | risk context: {record['risk_context']}"
        return {'kind': 'securex_record', 'source': f"SecureX threat #{record.get('id')}", 'excerpt': excerpt}

    def _conversation_messages(self, user_id: Optional[int], turns: int = 3) -> List[Dict[str, str]]:
        if not user_id or not self.db_manager:
            return []
        try:
            history = self.db_manager.get_conversations_for_user(user_id, limit=turns)
        except Exception:
            return []
        messages = []
        for entry in reversed(history):
            messages.append({'role': 'user', 'content': _untrusted('earlier question', (entry.get('query') or '')[:1000])})
            messages.append({'role': 'assistant', 'content': (entry.get('response') or '')[:1000]})
        return messages

    # ------------------------------------------------------------------
    # Questions
    # ------------------------------------------------------------------

    def answer_question_details(self, question: str, user_id: int = None) -> Dict[str, Any]:
        """Answer a question with evidence, uncertainty, and audit metadata.

        Flow: validate -> retrieve knowledge and SecureX records -> generate
        (provider or local fallback) -> attach warnings -> save history.
        """
        question = self._validate_question(question)
        knowledge = self.retriever.retrieve(question)
        evidence = [
            {'kind': 'knowledge', 'source': item['source'], 'excerpt': _clean_excerpt(item['text'], 400)}
            for item in knowledge
        ]

        records: List[Dict[str, Any]] = []
        if user_id and HISTORY_PATTERN.search(question):
            records = self._recent_threat_records()
            evidence.extend(self._record_evidence(record) for record in records)

        faq_answer = self.knowledge_base.get_faq_answer(question)

        provider_response = ''
        if self.provider_available():
            prompt = FAQ_PROMPT_TEMPLATE.format(question=question)
            prompt += '\n\nRetrieved security documentation:\n' + _untrusted(
                'knowledge base', self.retriever.format_context(knowledge)
            )
            if records:
                prompt += '\n\nSecureX threat records for this system (last 7 days):\n' + _untrusted(
                    'securex records', json.dumps(records, default=str)
                )
            provider_response = self._generate_response(prompt, self._conversation_messages(user_id))

        if provider_response:
            mode = 'llm'
            response = provider_response
            recommendations: List[str] = []
            uncertain = not evidence or bool(HEDGE_PATTERN.search(provider_response))
            confidence = 0.5 if uncertain else 0.75
        else:
            mode = 'local'
            response, recommendations = self._local_answer(question, faq_answer, knowledge, records, bool(user_id))
            has_support = bool(faq_answer or knowledge or records)
            uncertain = not has_support
            confidence = 0.85 if faq_answer else (0.6 if has_support else 0.2)

        warnings = []
        if uncertain:
            warnings.append(
                'I could not find enough verified evidence for this. Treat the answer as '
                'uncertain and investigate further before acting.'
            )
        elif mode == 'llm':
            warnings.append(ADVISORY_WARNING)
        if ACTION_PATTERN.search(question):
            warnings.append(NO_ACTION_NOTE)
        warning = ' '.join(warnings)

        self._store_conversation(user_id, question, response, confidence)

        return {
            'response': response,
            'recommendations': recommendations,
            'evidence': evidence,
            'sources': [item['source'] for item in evidence],
            'confidence': confidence,
            'uncertain': uncertain,
            'warning': warning,
            'mode': mode,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    def _store_conversation(self, user_id: Optional[int], question: str, response: str, confidence: float) -> None:
        if not user_id or not self.db_manager:
            return
        try:
            self.db_manager.log_conversation(user_id, question, response, confidence)
        except Exception as error:
            logger.warning('Failed to store conversation: %s', error)

    def _local_answer(self, question: str, faq_answer: Optional[str], knowledge: List[Dict[str, Any]],
                      records: List[Dict[str, Any]], authenticated: bool):
        """Compose an answer from verified sources without a language model."""
        parts: List[str] = []
        recommendations: List[str] = []

        if HISTORY_PATTERN.search(question) and authenticated and self.db_manager:
            parts.append(self._summarize_records(records))

        if faq_answer:
            parts.append(str(faq_answer))
        if knowledge:
            parts.append(_clean_excerpt(knowledge[0]['text'], 700))
            for item in knowledge:
                if not ADVICE_SECTION_PATTERN.search(item['source']):
                    continue
                for entry in _list_items(item['text']):
                    if entry not in recommendations:
                        recommendations.append(entry)
            recommendations = recommendations[:5]

        if not parts:
            parts.append(
                "I don't have enough verified information to answer this confidently. "
                "Please review the relevant alert or security logs and investigate further."
            )
        return '\n\n'.join(parts), recommendations

    @staticmethod
    def _summarize_records(records: List[Dict[str, Any]]) -> str:
        if not records:
            return 'SecureX has not recorded any threats on this system in the last 7 days.'
        counts: Dict[str, int] = {}
        for record in records:
            counts[record.get('risk_level') or 'Unknown'] = counts.get(record.get('risk_level') or 'Unknown', 0) + 1
        breakdown = ', '.join(
            f'{counts[level]} {level}' for level in ('Critical', 'High', 'Medium', 'Low', 'Unknown') if level in counts
        )
        lines = [f'Your {len(records)} most recent SecureX detections (last 7 days): {breakdown}.']
        for record in records[:5]:
            lines.append(
                f"- #{record.get('id')} {record.get('threat_name')} ({record.get('risk_level')}), "
                f"detected {record.get('detected_at')}, seen {record.get('occurrence_count') or 1} time(s), "
                f"status {record.get('status')}"
            )
        return '\n'.join(lines)

    def answer_question(self, question: str, user_id: int = None) -> str:
        """Answer a security question, preserving the original public API."""
        return str(self.answer_question_details(question, user_id)['response'])

    def get_conversation_history(self, user_id: int, limit: int = 50) -> list:
        """Return only the authenticated user's conversation history."""
        if not self.db_manager or not user_id:
            return []
        return [
            {key: entry.get(key) for key in ('id', 'query', 'response', 'confidence', 'created_at')}
            for entry in self.db_manager.get_conversations_for_user(user_id, limit=limit)
        ]

    # ------------------------------------------------------------------
    # Threat explanations
    # ------------------------------------------------------------------

    def explain_threat_details(self, threat: Dict, advisory: Optional[Dict] = None) -> Dict[str, Any]:
        """Explain why a threat was flagged, separating evidence from advice."""
        name = threat.get('threat_name', 'Unknown')
        category = threat.get('category', 'Unknown')
        record = {key: threat.get(key) for key in SAFE_THREAT_FIELDS if key in threat}
        evidence = [self._record_evidence(record)] if record.get('id') is not None else []

        knowledge = self.retriever.retrieve(f'{name} {category} {threat.get("description", "")}', limit=3)
        evidence.extend(
            {'kind': 'knowledge', 'source': item['source'], 'excerpt': _clean_excerpt(item['text'], 400)}
            for item in knowledge
        )

        recommendations: List[str] = []
        if advisory:
            actions = advisory.get('recommended_actions') or advisory.get('advice') or []
            if isinstance(actions, str):
                try:
                    actions = json.loads(actions)
                except ValueError:
                    actions = [actions]
            recommendations.extend(str(action) for action in actions if action)
            if advisory.get('description'):
                evidence.append({
                    'kind': 'securex_record',
                    'source': 'SecureX advisory',
                    'excerpt': _clean_excerpt(advisory['description'], 400),
                })

        threat_info = self.knowledge_base.get_threat_info(category)
        if not recommendations and threat_info:
            recommendations.extend(threat_info['prevention'])
        if not recommendations:
            for item in knowledge:
                if ADVICE_SECTION_PATTERN.search(item['source']):
                    recommendations.extend(_list_items(item['text']))
        recommendations = recommendations[:6]

        ai_response = ''
        if self.provider_available():
            ai_response = self._generate_response(
                THREAT_EXPLANATION_TEMPLATE.format(
                    threat_name=name,
                    category=category,
                    risk_level=threat.get('risk_level', 'Unknown'),
                    description=threat.get('description', 'No additional information available'),
                )
                + '\n\nSecureX evidence:\n'
                + _untrusted('securex evidence', json.dumps(evidence, default=str))
            )

        if ai_response:
            response, mode = ai_response, 'llm'
        else:
            mode = 'local'
            lines = [f'Threat: {name}', f"Risk level: {threat.get('risk_level', 'Unknown')}"]
            if threat.get('risk_score') is not None:
                lines[-1] += f" (score {threat.get('risk_score')})"
            lines.append(f'Category: {category}')
            if threat.get('occurrence_count'):
                lines.append(f"Seen {threat['occurrence_count']} time(s) from source {threat.get('source', 'unknown')}")
            lines.append('')
            lines.append('Why it was flagged:')
            lines.append(threat.get('description') or 'It matched a SecureX detection rule.')
            if threat_info:
                lines.append('')
                lines.append(f"What it is: {threat_info['description']}.")
                lines.append(f"Why it matters: {', '.join(threat_info['risks'])}.")
            elif knowledge:
                lines.append('')
                lines.append(_clean_excerpt(knowledge[0]['text'], 500))
            response = '\n'.join(lines)

        return {
            'response': response,
            'recommendations': recommendations,
            'evidence': evidence,
            'sources': [item['source'] for item in evidence],
            'warning': (ADVISORY_WARNING if mode == 'llm' else
                        'Verify the original threat evidence before taking action.') + ' ' + NO_ACTION_NOTE,
            'uncertain': not evidence,
            'mode': mode,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    def explain_threat(self, threat: Dict) -> str:
        """Explain a detected threat"""
        return str(self.explain_threat_details(threat)['response'])

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def generate_summary(self, threats: list, period: str = 'daily') -> str:
        """Generate threat summary report"""
        critical = sum(1 for t in threats if t.get('risk_level') == 'Critical')
        high = sum(1 for t in threats if t.get('risk_level') == 'High')
        medium = sum(1 for t in threats if t.get('risk_level') == 'Medium')
        low = sum(1 for t in threats if t.get('risk_level') == 'Low')

        ai_response = self._generate_response(
            REPORT_GENERATION_TEMPLATE.format(
                period=period,
                total_threats=len(threats),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
            )
        )
        if ai_response:
            return ai_response

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
