"""Tests for AI assistant."""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.assistant.ai_assistant import AIAssistant
from src.assistant.knowledge_base import KnowledgeBase


@pytest.fixture
def knowledge_base():
    return KnowledgeBase()


@pytest.fixture
def ai_assistant():
    return AIAssistant()


@pytest.fixture
def sample_threat():
    return {
        'threat_name': 'Test Malware',
        'category': 'Malware',
        'risk_level': 'High',
        'description': 'This is a test threat'
    }


def test_knowledge_base_threat_info(knowledge_base):
    """Test retrieving threat information"""
    info = knowledge_base.get_threat_info('Malware')
    assert info is not None
    assert 'description' in info
    assert 'risks' in info
    assert 'prevention' in info


def test_explain_threat(ai_assistant, sample_threat):
    """Test threat explanation generation"""
    explanation = ai_assistant.explain_threat(sample_threat)
    assert len(explanation) > 0
    assert sample_threat['threat_name'] in explanation


def test_answer_question(ai_assistant):
    """Test question answering"""
    response = ai_assistant.answer_question("What is malware?")
    assert len(response) > 0
    assert isinstance(response, str)


@patch('src.assistant.ai_assistant.requests.post')
def test_answer_question_uses_configured_ai_provider(mock_post, monkeypatch):
    """Test that enabled AI configuration sends the prompt to the provider."""
    monkeypatch.setenv('SECUREX_AI_API_KEY', 'test-key')
    provider_response = Mock()
    provider_response.json.return_value = {
        'choices': [{'message': {'content': 'Use MFA and update your software.'}}]
    }
    mock_post.return_value = provider_response

    assistant = AIAssistant(config={
        'ai': {
            'enabled': True,
            'model': 'test-model',
            'base_url': 'https://example.test/v1/chat/completions',
        }
    })

    response = assistant.answer_question('How do I protect my account?')

    assert response == 'Use MFA and update your software.'
    mock_post.assert_called_once()
    request = mock_post.call_args.kwargs
    assert request['headers']['Authorization'] == 'Bearer test-key'
    assert request['json']['model'] == 'test-model'
    assert request['json']['messages'][0]['role'] == 'system'


@patch('src.assistant.ai_assistant.requests.post')
def test_answer_question_falls_back_when_provider_fails(mock_post, monkeypatch):
    """Test that provider errors do not break the local assistant."""
    monkeypatch.setenv('SECUREX_AI_API_KEY', 'test-key')
    mock_post.side_effect = Exception('provider unavailable')

    assistant = AIAssistant(config={'ai': {'enabled': True}})

    response = assistant.answer_question('What is ransomware?')

    assert 'Ransomware is malicious software' in response


def test_faq_answer(knowledge_base):
    """Test FAQ functionality"""
    answer = knowledge_base.get_faq_answer("what is ransomware")
    assert answer is not None


def test_generate_summary(ai_assistant):
    """Test summary generation"""
    threats = [
        {'risk_level': 'Critical'},
        {'risk_level': 'High'},
        {'risk_level': 'Medium'},
    ]
    summary = ai_assistant.generate_summary(threats, 'daily')
    assert 'Critical: 1' in summary
    assert 'High: 1' in summary
