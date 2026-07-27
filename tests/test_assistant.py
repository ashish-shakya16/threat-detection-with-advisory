"""Tests for AI assistant."""

import pytest
import sys
from pathlib import Path

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
