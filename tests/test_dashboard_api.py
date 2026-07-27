"""Dashboard API tests."""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.dashboard.app import app


@pytest.fixture
def client():
    """Flask test client, authenticated as a logged-in user."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['username'] = 'test-fixture-user'
        yield client


def test_get_threats(client):
    """Test getting threats"""
    response = client.get('/api/threats/')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'data' in data


def test_get_stats(client):
    """Test getting statistics"""
    response = client.get('/api/stats/')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True


def test_get_analytics(client):
    """Test getting analytics"""
    response = client.get('/api/analytics/timeline')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True


def test_get_top_threats(client):
    """Test getting top threats"""
    response = client.get('/api/analytics/top-threats')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True


def test_get_critical_threats(client):
    """Test getting critical threats"""
    response = client.get('/api/threats/critical')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
