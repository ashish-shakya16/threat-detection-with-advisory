import pytest
from unittest.mock import Mock, patch
from src.notifications.notification_manager import NotificationManager
from src.notifications.email_service import EmailService
from src.exceptions import NotificationException


class TestNotificationManager:
    """Test notification manager initialization and rules."""

    def test_init_with_config(self):
        """Test NotificationManager initializes with configuration."""
        config = {
            'enabled': True,
            'notify_on_critical': True,
            'notify_on_high': True,
            'notify_on_medium': False,
            'recipients': ['admin@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        assert manager.enabled is True
        assert manager.notify_on_critical is True
        assert manager.recipients == ['admin@example.com']

    def test_should_notify_critical(self):
        """Test that critical threats trigger notifications when enabled."""
        config = {
            'enabled': True,
            'notify_on_critical': True,
            'notify_on_high': False,
            'recipients': ['admin@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        threat = {'risk_level': 'Critical', 'threat_name': 'Test Threat'}
        assert manager.should_notify(threat) is True

    def test_should_not_notify_low_when_disabled(self):
        """Test that low threats don't notify when disabled."""
        config = {
            'enabled': True,
            'notify_on_critical': False,
            'notify_on_high': False,
            'notify_on_medium': False,
            'notify_on_low': False,
            'recipients': ['admin@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        threat = {'risk_level': 'Low', 'threat_name': 'Test Threat'}
        assert manager.should_notify(threat) is False

    def test_notify_threat_success(self):
        """Test successful threat notification."""
        config = {
            'enabled': True,
            'notify_on_critical': True,
            'recipients': ['admin@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        manager.email_service = Mock(spec=EmailService)
        manager.email_service.send_bulk_email.return_value = {'admin@example.com': True}

        threat = {
            'risk_level': 'Critical',
            'threat_name': 'Test Threat',
            'category': 'Malware',
            'description': 'Test description',
            'risk_score': 0.95,
            'timestamp': '2026-07-27T12:00:00Z',
            'remediation_steps': ['Step 1', 'Step 2']
        }

        result = manager.notify_threat(threat)

        assert result is True
        manager.email_service.send_bulk_email.assert_called_once()

    def test_add_recipient(self):
        """Test adding a new recipient."""
        config = {
            'enabled': True,
            'recipients': ['admin@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        result = manager.add_recipient('user@example.com')

        assert result is True
        assert 'user@example.com' in manager.recipients

    def test_remove_recipient(self):
        """Test removing a recipient."""
        config = {
            'enabled': True,
            'recipients': ['admin@example.com', 'user@example.com'],
            'smtp': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': 'alerts@example.com',
                'sender_password': 'password'
            }
        }

        manager = NotificationManager(config)

        result = manager.remove_recipient('user@example.com')

        assert result is True
        assert 'user@example.com' not in manager.recipients
