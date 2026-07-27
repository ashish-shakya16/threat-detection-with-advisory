import pytest
from unittest.mock import Mock, patch
from src.notifications.email_service import EmailService
from src.exceptions import NotificationException


class TestEmailService:
    """Test email service initialization and configuration."""

    def test_init_with_valid_config(self):
        """Test EmailService initializes with valid SMTP config."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password',
            'use_tls': True
        }

        service = EmailService(config)

        assert service.smtp_server == 'smtp.gmail.com'
        assert service.smtp_port == 587
        assert service.sender_email == 'alerts@example.com'
        assert service.use_tls is True

    def test_init_with_missing_required_field(self):
        """Test EmailService raises exception when required field is missing."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_password': 'test_password'
        }

        with pytest.raises(NotificationException):
            EmailService(config)

    def test_validate_email_addresses_valid(self):
        """Test email validation accepts valid addresses."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password'
        }

        service = EmailService(config)

        assert service.validate_email('user@example.com') is True
        assert service.validate_email('john.doe+tag@company.co.uk') is True

    def test_validate_email_addresses_invalid(self):
        """Test email validation rejects invalid addresses."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password'
        }

        service = EmailService(config)

        assert service.validate_email('not_an_email') is False
        assert service.validate_email('missing@domain') is False
        assert service.validate_email('@nodomain.com') is False

    def test_send_email_success(self):
        """Test successful email send."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password'
        }

        service = EmailService(config)

        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value = mock_server

            result = service.send_email(
                'user@example.com',
                'Test Subject',
                '<h1>Test</h1>',
                'Test body'
            )

            assert result is True
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with('alerts@example.com', 'test_password')
            mock_server.send_message.assert_called_once()
            mock_server.quit.assert_called_once()

    def test_send_email_invalid_recipient(self):
        """Test send_email rejects invalid recipient."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password'
        }

        service = EmailService(config)

        with pytest.raises(NotificationException):
            service.send_email('invalid-email', 'Subject', '<h1>Body</h1>')

    def test_send_bulk_email(self):
        """Test bulk email sending."""
        config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'alerts@example.com',
            'sender_password': 'test_password'
        }

        service = EmailService(config)

        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = Mock()
            mock_smtp.return_value = mock_server

            recipients = ['user1@example.com', 'user2@example.com']
            results = service.send_bulk_email(recipients, 'Subject', '<h1>Body</h1>')

            assert len(results) == 2
            assert all(results.values())
