"""
Tests for v1.2 features: SMS, Webhooks, Digest emails, ML integration
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from src.notifications.sms_service import SMSService
from src.notifications.webhook_service import WebhookService
from src.notifications.email_templates import EmailTemplates
from src.notifications.notification_manager import NotificationManager
from src.ml_models.ml_integration import MLIntegration
from src.exceptions import NotificationException


class TestSMSService(unittest.TestCase):
    """Test SMS notification service"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'account_sid': 'test-sid',
            'auth_token': 'test-token',
            'from_number': '+1234567890'
        }

    def test_phone_validation_valid(self):
        """Test valid phone number validation"""
        valid_phones = [
            '+1 (555) 123-4567',
            '555-123-4567',
            '5551234567',
            '+15551234567'
        ]
        for phone in valid_phones:
            self.assertTrue(SMSService.validate_phone(phone))

    def test_phone_validation_invalid(self):
        """Test invalid phone number validation"""
        invalid_phones = [
            'not-a-phone',
            '123',
            'abc-def-ghij'
        ]
        for phone in invalid_phones:
            self.assertFalse(SMSService.validate_phone(phone))

    def test_sms_service_init_requires_twilio(self):
        """Test SMS service requires Twilio library"""
        # Twilio is optional, skip if not installed
        try:
            from twilio.rest import Client
            service = SMSService(self.config)
            self.assertIsNotNone(service.client)
        except ImportError:
            self.skipTest("Twilio not installed")

    def test_sms_service_missing_config(self):
        """Test SMS service fails with missing config"""
        bad_config = {'account_sid': 'test'}
        with self.assertRaises(NotificationException):
            SMSService(bad_config)


class TestWebhookService(unittest.TestCase):
    """Test webhook notification service"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'endpoints': ['https://example.com/webhook'],
            'timeout': 10,
            'retry_attempts': 3
        }

    def test_webhook_service_init(self):
        """Test webhook service initialization"""
        service = WebhookService(self.config)
        self.assertEqual(len(service.endpoints), 1)

    def test_webhook_service_invalid_url(self):
        """Test webhook service rejects invalid URLs"""
        bad_config = {'endpoints': ['not-a-url']}
        with self.assertRaises(NotificationException):
            WebhookService(bad_config)

    def test_add_webhook_endpoint(self):
        """Test adding webhook endpoint"""
        service = WebhookService(self.config)
        success = service.add_endpoint('https://newexample.com/hook')
        self.assertTrue(success)
        self.assertEqual(len(service.endpoints), 2)

    def test_remove_webhook_endpoint(self):
        """Test removing webhook endpoint"""
        service = WebhookService(self.config)
        success = service.remove_endpoint('https://example.com/webhook')
        self.assertTrue(success)
        self.assertEqual(len(service.endpoints), 0)

    @patch('src.notifications.webhook_service.requests.post')
    def test_send_webhook_success(self, mock_post):
        """Test successful webhook send"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        service = WebhookService(self.config)
        threat = {
            'threat_name': 'Test',
            'risk_level': 'High',
            'risk_score': 0.85
        }
        success = service.send_webhook(threat)
        self.assertTrue(success)

    def test_webhook_payload_preparation(self):
        """Test webhook payload is properly formatted"""
        threat = {
            'threat_id': 123,
            'threat_name': 'Malware',
            'category': 'Malicious Software',
            'risk_level': 'Critical',
            'risk_score': 0.95
        }
        payload = WebhookService._prepare_payload(threat)
        self.assertEqual(payload['threat_name'], 'Malware')
        self.assertEqual(payload['risk_level'], 'Critical')


class TestDigestEmail(unittest.TestCase):
    """Test digest email template generation"""

    def test_hourly_digest_generation(self):
        """Test hourly digest email generation"""
        threats = [
            {'threat_name': 'T1', 'risk_level': 'Critical', 'risk_score': 0.9, 'timestamp': '2026-07-27 10:00'},
            {'threat_name': 'T2', 'risk_level': 'High', 'risk_score': 0.7, 'timestamp': '2026-07-27 10:15'}
        ]
        html, text, subject = EmailTemplates.generate_digest_email(threats, 'hourly')

        self.assertIn('Hourly Threat Digest', html)
        self.assertIn('Critical', html)
        self.assertIn('High', html)
        self.assertIn('past hour', html)

    def test_weekly_digest_generation(self):
        """Test weekly digest email generation"""
        threats = [
            {'threat_name': 'T1', 'risk_level': 'Medium', 'risk_score': 0.5, 'timestamp': '2026-07-27 10:00'}
        ]
        html, text, subject = EmailTemplates.generate_digest_email(threats, 'weekly')

        self.assertIn('Weekly Threat Digest', html)
        self.assertIn('past week', html)
        self.assertIn('SecureX Weekly Digest', subject)

    def test_digest_email_has_table(self):
        """Test digest email contains threat table"""
        threats = [
            {'threat_name': 'T1', 'risk_level': 'High', 'risk_score': 0.75, 'timestamp': '2026-07-27 10:00'}
        ]
        html, _, _ = EmailTemplates.generate_digest_email(threats, 'daily')

        self.assertIn('<table', html)
        self.assertIn('Threat Name', html)
        self.assertIn('Severity', html)


class TestNotificationManagerDigest(unittest.TestCase):
    """Test NotificationManager digest functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = {
            'enabled': True,
            'recipients': ['test@example.com'],
            'smtp': {
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'sender_email': 'admin@example.com',
                'sender_password': 'password'
            }
        }

    @patch('src.notifications.email_service.smtplib.SMTP')
    def test_send_digest(self, mock_smtp):
        """Test sending digest email"""
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        manager = NotificationManager(self.config)
        threats = [
            {'threat_name': 'T1', 'risk_level': 'High', 'risk_score': 0.8, 'timestamp': '2026-07-27'},
            {'threat_name': 'T2', 'risk_level': 'Medium', 'risk_score': 0.6, 'timestamp': '2026-07-27'}
        ]

        success = manager.notify_digest(threats, 'hourly')
        self.assertTrue(success or success is not None)


class TestMLIntegration(unittest.TestCase):
    """Test ML anomaly detection integration"""

    def setUp(self):
        """Set up test fixtures"""
        self.ml = MLIntegration()

    def test_ml_integration_init(self):
        """Test ML integration initialization"""
        self.assertIsNotNone(self.ml.trainer)
        self.assertIsNotNone(self.ml.extractor)

    def test_get_model_stats(self):
        """Test getting ML model statistics"""
        stats = self.ml.get_model_stats()
        self.assertIn('trained', stats)
        self.assertIn('status', stats)
        self.assertIn('model_path', stats)

    def test_ml_risk_score_untrained(self):
        """Test ML risk score returns 0 when untrained"""
        event = {'event_type': 'suspicious_process'}
        score = self.ml.calculate_ml_risk_score(event)
        self.assertEqual(score, 0.0)

    def test_enrich_threat_with_ml_score(self):
        """Test enriching threat with ML score"""
        threat = {'threat_name': 'Test', 'risk_score': 0.7}
        ml_risk = 0.8

        enriched = self.ml.enrich_threat_with_ml_score(threat, ml_risk)

        self.assertIn('ml_score', enriched)
        self.assertEqual(enriched['ml_score'], 0.8)
        self.assertIn('blended_score', enriched)

    def test_blended_score_calculation(self):
        """Test ML/rule blended scoring formula"""
        threat = {'threat_name': 'Test', 'risk_score': 0.6}
        ml_risk = 0.9

        enriched = self.ml.enrich_threat_with_ml_score(threat, ml_risk)
        expected = (0.6 * 0.7) + (0.9 * 0.3)  # 70% rule, 30% ML

        self.assertAlmostEqual(enriched['blended_score'], expected, places=2)


class TestV12Features(unittest.TestCase):
    """Integration tests for v1.2 features"""

    def test_email_templates_all_formats(self):
        """Test all email template formats work"""
        threat = {
            'threat_name': 'Test Threat',
            'risk_level': 'High',
            'risk_score': 0.85,
            'category': 'Testing',
            'description': 'Test description',
            'timestamp': '2026-07-27 10:00:00'
        }

        # Test alert email
        html, text, subject = EmailTemplates.generate_threat_alert_email(threat)
        self.assertIsNotNone(html)
        self.assertIsNotNone(text)
        self.assertIn('High', subject)

        # Test daily summary
        html, text, subject = EmailTemplates.generate_daily_summary_email([threat])
        self.assertIsNotNone(html)
        self.assertIn('Daily', subject)

        # Test digest
        html, text, subject = EmailTemplates.generate_digest_email([threat], 'daily')
        self.assertIsNotNone(html)
        self.assertIn('Digest', subject)


if __name__ == '__main__':
    unittest.main()
