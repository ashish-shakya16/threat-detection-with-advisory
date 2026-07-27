"""Unit tests for SMSService phone validation."""

import unittest
from unittest.mock import patch, MagicMock

from src.notifications.sms_service import SMSService
from src.exceptions import NotificationException


def make_config():
    return {
        'account_sid': 'test_sid',
        'auth_token': 'test_token',
        'from_number': '+15551234567',
        'retry_attempts': 1,
        'retry_delay': 0,
    }


class TestSMSServicePhoneValidation(unittest.TestCase):
    def setUp(self):
        # Mock Twilio's Client so no real network calls happen and the
        # twilio package doesn't need to be installed/importable in CI.
        patcher = patch('twilio.rest.Client')
        self.addCleanup(patcher.stop)
        self.mock_client_class = patcher.start()

        self.service = SMSService(make_config())

    def test_validate_us_number_with_plus_prefix(self):
        self.assertTrue(SMSService.validate_phone('+14155552671'))

    def test_validate_uk_number(self):
        self.assertTrue(SMSService.validate_phone('+442071838750'))

    def test_validate_india_number(self):
        self.assertTrue(SMSService.validate_phone('+919876543210'))

    def test_reject_invalid_number(self):
        self.assertFalse(SMSService.validate_phone('not-a-phone-number'))

    def test_reject_too_short_number(self):
        self.assertFalse(SMSService.validate_phone('+1123'))

    def test_reject_number_missing_country_code(self):
        # phonenumbers requires a country code (E.164 format with +) to
        # unambiguously validate international numbers.
        self.assertFalse(SMSService.validate_phone('4155552671'))


if __name__ == '__main__':
    unittest.main()
