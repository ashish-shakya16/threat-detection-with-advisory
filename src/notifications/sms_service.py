"""
SMS Notification Service (v1.2 feature)

Provides SMS alerts for critical threats using Twilio integration.
"""

import logging
from typing import Dict, Any, List

import phonenumbers

from src.exceptions import NotificationException


class SMSService:
    """
    SMS notification service for critical threat alerts.

    Integrates with Twilio for SMS delivery with retry logic.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SMS service.

        Args:
            config: SMS configuration with keys:
                - account_sid: Twilio account SID
                - auth_token: Twilio auth token
                - from_number: Sender phone number
                - retry_attempts: Number of retry attempts
                - retry_delay: Seconds between retries
        """
        self.logger = logging.getLogger('SecureX.SMSService')

        self.account_sid = config.get('account_sid')
        self.auth_token = config.get('auth_token')
        self.from_number = config.get('from_number')
        self.retry_attempts = config.get('retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 2)

        self._validate_config()
        self._init_twilio()

    def _validate_config(self):
        """Validate SMS configuration."""
        if not self.account_sid or not self.auth_token:
            raise NotificationException("Twilio credentials not configured")
        if not self.from_number:
            raise NotificationException("SMS sender number not configured")

    def _init_twilio(self):
        """Initialize Twilio client."""
        try:
            from twilio.rest import Client
            self.client = Client(self.account_sid, self.auth_token)
            self.logger.info("Twilio client initialized")
        except ImportError:
            raise NotificationException("Twilio library not installed. Install: pip install twilio")
        except Exception as e:
            raise NotificationException(f"Failed to initialize Twilio: {str(e)}")

    @staticmethod
    def validate_phone(phone: str) -> bool:
        """
        Validate phone number format using Google's libphonenumber (via the
        phonenumbers package), which supports international numbers.

        Numbers must be in E.164 format with a leading '+' and country code
        (e.g. '+14155552671', '+442071838750') since a bare national number
        is ambiguous without knowing which country's numbering plan applies.
        """
        try:
            parsed = phonenumbers.parse(phone, None)
            return phonenumbers.is_valid_number(parsed)
        except phonenumbers.NumberParseException:
            return False

    def send_sms(self, recipient: str, message: str) -> bool:
        """
        Send SMS to single recipient.

        Args:
            recipient: Phone number
            message: SMS message body

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.validate_phone(recipient):
            self.logger.error(f"Invalid phone number: {recipient}")
            raise NotificationException(f"Invalid phone number: {recipient}")

        for attempt in range(self.retry_attempts):
            try:
                sms = self.client.messages.create(
                    body=message,
                    from_=self.from_number,
                    to=recipient
                )
                self.logger.info(f"SMS sent to {recipient}: {sms.sid}")
                return True
            except Exception as e:
                self.logger.warning(f"SMS send attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.retry_attempts - 1:
                    import time
                    time.sleep(self.retry_delay)

        self.logger.error(f"Failed to send SMS to {recipient} after {self.retry_attempts} attempts")
        return False

    def send_bulk_sms(self, recipients: List[str], message: str) -> Dict[str, bool]:
        """
        Send SMS to multiple recipients.

        Args:
            recipients: List of phone numbers
            message: SMS message body

        Returns:
            Dictionary mapping recipient to success status
        """
        results = {}
        for recipient in recipients:
            try:
                success = self.send_sms(recipient, message)
                results[recipient] = success
            except Exception as e:
                self.logger.error(f"Error sending to {recipient}: {str(e)}")
                results[recipient] = False

        return results
