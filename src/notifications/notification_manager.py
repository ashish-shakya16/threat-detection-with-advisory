"""
Notification Manager

Orchestrates alert notifications based on threat severity and user rules.
Coordinates between threat detection and notification channels (email, SMS, webhooks).
"""

import logging
from typing import Dict, List, Any, Optional

from src.notifications.email_service import EmailService
from src.notifications.email_templates import EmailTemplates
from src.exceptions import NotificationException


class NotificationManager:
    """
    Manages alert notifications based on threat severity and user configuration.

    Integrates with email service and provides rule-based notification logic.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize notification manager.

        Args:
            config: Configuration dictionary with keys:
                - enabled: Boolean, enable/disable notifications
                - notify_on_critical: Boolean
                - notify_on_high: Boolean
                - notify_on_medium: Boolean
                - notify_on_low: Boolean
                - recipients: List of email addresses
                - smtp: SMTP configuration for EmailService
        """
        self.logger = logging.getLogger('SecureX.NotificationManager')

        self.enabled = config.get('enabled', True)
        self.notify_on_critical = config.get('notify_on_critical', True)
        self.notify_on_high = config.get('notify_on_high', True)
        self.notify_on_medium = config.get('notify_on_medium', False)
        self.notify_on_low = config.get('notify_on_low', False)

        self.recipients = config.get('recipients', [])

        if not self.recipients:
            self.logger.warning("No recipients configured for notifications")

        # Initialize email service
        smtp_config = config.get('smtp', {})
        try:
            self.email_service = EmailService(smtp_config) if smtp_config else None
        except NotificationException as e:
            self.logger.error(f"Failed to initialize email service: {str(e)}")
            self.email_service = None

        self.logger.info(f"NotificationManager initialized with {len(self.recipients)} recipients")

    def should_notify(self, threat: Dict[str, Any]) -> bool:
        """
        Determine if a threat should trigger a notification.

        Args:
            threat: Threat dictionary with 'risk_level' key

        Returns:
            True if notification should be sent, False otherwise
        """
        if not self.enabled:
            return False

        if not self.recipients:
            return False

        if not self.email_service:
            return False

        risk_level = threat.get('risk_level', 'Low')

        notification_rules = {
            'Critical': self.notify_on_critical,
            'High': self.notify_on_high,
            'Medium': self.notify_on_medium,
            'Low': self.notify_on_low
        }

        return notification_rules.get(risk_level, False)

    def notify_threat(self, threat: Dict[str, Any]) -> bool:
        """
        Send threat notification to all configured recipients.

        Args:
            threat: Threat dictionary with full threat details

        Returns:
            True if at least one email sent successfully, False otherwise
        """
        if not self.should_notify(threat):
            return False

        try:
            html_body, text_body, subject = EmailTemplates.generate_threat_alert_email(threat)

            results = self.email_service.send_bulk_email(
                self.recipients,
                subject,
                html_body,
                text_body
            )

            successful = sum(1 for success in results.values() if success)
            self.logger.info(f"Threat notification sent: {successful}/{len(self.recipients)} recipients")

            return successful > 0

        except Exception as e:
            self.logger.error(f"Failed to send threat notification: {str(e)}")
            return False

    def notify_daily_summary(self, threats: List[Dict[str, Any]]) -> bool:
        """
        Send daily threat summary to all configured recipients.

        Args:
            threats: List of threat dictionaries from past 24 hours

        Returns:
            True if at least one email sent successfully, False otherwise
        """
        if not self.enabled or not self.recipients or not self.email_service:
            return False

        try:
            html_body, text_body, subject = EmailTemplates.generate_daily_summary_email(threats)

            results = self.email_service.send_bulk_email(
                self.recipients,
                subject,
                html_body,
                text_body
            )

            successful = sum(1 for success in results.values() if success)
            self.logger.info(f"Daily summary sent to {successful}/{len(self.recipients)} recipients")

            return successful > 0

        except Exception as e:
            self.logger.error(f"Failed to send daily summary: {str(e)}")
            return False

    def add_recipient(self, email: str) -> bool:
        """
        Add email recipient to notification list.

        Args:
            email: Email address to add

        Returns:
            True if added successfully, False if invalid
        """
        if not self.email_service:
            self.logger.error("Email service not initialized")
            return False

        if not self.email_service.validate_email(email):
            self.logger.error(f"Invalid email address: {email}")
            return False

        if email not in self.recipients:
            self.recipients.append(email)
            self.logger.info(f"Added recipient: {email}")
            return True

        return False

    def remove_recipient(self, email: str) -> bool:
        """
        Remove email recipient from notification list.

        Args:
            email: Email address to remove

        Returns:
            True if removed, False if not found
        """
        if email in self.recipients:
            self.recipients.remove(email)
            self.logger.info(f"Removed recipient: {email}")
            return True

        return False

    def notify_digest(self, threats: List[Dict[str, Any]], digest_type: str = 'hourly') -> bool:
        """
        Send batched digest of threats (v1.2 feature).

        Args:
            threats: List of threats to include in digest
            digest_type: 'hourly', 'daily', or 'weekly'

        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.enabled or not self.recipients or not self.email_service:
            return False

        try:
            html_body, text_body, subject = EmailTemplates.generate_digest_email(threats, digest_type)

            results = self.email_service.send_bulk_email(
                self.recipients,
                subject,
                html_body,
                text_body
            )

            successful = sum(1 for success in results.values() if success)
            self.logger.info(f"Digest ({digest_type}) sent to {successful}/{len(self.recipients)} recipients")

            return successful > 0

        except Exception as e:
            self.logger.error(f"Failed to send digest: {str(e)}")
            return False
