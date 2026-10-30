"""
Notification Manager

Orchestrates alert notifications based on threat severity and user rules.
Coordinates between threat detection and notification channels (email, SMS, webhooks).
"""

import logging
import hashlib
import os
import queue
import threading
import time
from typing import Dict, List, Any, Optional

from src.notifications.email_service import EmailService
from src.notifications.email_templates import EmailTemplates
from src.exceptions import NotificationException


PREFERENCES_SETTING_KEY = 'notifications.preferences'

# Used when a threat carries no advisory of its own, so every alert email
# still tells the reader what to do next.
DEFAULT_REMEDIATION_STEPS = {
    'Critical': [
        'Open the SecureX dashboard and review the full alert details immediately.',
        'Disconnect the affected device from the network if the activity is ongoing.',
        'Do not delete or modify related files until they have been investigated.',
        'Escalate to your security or IT administrator.',
    ],
    'High': [
        'Review the alert details in the SecureX dashboard.',
        'Confirm whether the process, file, or connection is expected.',
        'Run a full system scan with your antivirus software.',
        'Contact your administrator if the activity is not recognised.',
    ],
}


class NotificationManager:
    """
    Manages alert notifications based on threat severity and user configuration.

    Integrates with email service and provides rule-based notification logic.
    """

    def __init__(self, config: Dict[str, Any], db=None, dashboard_url: str = ''):
        """
        Initialize notification manager.

        Args:
            config: Configuration dictionary with keys:
                - enabled: Boolean, enable/disable notifications
                - notify_on_critical: Boolean
                - notify_on_high: Boolean
                - notify_on_medium: Boolean
                - notify_on_low: Boolean
                - cooldown_seconds: Duplicate-alert suppression window
                - recipients: List of email addresses
                - smtp: SMTP configuration for EmailService
            db: Optional DatabaseManager for delivery records, durable
                suppression, verified recipients and saved preferences
            dashboard_url: Link included in alert emails
        """
        self.logger = logging.getLogger('SecureX.NotificationManager')

        self.enabled = config.get('enabled', True)
        self.notify_on_critical = config.get('notify_on_critical', True)
        self.notify_on_high = config.get('notify_on_high', True)
        self.notify_on_medium = config.get('notify_on_medium', False)
        self.notify_on_low = config.get('notify_on_low', False)

        self.recipients = list(config.get('recipients', []))
        self.db = db
        self.dashboard_url = dashboard_url
        self.cooldown_seconds = int(config.get('cooldown_seconds', 300))
        # In-memory suppression for callers without a database (e.g. the CLI).
        self._recent_sends: Dict[tuple, float] = {}
        self._queue: Optional[queue.Queue] = None
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        if self.db:
            for recipient in self.db.get_verified_notification_recipients():
                if recipient not in self.recipients:
                    self.recipients.append(recipient)
            saved = self.db.get_setting(PREFERENCES_SETTING_KEY)
            if isinstance(saved, dict):
                self._apply_preferences(saved)

        if not self.recipients:
            self.logger.warning("No recipients configured for notifications")

        # Initialize email service. Credentials come from the environment so
        # they never need to be written into config files.
        smtp_config = dict(config.get('smtp', {}))
        password_env = smtp_config.get('sender_password_env', 'SECUREX_SMTP_PASSWORD')
        sender_email_env = smtp_config.get('sender_email_env', 'SECUREX_SMTP_SENDER')
        if password_env:
            smtp_config['sender_password'] = os.environ.get(password_env, smtp_config.get('sender_password', ''))
        if sender_email_env and os.environ.get(sender_email_env):
            smtp_config['sender_email'] = os.environ[sender_email_env]
        self.smtp_configured = bool(smtp_config.get('sender_password'))
        try:
            self.email_service = EmailService(smtp_config) if smtp_config else None
        except NotificationException as e:
            self.logger.error(f"Failed to initialize email service: {str(e)}")
            self.email_service = None

        self.logger.info(f"NotificationManager initialized with {len(self.recipients)} recipients")

    # ------------------------------------------------------------------
    # Preferences
    # ------------------------------------------------------------------

    def _apply_preferences(self, preferences: Dict[str, Any]) -> None:
        for key, attribute in {
            'enabled': 'enabled',
            'critical': 'notify_on_critical',
            'high': 'notify_on_high',
            'medium': 'notify_on_medium',
            'low': 'notify_on_low',
        }.items():
            if isinstance(preferences.get(key), bool):
                setattr(self, attribute, preferences[key])
        if 'cooldown_seconds' in preferences:
            self.cooldown_seconds = min(max(int(preferences['cooldown_seconds']), 0), 86400)

    def get_preferences(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'critical': self.notify_on_critical,
            'high': self.notify_on_high,
            'medium': self.notify_on_medium,
            'low': self.notify_on_low,
            'cooldown_seconds': self.cooldown_seconds,
        }

    def update_preferences(self, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """Apply and persist preferences. Raises ValueError for bad input."""
        if 'cooldown_seconds' in preferences:
            try:
                int(preferences['cooldown_seconds'])
            except (TypeError, ValueError):
                raise ValueError('cooldown_seconds must be a whole number of seconds')
        self._apply_preferences(preferences)
        current = self.get_preferences()
        if self.db:
            self.db.set_setting(PREFERENCES_SETTING_KEY, current)
        return current

    # ------------------------------------------------------------------
    # Threat alerts
    # ------------------------------------------------------------------

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

    def _recently_sent(self, fingerprint: str, recipient: str) -> bool:
        if self.db:
            return self.db.has_recent_notification(fingerprint, recipient, self.cooldown_seconds)
        sent_at = self._recent_sends.get((fingerprint, recipient))
        return sent_at is not None and time.monotonic() - sent_at < self.cooldown_seconds

    def _record(self, fingerprint: str, recipient: str, threat: Dict[str, Any],
                success: bool, error: str = '') -> None:
        if success:
            now = time.monotonic()
            self._recent_sends[(fingerprint, recipient)] = now
            if len(self._recent_sends) > 1000:
                self._recent_sends = {
                    key: sent_at for key, sent_at in self._recent_sends.items()
                    if now - sent_at < self.cooldown_seconds
                }
        if self.db:
            try:
                self.db.record_notification_delivery(
                    fingerprint,
                    recipient,
                    threat.get('threat_name', 'Unknown Threat'),
                    threat.get('risk_level', 'Unknown'),
                    'sent' if success else 'failed',
                    '' if success else (error or 'SMTP delivery failed'),
                )
            except Exception as e:
                self.logger.error(f"Failed to record notification delivery: {e}")

    def _build_email_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        email_threat = dict(threat)
        if self.dashboard_url:
            email_threat['dashboard_url'] = self.dashboard_url
        if not email_threat.get('description'):
            email_threat['description'] = (
                'SecureX flagged activity that matches a known threat pattern. '
                'Review the details below to confirm whether it is expected.'
            )
        if not email_threat.get('remediation_steps'):
            email_threat['remediation_steps'] = (
                list(threat.get('advice') or [])
                or DEFAULT_REMEDIATION_STEPS.get(threat.get('risk_level'), DEFAULT_REMEDIATION_STEPS['High'])
            )
        return email_threat

    def _send_to(self, recipients: List[str], fingerprint: str, threat: Dict[str, Any]) -> Dict[str, bool]:
        """Send one alert to the given recipients and record each outcome."""
        try:
            html_body, text_body, subject = EmailTemplates.generate_threat_alert_email(
                self._build_email_threat(threat)
            )
            results = self.email_service.send_bulk_email(recipients, subject, html_body, text_body)
        except Exception as e:
            self.logger.error(f"Failed to send threat notification: {str(e)}")
            for recipient in recipients:
                self._record(fingerprint, recipient, threat, False, str(e))
            return {recipient: False for recipient in recipients}

        errors = getattr(self.email_service, 'last_errors', {})
        if not isinstance(errors, dict):
            errors = {}
        for recipient, success in results.items():
            self._record(fingerprint, recipient, threat, success, str(errors.get(recipient, '')))
        return results

    def notify_threat(self, threat: Dict[str, Any]) -> bool:
        """
        Send threat notification to all configured recipients.

        Recipients who already received the same alert within the cooldown
        window are skipped. Failed sends are recorded but do not start the
        cooldown, so the next detection retries them.

        Args:
            threat: Threat dictionary with full threat details

        Returns:
            True if at least one email sent successfully, False otherwise
        """
        if not self.should_notify(threat):
            return False

        fingerprint = self._fingerprint(threat)
        with self._lock:
            recipients = [r for r in self.recipients if not self._recently_sent(fingerprint, r)]
            if not recipients:
                self.logger.info('Suppressed duplicate notification for %s', fingerprint[:12])
                return False

            results = self._send_to(recipients, fingerprint, threat)

        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"Threat notification sent: {successful}/{len(recipients)} recipients")
        return successful > 0

    def start_worker(self, max_queue_size: int = 100) -> None:
        """Start a background thread so SMTP delays never block detection."""
        if self._worker and self._worker.is_alive():
            return
        self._queue = queue.Queue(maxsize=max_queue_size)
        self._worker = threading.Thread(target=self._run_worker, name='securex-email-worker', daemon=True)
        self._worker.start()

    def _run_worker(self) -> None:
        while True:
            threat = self._queue.get()
            try:
                self.notify_threat(threat)
            except Exception as e:
                self.logger.error(f"Email worker error: {e}")
            finally:
                self._queue.task_done()

    def enqueue_threat(self, threat: Dict[str, Any]) -> bool:
        """Queue a threat for background delivery; sends inline if no worker runs."""
        if not self.should_notify(threat):
            return False
        if not self._queue:
            return self.notify_threat(threat)
        try:
            self._queue.put_nowait(dict(threat))
            return True
        except queue.Full:
            self.logger.warning('Email notification queue is full; dropping alert for %s',
                                threat.get('threat_name', 'Unknown Threat'))
            return False

    def send_test_email(self) -> Dict[str, Any]:
        """Send a test alert to every recipient, bypassing severity rules and cooldown."""
        if not self.email_service:
            return {'success': False, 'error': 'Email service is not configured', 'results': {}}
        if not self.recipients:
            return {'success': False, 'error': 'No verified recipients configured', 'results': {}}

        test_threat = {
            'threat_name': 'SecureX Test Alert',
            'risk_level': 'High',
            'risk_score': 0.85,
            'category': 'Test',
            'description': 'This is a test notification. No real threat was detected.',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_data': {'event_type': 'test_email'},
            'remediation_steps': ['No action is required. Your email alerts are working.'],
        }
        results = self._send_to(list(self.recipients), 'test-email', test_threat)
        errors = getattr(self.email_service, 'last_errors', {})
        failed = [r for r, ok in results.items() if not ok]
        error = ''
        if failed:
            error = '; '.join(
                f"{r}: {errors.get(r, 'delivery failed')}" if isinstance(errors, dict) else r
                for r in failed
            )
        return {'success': any(results.values()), 'results': results, 'error': error}

    @staticmethod
    def _fingerprint(threat: Dict[str, Any]) -> str:
        """Create a stable, non-sensitive duplicate-suppression key."""
        event_data = threat.get('event_data') or {}
        parts = [str(threat.get(key, '')) for key in ('threat_name', 'category', 'risk_level', 'source')]
        # Distinguish the same rule firing on different processes or hosts.
        parts += [str(event_data.get(key, '')) for key in ('process_name', 'remote_ip', 'remote_port')]
        return hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()

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
            if self.db:
                self.db.revoke_notification_recipient(email)
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
