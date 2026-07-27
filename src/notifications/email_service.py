"""
Email Notification Service

Handles SMTP email delivery for security alerts with retry logic,
validation, and error recovery.
"""

import logging
import re
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any

from src.exceptions import NotificationException


class EmailService:
    """
    SMTP-based email service for sending security alerts.

    Supports multiple email providers via configuration.
    Includes email validation, retry logic, and error handling.
    """

    # Email regex pattern (RFC 5322 simplified)
    EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize email service with SMTP configuration.

        Args:
            config: Dictionary with keys:
                - smtp_server: SMTP server hostname (e.g., smtp.gmail.com)
                - smtp_port: SMTP port (typically 587 for TLS, 465 for SSL)
                - sender_email: Email address to send from
                - sender_password: SMTP password or app-specific password
                - use_tls: Boolean, use TLS encryption (default True)
                - retry_attempts: Number of retry attempts (default 3)
                - retry_delay: Seconds between retries (default 2)

        Raises:
            NotificationException: If required config fields are missing
        """
        self.logger = logging.getLogger('SecureX.EmailService')

        # Validate required fields
        required_fields = ['smtp_server', 'smtp_port', 'sender_email', 'sender_password']
        for field in required_fields:
            if field not in config:
                msg = f"Missing required email config field: {field}"
                self.logger.error(msg)
                raise NotificationException(msg)

        self.smtp_server = config['smtp_server']
        self.smtp_port = config['smtp_port']
        self.sender_email = config['sender_email']
        self.sender_password = config['sender_password']
        self.use_tls = config.get('use_tls', True)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 2)

        self.logger.info(f"EmailService initialized for {self.sender_email} on {self.smtp_server}:{self.smtp_port}")

    def validate_email(self, email: str) -> bool:
        """
        Validate email address format.

        Args:
            email: Email address to validate

        Returns:
            True if valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False

        return bool(re.match(self.EMAIL_PATTERN, email.strip()))

    def send_email(self, recipient: str, subject: str, html_body: str,
                   text_body: Optional[str] = None) -> bool:
        """
        Send email via SMTP with retry logic.

        Args:
            recipient: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text fallback (optional)

        Returns:
            True if sent successfully, False otherwise
        """
        # Validate recipient
        if not self.validate_email(recipient):
            self.logger.error(f"Invalid recipient email: {recipient}")
            raise NotificationException(f"Invalid email address: {recipient}")

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = recipient

        # Add text fallback if provided
        if text_body:
            part1 = MIMEText(text_body, 'plain')
            msg.attach(part1)

        # Add HTML body
        part2 = MIMEText(html_body, 'html')
        msg.attach(part2)

        # Send with retry logic
        for attempt in range(1, self.retry_attempts + 1):
            try:
                self.logger.debug(f"Sending email to {recipient} (attempt {attempt}/{self.retry_attempts})")

                server = smtplib.SMTP(self.smtp_server, self.smtp_port)

                if self.use_tls:
                    server.starttls()

                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
                server.quit()

                self.logger.info(f"Email sent successfully to {recipient}")
                return True

            except smtplib.SMTPAuthenticationError as e:
                msg_text = "SMTP authentication failed - check email/password"
                self.logger.error(f"{msg_text}: {str(e)}")
                raise NotificationException(msg_text)

            except smtplib.SMTPException as e:
                if attempt < self.retry_attempts:
                    self.logger.warning(f"SMTP error on attempt {attempt}: {str(e)}. Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    msg_text = f"SMTP error after {self.retry_attempts} attempts: {str(e)}"
                    self.logger.error(msg_text)
                    raise NotificationException(msg_text)

            except Exception as e:
                msg_text = f"Unexpected error sending email: {str(e)}"
                self.logger.error(msg_text)
                raise NotificationException(msg_text)

        return False

    def send_bulk_email(self, recipients: List[str], subject: str,
                       html_body: str, text_body: Optional[str] = None) -> Dict[str, bool]:
        """
        Send email to multiple recipients.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text fallback (optional)

        Returns:
            Dictionary mapping recipient to success status
        """
        results = {}

        for recipient in recipients:
            try:
                self.send_email(recipient, subject, html_body, text_body)
                results[recipient] = True
            except NotificationException as e:
                self.logger.error(f"Failed to send email to {recipient}: {str(e)}")
                results[recipient] = False

        return results
