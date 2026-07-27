"""
Notifications subsystem for SecureX.

Handles alert delivery via email, SMS, and webhooks.
"""

from src.notifications.email_service import EmailService

__all__ = ['EmailService']
