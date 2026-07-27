"""Custom exceptions for SecureX."""


class SecureXException(Exception):
    """Base exception for SecureX"""
    pass


class DatabaseException(SecureXException):
    """Database-related exceptions"""
    pass


class ConfigurationException(SecureXException):
    """Configuration-related exceptions"""
    pass


class DetectionException(SecureXException):
    """Detection engine exceptions"""
    pass


class AdvisoryException(SecureXException):
    """Advisory generation exceptions"""
    pass


class AIAssistantException(SecureXException):
    """AI assistant exceptions"""
    pass


class ValidationException(SecureXException):
    """Data validation exceptions"""
    pass


class NotificationException(SecureXException):
    """
    Raised when email notification or alert delivery fails.

    Examples:
    - SMTP connection failure
    - Invalid email configuration
    - Recipient validation failure
    """
    pass
