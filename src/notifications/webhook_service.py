"""
Webhook Notification Service (v1.2 feature)

Sends threat notifications to custom webhooks for integration with external systems.
"""

import logging
import json
import requests
from typing import Dict, Any, List

from src.exceptions import NotificationException


class WebhookService:
    """
    Webhook notification service for external integrations.

    Posts threat data to configured webhook endpoints with retry logic.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize webhook service.

        Args:
            config: Webhook configuration with keys:
                - endpoints: List of webhook URLs
                - timeout: Request timeout in seconds
                - retry_attempts: Number of retry attempts
                - retry_delay: Seconds between retries
                - headers: Optional custom HTTP headers
        """
        self.logger = logging.getLogger('SecureX.WebhookService')

        self.endpoints = config.get('endpoints', [])
        self.timeout = config.get('timeout', 10)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.retry_delay = config.get('retry_delay', 2)
        self.headers = config.get('headers', {'Content-Type': 'application/json'})

        self._validate_config()

    def _validate_config(self):
        """Validate webhook configuration."""
        if not self.endpoints:
            raise NotificationException("No webhook endpoints configured")
        for url in self.endpoints:
            if not url.startswith(('http://', 'https://')):
                raise NotificationException(f"Invalid webhook URL: {url}")

    @staticmethod
    def _prepare_payload(threat: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare threat data for webhook transmission."""
        return {
            'threat_id': threat.get('threat_id'),
            'threat_name': threat.get('threat_name'),
            'category': threat.get('category'),
            'risk_level': threat.get('risk_level'),
            'risk_score': threat.get('risk_score'),
            'severity': threat.get('severity'),
            'confidence': threat.get('confidence'),
            'timestamp': threat.get('timestamp'),
            'description': threat.get('description'),
            'event_data': threat.get('event_data', {}),
            'remediation_steps': threat.get('remediation_steps', [])
        }

    def send_webhook(self, threat: Dict[str, Any], endpoint_url: str = None) -> bool:
        """
        Send threat notification to webhook endpoint.

        Args:
            threat: Threat dictionary
            endpoint_url: Override default endpoint

        Returns:
            True if sent successfully, False otherwise
        """
        payload = self._prepare_payload(threat)

        urls = [endpoint_url] if endpoint_url else self.endpoints

        for url in urls:
            for attempt in range(self.retry_attempts):
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        headers=self.headers,
                        timeout=self.timeout
                    )

                    if response.status_code < 400:
                        self.logger.info(f"Webhook sent to {url}: {response.status_code}")
                        return True
                    else:
                        self.logger.warning(f"Webhook returned {response.status_code}: {response.text}")

                except requests.exceptions.Timeout:
                    self.logger.warning(f"Webhook timeout attempt {attempt + 1}: {url}")
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Webhook send attempt {attempt + 1} failed: {str(e)}")

                if attempt < self.retry_attempts - 1:
                    import time
                    time.sleep(self.retry_delay)

        self.logger.error(f"Failed to send webhook after {self.retry_attempts} attempts")
        return False

    def send_bulk_webhooks(self, threat: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send threat notification to all configured endpoints.

        Args:
            threat: Threat dictionary

        Returns:
            Dictionary mapping endpoint to success status
        """
        results = {}
        for endpoint in self.endpoints:
            try:
                success = self.send_webhook(threat, endpoint)
                results[endpoint] = success
            except Exception as e:
                self.logger.error(f"Error sending to {endpoint}: {str(e)}")
                results[endpoint] = False

        return results

    def add_endpoint(self, url: str) -> bool:
        """Add new webhook endpoint."""
        if not url.startswith(('http://', 'https://')):
            self.logger.error(f"Invalid URL: {url}")
            return False

        if url not in self.endpoints:
            self.endpoints.append(url)
            self.logger.info(f"Added webhook endpoint: {url}")
            return True

        return False

    def remove_endpoint(self, url: str) -> bool:
        """Remove webhook endpoint."""
        if url in self.endpoints:
            self.endpoints.remove(url)
            self.logger.info(f"Removed webhook endpoint: {url}")
            return True

        return False
