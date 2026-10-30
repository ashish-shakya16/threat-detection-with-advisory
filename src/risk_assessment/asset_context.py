"""Asset and exposure context for risk scoring.

The same detection matters more on a critical machine, on an
internet-facing connection, or under a privileged account. This module turns
those facts into documented multipliers that RiskScorer.adjust_risk_by_context
applies, and records them on the threat so the reasoning is visible.

    asset criticality (config: risk_assessment.asset_context.device_criticality)
        low 0.85 | medium 1.00 | high 1.15 | critical 1.30
    network exposure (from the event's remote/local addresses)
        local 1.00 | internal 1.05 | internet 1.20
    privileged account (SYSTEM / Administrator / root, or configured names)
        x1.15

The multipliers are a transparent heuristic chosen for this prototype, not an
empirically calibrated model.
"""

import ipaddress
from typing import Any, Dict, Optional

CRITICALITY_MULTIPLIERS = {'low': 0.85, 'medium': 1.0, 'high': 1.15, 'critical': 1.3}
EXPOSURE_MULTIPLIERS = {'local': 1.0, 'internal': 1.05, 'internet': 1.2}
DEFAULT_PRIVILEGED_ACCOUNTS = ('nt authority\\system', 'system', 'administrator', 'root')


def _address_host(value: Any) -> Optional[str]:
    """Extract the host from 'ip', 'ip:port' or '[ipv6]:port'."""
    if not value:
        return None
    text = str(value).strip()
    if text.startswith('['):
        return text[1:text.index(']')] if ']' in text else None
    if text.count(':') == 1:
        return text.split(':')[0]
    return text


def classify_exposure(event_data: Dict[str, Any]) -> str:
    """local: no remote peer | internal: private/LAN peer | internet: public peer
    or a service listening on all interfaces."""
    remote = _address_host(event_data.get('remote_ip'))
    if remote:
        try:
            ip = ipaddress.ip_address(remote)
        except ValueError:
            return 'internet'  # hostnames are treated as external
        if ip.is_loopback:
            return 'local'
        # Private, link-local and reserved ranges are not reachable from the internet.
        return 'internet' if ip.is_global else 'internal'
    local = _address_host(event_data.get('local_address'))
    if local in ('0.0.0.0', '::') and str(event_data.get('status', '')).upper() == 'LISTEN':
        return 'internet'
    return 'local'


class AssetContextResolver:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        context_config = ((config or {}).get('risk_assessment', {}) or {}).get('asset_context', {}) or {}
        criticality = str(context_config.get('device_criticality', 'medium')).lower()
        self.device_criticality = criticality if criticality in CRITICALITY_MULTIPLIERS else 'medium'
        self.privileged_accounts = {
            name.lower() for name in context_config.get('privileged_accounts', DEFAULT_PRIVILEGED_ACCOUNTS)
        }

    def resolve(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        event = threat.get('event_data') or {}
        username = str(event.get('username') or '')
        short_name = username.split('\\')[-1].lower()
        privileged = bool(username) and (
            username.lower() in self.privileged_accounts or short_name in self.privileged_accounts
        )
        return {
            'asset_criticality': self.device_criticality,
            'exposure': classify_exposure(event),
            'privileged_user': privileged,
        }
