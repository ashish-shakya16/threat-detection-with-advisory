"""
Email Template System

Provides HTML email templates for different threat levels and categories.
Templates include threat details, remediation steps, and company branding.
"""

from typing import Dict, Any
from html import escape


class EmailTemplates:
    """
    Email template generator for security alerts.

    Provides formatted HTML emails for Critical, High, Medium, and Low threats.
    """

    COMPANY_NAME = "SecureX"
    COMPANY_LOGO_URL = "https://example.com/logo.png"
    SUPPORT_EMAIL = "support@example.com"
    SAFE_EVENT_KEYS = {
        'process_name', 'pid', 'remote_ip', 'remote_port', 'local_address',
        'status', 'reason', 'connection_count', 'threshold', 'event_type',
    }

    @staticmethod
    def get_threat_color(risk_level: str) -> str:
        """Get color for threat level badge."""
        colors = {
            'Critical': '#d32f2f',
            'High': '#f57c00',
            'Medium': '#fbc02d',
            'Low': '#388e3c'
        }
        return colors.get(risk_level, '#757575')

    @staticmethod
    def get_threat_icon(risk_level: str) -> str:
        """Get icon emoji for threat level."""
        icons = {
            'Critical': '🚨',
            'High': '⚠️',
            'Medium': '⚡',
            'Low': 'ℹ️'
        }
        return icons.get(risk_level, '•')

    @classmethod
    def generate_threat_alert_email(cls, threat: Dict[str, Any]) -> tuple:
        """
        Generate HTML and plain text email for threat alert.

        Args:
            threat: Threat dictionary with detection details

        Returns:
            Tuple of (html_body, text_body, subject)
        """
        threat_name = escape(threat.get('threat_name', 'Unknown Threat'))
        risk_level = threat.get('risk_level', 'Low')
        risk_score = threat.get('risk_score', 0)
        category = escape(threat.get('category', 'Unknown'))
        description = escape(threat.get('description', 'No description available'))
        timestamp = escape(str(threat.get('timestamp', threat.get('detected_at', 'Unknown'))))

        color = cls.get_threat_color(risk_level)
        icon = cls.get_threat_icon(risk_level)

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: {color};
            color: white;
            padding: 24px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: bold;
        }}
        .content {{
            padding: 24px;
        }}
        .threat-badge {{
            display: inline-block;
            background-color: {color};
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            margin: 12px 0;
        }}
        .detail-row {{
            margin: 12px 0;
            padding: 12px;
            background-color: #f9f9f9;
            border-left: 4px solid {color};
        }}
        .detail-label {{
            font-weight: bold;
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .detail-value {{
            color: #333;
            margin-top: 4px;
        }}
        .action-steps {{
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 16px;
            margin: 16px 0;
        }}
        .action-steps h3 {{
            margin-top: 0;
            color: #856404;
        }}
        .action-steps ol {{
            margin: 12px 0;
            padding-left: 20px;
        }}
        .action-steps li {{
            margin: 8px 0;
            color: #856404;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 16px 24px;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{icon} {risk_level} Threat Detected</h1>
        </div>

        <div class="content">
            <h2>{threat_name}</h2>

            <div class="threat-badge">{risk_level} - Risk Score: {risk_score:.1%}</div>

            <p>{description}</p>

            <div class="detail-row">
                <div class="detail-label">Threat Category</div>
                <div class="detail-value">{category}</div>
            </div>

            <div class="detail-row">
                <div class="detail-label">Detected At</div>
                <div class="detail-value">{timestamp}</div>
            </div>
"""

        event_data = {
            key: value for key, value in (threat.get('event_data', {}) or {}).items()
            if key in cls.SAFE_EVENT_KEYS
        }
        if event_data:
            html_body += '<div class="detail-row"><div class="detail-label">Technical Details</div><div class="detail-value"><ul>'
            for key, value in event_data.items():
                safe_key = escape(str(key))
                safe_value = escape(str(value))
                html_body += f'<li><strong>{safe_key}:</strong> {safe_value}</li>'
            html_body += '</ul></div></div>'

        remediation_steps = threat.get('remediation_steps', [])
        if remediation_steps:
            html_body += """
            <div class="action-steps">
                <h3>Recommended Actions</h3>
                <ol>
"""
            for step in remediation_steps:
                safe_step = escape(str(step))
                html_body += f'                    <li>{safe_step}</li>\n'
            html_body += """
                </ol>
            </div>
"""

        dashboard_url = threat.get('dashboard_url', '')
        dashboard_link = ''
        if dashboard_url:
            dashboard_link = (
                '<p><a href="' + escape(str(dashboard_url), quote=True) + '">'
                'Open the authenticated SecureX dashboard</a></p>'
            )

        html_body += """
            <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e0e0e0;">
                <p><strong>Need help?</strong></p>
                <p>Visit the SecureX dashboard to view more details, or contact our support team at """ + escape(cls.SUPPORT_EMAIL) + """</p>
                """ + dashboard_link + """
            </div>
        </div>

        <div class="footer">
            <p>Copyright 2026 """ + cls.COMPANY_NAME + """. All rights reserved.<br/>
            This is an automated security alert. Do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

        text_body = f"""{risk_level} THREAT ALERT: {threat_name}

{description}

THREAT DETAILS:
- Category: {category}
- Risk Level: {risk_level}
- Risk Score: {risk_score:.1%}
- Detected: {timestamp}

TECHNICAL DETAILS:
"""
        if event_data:
            for key, value in event_data.items():
                text_body += f"- {key}: {value}\n"
        else:
            text_body += "- No technical details available\n"

        if remediation_steps:
            text_body += "\nRECOMMENDED ACTIONS:\n"
            for i, step in enumerate(remediation_steps, 1):
                text_body += f"{i}. {step}\n"

        dashboard_text = f"\nOpen dashboard: {dashboard_url}\n" if dashboard_url else ''
        text_body += f"""

Need help? Contact {cls.SUPPORT_EMAIL}
    {dashboard_text}

---
This is an automated security alert from SecureX. Do not reply to this email.
"""

        subject = f"[{risk_level}] {threat_name} detected on your system"

        return html_body, text_body, subject

    @classmethod
    def generate_daily_summary_email(cls, threats: list) -> tuple:
        """
        Generate HTML and plain text email for daily threat summary.

        Args:
            threats: List of threat dictionaries from past 24 hours

        Returns:
            Tuple of (html_body, text_body, subject)
        """
        total = len(threats)
        critical = sum(1 for t in threats if t.get('risk_level') == 'Critical')
        high = sum(1 for t in threats if t.get('risk_level') == 'High')
        medium = sum(1 for t in threats if t.get('risk_level') == 'Medium')
        low = sum(1 for t in threats if t.get('risk_level') == 'Low')

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #1976d2;
            color: white;
            padding: 24px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 24px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin: 16px 0;
        }}
        .stat-box {{
            padding: 12px;
            border-radius: 4px;
            text-align: center;
        }}
        .stat-box.critical {{
            background-color: #ffebee;
            border-left: 4px solid #d32f2f;
        }}
        .stat-box.high {{
            background-color: #fff3e0;
            border-left: 4px solid #f57c00;
        }}
        .stat-box.medium {{
            background-color: #fffde7;
            border-left: 4px solid #fbc02d;
        }}
        .stat-box.low {{
            background-color: #e8f5e9;
            border-left: 4px solid #388e3c;
        }}
        .stat-number {{
            font-size: 28px;
            font-weight: bold;
            color: #333;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }}
        .threat-list {{
            margin: 16px 0;
        }}
        .threat-item {{
            padding: 12px;
            margin: 8px 0;
            background-color: #f9f9f9;
            border-left: 4px solid #1976d2;
            border-radius: 2px;
        }}
        .threat-name {{
            font-weight: bold;
            color: #333;
        }}
        .threat-meta {{
            font-size: 12px;
            color: #666;
            margin-top: 4px;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 16px 24px;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Daily Security Summary</h1>
        </div>

        <div class="content">
            <p>Hello,</p>
            <p>Here's your security summary for the past 24 hours.</p>

            <div class="stats-grid">
                <div class="stat-box critical">
                    <div class="stat-number">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box high">
                    <div class="stat-number">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box medium">
                    <div class="stat-number">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box low">
                    <div class="stat-number">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>

            <p><strong>Total Threats: {total}</strong></p>
"""

        if threats:
            html_body += '<div class="threat-list"><strong>Top Threats:</strong>'
            for threat in threats[:10]:
                name = escape(threat.get('threat_name', 'Unknown'))
                level = threat.get('risk_level', 'Unknown')
                time = threat.get('timestamp', 'Unknown')
                html_body += f'<div class="threat-item"><div class="threat-name">{name}</div><div class="threat-meta">{level} • {time}</div></div>'
            html_body += '</div>'

        html_body += """
        </div>

        <div class="footer">
            <p>Copyright 2026 SecureX. All rights reserved.<br/>
            This is an automated summary email. Do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

        text_body = f"""Daily Security Summary

Total Threats: {total}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}

Top Threats:
"""
        for threat in threats[:10]:
            text_body += f"- {threat.get('threat_name', 'Unknown')} ({threat.get('risk_level', 'Unknown')})\n"

        text_body += "\n---\nThis is an automated summary email from SecureX. Do not reply to this email."

        subject = f"SecureX Daily Summary - {total} threats detected"

        return html_body, text_body, subject

    @classmethod
    def generate_digest_email(cls, threats: list, digest_type: str = 'hourly') -> tuple:
        """
        Generate digest email with multiple threats batched (v1.2 feature).

        Args:
            threats: List of threat dictionaries
            digest_type: 'hourly', 'daily', or 'weekly'

        Returns:
            Tuple of (html_body, text_body, subject)
        """
        total = len(threats)
        critical = sum(1 for t in threats if t.get('risk_level') == 'Critical')
        high = sum(1 for t in threats if t.get('risk_level') == 'High')

        time_label = {'hourly': 'past hour', 'daily': 'past day', 'weekly': 'past week'}.get(digest_type, 'period')

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 700px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #1976d2;
            color: white;
            padding: 24px;
            text-align: center;
        }}
        .content {{
            padding: 24px;
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin: 16px 0;
        }}
        .stat-card {{
            text-align: center;
            padding: 16px;
            background-color: #f9f9f9;
            border-radius: 4px;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #1976d2;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-top: 4px;
        }}
        .threat-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
        }}
        .threat-table thead {{
            background-color: #f5f5f5;
            border-bottom: 2px solid #ddd;
        }}
        .threat-table th {{
            text-align: left;
            padding: 12px;
            font-weight: bold;
            color: #333;
        }}
        .threat-table td {{
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .threat-table tr:hover {{
            background-color: #fafafa;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge.critical {{
            background-color: #ffebee;
            color: #d32f2f;
        }}
        .badge.high {{
            background-color: #fff3e0;
            color: #f57c00;
        }}
        .badge.medium {{
            background-color: #fffde7;
            color: #f9a825;
        }}
        .badge.low {{
            background-color: #e8f5e9;
            color: #388e3c;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 16px 24px;
            border-top: 1px solid #e0e0e0;
            font-size: 12px;
            color: #666;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{digest_type.capitalize()} Threat Digest</h1>
            <p>Summary for the {time_label}</p>
        </div>

        <div class="content">
            <div class="summary-stats">
                <div class="stat-card">
                    <div class="stat-value">{total}</div>
                    <div class="stat-label">Total Threats</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #d32f2f;">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #f57c00;">{high}</div>
                    <div class="stat-label">High</div>
                </div>
            </div>

            <table class="threat-table">
                <thead>
                    <tr>
                        <th>Threat Name</th>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
"""

        for threat in threats[:20]:
            name = escape(threat.get('threat_name', 'Unknown'))
            level = threat.get('risk_level', 'Unknown')
            score = threat.get('risk_score', 0)
            time = threat.get('timestamp', 'Unknown')[:16]
            badge_class = level.lower()
            html_body += f"""                    <tr>
                        <td>{name}</td>
                        <td><span class="badge {badge_class}">{level}</span></td>
                        <td>{score:.1%}</td>
                        <td>{time}</td>
                    </tr>
"""

        html_body += """                </tbody>
            </table>

            <p style="font-size: 12px; color: #666; margin-top: 16px;">
                Showing {0} of {1} threats. Visit the dashboard for complete details.
            </p>
        </div>

        <div class="footer">
            <p>Copyright 2026 SecureX. All rights reserved.<br/>
            This is an automated digest email. Do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
""".format(min(20, total), total)

        text_body = f"""{digest_type.upper()} THREAT DIGEST

Summary for the {time_label}:
Total Threats: {total}
Critical: {critical}
High: {high}

Threats ({min(20, total)} of {total}):
"""
        for threat in threats[:20]:
            name = threat.get('threat_name', 'Unknown')
            level = threat.get('risk_level', 'Unknown')
            score = threat.get('risk_score', 0)
            text_body += f"- {name} ({level}, {score:.1%})\n"

        text_body += "\n---\nVisit the dashboard for complete details.\nSecureX - Automated digest"

        subject = f"SecureX {digest_type.capitalize()} Digest - {total} threats"

        return html_body, text_body, subject
