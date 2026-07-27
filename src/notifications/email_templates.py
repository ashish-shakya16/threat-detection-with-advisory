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
        timestamp = threat.get('timestamp', 'Unknown')

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

        event_data = threat.get('event_data', {})
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

        html_body += """
            <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e0e0e0;">
                <p><strong>Need help?</strong></p>
                <p>Visit the SecureX dashboard to view more details, or contact our support team at """ + escape(cls.SUPPORT_EMAIL) + """</p>
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

        text_body += f"""

Need help? Contact {cls.SUPPORT_EMAIL}

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
