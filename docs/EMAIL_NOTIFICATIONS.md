# Email Notifications Setup Guide

SecureX can send email alerts when security threats are detected on your system.

## Features

- **Real-time alerts** for Critical and High-risk threats
- **HTML-formatted emails** with detailed threat information
- **Daily summaries** of detected threats
- **Configurable recipients** for team-based security monitoring
- **Retry logic** to ensure reliable delivery
- **Support for Gmail, Outlook, and custom SMTP** servers

## Configuration

### Step 1: Enable Email Notifications

Edit `config/config.yaml`:

```yaml
notifications:
  enabled: true
  notify_on_critical: true
  notify_on_high: true
  notify_on_medium: false
  recipients:
    - "your-email@example.com"
```

### Step 2: Configure SMTP

#### For Gmail:

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Visit https://myaccount.google.com/apppasswords
   - Select "Mail" and "Windows Computer"
   - Copy the 16-character password
3. Update `config.yaml`:

```yaml
  smtp:
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender_email: "your-email@gmail.com"
    sender_password: "your-16-char-app-password"
    use_tls: true
```

#### For Outlook:

```yaml
  smtp:
    smtp_server: "smtp-mail.outlook.com"
    smtp_port: 587
    sender_email: "your-email@outlook.com"
    sender_password: "your-outlook-password"
    use_tls: true
```

#### For Custom SMTP:

Contact your email provider for SMTP settings:

```yaml
  smtp:
    smtp_server: "mail.your-company.com"
    smtp_port: 587  # or 465 for SSL
    sender_email: "alerts@your-company.com"
    sender_password: "your-password"
    use_tls: true
```

### Step 3: Test Configuration

Test your email setup:

```bash
python -c "
from src.notifications.email_service import EmailService
from src.utils import Config

config = Config('config/config.yaml')
smtp_config = config.config.get('notifications', {}).get('smtp', {})
service = EmailService(smtp_config)
service.send_email('test@example.com', 'Test', '<h1>Test Email</h1>', 'Test')
print('Email sent successfully!')
"
```

## Email Alert Types

### Critical Threat Alert

Sent immediately when a Critical-level threat is detected:
- Threat name and category
- Risk score and severity
- Technical details (process name, network connection, etc.)
- Recommended remediation steps
- Link to dashboard for more details

### Daily Summary

Optional daily summary of all threats detected:
- Threat count by severity level
- Top detected threats
- Overall system risk assessment

## Troubleshooting

### "SMTP authentication failed"

- Verify sender_email and sender_password are correct
- For Gmail, ensure you're using an App Password, not your account password
- Check that 2-Factor Authentication is enabled on your account

### "Connection timeout"

- Verify SMTP server address and port are correct
- Check firewall/router allows outbound connections on the SMTP port
- Try port 465 (SSL) instead of 587 (TLS)

### "Email not received"

- Check spam/junk folder
- Verify recipient email addresses are correct
- Check email server logs for bounce messages
- Enable "Less secure app access" if using Gmail with password (not recommended)

### "Notifications disabled"

- Verify `enabled: true` in `config.yaml`
- Verify at least one recipient is configured
- Check logs for initialization errors: `grep "NotificationManager" data/logs/app.log`

## Security Best Practices

1. **Never commit passwords to git** — use environment variables or .env file
2. **Use app-specific passwords** for Gmail/Outlook instead of account passwords
3. **Restrict sender email permissions** to SMTP-only access
4. **Encrypt configuration files** if stored on shared systems
5. **Rotate passwords** periodically
6. **Monitor sent emails** for unauthorized alerts

## Example: Environment Variable Setup

Store sensitive credentials in `.env`:

```bash
SECUREX_SMTP_PASSWORD=your-app-password
```

Then in Python:

```python
import os
config['notifications']['smtp']['sender_password'] = os.getenv('SECUREX_SMTP_PASSWORD')
```

## API Reference

### NotificationManager

```python
from src.notifications.notification_manager import NotificationManager

manager = NotificationManager(config)

# Send immediate threat alert
manager.notify_threat(threat_dict)

# Send daily summary
manager.notify_daily_summary(threats_list)

# Manage recipients
manager.add_recipient('new-user@example.com')
manager.remove_recipient('old-user@example.com')

# Check if notification should be sent
if manager.should_notify(threat_dict):
    manager.notify_threat(threat_dict)
```

### EmailService

```python
from src.notifications.email_service import EmailService

service = EmailService(smtp_config)

# Validate email
if service.validate_email('user@example.com'):
    print("Valid email")

# Send single email
service.send_email('user@example.com', 'Subject', '<h1>Body</h1>', 'Plain text')

# Send to multiple recipients
results = service.send_bulk_email(
    ['user1@example.com', 'user2@example.com'],
    'Subject',
    '<h1>Body</h1>'
)

# Check results
for email, success in results.items():
    if success:
        print(f"Sent to {email}")
```

## Support

For issues or questions:
1. Check logs: `tail -f data/logs/app.log | grep -i email`
2. Enable debug logging in config.yaml
3. Test SMTP connectivity: `python -m smtplib -t user@example.com < message.txt`
4. Contact support at support@example.com
