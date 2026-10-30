# Ransomware

Ransomware encrypts files, or locks the whole system, and demands payment, usually in cryptocurrency, for the decryption key. Modern ransomware groups often also steal data first and threaten to publish it (double extortion).

## How it gets in
Phishing emails with malicious attachments or links, exposed Remote Desktop (RDP) with weak passwords, unpatched software vulnerabilities, and malicious downloads.

## Warning signs
- Many files suddenly renamed with an unfamiliar extension or becoming unreadable.
- Ransom notes (text or HTML files) appearing in folders.
- Very high disk activity and CPU use from an unknown process.
- Shadow copies or backups being deleted, often through vssadmin or wmic commands.
- Security software being disabled.

## What to do if you suspect ransomware
1. Disconnect the affected device from the network immediately (unplug the cable, turn off Wi-Fi) to stop it spreading.
2. Do not turn the device off if you can avoid it; memory can contain useful evidence.
3. Report to your administrator or incident response team.
4. Do not pay the ransom without expert and legal advice. Payment does not guarantee recovery.
5. Restore from clean, offline backups after the threat has been removed.

## Prevention
- Keep regular, tested, offline or immutable backups (the 3-2-1 rule: 3 copies, 2 media types, 1 offsite).
- Patch the operating system and applications promptly.
- Disable or protect RDP with multi-factor authentication and a VPN.
- Use antivirus with ransomware protection and enable controlled folder access on Windows.
- Train users to recognise phishing.
