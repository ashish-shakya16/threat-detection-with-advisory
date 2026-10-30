# How SecureX Detects and Rates Threats

## How an alert is produced
SecureX collects events from the system monitor (running processes, CPU and memory use, new processes) and the network monitor (open ports, connection counts, remote destinations). Each event is checked against detection rules in `config/rules.json`. When a rule matches, the risk scorer combines the rule severity, the rule confidence, and context such as off-hours activity (10 PM to 6 AM) into a risk score from 0 to 1. An optional Isolation Forest machine-learning model also flags unusual system behaviour as anomalies.

## Risk levels
- Low: risk score below 0.30. Usually informational. Review when convenient.
- Medium: 0.30 to 0.59. Worth checking soon to confirm the activity is expected.
- High: 0.60 to 0.84. Investigate promptly. Email alerts are sent for High by default.
- Critical: 0.85 and above. Investigate immediately. Email alerts are sent for Critical by default.

A risk level is an estimate, not proof of compromise. False positives happen, for example when a legitimate tool behaves like a known attack pattern.

## Detection methods and classifications
Every detection gets a classification, the evidence behind it, and a verification status. The status is always "unverified" because SecureX has no malware-signature database or threat-intelligence feed.
- Behaviour rules: classified as suspicious process (malware-like pattern, script abuse, code injection, privilege escalation), network anomaly (suspicious port, scanning or flooding, possible data exfiltration), brute-force activity, suspicious file activity, or resource abuse.
- Ransomware-like behaviour: the file-activity monitor watches Documents, Desktop and Pictures. Many files changed or renamed within 30 seconds is "Suspicious bulk file modification". Mass renames to one unusual extension (for example .locked), a ransom-note file, or two signals together is "Possible ransomware-like behaviour". Windows does not report which process made the changes, and backups or sync tools can cause similar activity.
- Unknown threats: SecureX first learns normal per-process behaviour (CPU, memory, threads, connections, remote addresses and ports). Afterwards, processes that deviate strongly are reported as "Unknown suspicious activity", listing the measurements that stood out. They are never given a malware name.
- Phishing URL check: on the Detection page, a pasted link is checked locally for look-alike domains, brand names outside the official domain, IP-address links, hidden destinations behind "@" or link shorteners, punycode and abused top-level domains. The link is never opened, and no indicators does not prove a link is safe.

## Risk context
The base score is adjusted for context, and the reasons are listed on the threat:
- Asset criticality: how important this device is, set by the administrator (low x0.85, medium x1.0, high x1.15, critical x1.3).
- Network exposure: a connection to a public internet address or a service listening on all interfaces (x1.2), a private/LAN address (x1.05), or no remote peer (x1.0).
- Privileged account: activity under SYSTEM, Administrator or root (x1.15).
- Off-hours activity between 10 PM and 6 AM (x1.1).
- Isolation Forest anomaly score, once a model has been trained, blended with the rule score.
These multipliers are a documented heuristic, not a statistically calibrated model.

## Recurring threats
If the same threat from the same source is seen again within a few minutes, SecureX increases the occurrence count on the existing record instead of creating a new one. A high occurrence count means the condition is ongoing.

## Detection rules and what they mean
- Suspicious Process Execution (Malware, high): a process name or behaviour matches known malicious patterns. Check the process path, publisher and whether you started it.
- Multiple Failed Login Attempts (Brute Force, medium): repeated failed sign-ins may mean someone is guessing passwords. Use strong unique passwords and enable multi-factor authentication.
- Unusual Port Connection (Network Attack, medium): a connection to a port commonly used by remote-access tools or malware. Confirm which program owns the connection.
- Excessive CPU Usage (Resource Abuse, low): sustained high CPU can be normal heavy work, but can also indicate cryptomining malware.
- Critical System File Modification (File Tampering, high): protected system files changed. Unexpected changes can indicate rootkits or tampering.
- Excessive Network Connections (Network Scan, medium): many simultaneous connections can indicate scanning, a worm, or a botnet client.
- Privilege Escalation Attempt (Privilege Escalation, high): a process tried to gain administrator or SYSTEM rights.
- Suspicious Script Execution (Script Attack, medium): scripting engines such as PowerShell, cmd or wscript running in a way attackers often use.
- Data Exfiltration Indicator (Data Theft, high): unusually large outbound transfers that may mean data is being stolen.
- Memory Injection Detected (Code Injection, high): code was written into another process, a common malware technique to hide.

## What SecureX does and does not do automatically
SecureX uses a graduated response:
- Low risk: the threat is recorded (observe).
- Medium and above: recorded and, if email alerts are enabled for that level, emailed (alert).
- High and above, when a running process is involved: SecureX proposes suspending the process. Suspension is reversible with Resume.
- Critical: SecureX also proposes terminating the process.

Proposals are never carried out automatically. A logged-in user must approve each one in the threat details. Before acting, SecureX re-checks that the process ID still belongs to the same process, refuses core Windows processes and SecureX itself, ignores proposals older than 30 minutes, and limits how many actions can run per minute. By default the administrator setting `response.execution_enabled` is off, so approvals are recorded as dry runs. Every proposal, approval, rejection and execution is written to the tamper-evident audit log.

SecureX never deletes or quarantines files, and the AI assistant cannot take any action on the system.

## Investigating an alert
1. Open the threat in the dashboard and read the description, source and technical details.
2. Decide whether the activity is expected (for example, software you just installed).
3. If it is not expected, run a full antivirus scan and check the process location and digital signature.
4. If the device may be compromised, disconnect it from the network and contact your administrator.
5. Mark the threat as resolved or as a false positive once investigated.
