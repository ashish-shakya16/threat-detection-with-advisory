# Network Threats

## Port scanning
An attacker probes many ports to find services to attack. Signs include many connection attempts to different ports from one address, or your own device opening many connections (which may mean malware on it is scanning others).

## Suspicious ports
Some ports are commonly used by remote-access tools, backdoors or malware, for example 4444 (Metasploit default), 1337, 31337, 6667 (IRC botnets), 5900 (VNC) and 3389 (RDP) when exposed to the internet. A connection on these ports is not proof of an attack, but the owning process should be identified.

## Command-and-control (C2) and botnets
Infected devices regularly contact an attacker's server for instructions. Signs include periodic outbound connections to unfamiliar IP addresses or domains, often at fixed intervals, and connections from processes that should not use the network.

## Data exfiltration
Large or unusual outbound transfers, especially at night or to unfamiliar destinations, may mean data is being stolen.

## Brute-force attacks
Repeated login attempts against RDP, SSH, web logins or email accounts, trying many passwords. Account lockouts and many failed login events are typical signs.

## Denial of service
Floods of traffic that overwhelm a service so legitimate users cannot reach it.

## Recommended response
- Identify which process owns the connection (for example with `netstat -ano` and Task Manager, or Resource Monitor).
- Block unknown remote addresses at the firewall after confirming they are not needed.
- Close or firewall services that do not need to be reachable from the internet, especially RDP.
- Use strong passwords, account lockout policies and multi-factor authentication against brute force.
- If C2 traffic or exfiltration is suspected, disconnect the device and contact your administrator.
