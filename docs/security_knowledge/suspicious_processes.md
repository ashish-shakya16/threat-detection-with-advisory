# Suspicious Processes on Windows

A suspicious process is a running program whose name, location, behaviour or resource use does not match what is expected. Malware often hides by imitating legitimate process names.

## Signs a process may be malicious
- A name that imitates a system process with small changes, for example svch0st.exe or scvhost.exe instead of svchost.exe.
- A system process name running from the wrong folder, such as svchost.exe in a user's AppData or Temp folder. Real core Windows processes run from C:\Windows\System32.
- No publisher or an invalid digital signature.
- Sustained high CPU, memory, disk or network use with no visible window.
- Scripting engines (powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe) started by Office documents, browsers or email clients, or using encoded commands.
- Processes that start automatically from unusual registry Run keys or scheduled tasks.

## How to check safely
1. Open Task Manager, right-click the process and choose "Open file location" to see where it runs from.
2. Check the file's Properties > Digital Signatures tab for a trusted publisher.
3. Search the exact file name and path from a trusted source, or upload the file hash (not the file) to a reputable scanner.
4. Use Microsoft Sysinternals Process Explorer or Autoruns for deeper inspection.

## Response
Do not end processes or delete files you have not identified; stopping a real system process can crash Windows, and deleting evidence makes investigation harder. If a process is confirmed malicious, run a full antivirus scan, let the antivirus quarantine it, and contact your administrator. SecureX only suspends or ends a process after you approve its response proposal, and suspension can be undone.
