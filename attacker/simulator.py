"""
SecureX attack simulator - harmless "attacker-like" activity for testing.

Every scenario mimics what a real attack looks like to SecureX's detectors
without doing anything harmful, and cleans up after itself:

    process     runs a renamed copy of ping.exe called "nmap_sim.exe"
                -> RULE_001 Suspicious Process Execution
    backdoor    opens a loopback connection to port 4444 (Metasploit default)
                -> RULE_003 Unusual Port Connection
    portscan    opens 120 loopback connections from one process
                -> RULE_006 Excessive Network Connections
    ransomware  creates dummy files in a sandbox folder under Documents,
                renames them to ".locked" and drops a fake ransom note
                -> Ransomware-like behaviour alert
    bruteforce  sends wrong passwords for a fake user to the dashboard login
                -> failed logins in the Audit page
    cpu         keeps one CPU core busy
                -> RULE_004 Excessive CPU Usage

Only loopback (127.0.0.1) is used for network scenarios, nothing is sent to
other machines, and no real user files are touched.

Usage (start monitoring in the dashboard first):
    python attacker/attacker_app.py                   # window with buttons
    python attacker/simulator.py --list               # command line
    python attacker/simulator.py all --parallel
    python attacker/simulator.py backdoor ransomware --hold 60
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

SANDBOX_NAME = 'SecureX_Attack_Simulation'


# The GUI replaces this with a function that appends to its log window.
log_sink = None


def log(message):
    line = f'[{time.strftime("%H:%M:%S")}] {message}'
    if log_sink:
        log_sink(line)
    else:
        print(line, flush=True)


def _hold(seconds, what):
    log(f'  holding {what} for {seconds}s so the next monitoring scan sees it...')
    time.sleep(seconds)


def _listener():
    """A loopback TCP listener that accepts and keeps connections open."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return server


def simulate_process(hold):
    """Run a harmless program under a name SecureX treats as a hacking tool."""
    if os.name != 'nt':
        log('  skipped: process scenario uses ping.exe and only runs on Windows')
        return
    ping = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'PING.EXE'
    workdir = Path(tempfile.mkdtemp(prefix='securex_sim_'))
    fake_tool = workdir / 'nmap_sim.exe'
    shutil.copy2(ping, fake_tool)
    log(f'  started {fake_tool.name} (a renamed copy of ping.exe pinging 127.0.0.1)')
    proc = subprocess.Popen([str(fake_tool), '-n', str(hold + 5), '127.0.0.1'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _hold(hold, 'the process')
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(workdir, ignore_errors=True)


def simulate_backdoor(hold, port=4444):
    """Connect to a local listener on a classic backdoor port."""
    server = _listener()
    try:
        server.bind(('127.0.0.1', port))
    except OSError as exc:
        log(f'  skipped: port {port} is in use ({exc})')
        return
    server.listen(5)
    client = socket.create_connection(('127.0.0.1', port))
    accepted, _ = server.accept()
    log(f'  connected 127.0.0.1 -> 127.0.0.1:{port}')
    try:
        _hold(hold, 'the connection')
    finally:
        for sock in (client, accepted, server):
            sock.close()


def simulate_portscan(hold, count=120):
    """Open many connections from this one process, like a scanner would."""
    server = _listener()
    server.bind(('127.0.0.1', 0))
    server.listen(count + 10)
    port = server.getsockname()[1]
    clients, accepted = [], []
    for _ in range(count):
        clients.append(socket.create_connection(('127.0.0.1', port)))
        accepted.append(server.accept()[0])
    log(f'  opened {count} connections to 127.0.0.1:{port}')
    try:
        _hold(hold, 'the connections')
    finally:
        for sock in clients + accepted + [server]:
            sock.close()


def _documents_dir():
    """The Documents folder SecureX watches (OneDrive-redirected or local)."""
    candidates = []
    if os.environ.get('OneDrive'):
        candidates.append(Path(os.environ['OneDrive']) / 'Documents')
    candidates.append(Path.home() / 'Documents')
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[-1]


def simulate_ransomware(hold, files=50):
    """Encrypt-like burst: create dummy files, rename them, drop a ransom note."""
    sandbox = _documents_dir() / SANDBOX_NAME
    if sandbox.exists():
        shutil.rmtree(sandbox)
    sandbox.mkdir(parents=True)
    log(f'  sandbox folder: {sandbox}')
    try:
        for i in range(files):
            (sandbox / f'dummy_{i:03d}.txt').write_text('SecureX simulation dummy file\n')
        for i in range(files):
            src = sandbox / f'dummy_{i:03d}.txt'
            src.rename(src.with_suffix('.locked'))
        # Keep the note open while holding, like ransomware that is still
        # writing; SecureX uses open files to identify the responsible process.
        with open(sandbox / 'HOW_TO_DECRYPT_FILES.txt', 'w') as note:
            note.write('This is a SecureX test. No files were encrypted.\n')
            note.flush()
            log(f'  renamed {files} dummy files to .locked and created HOW_TO_DECRYPT_FILES.txt')
            _hold(hold, 'the sandbox (ransom note kept open)')
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
        log('  sandbox folder removed')


def simulate_bruteforce(hold, base_url, attempts=8):
    """Send wrong passwords for a non-existent user to the dashboard login."""
    url = f'{base_url.rstrip("/")}/api/auth/login'
    failures = 0
    for i in range(attempts):
        body = json.dumps({'username': 'sim_attacker', 'password': f'wrong-{i}'}).encode()
        request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            failures += exc.code == 401
        except urllib.error.URLError as exc:
            log(f'  skipped: dashboard not reachable at {base_url} ({exc.reason})')
            return
        time.sleep(0.3)
    log(f'  {failures}/{attempts} login attempts rejected (see the Audit page)')


def simulate_cpu(hold):
    """Keep one core busy so this process shows near 100% CPU."""
    stop = time.monotonic() + hold
    log(f'  burning one CPU core for {hold}s...')
    while time.monotonic() < stop:
        sum(i * i for i in range(10000))


SCENARIOS = {
    'process': (simulate_process, 'renamed ping.exe as "nmap_sim.exe"'),
    'backdoor': (simulate_backdoor, 'loopback connection to port 4444'),
    'portscan': (simulate_portscan, '120 loopback connections from one process'),
    'ransomware': (simulate_ransomware, 'rename burst + fake ransom note in a sandbox folder'),
    'bruteforce': (simulate_bruteforce, 'failed dashboard logins for a fake user'),
    'cpu': (simulate_cpu, 'one CPU core at 100%'),
}
# "cpu" is noisy and slow to register, so it only runs when asked for by name.
DEFAULT_ALL = ['process', 'backdoor', 'portscan', 'ransomware', 'bruteforce']


def run_scenario(name, hold, url='http://127.0.0.1:5000'):
    """Run one scenario by name, logging start, errors and completion."""
    func, description = SCENARIOS[name]
    log(f'>> {name}: {description}')
    try:
        if name == 'bruteforce':
            func(hold, url)
        else:
            func(hold)
    except Exception as exc:
        log(f'  {name} failed: {exc}')
    log(f'<< {name} done')


def main():
    parser = argparse.ArgumentParser(description='Harmless attack simulator for testing SecureX.')
    parser.add_argument('scenarios', nargs='*', help='scenario names, or "all"')
    parser.add_argument('--list', action='store_true', help='list scenarios and exit')
    parser.add_argument('--hold', type=int, default=45,
                        help='seconds to keep each activity alive (default 45)')
    parser.add_argument('--url', default='http://127.0.0.1:5000',
                        help='dashboard URL for the bruteforce scenario')
    parser.add_argument('--parallel', action='store_true',
                        help='run the scenarios at the same time instead of one by one')
    args = parser.parse_args()

    if args.list or not args.scenarios:
        print('Scenarios:')
        for name, (_, description) in SCENARIOS.items():
            print(f'  {name:<11} {description}')
        print('\n"all" runs: ' + ', '.join(DEFAULT_ALL))
        return 0

    names = DEFAULT_ALL if args.scenarios == ['all'] else args.scenarios
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        parser.error(f'unknown scenario(s): {", ".join(unknown)}')

    def run(name):
        run_scenario(name, args.hold, args.url)

    log('SecureX attack simulator - make sure monitoring is started in the dashboard')
    if args.parallel:
        threads = [threading.Thread(target=run, args=(n,)) for n in names]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    else:
        for name in names:
            run(name)
    log('Finished. Check the Dashboard / Threats / Audit pages.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
