"""Tests for the classifier, ransomware-like behaviour monitor, phishing URL
analyzer and behaviour-baseline anomaly detector."""

import os
import time

import numpy as np
import pytest

from src.detection.behaviour_baseline import FEATURES, BehaviourBaseline
from src.detection.phishing_url import analyze_url
from src.detection.ransomware_monitor import RansomwareBehaviourDetector, RansomwareMonitor
from src.detection.threat_classifier import UNKNOWN, classify

# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def test_rule_detection_is_classified_but_never_confirmed():
    threat = classify({'category': 'Malware', 'rule_matched': 'RULE_001', 'description': 'Suspicious name',
                       'event_data': {'process_name': 'svch0st.exe', 'pid': 42}})
    assert threat['classification'] == 'Suspicious process (malware-like pattern)'
    assert threat['detection_method'] == 'rule'
    assert threat['verification_status'] == 'unverified'
    assert 'Process: svch0st.exe' in threat['evidence']


def test_unmapped_category_and_anomalies_are_unknown():
    assert classify({'category': 'Something new'})['classification'] == UNKNOWN
    anomaly = classify({'detection_method': 'anomaly', 'evidence': ['connections: 90']})
    assert anomaly['classification'] == UNKNOWN
    assert any('insufficient evidence' in line for line in anomaly['evidence'])


# ---------------------------------------------------------------------------
# Ransomware-like behaviour
# ---------------------------------------------------------------------------

SMALL = {'thresholds': {'window_seconds': 30, 'bulk_modification': 10, 'rename_burst': 8,
                        'extension_change': 5, 'many_directories': 50, 'cooldown_seconds': 300}}


def test_normal_activity_does_not_alert():
    detector = RansomwareBehaviourDetector(SMALL)
    for i in range(5):
        assert detector.record('modified', f'C:/docs/file{i}.docx', now=float(i)) is None


def test_repeated_events_for_one_file_count_once():
    detector = RansomwareBehaviourDetector(SMALL)
    alerts = [detector.record('modified', 'C:/docs/same.docx', now=float(i)) for i in range(50)]
    assert not any(alerts)


def test_bulk_modification_alone_is_only_suspicious():
    detector = RansomwareBehaviourDetector(SMALL)
    alert = None
    for i in range(10):
        alert = detector.record('modified', f'C:/docs/file{i}.docx', now=float(i)) or alert
    assert alert['classification'] == 'Suspicious bulk file modification'
    assert alert['severity'] == 'high'
    assert any('does not report which process' in line for line in alert['evidence'])


def test_encrypting_renames_are_possible_ransomware():
    detector = RansomwareBehaviourDetector(SMALL)
    alert = None
    for i in range(8):
        alert = detector.record('moved', f'C:/docs/file{i}.docx', f'C:/docs/file{i}.docx.locked', now=float(i)) or alert
    assert alert['classification'] == 'Possible ransomware-like behaviour'
    assert alert['severity'] == 'critical'
    assert any('".locked"' in line for line in alert['evidence'])


def test_ransom_note_and_cooldown():
    detector = RansomwareBehaviourDetector(SMALL)
    first = detector.record('created', 'C:/docs/HOW_TO_DECRYPT_FILES.txt', now=0.0)
    assert first['classification'] == 'Possible ransomware-like behaviour'
    assert detector.record('created', 'C:/docs/README_RECOVER_FILES.txt', now=10.0) is None  # cooldown


def test_alert_attributed_to_process_holding_file_in_folder(tmp_path):
    import subprocess
    import sys
    from src.detection.ransomware_monitor import attribute_process, io_snapshot
    baseline = io_snapshot()
    holder = subprocess.Popen([sys.executable, '-c',
                               'import sys,time; f=open(sys.argv[1],"w"); print("ready",flush=True); time.sleep(30)',
                               str(tmp_path / 'HOW_TO_DECRYPT_FILES.txt')],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == 'ready'
        detector = RansomwareBehaviourDetector(SMALL)
        alert = detector.record('created', str(tmp_path / 'HOW_TO_DECRYPT_FILES.txt'), now=0.0)
        attribute_process(alert, baseline)
        # A venv python.exe may launch the real interpreter as a child process.
        assert alert['event_data']['pid'] in {holder.pid, *(c.pid for c in __import__('psutil').Process(holder.pid).children())}
        assert any('Suspected process' in line for line in alert['evidence'])
        assert not any('does not report which process' in line for line in alert['evidence'])
    finally:
        holder.kill()
        holder.wait()


def test_alert_without_matching_process_is_unchanged(tmp_path):
    from src.detection.ransomware_monitor import attribute_process, io_snapshot
    detector = RansomwareBehaviourDetector(SMALL)
    alert = detector.record('created', str(tmp_path / 'HOW_TO_DECRYPT_FILES.txt'), now=0.0)
    attribute_process(alert, io_snapshot())
    assert 'pid' not in alert['event_data']
    assert any('does not report which process' in line for line in alert['evidence'])


def test_events_outside_window_expire():
    detector = RansomwareBehaviourDetector(SMALL)
    for i in range(9):
        detector.record('modified', f'C:/docs/old{i}.txt', now=float(i))
    # 40 seconds later the earlier 9 have left the 30-second window.
    assert detector.record('modified', 'C:/docs/new.txt', now=49.0) is None


def test_live_monitor_detects_real_file_burst(tmp_path):
    monitor = RansomwareMonitor({'watch_paths': [str(tmp_path)], **SMALL})
    monitor.start()
    try:
        assert monitor.status()['running']
        for i in range(10):
            (tmp_path / f'doc{i}.txt').write_text('data')
        for i in range(10):
            os.rename(tmp_path / f'doc{i}.txt', tmp_path / f'doc{i}.txt.encrypted')
        alerts = []
        for _ in range(50):
            alerts += monitor.drain_alerts()
            if alerts:
                break
            time.sleep(0.1)
    finally:
        monitor.stop()
    assert alerts and alerts[0]['detection_method'] == 'file_behaviour'


# ---------------------------------------------------------------------------
# Phishing URLs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('url,verdict', [
    ('https://www.paypal.com/signin', 'No known phishing indicators'),
    ('https://accounts.google.com/', 'No known phishing indicators'),
    ('http://paypa1.com/login', 'High-risk URL indicators'),
    ('https://secure-paypal.account-verify.xyz/login', 'High-risk URL indicators'),
    ('http://www.google.com@evil.example/', 'High-risk URL indicators'),
    ('https://bit.ly/3abc', 'Suspicious URL'),
    ('https://xn--pple-43d.com', 'Suspicious URL'),
])
def test_phishing_verdicts(url, verdict):
    assert analyze_url(url)['verdict'] == verdict


def test_short_brand_names_do_not_false_positive():
    assert analyze_url('https://www.frisbie-shop.com/')['score'] == 0


@pytest.mark.parametrize('bad', ['', '   ', 'ftp://example.com', 'javascript:alert(1)', 'http://' + 'a' * 2100, None])
def test_invalid_urls_are_rejected(bad):
    with pytest.raises(ValueError):
        analyze_url(bad)


def test_result_always_states_limitations():
    result = analyze_url('example.com')
    assert result['url'] == 'http://example.com'
    assert 'not proven safe' in result['limitations']


# ---------------------------------------------------------------------------
# Behaviour baseline (unknown threats)
# ---------------------------------------------------------------------------

def normal_rows(rng, count=60):
    return [{'pid': 1000 + i, 'name': f'app{i % 12}.exe', 'username': 'user', 'values': {
        'cpu_percent': abs(rng.normal(1, 0.5)), 'memory_percent': abs(rng.normal(1, 0.3)),
        'num_threads': int(rng.integers(5, 30)), 'connections': int(rng.integers(0, 3)),
        'remote_ips': int(rng.integers(0, 2)), 'remote_ports': int(rng.integers(0, 2)),
        'public_remote_ips': int(rng.integers(0, 2)), 'suspicious_port_connections': 0,
    }} for i in range(count)]


def test_baseline_learns_then_flags_unusual_process(tmp_path):
    rng = np.random.default_rng(0)
    snapshots = iter([normal_rows(rng) for _ in range(5)])
    baseline = BehaviourBaseline(str(tmp_path), {'min_cycles': 5, 'min_samples': 200},
                                 collector=lambda: next(snapshots))
    for _ in range(4):
        assert baseline.observe() == []
        assert baseline.status()['state'] == 'learning'
    baseline.observe()
    assert baseline.status()['state'] == 'active'

    beacon = {'pid': 666, 'name': 'updater-x.exe', 'username': 'user', 'values': {
        'cpu_percent': 2, 'memory_percent': 1, 'num_threads': 12, 'connections': 80, 'remote_ips': 60,
        'remote_ports': 40, 'public_remote_ips': 60, 'suspicious_port_connections': 6}}
    baseline.collector = lambda: normal_rows(rng, 30) + [beacon]
    threats = baseline.observe()
    flagged = [t for t in threats if t['event_data']['pid'] == 666]
    assert flagged, 'the beaconing process should be flagged'
    threat = classify(flagged[0])
    assert threat['classification'] == UNKNOWN
    assert any('network connections: 80' in line for line in threat['evidence'])
    assert any('never seen' in line for line in threat['evidence'])
    # Normal processes stay quiet (allowing for the ~0.5% threshold).
    assert len(threats) <= 2

    # Cooldown: the same process name is not re-reported immediately.
    assert not [t for t in baseline.observe() if t['event_data']['pid'] == 666]


def test_baseline_persists_and_resets(tmp_path):
    rng = np.random.default_rng(1)
    config = {'min_cycles': 2, 'min_samples': 50}
    first = BehaviourBaseline(str(tmp_path), config, collector=lambda: normal_rows(rng))
    first.observe()
    assert BehaviourBaseline(str(tmp_path), config).status()['cycles'] == 1  # learning progress survives restart
    first.observe()
    reloaded = BehaviourBaseline(str(tmp_path), config)
    assert reloaded.status()['state'] == 'active'
    reloaded.reset()
    assert reloaded.status()['state'] == 'learning' and not os.listdir(tmp_path)


def test_real_snapshot_has_expected_features():
    from src.detection.behaviour_baseline import collect_snapshot
    rows = collect_snapshot()
    assert rows and set(rows[0]['values']) == set(FEATURES)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    import src.dashboard.app as app_module
    app_module.app.config['TESTING'] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def test_detection_endpoints_require_login(client):
    assert client.post('/api/phishing/analyze', json={'url': 'x.com'}).status_code == 401
    assert client.get('/api/detection/status').status_code == 401
    assert client.post('/api/detection/baseline/reset').status_code == 401


def test_phishing_endpoint(client):
    with client.session_transaction() as sess:
        sess['username'] = 'alice'
    body = client.post('/api/phishing/analyze', json={'url': 'http://paypa1.com/login'}).get_json()
    assert body['data']['verdict'] == 'High-risk URL indicators'
    assert client.post('/api/phishing/analyze', json={'url': 'ftp://x'}).status_code == 400
    assert client.post('/api/phishing/analyze', json=['nope']).status_code == 400
    status = client.get('/api/detection/status').get_json()['data']
    assert status['anomaly_baseline']['state'] in ('learning', 'active')
    assert status['rules'] == 10
