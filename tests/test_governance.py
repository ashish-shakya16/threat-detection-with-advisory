"""Tests for the audit log (G7), graduated response (G6), risk context (G4)
and the dataset evaluation pipeline (G1).

The dataset tests use small *synthetic* CSV fixtures that only mimic the
CIC-IDS2017 and UNSW-NB15 column layouts. They test the pipeline mechanics,
not detection quality.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import numpy as np
import pandas as pd
import psutil
import pytest

from src.audit import AuditLog
from src.database.db_manager import DatabaseManager
from src.ml_models import dataset_evaluation
from src.response import ResponseError, ResponseManager, response_level_for
from src.risk_assessment.asset_context import AssetContextResolver, classify_exposure
from src.risk_assessment.risk_scorer import RiskScorer


@pytest.fixture
def db():
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    os.remove(path)
    manager = DatabaseManager(path)
    yield manager
    if os.path.exists(path):
        os.remove(path)


# ---------------------------------------------------------------------------
# G7 audit log
# ---------------------------------------------------------------------------

def test_audit_chain_detects_tampering(db):
    audit = AuditLog(db.db_path)
    for i in range(3):
        audit.record('alice', 'threat.status_change', 'threat', i, details={'status': 'resolved'})
    assert audit.verify_chain() == {'valid': True, 'checked': 3, 'first_invalid_id': None}

    conn = sqlite3.connect(db.db_path)
    conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 2")
    conn.commit()
    conn.close()
    assert audit.verify_chain()['first_invalid_id'] == 2


def test_audit_chain_detects_deletion(db):
    audit = AuditLog(db.db_path)
    for i in range(3):
        audit.record('alice', 'auth.login')
    conn = sqlite3.connect(db.db_path)
    conn.execute('DELETE FROM audit_log WHERE id = 2')
    conn.commit()
    conn.close()
    assert audit.verify_chain()['valid'] is False


def test_audit_redacts_secrets_and_filters(db):
    audit = AuditLog(db.db_path)
    audit.record('alice', 'notifications.preferences_update', details={'smtp_password': 'hunter2', 'high': True})
    audit.record('bob', 'auth.login', outcome='failure')
    entries = audit.list()['entries']
    assert entries[1]['details'] == {'smtp_password': '[redacted]', 'high': True}
    assert audit.list(action='auth.')['total'] == 1
    assert audit.list(actor='alice')['entries'][0]['action'] == 'notifications.preferences_update'


# ---------------------------------------------------------------------------
# G6 graduated response
# ---------------------------------------------------------------------------

@pytest.fixture
def child_process():
    """A harmless, short-lived process to act on."""
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    yield psutil.Process(process.pid)
    if process.poll() is None:
        process.kill()
        process.wait()


def threat_for(pid, risk_level):
    return {'threat_name': 'Suspicious Process Execution', 'risk_level': risk_level,
            'event_data': {'pid': pid, 'process_name': 'python.exe'}}


def test_response_levels_follow_risk():
    assert [response_level_for(level) for level in ('Low', 'Medium', 'High', 'Critical')] == [0, 1, 2, 3]


def test_policy_proposes_by_level_and_deduplicates(db, child_process):
    manager = ResponseManager(db.db_path, AuditLog(db.db_path), {'protected_processes': []})
    assert manager.propose_for_threat(1, threat_for(child_process.pid, 'Medium')) == []
    assert len(manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))) == 1
    created = manager.propose_for_threat(2, threat_for(child_process.pid, 'Critical'))
    # The suspend proposal already exists; only terminate is new.
    assert [manager.get(i)['action'] for i in created] == ['terminate_process']


def test_protected_and_own_processes_are_never_proposed(db):
    manager = ResponseManager(db.db_path)
    assert manager.propose_for_threat(1, threat_for(os.getpid(), 'Critical')) == []
    assert manager.propose_for_threat(1, threat_for(4, 'Critical')) == []


def test_approval_is_dry_run_when_execution_disabled(db, child_process):
    audit = AuditLog(db.db_path)
    manager = ResponseManager(db.db_path, audit, {'protected_processes': []})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    result = manager.approve(proposal_id, 'alice')
    assert result['status'] == 'dry_run' and result['decided_by'] == 'alice'
    assert child_process.status() != psutil.STATUS_STOPPED
    assert [e['action'] for e in audit.list()['entries']][:2] == ['response.approved', 'response.proposed']
    with pytest.raises(ResponseError):
        manager.approve(proposal_id, 'alice')  # already decided


def test_approved_suspend_executes_and_can_be_resumed(db, child_process):
    manager = ResponseManager(db.db_path, AuditLog(db.db_path),
                              {'execution_enabled': True, 'protected_processes': []})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    assert manager.approve(proposal_id, 'alice')['status'] == 'executed'
    assert child_process.status() == psutil.STATUS_STOPPED
    assert manager.resume(proposal_id, 'alice')['status'] == 'resumed'
    assert child_process.status() != psutil.STATUS_STOPPED


def test_approved_terminate_executes(db, child_process):
    manager = ResponseManager(db.db_path, None, {'execution_enabled': True, 'protected_processes': []})
    ids = manager.propose_for_threat(1, threat_for(child_process.pid, 'Critical'))
    terminate = next(i for i in ids if manager.get(i)['action'] == 'terminate_process')
    assert manager.approve(terminate, 'alice')['status'] == 'executed'
    assert not child_process.is_running() or child_process.status() == psutil.STATUS_ZOMBIE


def test_pid_reuse_is_refused(db, child_process):
    manager = ResponseManager(db.db_path, None, {'execution_enabled': True, 'protected_processes': []})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    conn = sqlite3.connect(db.db_path)
    conn.execute('UPDATE response_actions SET target_create_time = target_create_time - 100 WHERE id = ?',
                 (proposal_id,))
    conn.commit()
    conn.close()
    with pytest.raises(ResponseError, match='different process'):
        manager.approve(proposal_id, 'alice')
    assert manager.get(proposal_id)['status'] == 'failed'
    assert child_process.status() != psutil.STATUS_STOPPED


def test_rejection_and_expiry(db, child_process):
    manager = ResponseManager(db.db_path, None, {'protected_processes': [], 'proposal_ttl_minutes': 0})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    with pytest.raises(ResponseError, match='expired'):
        manager.approve(proposal_id, 'alice')

    manager = ResponseManager(db.db_path, None, {'protected_processes': []})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    assert manager.reject(proposal_id, 'alice')['status'] == 'rejected'


def test_execution_rate_limit(db, child_process):
    manager = ResponseManager(db.db_path, None, {'execution_enabled': True, 'protected_processes': [],
                                                 'max_executions_per_minute': 0})
    proposal_id = manager.propose_for_threat(1, threat_for(child_process.pid, 'High'))[0]
    with pytest.raises(ResponseError, match='Too many'):
        manager.approve(proposal_id, 'alice')
    assert manager.get(proposal_id)['status'] == 'proposed'


# ---------------------------------------------------------------------------
# G4 risk context
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('event,expected', [
    ({'remote_ip': '8.8.8.8'}, 'internet'),
    ({'remote_ip': '192.168.1.20'}, 'internal'),
    ({'remote_ip': '127.0.0.1'}, 'local'),
    ({'local_address': '0.0.0.0:3389', 'status': 'LISTEN'}, 'internet'),
    ({'local_address': '127.0.0.1:5000', 'status': 'LISTEN'}, 'local'),
    ({}, 'local'),
])
def test_exposure_classification(event, expected):
    assert classify_exposure(event) == expected


def test_asset_context_changes_score_and_records_reasons():
    config = {'risk_assessment': {'asset_context': {'device_criticality': 'critical'}}}
    scorer = RiskScorer(config)
    context = AssetContextResolver(config).resolve({'event_data': {
        'remote_ip': '8.8.4.4', 'username': 'NT AUTHORITY\\SYSTEM'}})
    assert context == {'asset_criticality': 'critical', 'exposure': 'internet', 'privileged_user': True}

    adjusted = scorer.adjust_risk_by_context({'risk_score': 0.5}, context)
    assert adjusted['risk_score'] == pytest.approx(0.5 * 1.15 * 1.3 * 1.2, abs=1e-3)
    assert adjusted['risk_level'] == 'Critical'
    assert any('critical asset criticality' in reason for reason in adjusted['risk_adjustments'])

    low = RiskScorer({}).adjust_risk_by_context({'risk_score': 0.5}, {'asset_criticality': 'low'})
    assert low['risk_score'] < 0.5


def test_risk_context_is_stored_with_threat(db):
    threat_id = db.log_threat({'threat_name': 'x', 'risk_level': 'High', 'risk_score': 0.7,
                               'risk_context': {'exposure': 'internet'}})
    assert '"internet"' in db.get_threat_by_id(threat_id)['risk_context']


# ---------------------------------------------------------------------------
# G1 dataset evaluation (synthetic fixtures)
# ---------------------------------------------------------------------------

def _cicids_frame(rng, benign, attacks, attack_label='DDoS'):
    rows = benign + attacks
    labels = ['BENIGN'] * benign + [attack_label] * attacks
    shift = np.r_[np.zeros(benign), np.full(attacks, 6.0)]
    return pd.DataFrame({
        'Flow ID': [f'f{i}' for i in range(rows)],
        ' Source IP': '10.0.0.1',
        ' Destination Port': rng.integers(1, 65535, rows),
        ' Timestamp': '3/7/2017 8:55',
        ' Flow Duration': rng.normal(100, 10, rows) + shift * 10,
        ' Total Fwd Packets': rng.normal(10, 2, rows) + shift,
        'Flow Bytes/s': rng.normal(500, 50, rows) + shift * 50,
        ' Fwd Header Length': rng.normal(40, 4, rows) + shift,
        ' Fwd Header Length.1': 0.0,
        ' Constant': 1.0,
        ' Label': labels,
    })


@pytest.fixture
def cicids_files(tmp_path):
    rng = np.random.default_rng(0)
    train = _cicids_frame(rng, 600, 60)
    train.loc[0, 'Flow Bytes/s'] = np.inf
    train.loc[1, ' Flow Duration'] = np.nan
    train = pd.concat([train, train.iloc[[5, 6]]])            # duplicates
    test = _cicids_frame(rng, 300, 100, 'PortScan')
    test = pd.concat([test, train.iloc[[10]]])                # leaks a training row
    paths = (tmp_path / 'Monday-synthetic.csv', tmp_path / 'Friday-synthetic.csv')
    train.to_csv(paths[0], index=False)
    test.to_csv(paths[1], index=False)
    return [str(paths[0])], [str(paths[1])]


def test_cicids_preparation_cleans_and_prevents_leakage(cicids_files):
    data = dataset_evaluation.prepare('cicids2017', *cicids_files)
    assert data.cleaning['train_rows_after_nan_inf'] == data.cleaning['train_rows_raw'] - 2
    assert data.cleaning['train_rows_after_dedup'] == data.cleaning['train_rows_after_nan_inf'] - 2
    assert data.cleaning['test_rows_overlapping_train_removed'] == 1
    assert data.cleaning['constant_features_dropped'] == 1
    for removed in ('Flow ID', 'Source IP', 'Destination Port', 'Timestamp', 'Fwd Header Length.1', 'Constant'):
        assert removed not in data.feature_names
    assert data.feature_names == ['Flow Duration', 'Total Fwd Packets', 'Flow Bytes/s', 'Fwd Header Length']


def test_cicids_evaluation_report(cicids_files, tmp_path):
    report = dataset_evaluation.evaluate('cicids2017', *cicids_files, target_fpr=0.05, n_estimators=50)
    test = report['test_metrics']
    assert set(test) >= {'precision', 'recall', 'f1', 'false_positive_rate', 'roc_auc', 'confusion_matrix'}
    # Threshold comes from validation data; check it hits the target there.
    assert report['validation_metrics']['false_positive_rate'] <= 0.06
    assert test['support'] == {'benign': 300, 'attack': 100}
    assert set(report['test_flagged_rate_by_category']) == {'BENIGN', 'PortScan'}
    assert report['files']['train'][0]['sha256']

    paths = dataset_evaluation.save_report(report, str(tmp_path / 'reports'), save_model=True)
    assert os.path.exists(paths['json']) and os.path.exists(paths['model'])
    markdown = open(paths['markdown'], encoding='utf-8').read()
    assert '## Limitations' in markdown and 'Test confusion matrix' in markdown


def test_unsw_uses_categorical_features_from_training_only(tmp_path):
    rng = np.random.default_rng(1)

    def frame(rows, attacks, protos):
        label = np.r_[np.zeros(rows - attacks, int), np.ones(attacks, int)]
        return pd.DataFrame({
            'id': range(rows), 'dur': rng.normal(1, 0.1, rows) + label * 3, 'proto': rng.choice(protos, rows),
            'service': '-', 'state': rng.choice(['FIN', 'INT'], rows), 'sbytes': rng.normal(500, 50, rows) + label * 900,
            'attack_cat': np.where(label == 1, 'Exploits', 'Normal'), 'label': label,
        })

    frame(400, 40, ['tcp', 'udp']).to_csv(tmp_path / 'UNSW_NB15_training-set.csv', index=False)
    frame(200, 50, ['tcp', 'udp', 'sctp']).to_csv(tmp_path / 'UNSW_NB15_testing-set.csv', index=False)
    data = dataset_evaluation.prepare('unsw-nb15', [str(tmp_path / 'UNSW_NB15_training-set.csv')],
                                      [str(tmp_path / 'UNSW_NB15_testing-set.csv')])
    assert 'proto_tcp' in data.feature_names and 'proto_sctp' not in data.feature_names
    assert 'id' not in data.feature_names and 'label' not in data.feature_names
    assert set(data.test_categories) == {'Normal', 'Exploits'}


def test_cli_refuses_same_file_for_train_and_test(cicids_files):
    script = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts', 'evaluate_datasets.py')
    result = subprocess.run([sys.executable, script, '--dataset', 'cicids2017', '--train', cicids_files[0][0],
                             '--test', cicids_files[0][0]], capture_output=True, text=True)
    assert result.returncode != 0 and 'cannot be used for training and testing' in result.stderr


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@pytest.fixture
def client(db, monkeypatch):
    import src.dashboard.app as app_module
    audit = AuditLog(db.db_path)
    monkeypatch.setattr(app_module, 'db', db)
    monkeypatch.setattr(app_module, 'audit_log', audit)
    monkeypatch.setitem(app_module.app.config, 'SECUREX_AUDIT', audit)
    monkeypatch.setattr(app_module, 'response_manager',
                        ResponseManager(db.db_path, audit, {'protected_processes': []}))
    app_module.app.config['TESTING'] = True
    from src.auth import hash_password
    db.create_user('alice', 'alice@example.com', hash_password('pw'))
    with app_module.app.test_client() as test_client:
        yield test_client, app_module


def test_suite_never_uses_real_database():
    import src.dashboard.app as app_module
    assert os.path.abspath(app_module.db.db_path) != os.path.abspath('data/db/threats.db')


def test_governance_endpoints_require_login(client):
    test_client = client[0]
    for method, url in [('get', '/api/audit'), ('get', '/api/audit/verify'), ('get', '/api/responses'),
                        ('post', '/api/responses/1/approve'), ('post', '/api/responses/1/reject'),
                        ('post', '/api/responses/1/resume')]:
        assert getattr(test_client, method)(url).status_code == 401


def test_login_attempts_and_actions_are_audited(client):
    test_client = client[0]
    assert test_client.post('/api/auth/login', json={'username': 'alice', 'password': 'bad'}).status_code == 401
    assert test_client.post('/api/auth/login', json={'username': 'alice', 'password': 'pw'}).status_code == 200
    body = test_client.get('/api/audit').get_json()['data']
    assert [(e['action'], e['outcome']) for e in body['entries']] == [('auth.login', 'success'),
                                                                     ('auth.login', 'failure')]
    assert test_client.get('/api/audit/verify').get_json()['data']['valid'] is True
    assert test_client.get('/api/audit?limit=x').status_code == 400


def test_response_api_flow(client, child_process):
    test_client, app_module = client
    test_client.post('/api/auth/login', json={'username': 'alice', 'password': 'pw'})
    proposal_id = app_module.response_manager.propose_for_threat(7, threat_for(child_process.pid, 'High'))[0]

    listing = test_client.get('/api/responses?threat_id=7').get_json()
    assert listing['execution_enabled'] is False and listing['data'][0]['status'] == 'proposed'
    approved = test_client.post(f'/api/responses/{proposal_id}/approve').get_json()
    assert approved['data']['status'] == 'dry_run'
    again = test_client.post(f'/api/responses/{proposal_id}/approve')
    assert again.status_code == 409
    actions = [e['action'] for e in test_client.get('/api/audit').get_json()['data']['entries']]
    assert 'response.approved' in actions and 'response.proposed' in actions
