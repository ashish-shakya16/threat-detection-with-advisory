"""Unknown-threat detection from a learned baseline of this machine's behaviour.

During a learning phase SecureX records per-process snapshots (CPU, memory,
threads, network connections, remote addresses and ports) every monitoring
cycle. Once it has enough samples it fits an Isolation Forest on them and
sets the alert threshold at a high quantile of the training scores (default
99.5%, i.e. roughly 0.5% of normal snapshots would score that high).

After that, any process whose behaviour scores above the threshold is
reported as "Unknown suspicious activity", with the features that deviate
most from normal as evidence. It is never given a malware-family label.

Isolation Forest cannot tell "just above the largest value seen" from "far
beyond it", so a range check complements it: a process is also flagged when
two or more measurements exceed the largest value seen during learning by a
wide margin, or when it connects to commonly abused ports that never
appeared during learning.

Assumes the machine is not compromised while the baseline is learned.
"""

import ipaddress
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import psutil

logger = logging.getLogger('securex')

FEATURES = [
    'cpu_percent', 'memory_percent', 'num_threads', 'connections',
    'remote_ips', 'remote_ports', 'public_remote_ips', 'suspicious_port_connections',
]
FEATURE_LABELS = {
    'cpu_percent': 'CPU %', 'memory_percent': 'memory %', 'num_threads': 'threads',
    'connections': 'network connections', 'remote_ips': 'distinct remote addresses',
    'remote_ports': 'distinct remote ports', 'public_remote_ips': 'internet addresses contacted',
    'suspicious_port_connections': 'connections to commonly abused ports',
}
COUNT_FEATURES = slice(2, len(FEATURES))  # log-scaled
# Margin above the learned maximum that counts as "far beyond normal":
# +25 percentage points for CPU/memory, x2 (log1p + 0.7) for counts.
EXCEED_MARGIN = np.array([25.0, 25.0] + [0.7] * (len(FEATURES) - 2))
SUSPICIOUS_PORT_INDEX = FEATURES.index('suspicious_port_connections')
SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321, 9001, 3389, 5900}
IGNORED_PIDS = {0, 4}


def _is_public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def collect_snapshot() -> List[Dict[str, Any]]:
    """One row per running process with the baseline features."""
    by_pid = defaultdict(list)
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid and conn.raddr:
                by_pid[conn.pid].append(conn.raddr)
    except (psutil.AccessDenied, OSError):
        pass

    rows = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        pid = proc.info['pid']
        if pid in IGNORED_PIDS:
            continue
        try:
            cpu = proc.cpu_percent(None)
            memory = proc.memory_percent()
            threads = proc.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        remotes = by_pid.get(pid, [])
        values = {
            'cpu_percent': cpu,
            'memory_percent': memory,
            'num_threads': threads,
            'connections': len(remotes),
            'remote_ips': len({r.ip for r in remotes}),
            'remote_ports': len({r.port for r in remotes}),
            'public_remote_ips': len({r.ip for r in remotes if _is_public(r.ip)}),
            'suspicious_port_connections': sum(1 for r in remotes if r.port in SUSPICIOUS_PORTS),
        }
        rows.append({'pid': pid, 'name': proc.info['name'] or '?', 'username': proc.info.get('username') or '',
                     'values': values})
    return rows


def to_matrix(rows: List[Dict[str, Any]]) -> np.ndarray:
    if not rows:
        return np.zeros((0, len(FEATURES)))
    matrix = np.array([[row['values'][name] for name in FEATURES] for row in rows], dtype=float)
    matrix[:, COUNT_FEATURES] = np.log1p(matrix[:, COUNT_FEATURES])
    return matrix


class BehaviourBaseline:
    def __init__(self, model_dir: str, config: Optional[Dict[str, Any]] = None, collector=collect_snapshot):
        config = config or {}
        self.enabled = bool(config.get('enabled', True))
        self.min_samples = int(config.get('min_samples', 3000))
        self.min_cycles = int(config.get('min_cycles', 30))
        self.max_samples = int(config.get('max_samples', 30000))
        self.threshold_quantile = float(config.get('threshold_quantile', 0.995))
        self.alert_cooldown = float(config.get('alert_cooldown_seconds', 3600))
        self.model_path = os.path.join(model_dir, 'behaviour_baseline.joblib')
        self.samples_path = os.path.join(model_dir, 'behaviour_baseline_samples.npz')
        self.collector = collector
        self.model: Optional[Dict[str, Any]] = None
        self.samples = np.zeros((0, len(FEATURES)))
        self.names: set = set()
        self.cycles = 0
        self._last_alert: Dict[str, float] = {}
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        import joblib
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                return
            except Exception as error:
                logger.warning('Could not load behaviour baseline: %s', error)
        if os.path.exists(self.samples_path):
            try:
                data = np.load(self.samples_path, allow_pickle=False)
                self.samples, self.cycles = data['samples'], int(data['cycles'])
                self.names = set(data['names'].tolist())
            except Exception as error:
                logger.warning('Could not load baseline samples: %s', error)

    def _save_samples(self) -> None:
        os.makedirs(os.path.dirname(self.samples_path), exist_ok=True)
        np.savez(self.samples_path, samples=self.samples, cycles=self.cycles, names=np.array(sorted(self.names)))

    def _train(self) -> None:
        import joblib
        from sklearn.ensemble import IsolationForest

        # Calibrate the threshold on held-out snapshots: scores of the training
        # samples themselves are optimistic and would set it too low.
        order = np.random.default_rng(42).permutation(len(self.samples))
        split = int(len(order) * 0.8)
        forest = IsolationForest(n_estimators=200, contamination='auto', random_state=42)
        forest.fit(self.samples[order[:split]])
        scores = -forest.score_samples(self.samples[order[split:]])  # higher = more unusual
        self.model = {
            'forest': forest,
            'threshold': float(np.quantile(scores, self.threshold_quantile)),
            'p50': np.median(self.samples, axis=0),
            'p99': np.quantile(self.samples, 0.99, axis=0),
            'max': self.samples.max(axis=0),
            'known_names': sorted(self.names),
            'trained_at': datetime.now(timezone.utc).isoformat(),
            'n_samples': int(len(self.samples)),
            'n_cycles': self.cycles,
            'features': FEATURES,
        }
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        if os.path.exists(self.samples_path):
            os.remove(self.samples_path)
        logger.info('Behaviour baseline trained on %d samples from %d cycles', len(self.samples), self.cycles)

    # ------------------------------------------------------------------
    def observe(self) -> List[Dict[str, Any]]:
        """Collect one snapshot: learn from it, or return anomaly threats."""
        if not self.enabled:
            return []
        rows = self.collector()
        matrix = to_matrix(rows)
        if self.model is None:
            self.samples = np.vstack([self.samples, matrix])[-self.max_samples:]
            self.names.update(row['name'].lower() for row in rows)
            self.cycles += 1
            if len(self.samples) >= self.min_samples and self.cycles >= self.min_cycles:
                self._train()
            else:
                self._save_samples()
            return []
        if not len(rows):
            return []

        scores = -self.model['forest'].score_samples(matrix)
        threats = []
        now = time.monotonic()
        for row, values, score in zip(rows, matrix, scores):
            exceeded = self._far_beyond_normal(values)
            if score <= self.model['threshold'] and len(exceeded) < 2                     and SUSPICIOUS_PORT_INDEX not in exceeded:
                continue
            key = row['name'].lower()
            if now - self._last_alert.get(key, -1e9) < self.alert_cooldown:
                continue
            self._last_alert[key] = now
            threats.append(self._to_threat(row, values, float(score), len(exceeded)))
        return threats

    def _far_beyond_normal(self, values: np.ndarray) -> List[int]:
        maximum = self.model.get('max', self.model['p99'])
        return [i for i in range(len(FEATURES)) if values[i] > maximum[i] + EXCEED_MARGIN[i]]

    def _to_threat(self, row: Dict[str, Any], values: np.ndarray, score: float, exceeded: int = 0) -> Dict[str, Any]:
        evidence = []
        for index, name in enumerate(FEATURES):
            if values[index] > self.model['p99'][index] and row['values'][name] > 0:
                normal = self.model['p99'][index]
                normal = np.expm1(normal) if index >= COUNT_FEATURES.start else normal
                evidence.append(f"{FEATURE_LABELS[name]}: {row['values'][name]:.0f} "
                                f"(on this machine 99% of processes have up to {normal:.0f})")
        if not evidence:
            evidence.append('Unusual combination of resource and network behaviour, '
                            'though no single measurement is extreme.')
        if row['name'].lower() not in self.model['known_names']:
            evidence.append(f"\"{row['name']}\" was never seen while the baseline was learned.")
        excess = score - self.model['threshold']
        return {
            'threat_name': f"Unusual behaviour: {row['name']}",
            'category': 'Unknown',
            'detection_method': 'anomaly',
            'severity': 'high' if excess > 0.08 or exceeded >= 3 else 'medium',
            'confidence': 0.4,
            'impact': 'unknown',
            'description': 'Process behaviour deviates strongly from what is normal on this machine.',
            'source': 'behaviour_baseline',
            'timestamp': datetime.now().isoformat(),
            'anomaly_score': round(score, 4),
            'evidence': evidence,
            'event_data': {
                'process_name': row['name'], 'pid': row['pid'], 'username': row['username'],
                'reason': (f"Anomaly score {score:.3f} (threshold {self.model['threshold']:.3f}); "
                           f"{exceeded} measurement(s) far beyond anything seen while learning"),
                'event_type': 'behaviour_anomaly',
            },
        }

    # ------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        if not self.enabled:
            return {'state': 'disabled'}
        if self.model is None:
            return {
                'state': 'learning', 'samples': int(len(self.samples)), 'cycles': self.cycles,
                'required_samples': self.min_samples, 'required_cycles': self.min_cycles,
                'progress': round(min(len(self.samples) / self.min_samples, self.cycles / self.min_cycles, 1.0), 3),
            }
        return {
            'state': 'active', 'trained_at': self.model['trained_at'], 'samples': self.model['n_samples'],
            'cycles': self.model['n_cycles'], 'threshold': round(self.model['threshold'], 4),
            'false_positive_target': round(1 - self.threshold_quantile, 4),
        }

    def reset(self) -> None:
        """Forget the baseline and start learning again."""
        for path in (self.model_path, self.samples_path):
            if os.path.exists(path):
                os.remove(path)
        self.model, self.samples, self.names, self.cycles = None, np.zeros((0, len(FEATURES))), set(), 0
