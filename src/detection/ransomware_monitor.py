"""Ransomware-like behaviour detection from file-system activity.

Watches configured folders (watchdog) and correlates file events over a
sliding window. Signals:

    bulk_modification   many files created/modified in the window
    rename_burst        many renames in the window
    extension_change    many files renamed to the same new, unusual extension
                        (e.g. report.docx -> report.docx.locked)
    ransom_note         a file named like a typical ransom note was created
    many_directories    activity spread across many directories

Bulk modification or renames alone      -> "Suspicious bulk file modification" (High)
Two signals, an unusual extension change,
or a ransom note                         -> "Possible ransomware-like behaviour" (Critical)

Windows file events do not say which process made the change. When an alert
is collected, processes that have a file open (or their working directory)
inside the affected folders are looked up; if exactly one is found it is
attached as the suspected process so the Response Center can propose
containment for a human to approve. Otherwise the alert names no process.
Legitimate
tools (backups, sync clients, archivers, builds) can trigger the same
signals. Only paths and extensions are recorded, never file contents.
"""

import logging
import os
import re
import threading
import time
from collections import Counter, deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger('securex')

RANSOM_NOTE_PATTERN = re.compile(
    r'(readme|read_me|how_to|how-to|help|restore|recover|decrypt|instruction|_readme_|!!!)'
    r'.*(decrypt|recover|restore|files|ransom|unlock)|ransom',
    re.IGNORECASE,
)
COMMON_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.jpeg', '.png', '.gif',
    '.mp3', '.mp4', '.zip', '.csv', '.json', '.xml', '.html', '.py', '.js', '.ts', '.tsx', '.md', '.log',
    '.tmp', '.bak', '.ini', '.db', '.sqlite', '.exe', '.dll', '.lnk', '.crdownload', '.part',
}
DEFAULT_THRESHOLDS = {
    'window_seconds': 30,
    'bulk_modification': 150,
    'rename_burst': 40,
    'extension_change': 20,
    'many_directories': 15,
    'cooldown_seconds': 300,
}


class RansomwareBehaviourDetector:
    """Pure correlation logic, fed with (kind, path, dest_path) events."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.thresholds = {**DEFAULT_THRESHOLDS, **(config.get('thresholds') or {})}
        self.ignored_extensions = {e.lower() for e in config.get('ignored_extensions', [])}
        self._events: Deque[Tuple[float, str, str, str]] = deque()
        self._last_alert: Optional[float] = None
        self._lock = threading.Lock()

    def record(self, kind: str, path: str, dest_path: str = '', now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Record one event; returns an alert when the window crosses a threshold."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._events.append((now, kind, path, dest_path))
            window = self.thresholds['window_seconds']
            while self._events and now - self._events[0][0] > window:
                self._events.popleft()
            if self._last_alert is not None and now - self._last_alert < self.thresholds['cooldown_seconds']:
                return None
            alert = self._evaluate()
            if alert:
                self._last_alert = now
                self._events.clear()
            return alert

    def _evaluate(self) -> Optional[Dict[str, Any]]:
        t = self.thresholds
        # Windows reports several events per write, so count distinct files.
        modifications = {e[2] for e in self._events if e[1] in ('created', 'modified')}
        renames = {(e[2], e[3]) for e in self._events if e[1] == 'moved'}
        new_extensions = Counter()
        for src, dest in renames:
            old_ext, new_ext = os.path.splitext(src)[1].lower(), os.path.splitext(dest)[1].lower()
            if new_ext and new_ext != old_ext and new_ext not in COMMON_EXTENSIONS \
                    and new_ext not in self.ignored_extensions:
                new_extensions[new_ext] += 1
        names = {os.path.basename(e[3] or e[2]) for e in self._events if e[1] in ('created', 'moved')}
        notes = sorted(name for name in names if RANSOM_NOTE_PATTERN.search(name))
        directories = {os.path.dirname(e[3] or e[2]) for e in self._events}

        signals: List[str] = []
        evidence: List[str] = []
        if len(modifications) >= t['bulk_modification']:
            signals.append('bulk_modification')
            evidence.append(f"{len(modifications)} files created or modified within {t['window_seconds']} seconds")
        if len(renames) >= t['rename_burst']:
            signals.append('rename_burst')
            evidence.append(f"{len(renames)} files renamed within {t['window_seconds']} seconds")
        if new_extensions:
            ext, count = new_extensions.most_common(1)[0]
            if count >= t['extension_change']:
                signals.append('extension_change')
                evidence.append(f'{count} files renamed to the unusual extension "{ext}"')
        if notes:
            signals.append('ransom_note')
            evidence.append(f"File(s) named like a ransom note created: {', '.join(notes[:3])}")
        if len(directories) >= t['many_directories'] and (modifications or renames):
            signals.append('many_directories')
            evidence.append(f'Activity spread across {len(directories)} folders')

        if not signals or signals == ['many_directories']:
            return None
        # Renaming many files to one new, unusual extension and dropping ransom
        # notes are the hallmarks of encryption, so either alone escalates.
        possible_ransomware = len(signals) >= 2 or bool({'ransom_note', 'extension_change'} & set(signals))
        classification = 'Possible ransomware-like behaviour' if possible_ransomware \
            else 'Suspicious bulk file modification'
        evidence.append(NO_PROCESS_EVIDENCE)
        evidence.append('Backups, sync clients, archivers and builds can cause similar activity.')
        return {
            'threat_name': classification,
            'classification': classification,
            'detection_method': 'file_behaviour',
            'category': 'Ransomware-like behaviour',
            'severity': 'critical' if possible_ransomware else 'high',
            'confidence': 0.7 if possible_ransomware else 0.5,
            'impact': 'data_loss',
            'description': 'Unusual burst of file activity in monitored folders: ' + '; '.join(evidence[:3]),
            'source': 'file_monitor',
            'timestamp': datetime.now().isoformat(),
            'evidence': evidence,
            'event_data': {
                'reason': ', '.join(signals),
                'event_type': 'file_activity',
                'sample_paths': sorted(directories)[:5],
                'file_operations': len(modifications) + len(renames),
            },
        }


NO_PROCESS_EVIDENCE = 'The operating system does not report which process made these changes.'


def _within(path: str, folders: List[str]) -> bool:
    path = os.path.normcase(os.path.abspath(path))
    return any(path == folder or path.startswith(folder + os.sep) for folder in folders)


def io_snapshot() -> Dict[int, Tuple[str, int]]:
    """Cumulative write + other (create/rename/delete) operation counts per process."""
    try:
        import psutil
    except ImportError:
        return {}
    counts = {}
    for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
        io = proc.info.get('io_counters')
        if io:
            counts[proc.info['pid']] = (proc.info['name'] or '', io.write_count + io.other_count)
    return counts


def busy_processes(baseline: Dict[int, Tuple[str, int]], min_operations: int, limit: int = 20) -> List[int]:
    """PIDs that performed at least min_operations file operations since baseline."""
    deltas = []
    for pid, (_, count) in io_snapshot().items():
        before = baseline.get(pid, ('', 0))[1]  # a process started since then counts in full
        if count - before >= min_operations:
            deltas.append((count - before, pid))
    return [pid for _, pid in sorted(deltas, reverse=True)[:limit]]


def find_processes_in_folders(folders: List[str], exclude_pids=(), pids=None) -> List[Tuple[int, str]]:
    """Processes with an open file or working directory inside any folder.

    Listing open files costs ~0.3 s per process on Windows, so callers pass a
    shortlist in ``pids``; without one every process is checked (slow).
    """
    try:
        import psutil
    except ImportError:
        return []
    from concurrent.futures import ThreadPoolExecutor
    folders = [os.path.normcase(os.path.abspath(f)) for f in folders if f]
    if not folders:
        return []
    if pids is None:
        pids = psutil.pids()
    pids = [pid for pid in pids if pid > 4 and pid not in exclude_pids]

    def check(pid):
        try:
            proc = psutil.Process(pid)
            paths = [f.path for f in proc.open_files()]
            paths.append(proc.cwd())
            if any(_within(path, folders) for path in paths):
                return pid, proc.name()
        except (psutil.Error, OSError):
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(pids)))) as pool:
        return [hit for hit in pool.map(check, pids) if hit]


def attribute_process(alert: Dict[str, Any], baseline: Optional[Dict[int, Tuple[str, int]]] = None) -> None:
    """Attach the suspected process to an alert when exactly one is found.

    With a ``baseline`` io_snapshot, only processes busy enough since then to
    have caused the burst are checked, which keeps this to a few seconds.
    """
    event = alert.setdefault('event_data', {})
    if isinstance(event.get('pid'), int):
        return
    pids = None
    if baseline is not None:
        min_operations = max(10, int(event.get('file_operations', 0)) // 2)
        pids = busy_processes(baseline, min_operations)
    candidates = find_processes_in_folders(event.get('sample_paths') or [], {os.getpid()}, pids)
    evidence = alert.setdefault('evidence', [])
    if len(candidates) == 1:
        pid, name = candidates[0]
        event['pid'], event['process_name'] = pid, name
        note = (f'Suspected process: {name} (PID {pid}) was active and had files open in the affected '
                'folder. Verify before approving any response.')
    elif candidates:
        names = ', '.join(f'{name} ({pid})' for pid, name in candidates[:5])
        note = f'Several processes had files open in the affected folder: {names}. No single process was attributed.'
    else:
        return
    alert['evidence'] = [note if line == NO_PROCESS_EVIDENCE else line for line in evidence]
    if note not in alert['evidence']:
        alert['evidence'].append(note)


class RansomwareMonitor:
    """Runs the detector on live watchdog events and queues alerts."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.enabled = bool(config.get('enabled', True))
        self.watch_paths = [os.path.expandvars(os.path.expanduser(p)) for p in config.get(
            'watch_paths', ['~/Documents', '~/Desktop', '~/Pictures',
                            '%OneDrive%/Documents', '%OneDrive%/Desktop', '%OneDrive%/Pictures'])]
        self.detector = RansomwareBehaviourDetector(config)
        self._alerts: List[Dict[str, Any]] = []
        self._alerts_lock = threading.Lock()
        self._observer = None
        self.watching: List[str] = []
        self.error = ''
        # Rolling io_snapshot()s, so an alert can be compared with activity
        # from before the burst started (see attribute_process).
        self._baselines: Deque[Dict[int, Tuple[str, int]]] = deque(maxlen=3)
        self._sampler: Optional[threading.Thread] = None
        self._stop_sampling = threading.Event()

    def _sample_io(self, interval: float = 10.0) -> None:
        while not self._stop_sampling.is_set():
            try:
                self._baselines.append(io_snapshot())
            except Exception as error:  # never let sampling kill the monitor
                logger.debug('I/O snapshot failed: %s', error)
            self._stop_sampling.wait(interval)

    def start(self) -> None:
        if not self.enabled or self._observer:
            return
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            self.error = 'watchdog is not installed'
            return

        monitor = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory or event.event_type not in ('created', 'modified', 'moved'):
                    return
                alert = monitor.detector.record(event.event_type, event.src_path,
                                                getattr(event, 'dest_path', '') or '')
                if alert:
                    logger.warning('File-behaviour alert: %s', alert['classification'])
                    with monitor._alerts_lock:
                        monitor._alerts.append(alert)

        observer = Observer()
        for path in dict.fromkeys(os.path.normcase(os.path.abspath(p)) for p in self.watch_paths):
            if os.path.isdir(path):
                try:
                    observer.schedule(Handler(), path, recursive=True)
                    self.watching.append(path)
                except OSError as error:
                    logger.warning('Cannot watch %s: %s', path, error)
        if not self.watching:
            self.error = 'None of the configured folders exist'
            return
        observer.daemon = True
        observer.start()
        self._observer = observer
        self._stop_sampling.clear()
        self._sampler = threading.Thread(target=self._sample_io, name='securex-io-sampler', daemon=True)
        self._sampler.start()
        logger.info('Ransomware-behaviour monitor watching %d folder(s)', len(self.watching))

    def stop(self) -> None:
        self._stop_sampling.set()
        if self._observer:
            self._observer.stop()
            self._observer = None

    def drain_alerts(self) -> List[Dict[str, Any]]:
        with self._alerts_lock:
            alerts, self._alerts = self._alerts, []
        if alerts and self._baselines:
            baseline = self._baselines[0]
            for alert in alerts:
                try:
                    attribute_process(alert, baseline)
                except Exception as error:
                    logger.warning('Process attribution failed: %s', error)
        return alerts

    def status(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'running': self._observer is not None,
            'watching': self.watching,
            'thresholds': self.detector.thresholds,
            'error': self.error,
        }
