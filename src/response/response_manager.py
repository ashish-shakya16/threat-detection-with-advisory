"""Graduated, human-approved threat response.

Response levels:
    0 OBSERVE   - record only (Low risk)
    1 ALERT     - record and notify (Medium and above; see NotificationManager)
    2 CONTAIN   - propose suspending the process (High and above). Reversible.
    3 TERMINATE - propose ending the process (Critical only).

Levels 2 and 3 are only ever *proposed* by policy. Nothing is executed until
an authenticated user approves a proposal, and even then only when
response.execution_enabled is true; otherwise the approval is recorded as a
dry run. Because an automated response loop is itself an attack surface,
approval re-checks that the target is still the same process (PID plus
creation time, to defeat PID reuse), refuses protected system processes and
SecureX itself, expires stale proposals, and rate-limits executions. Every
step is written to the audit log.
"""

import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger('securex')

OBSERVE, ALERT, CONTAIN, TERMINATE = 0, 1, 2, 3
RISK_ORDER = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
ACTION_LEVELS = {'suspend_process': CONTAIN, 'resume_process': CONTAIN, 'terminate_process': TERMINATE}

DEFAULT_PROTECTED = [
    'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe',
    'fontdrvhost.exe', 'memcompression', 'msmpeng.exe',
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fmt(moment: datetime) -> str:
    return moment.strftime('%Y-%m-%d %H:%M:%S')


def response_level_for(risk_level: str) -> int:
    """Highest response level the policy allows for a risk level."""
    rank = RISK_ORDER.get(risk_level, 0)
    return {0: OBSERVE, 1: ALERT, 2: CONTAIN, 3: TERMINATE}[rank]


class ResponseError(Exception):
    """Raised when a proposal cannot be approved or executed."""


class ResponseManager:
    def __init__(self, db_path: str, audit=None, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.db_path = db_path
        self.audit = audit
        self.execution_enabled = bool(config.get('execution_enabled', False))
        self.proposal_ttl = timedelta(minutes=int(config.get('proposal_ttl_minutes', 30)))
        self.max_executions_per_minute = int(config.get('max_executions_per_minute', 5))
        self.protected = {name.lower() for name in config.get('protected_processes', DEFAULT_PROTECTED)}
        self._own_pids = {os.getpid(), os.getppid()}
        self._recent_executions: List[float] = []

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _audit(self, actor, action, proposal_id, outcome='success', details=None, source_ip=''):
        if self.audit:
            self.audit.record(actor, action, 'response_action', proposal_id, outcome, details, source_ip)

    # ------------------------------------------------------------------
    # Proposals
    # ------------------------------------------------------------------

    def _is_protected(self, pid: int, name: str) -> bool:
        return pid <= 4 or pid in self._own_pids or (name or '').lower() in self.protected

    def propose_for_threat(self, threat_id: int, threat: Dict[str, Any]) -> List[int]:
        """Create containment proposals allowed by policy for this threat."""
        level = response_level_for(threat.get('risk_level', 'Low'))
        event = threat.get('event_data') or {}
        pid = event.get('pid')
        if level < CONTAIN or not isinstance(pid, int):
            return []
        try:
            process = psutil.Process(pid)
            name, create_time = process.name(), process.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
        if self._is_protected(pid, name):
            logger.info('Not proposing response for protected process %s (%s)', name, pid)
            return []

        actions = ['suspend_process'] + (['terminate_process'] if level >= TERMINATE else [])
        created = []
        now = _utc_now()
        conn = self._connect()
        try:
            for action in actions:
                duplicate = conn.execute(
                    "SELECT 1 FROM response_actions WHERE action = ? AND target_pid = ? "
                    "AND target_create_time = ? AND status = 'proposed' AND expires_at > ?",
                    (action, pid, create_time, _fmt(now)),
                ).fetchone()
                if duplicate:
                    continue
                cursor = conn.execute(
                    'INSERT INTO response_actions (threat_id, action, response_level, target_pid, target_name, '
                    'target_create_time, risk_level, reason, status, proposed_at, expires_at) '
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
                    (threat_id, action, ACTION_LEVELS[action], pid, name, create_time,
                     threat.get('risk_level'), f"{threat.get('threat_name', 'Threat')} ({threat.get('risk_level')})",
                     _fmt(now), _fmt(now + self.proposal_ttl)),
                )
                created.append(cursor.lastrowid)
            conn.commit()
        finally:
            conn.close()
        for proposal_id in created:
            self._audit('system', 'response.proposed', proposal_id,
                        details={'threat_id': threat_id, 'pid': pid, 'process': name})
        return created

    def get(self, proposal_id: int) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute('SELECT * FROM response_actions WHERE id = ?', (proposal_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list(self, threat_id: Optional[int] = None, status: str = '', limit: int = 50) -> List[Dict[str, Any]]:
        self.expire_stale()
        clauses, params = [], []
        if threat_id is not None:
            clauses.append('threat_id = ?')
            params.append(threat_id)
        if status:
            clauses.append('status = ?')
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
        conn = self._connect()
        try:
            rows = conn.execute(
                f'SELECT * FROM response_actions {where} ORDER BY id DESC LIMIT ?', (*params, limit)
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def expire_stale(self) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE response_actions SET status = 'expired' WHERE status = 'proposed' AND expires_at <= ?",
                (_fmt(_utc_now()),),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def _update(self, proposal_id: int, **fields) -> None:
        assignments = ', '.join(f'{key} = ?' for key in fields)
        conn = self._connect()
        try:
            conn.execute(f'UPDATE response_actions SET {assignments} WHERE id = ?', (*fields.values(), proposal_id))
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------

    def reject(self, proposal_id: int, actor: str, source_ip: str = '') -> Dict[str, Any]:
        proposal = self._require_open(proposal_id)
        self._update(proposal_id, status='rejected', decided_by=actor, decided_at=_fmt(_utc_now()))
        self._audit(actor, 'response.rejected', proposal_id, details={'action': proposal['action']},
                    source_ip=source_ip)
        return self.get(proposal_id)

    def approve(self, proposal_id: int, actor: str, source_ip: str = '') -> Dict[str, Any]:
        """Approve a proposal and execute it if execution is enabled."""
        proposal = self._require_open(proposal_id)
        decided_at = _fmt(_utc_now())
        try:
            process = self._verify_target(proposal)
        except ResponseError as error:
            self._update(proposal_id, status='failed', decided_by=actor, decided_at=decided_at,
                         result_message=str(error))
            self._audit(actor, 'response.approved', proposal_id, 'failed', {'error': str(error)}, source_ip)
            raise

        if not self.execution_enabled:
            message = 'Approved as dry run: response.execution_enabled is false, so no action was taken.'
            self._update(proposal_id, status='dry_run', decided_by=actor, decided_at=decided_at,
                         result_message=message)
            self._audit(actor, 'response.approved', proposal_id, 'dry_run',
                        {'action': proposal['action'], 'pid': proposal['target_pid']}, source_ip)
            return self.get(proposal_id)

        self._check_rate_limit()
        try:
            message = self._execute(proposal['action'], process)
        except (psutil.Error, OSError) as error:
            self._update(proposal_id, status='failed', decided_by=actor, decided_at=decided_at,
                         result_message=f'Execution failed: {error}')
            self._audit(actor, 'response.executed', proposal_id, 'failed', {'error': str(error)}, source_ip)
            raise ResponseError(f'Execution failed: {error}')
        self._update(proposal_id, status='executed', decided_by=actor, decided_at=decided_at,
                     executed_at=_fmt(_utc_now()), result_message=message)
        self._audit(actor, 'response.executed', proposal_id, 'success',
                    {'action': proposal['action'], 'pid': proposal['target_pid'],
                     'process': proposal['target_name']}, source_ip)
        return self.get(proposal_id)

    def resume(self, proposal_id: int, actor: str, source_ip: str = '') -> Dict[str, Any]:
        """Roll back an executed suspension."""
        proposal = self.get(proposal_id)
        if not proposal or proposal['action'] != 'suspend_process' or proposal['status'] != 'executed':
            raise ResponseError('Only an executed suspension can be resumed')
        process = self._verify_target(proposal)
        try:
            process.resume()
        except psutil.Error as error:
            self._audit(actor, 'response.resumed', proposal_id, 'failed', {'error': str(error)}, source_ip)
            raise ResponseError(f'Resume failed: {error}')
        self._update(proposal_id, status='resumed', result_message='Process resumed by user')
        self._audit(actor, 'response.resumed', proposal_id, details={'pid': proposal['target_pid']},
                    source_ip=source_ip)
        return self.get(proposal_id)

    def _require_open(self, proposal_id: int) -> Dict[str, Any]:
        self.expire_stale()
        proposal = self.get(proposal_id)
        if not proposal:
            raise ResponseError('Response proposal not found')
        if proposal['status'] != 'proposed':
            raise ResponseError(f"Proposal is already {proposal['status']}")
        return proposal

    def _verify_target(self, proposal: Dict[str, Any]) -> psutil.Process:
        """Make sure the PID still refers to the process that was flagged."""
        pid = proposal['target_pid']
        try:
            process = psutil.Process(pid)
            name, create_time = process.name(), process.create_time()
        except psutil.NoSuchProcess:
            raise ResponseError('The process is no longer running')
        except psutil.AccessDenied:
            raise ResponseError('Access denied while checking the process')
        if abs(create_time - (proposal['target_create_time'] or 0)) > 0.01 or name != proposal['target_name']:
            raise ResponseError('The PID now belongs to a different process; refusing to act')
        if self._is_protected(pid, name):
            raise ResponseError(f'{name} is a protected process; refusing to act')
        return process

    def _check_rate_limit(self) -> None:
        now = time.monotonic()
        self._recent_executions = [t for t in self._recent_executions if now - t < 60]
        if len(self._recent_executions) >= self.max_executions_per_minute:
            raise ResponseError('Too many response actions in the last minute; try again shortly')
        self._recent_executions.append(now)

    @staticmethod
    def _execute(action: str, process: psutil.Process) -> str:
        if action == 'suspend_process':
            process.suspend()
            return 'Process suspended. It can be resumed from SecureX.'
        if action == 'terminate_process':
            process.terminate()
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                return 'Terminate signal sent; the process has not exited yet.'
            return 'Process terminated.'
        raise ResponseError(f'Unknown action {action}')
