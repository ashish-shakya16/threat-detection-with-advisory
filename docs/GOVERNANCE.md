# Risk Context, Graduated Response and Audit Log

## Risk context

After the rule-based score is calculated, `perform_scan()` in
`src/dashboard/app.py` adjusts it with `AssetContextResolver`
(`src/risk_assessment/asset_context.py`) and `RiskScorer.adjust_risk_by_context`:

| Factor | Source | Multiplier |
|---|---|---|
| Asset criticality | `risk_assessment.asset_context.device_criticality` in `config.yaml` | low 0.85, medium 1.0, high 1.15, critical 1.3 |
| Network exposure | event's remote IP / listening address | local 1.0, internal (private, link-local, reserved) 1.05, internet (globally routable, or listening on all interfaces) 1.2 |
| Privileged account | event username matches `privileged_accounts` | 1.15 |
| Off-hours | 22:00-06:00 local time | 1.1 |
| ML anomaly score | Isolation Forest, once trained via `POST /api/ml/train` | blended 70% rule / 30% ML, never lowers the score |

The score is capped at 1.0 and re-classified (Low < 0.3 ≤ Medium < 0.6 ≤ High <
0.85 ≤ Critical). The factors and reasons are stored in `threats.risk_context` and
shown in the threat dialog. These multipliers are a transparent heuristic for this
prototype, not a calibrated model.

## Graduated response

`src/response/response_manager.py`

| Level | Trigger | What happens |
|---|---|---|
| 0 Observe | Low | Threat recorded |
| 1 Alert | Medium+ | Recorded; emailed if enabled for that severity |
| 2 Contain | High+ with a live process | *Proposal* to suspend the process (reversible) |
| 3 Terminate | Critical with a live process | Additional *proposal* to terminate the process |

Safeguards (the response loop is itself an attack surface):

- **Human approval:** proposals never run automatically. A logged-in user approves
  or rejects each one in the threat dialog or the Response Center.
- **Kill switch:** `response.execution_enabled` is `false` by default. Approvals are
  then recorded as `dry_run` and nothing is done to the process.
- **Target re-verification:** at approval, the PID must still have the same process
  name and creation time, which defeats PID reuse.
- **Protected processes:** core Windows processes, PIDs ≤ 4 and SecureX's own
  process and parent are never proposed or acted on.
- **Expiry:** proposals expire after `proposal_ttl_minutes` (30 minutes by default).
- **Rate limit:** at most `max_executions_per_minute` executions (5 by default).
- **Rollback:** an executed suspension can be resumed.
- **Accountability:** every proposal, approval, rejection, execution, failure and
  resume is written to the audit log with the user and source IP.

Out of scope: file quarantine, firewall blocking and network isolation are not
implemented.

API (login required): `GET /api/responses?threat_id=&status=`,
`POST /api/responses/<id>/approve`, `POST /api/responses/<id>/reject`,
`POST /api/responses/<id>/resume`.

To enable real execution, set `response.execution_enabled: true` and run SecureX
with enough privileges to suspend the target processes. Test it first on a
non-production machine.

## Audit log

`src/audit/audit_log.py` and the `audit_log` table.

Recorded actions: `auth.login` (success and failure), `auth.logout`, `scan.run`,
`monitoring.start`/`stop`, `threat.status_change`, `response.*`,
`notifications.preferences_update`, `notifications.recipient_*`,
`notifications.test_email`, `assistant.explain`, `audit.verify`.

Each entry stores the time (UTC), actor, action, target, outcome, details (with
secret-looking keys redacted) and source IP. Entries are **hash-chained**: each
entry's SHA-256 covers its content and the previous entry's hash.
`GET /api/audit/verify` (or **Verify integrity** on the Audit Log page) recomputes
the chain and reports the first edited or missing entry.

Limitation: the chain makes tampering *evident*. It does not stop someone who can
write the database file from rebuilding the whole chain. For stronger guarantees,
export entries regularly to write-once storage or sign the chain head.

API (login required): `GET /api/audit?limit=&offset=&action=&actor=`,
`GET /api/audit/verify`.
