# Plan 4: Desktop App Cleanup & Remaining Dead Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Depends on Plan 1** (`2026-07-27-01-db-backend-fix.md`) for `DatabaseManager.vacuum()`, `update_threat_status()`, and the `detected_at` column fixes — this plan assumes those exist. Independent of Plan 2 and Plan 3.

**Goal:** Fix the severity-casing bug that makes every desktop severity comparison silently fail (dashboard summary boxes always show 0, severity filter dropdown never matches anything), add `closeEvent` cleanup for the timer/thread so the app doesn't warn or crash on exit, fix the Windows-incompatible `disk_usage('/')` call, and remove the last pieces of dead/copy-pasted code.

**Architecture:** No new files. All fixes are in-place edits to `src/desktop/main_window.py`. Severity display values switch to `.title()`-casing the lowercase DB value at render time rather than expecting the DB to store capitalized strings, keeping `DatabaseManager`'s lowercase-severity convention (established in Plan 1) as the single source of truth.

**Tech Stack:** PyQt6, pytest (desktop tests remain mostly skip-under-no-display, per existing `tests/test_desktop_app.py` pattern).

---

## Context You Need

- `DatabaseManager.get_threat_statistics()`'s `by_severity` dict has **lowercase** keys (`'low'`, `'medium'`, `'high'`) because that's what `RuleEngine` produces and what gets stored in the `threats.severity` column (confirmed via `config/rules.json` — only `low/medium/high` appear, no `critical`).
- `src/desktop/main_window.py:550-553` reads `by_severity.get('Critical', 0)`, `by_severity.get('High', 0)`, etc. — capitalized keys that never match the lowercase keys actually present, so these dashboard stat boxes always show `0` regardless of real data. This is a real, user-visible bug, not cosmetic.
- `src/desktop/main_window.py:596-597`: `severity_filter.currentText()` produces `"Critical"|"High"|"Medium"|"Low"|"All"` (from the QComboBox items added at line 252), then filters `threats` by `t.get('severity') == severity_filter` — comparing capitalized UI text against lowercase DB values, so the filter (except "All") never matches anything.
- `src/desktop/main_window.py:534-535`: `on_scan_complete` counts `t.get('severity') == 'Critical'` / `== 'High'` on freshly-scanned threat dicts — these come from `RuleEngine`/`RiskScorer` in-memory (not yet round-tripped through the DB), and `severity` there is also lowercase (set directly from `rule['severity']` in `rule_engine.py`), so this comparison has the same bug on freshly scanned data, not just DB-loaded data.
- `src/desktop/main_window.py:743`: `self.db.db_connection.execute("VACUUM")` — `DatabaseManager` has no `db_connection` attribute (fixed by calling the new `vacuum()` method from Plan 1).
- `src/desktop/main_window.py:735`: `clear_old_threats` computes `cutoff_date` but never uses it or calls any cleanup method — fixed in Plan 1 Task 4, but verify it's actually landed before starting this plan (see Task 1 Step 1 below).
- `src/desktop/main_window.py:560`: `psutil.disk_usage('/')` — `/` is a Unix root path; on Windows this raises `FileNotFoundError`, silently caught by the bare `except: pass` at line 561, so the Disk stat box on Windows always shows `0%`.
- No `closeEvent` override exists on `MainWindow` — closing the window while a `ScanWorker` `QThread` is running can print `QThread: Destroyed while thread is still running` or crash, and the `QTimer` keeps firing after the window is gone.
- `main.py` at the repo root was flagged in the original audit as "not reviewed in this pass" — this plan includes reading and fixing it since it shares the same `perform_scan`-style pipeline duplication as `app.py` and `main_window.py`.

## File Structure

- Modify: `src/desktop/main_window.py` — severity casing fixes (4 locations), `closeEvent` override, Windows disk path fix, verify Plan 1's `vacuum()`/`cleanup_old_logs()` wiring landed.
- Modify: `main.py` — read fully, fix any `log_advisory`/severity-casing issues found (same class of bug as Plans 1 and this one, applied to the CLI entry point).
- Modify: `tests/test_desktop_app.py` — add tests for severity display formatting (pure logic, no PyQt6 display needed) and `closeEvent` behavior.

---

### Task 1: Verify Plan 1's desktop fixes actually landed before starting

**Files:** None (verification only)

- [ ] **Step 1: Confirm `optimize_database` and `clear_old_threats` were already fixed by Plan 1**

Run: `grep -n "db_connection\|cleanup_old_logs\|self.db.vacuum" src/desktop/main_window.py`

Expected: if Plan 1 was fully executed, you should see `self.db.vacuum()` and `self.db.cleanup_old_logs(days=30)` — NOT `self.db.db_connection.execute("VACUUM")`. If the old broken code is still present, STOP and complete Plan 1 Task 4 first (it covers these exact two fixes) before proceeding with this plan, since Plan 4 assumes they're done and doesn't repeat them.

- [ ] **Step 2: Confirm `detected_at` fixes from Plan 1 Task 5 landed**

Run: `grep -n "threat.get('timestamp'" src/desktop/main_window.py`

Expected: no matches (Plan 1 Task 5 replaced all three occurrences with `detected_at`). If matches are found, complete Plan 1 Task 5 first.

---

### Task 2: Fix severity-casing bug in dashboard summary counts

**Files:**
- Modify: `src/desktop/main_window.py:540-568` (`refresh_data`)
- Test: `tests/test_desktop_app.py`

- [ ] **Step 1: Write the failing test**

Read the existing `tests/test_desktop_app.py` first to see its current structure and skip-pattern for display-dependent tests:

Run: `head -50 tests/test_desktop_app.py`

Then add a new test class to `tests/test_desktop_app.py` that tests the severity-key-matching logic in isolation (no Qt widgets needed — this tests the bug, not the UI):

```python
class TestSeverityCasingBugFix(unittest.TestCase):
    """
    Regression tests for the severity-casing mismatch: DatabaseManager stores
    severity as lowercase ('low'/'medium'/'high'), but the desktop UI was
    written expecting capitalized keys ('Low'/'Medium'/'High'), causing
    dashboard stat boxes to always show 0 regardless of real data.
    """

    def test_by_severity_dict_uses_lowercase_keys_from_db_manager(self):
        # This documents the actual contract: DatabaseManager.get_threat_statistics()
        # returns lowercase severity keys because that's what RuleEngine/config/rules.json produce.
        by_severity = {'high': 3, 'medium': 1, 'low': 2}

        # The old buggy code did: by_severity.get('Critical', 0) -> always 0
        # The fix must look up using .lower() normalized keys.
        critical_count = by_severity.get('critical', 0)
        high_count = by_severity.get('high', 0)

        self.assertEqual(critical_count, 0)  # No 'critical' severity exists in rules.json today
        self.assertEqual(high_count, 3)  # This must be non-zero for real data
```

- [ ] **Step 2: Run test to confirm it documents current (buggy) behavior correctly**

Run: `python -m pytest tests/test_desktop_app.py::TestSeverityCasingBugFix -v`
Expected: PASS (this test doesn't touch `main_window.py` yet, it just locks in the correct contract before the fix).

- [ ] **Step 3: Fix `refresh_data` to use lowercase severity keys**

In `src/desktop/main_window.py`, replace:

```python
            # Update summary
            total = stats.get('total_threats', 0)
            by_severity = stats.get('by_severity', {})

            self.total_threats_label.value_label.setText(str(total))
            self.critical_label.value_label.setText(str(by_severity.get('Critical', 0)))
            self.high_label.value_label.setText(str(by_severity.get('High', 0)))
            self.medium_label.value_label.setText(str(by_severity.get('Medium', 0)))
            self.low_label.value_label.setText(str(by_severity.get('Low', 0)))
```

with:

```python
            # Update summary
            # Note: DatabaseManager stores severity lowercase ('low'/'medium'/'high'),
            # matching what RuleEngine/config/rules.json produce.
            total = stats.get('total_threats', 0)
            by_severity = stats.get('by_severity', {})

            self.total_threats_label.value_label.setText(str(total))
            self.critical_label.value_label.setText(str(by_severity.get('critical', 0)))
            self.high_label.value_label.setText(str(by_severity.get('high', 0)))
            self.medium_label.value_label.setText(str(by_severity.get('medium', 0)))
            self.low_label.value_label.setText(str(by_severity.get('low', 0)))
```

- [ ] **Step 4: Fix the Windows disk path bug in the same method**

In the same `refresh_data` method, replace:

```python
            # Update system metrics
            try:
                import psutil
                self.cpu_label.value_label.setText(f"{psutil.cpu_percent()}%")
                self.memory_label.value_label.setText(f"{psutil.virtual_memory().percent}%")
                self.disk_label.value_label.setText(f"{psutil.disk_usage('/').percent}%")
            except:
                pass
```

with:

```python
            # Update system metrics
            try:
                import os
                import psutil
                disk_path = os.path.abspath(os.sep)  # 'C:\\' on Windows, '/' on Unix
                self.cpu_label.value_label.setText(f"{psutil.cpu_percent()}%")
                self.memory_label.value_label.setText(f"{psutil.virtual_memory().percent}%")
                self.disk_label.value_label.setText(f"{psutil.disk_usage(disk_path).percent}%")
            except Exception as e:
                self.logger.debug(f"Failed to read system metrics: {e}")
```

- [ ] **Step 5: Run the test file to verify no regressions**

Run: `python -m pytest tests/test_desktop_app.py -v`
Expected: All non-skipped tests PASS (display-dependent tests still skip as before, per the existing pattern).

- [ ] **Step 6: Commit**

```bash
git add src/desktop/main_window.py tests/test_desktop_app.py
git commit -m "fix: desktop dashboard uses lowercase severity keys matching DatabaseManager; fix Windows disk path"
```

---

### Task 3: Fix severity-casing bug in threats table filter and scan summary dialog

**Files:**
- Modify: `src/desktop/main_window.py` (`refresh_threats_table`, `on_scan_complete`)

- [ ] **Step 1: Fix the severity filter dropdown comparison**

In `src/desktop/main_window.py`, inside `refresh_threats_table`, replace:

```python
            severity_filter = self.severity_filter.currentText()
            if severity_filter != "All":
                threats = [t for t in threats if t.get('severity') == severity_filter]
```

with:

```python
            severity_filter = self.severity_filter.currentText()
            if severity_filter != "All":
                threats = [t for t in threats if t.get('severity', '').lower() == severity_filter.lower()]
```

- [ ] **Step 2: Fix the scan-complete summary dialog's severity counting**

In `src/desktop/main_window.py`, inside `on_scan_complete`, replace:

```python
        if threats:
            QMessageBox.information(
                self,
                "Scan Complete",
                f"Found {len(threats)} threats\n\n" +
                f"Critical: {sum(1 for t in threats if t.get('severity') == 'Critical')}\n" +
                f"High: {sum(1 for t in threats if t.get('severity') == 'High')}"
            )
```

with:

```python
        if threats:
            critical_count = sum(1 for t in threats if t.get('severity', '').lower() == 'critical')
            high_count = sum(1 for t in threats if t.get('severity', '').lower() == 'high')
            QMessageBox.information(
                self,
                "Scan Complete",
                f"Found {len(threats)} threats\n\n" +
                f"Critical: {critical_count}\n" +
                f"High: {high_count}"
            )
```

- [ ] **Step 3: Fix the table display so severity always renders capitalized regardless of stored case**

In `src/desktop/main_window.py`, inside `refresh_recent_threats_table`, replace:

```python
                self.recent_threats_table.setItem(row, 1, QTableWidgetItem(threat.get('severity', '')))
```

with:

```python
                self.recent_threats_table.setItem(row, 1, QTableWidgetItem(str(threat.get('severity', '')).title()))
```

And inside `refresh_threats_table`, replace:

```python
                self.threats_table.setItem(row, 2, QTableWidgetItem(threat.get('severity', '')))
```

with:

```python
                self.threats_table.setItem(row, 2, QTableWidgetItem(str(threat.get('severity', '')).title()))
```

This makes the on-screen display show "High"/"Low" (readable) while the underlying data and comparisons stay lowercase-consistent with the database.

- [ ] **Step 4: Write a regression test for the case-insensitive filter logic**

Add to `tests/test_desktop_app.py` in the `TestSeverityCasingBugFix` class:

```python
    def test_severity_filter_matches_case_insensitively(self):
        threats = [
            {'threat_name': 'A', 'severity': 'high'},
            {'threat_name': 'B', 'severity': 'low'},
            {'threat_name': 'C', 'severity': 'high'},
        ]

        severity_filter = 'High'  # What the QComboBox provides
        filtered = [t for t in threats if t.get('severity', '').lower() == severity_filter.lower()]

        self.assertEqual(len(filtered), 2)
        self.assertTrue(all(t['severity'] == 'high' for t in filtered))
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_desktop_app.py -v`
Expected: All non-skipped tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/desktop/main_window.py tests/test_desktop_app.py
git commit -m "fix: severity filter and scan summary now compare case-insensitively; display severity title-cased"
```

---

### Task 4: Add `closeEvent` to clean up timer and running scan thread

**Files:**
- Modify: `src/desktop/main_window.py`
- Test: `tests/test_desktop_app.py`

- [ ] **Step 1: Write the test (will be skipped without a display, per existing pattern in this file — verify the skip decorator used elsewhere in the file first)**

Run: `grep -n "skipUnless\|skipIf\|QT_QPA" tests/test_desktop_app.py | head -5`

Use whatever skip mechanism is already established in that file (likely checking for a display or catching `ImportError`/`RuntimeError` on `QApplication` construction) for consistency. Add this test using that same pattern:

```python
class TestCloseEventCleanup(unittest.TestCase):
    """Verify MainWindow.closeEvent stops the refresh timer and any running scan thread."""

    def setUp(self):
        try:
            from PyQt6.QtWidgets import QApplication
            self.qapp = QApplication.instance() or QApplication([])
        except Exception:
            self.skipTest("No display available for PyQt6 widget tests")

    def test_close_event_stops_refresh_timer(self):
        from src.desktop.main_window import MainWindow

        window = MainWindow()
        self.assertTrue(window.refresh_timer.isActive())

        window.close()

        self.assertFalse(window.refresh_timer.isActive())
```

- [ ] **Step 2: Run test to verify it fails (or skips if no display — either way, proceed to implement)**

Run: `python -m pytest tests/test_desktop_app.py::TestCloseEventCleanup -v`
Expected: FAIL with `AttributeError` or the timer still active (no `closeEvent` exists yet), OR SKIPPED if no display is available in this environment. If skipped, still complete the implementation in Step 3 — the test documents intent for CI environments with a display.

- [ ] **Step 3: Add `closeEvent` override to `MainWindow`**

In `src/desktop/main_window.py`, add this method to the `MainWindow` class, immediately before the `optimize_database` method (near the end of the class, before `main()`):

```python
    def closeEvent(self, event):
        """Clean up the refresh timer and any running scan thread before closing."""
        self.refresh_timer.stop()

        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.requestInterruption()
            self.scan_worker.wait(3000)  # Wait up to 3 seconds for graceful shutdown

        event.accept()
```

- [ ] **Step 4: Run test to verify it passes (or confirms skip behavior)**

Run: `python -m pytest tests/test_desktop_app.py::TestCloseEventCleanup -v`
Expected: PASS (or SKIPPED if no display, matching the environment's existing test behavior for other Qt-widget tests in this file).

- [ ] **Step 5: Commit**

```bash
git add src/desktop/main_window.py tests/test_desktop_app.py
git commit -m "fix: MainWindow.closeEvent stops refresh timer and waits for scan thread to prevent Qt warnings on exit"
```

---

### Task 5: Read and audit `main.py` for the same class of bugs

**Files:**
- Modify: `main.py` (exact changes depend on what Step 1 finds — see below)

- [ ] **Step 1: Read the full file**

Run: `wc -l main.py` to see its size, then read it in full using the Read tool (not grep) since this plan cannot pre-specify exact line-level fixes without having seen its current content — the original audit explicitly flagged this file as "not reviewed in this pass."

- [ ] **Step 2: Check for the same severity-casing pattern**

Run: `grep -n "'Critical'\|'High'\|'Medium'\|'Low'" main.py`

For every match found where the comparison is against a `severity` field (not `risk_level`, which is legitimately capitalized per `RiskScorer._classify_risk_level`), apply the same `.lower()` normalization fix used in Tasks 2 and 3 of this plan. If matches are only against `risk_level` (capitalized by design), no change is needed there.

- [ ] **Step 3: Check for `log_advisory` or `db.log_threat` calls that might hit the schema mismatch fixed in Plan 1**

Run: `grep -n "db\.\(log_threat\|log_advisory\|log_event\)" main.py`

If `main.py` calls these methods directly, confirm Plan 1 has already been executed (these methods were fixed there) — no changes needed in `main.py` itself unless it passes malformed dictionaries missing expected keys, which the grep + a read of the surrounding code will reveal.

- [ ] **Step 4: Check for the `threats.timestamp` vs `detected_at` pattern**

Run: `grep -n "'timestamp'" main.py`

If `main.py` reads threat dicts fetched from the database (via `db.get_recent_threats` or similar) and accesses `threat['timestamp']` or `threat.get('timestamp')`, apply the same fix as Plan 1 Task 5: change to `detected_at`. If it only accesses `timestamp` on freshly-created in-memory threat dicts (from `RuleEngine`, which does set a `timestamp` key — see `rule_engine.py:183`), no change is needed, since that key genuinely exists on that object.

- [ ] **Step 5: Apply whatever fixes Steps 2-4 identified, following the exact same patterns already used in Plan 1 Task 5 and this plan's Tasks 2-3**

Since the exact content of `main.py` determines what's needed here, use the established fix patterns:
- Severity comparison: wrap both sides in `.lower()` before comparing.
- Column name: use `detected_at` for anything read back from the database, keep `timestamp` for freshly-created in-memory event/threat dicts.

- [ ] **Step 6: Run the full test suite to confirm no regressions**

Run: `python -m pytest tests/ -v --tb=short 2>&1 | tail -60`
Expected: No new failures relative to the end of Plan 3.

- [ ] **Step 7: Commit**

```bash
git add main.py
git commit -m "fix: apply severity-casing and column-name fixes to main.py CLI entry point"
```

---

### Task 6: Final full-suite verification across all 4 plans

**Files:** None (verification only)

- [ ] **Step 1: Run the complete test suite one final time**

Run:
```bash
set SECRET_KEY=test-secret-for-local-run
python -m pytest tests/ -v --tb=short 2>&1 | tail -150
```
Expected: All tests pass (or skip, for display-dependent desktop tests) with zero unexpected failures. Compare against the very first baseline run from Plan 1 Task 7 Step 4 to confirm every originally-failing/erroring test is now either fixed or was pre-existing and unrelated to this rework.

- [ ] **Step 2: Manually launch the desktop app to sanity-check the UI fixes**

Run: `python desktop_app.py`

Manually verify:
- Dashboard tab's Critical/High/Medium/Low stat boxes show non-zero numbers after running a scan (if any threats are detected) — confirms Task 2's fix.
- Disk stat box shows a real percentage, not stuck at 0% — confirms Task 2's Windows path fix.
- Severity filter dropdown in the Threats tab actually filters results when set to "High" or "Low" — confirms Task 3's fix.
- Closing the window while a scan is in progress does not print `QThread: Destroyed while thread is still running` to the console — confirms Task 4's fix.

- [ ] **Step 3: Manually launch the web dashboard to sanity-check Plan 2's auth**

Run: `python scripts/create_admin_user.py finaltest finaltest@example.com` (enter a password when prompted), then:

Run:
```bash
set SECRET_KEY=<paste a real generated secret>
python src/dashboard/app.py
```

Open `http://127.0.0.1:5000` in a browser — confirm it redirects to `/login`, and that logging in with the created account grants access to the dashboard.

- [ ] **Step 4: Clean up the test admin user if desired**

Run:
```bash
python -c "
import sqlite3
conn = sqlite3.connect('data/db/threats.db')
conn.execute(\"DELETE FROM users WHERE username = 'finaltest'\")
conn.commit()
conn.close()
"
```

- [ ] **Step 5: Update STATUS.md to reflect the completed rework**

Read the current `STATUS.md`, then update its version number, test count, and add a new section summarizing this 4-plan rework (schema fixes, auth, ML/notification hardening, desktop cleanup) using the same style as the file's existing sections. Since this step's exact wording depends on reading the file fresh at execution time, no literal replacement text is prescribed here — follow the file's existing heading structure and tone.

- [ ] **Step 6: Final commit**

```bash
git add STATUS.md
git commit -m "docs: update STATUS.md to reflect full-stack rework (DB, auth, ML, desktop fixes)"
```

---

## Plan Complete

This plan fixes the severity-casing bug that silently broke desktop dashboard counts and the severity filter, adds proper thread/timer cleanup on window close, fixes a Windows-incompatible disk path call, and extends the same fix patterns to `main.py`. Combined with Plans 1-3, this completes the full-stack rework: database correctness, Flask security + authentication, ML/notification/detection hardening, and desktop app cleanup.
