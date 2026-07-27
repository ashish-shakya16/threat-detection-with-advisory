# Plan 3: ML, Notifications & Detection Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Depends on Plan 1** (`2026-07-27-01-db-backend-fix.md`) for `DatabaseManager.create_user`-style connection safety patterns and `requirements.txt`. Independent of Plan 2.

**Goal:** Fix the ML pipeline's fake/constant features, replace unsafe `pickle` model loading with `joblib` + integrity checking, add international phone support to SMS notifications, implement the missing `log_conversation` DB method so AI assistant conversations actually persist, and fix the silent bare-except failures found across the assistant/notification code.

**Architecture:** No new services. `FeatureExtractor` gains two real feature computations (suspicious port count, registry/file change proxy) instead of hardcoded constants. `AnomalyDetector` switches from `pickle` to `joblib` (already a `scikit-learn` transitive dependency, no new package needed) and adds a SHA-256 checksum file written alongside the model so tampering is detectable. `SMSService` swaps its hand-rolled US-only regex for the `phonenumbers` library (Google's libphonenumber port), the industry-standard choice for this exact problem.

**Tech Stack:** scikit-learn, joblib, phonenumbers (new dependency), pytest.

---

## Context You Need

- `src/ml_models/feature_extractor.py:21-32`: `extract_from_process` hardcodes `1.0` for `process_count` (line 26) and `0.0` for `suspicious_port_count` (line 28) and `0.0` for `registry_changes` (line 30) — these three of seven "features" carry zero real signal into the Isolation Forest model, degrading detection quality.
- `src/ml_models/anomaly_detector.py:46-59`: `save_model`/`load_model` use raw `pickle.dump`/`pickle.load` with no integrity check — if the `.pkl` file is ever replaced by an attacker with a crafted payload, `pickle.load` executes arbitrary code on load.
- `src/notifications/sms_service.py:62-66`: `validate_phone` regex only matches North American Numbering Plan formats; rejects all international numbers.
- `src/assistant/knowledge_base.py:49-55`: `store_conversation` calls `self.db_manager.log_conversation(...)`, a method that doesn't exist on `DatabaseManager`, wrapped in a bare `except Exception: pass` — every AI conversation silently fails to save, with no visible error anywhere.
- `schema.sql:96-104` already defines an `ai_conversations` table: `id, user_id, query, response, confidence, created_at` — reuse this exactly.
- `src/dashboard/app.py:404-413` (`monitoring_loop`) has `except: pass` around the psutil metrics emit — a bare except with no exception type, which also catches `KeyboardInterrupt`/`SystemExit`. This needs at minimum an exception type and a debug log line.
- `src/desktop/main_window.py` has a similar bare `except: pass` pattern around its own psutil-based dashboard refresh — covered in Plan 4 since it's desktop-specific, not touched here.
- `RiskScorer.adjust_risk_by_context` (`risk_scorer.py:233-277`) is fully implemented but never called from anywhere in the pipeline — this plan wires it into `perform_scan()` in `app.py` using "off-hours" as the only currently-computable context signal (no user/session tracking exists yet for "repeat offender" or "privileged user" — those stay unwired since implementing them would require features this project doesn't have yet, and inventing fake context data would be worse than not calling the function).

## File Structure

- Modify: `src/ml_models/feature_extractor.py` — real `suspicious_port_count` and `registry_changes` (renamed conceptually to "file operation count" since no registry-monitoring exists — using `num_files` from the same list-monitor data source already available) computation.
- Modify: `src/ml_models/anomaly_detector.py` — switch to `joblib`, add SHA-256 checksum verification.
- Modify: `src/notifications/sms_service.py` — use `phonenumbers` for validation.
- Modify: `src/database/db_manager.py` — add `log_conversation` and `get_conversations_for_user` methods.
- Modify: `src/assistant/knowledge_base.py` — remove bare except, log failures instead of swallowing.
- Modify: `src/dashboard/app.py` — fix bare except in `monitoring_loop`, wire up `adjust_risk_by_context` for off-hours detection.
- Modify: `requirements.txt` — add `phonenumbers`, `joblib`.
- Create: `tests/test_feature_extractor.py`
- Create: `tests/test_anomaly_detector.py`
- Modify: `tests/test_notification_manager.py` (extend with international phone tests, if this file already tests `SMSService`; otherwise add to a new `tests/test_sms_service.py`)

---

### Task 1: Fix `FeatureExtractor`'s constant/fake features

**Files:**
- Modify: `src/ml_models/feature_extractor.py`
- Create: `tests/test_feature_extractor.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_feature_extractor.py`:

```python
"""Unit tests for FeatureExtractor."""

import unittest
import numpy as np

from src.ml_models.feature_extractor import FeatureExtractor


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()

    def test_feature_names_length_matches_extracted_vector_length(self):
        process_info = {
            'cpu_percent': 50.0,
            'memory_percent': 30.0,
            'num_connections': 5,
            'num_files': 2,
        }

        features = self.extractor.extract_from_process(process_info)

        self.assertEqual(len(features), len(self.extractor.get_feature_names()))

    def test_suspicious_port_count_reflects_actual_suspicious_ports(self):
        process_info = {
            'cpu_percent': 10.0,
            'memory_percent': 10.0,
            'num_connections': 3,
            'num_files': 0,
            'remote_ports': [4444, 80, 5555],  # 4444 and 5555 are suspicious per config/rules.json
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        port_index = feature_names.index('suspicious_port_count')

        self.assertEqual(features[port_index], 2.0)

    def test_suspicious_port_count_zero_when_no_suspicious_ports(self):
        process_info = {
            'cpu_percent': 10.0,
            'memory_percent': 10.0,
            'num_connections': 1,
            'num_files': 0,
            'remote_ports': [80, 443],
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        port_index = feature_names.index('suspicious_port_count')

        self.assertEqual(features[port_index], 0.0)

    def test_process_count_defaults_to_one_process(self):
        process_info = {'cpu_percent': 5.0, 'memory_percent': 5.0}

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        process_count_index = feature_names.index('process_count')

        # A single process_info dict represents exactly one process being scored.
        self.assertEqual(features[process_count_index], 1.0)

    def test_file_operations_uses_real_num_files_value(self):
        process_info = {
            'cpu_percent': 5.0,
            'memory_percent': 5.0,
            'num_files': 17,
        }

        features = self.extractor.extract_from_process(process_info)
        feature_names = self.extractor.get_feature_names()
        file_ops_index = feature_names.index('file_operations')

        self.assertEqual(features[file_ops_index], 17.0)

    def test_extract_from_batch_empty_list_returns_correct_shape(self):
        result = self.extractor.extract_from_batch([])
        self.assertEqual(result.shape, (0, len(self.extractor.get_feature_names())))


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_feature_extractor.py -v`
Expected: `test_suspicious_port_count_reflects_actual_suspicious_ports` and `test_suspicious_port_count_zero_when_no_suspicious_ports` FAIL (current code always returns `0.0` for suspicious_port_count regardless of input). Other tests should already PASS since they test unchanged behavior.

- [ ] **Step 3: Implement real `suspicious_port_count` computation**

Replace the entire contents of `src/ml_models/feature_extractor.py` with:

```python
"""Feature extraction for ML models."""

import numpy as np
from typing import Dict, List

# Ports commonly associated with malware/backdoors, matching config/rules.json's
# RULE_003 "Unusual Port Connection" list, so the ML feature signal stays
# consistent with the rule-based detector's own definition of "suspicious."
SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337}


class FeatureExtractor:
    """Extract ML features from system events"""

    def __init__(self):
        self.feature_names = [
            'cpu_usage',
            'memory_usage',
            'process_count',
            'network_connections',
            'suspicious_port_count',
            'file_operations',
            'registry_changes'
        ]

    def extract_from_process(self, process_info: Dict) -> np.ndarray:
        """Extract features from a process"""
        remote_ports = process_info.get('remote_ports', [])
        suspicious_port_count = float(sum(1 for port in remote_ports if port in SUSPICIOUS_PORTS))

        features = [
            float(process_info.get('cpu_percent', 0)),
            float(process_info.get('memory_percent', 0)),
            1.0,
            float(process_info.get('num_connections', 0)),
            suspicious_port_count,
            float(process_info.get('num_files', 0)),
            float(process_info.get('registry_changes', 0)),
        ]
        return np.array(features)

    def extract_from_batch(self, events: List[Dict]) -> np.ndarray:
        """Extract features from multiple events"""
        if not events:
            return np.array([]).reshape(0, len(self.feature_names))

        features_list = []
        for event in events:
            features = self.extract_from_process(event)
            features_list.append(features)

        return np.array(features_list)

    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_names
```

Note on `registry_changes`: no registry-monitoring data source exists anywhere in this codebase (confirmed — `src/monitors/` only has `system_monitor.py` and `network_monitor.py`, no file/registry watcher despite `config.yaml`'s `monitoring.file` section suggesting one was planned). Rather than inventing fake data, this now reads `process_info.get('registry_changes', 0)` so the feature is real if a future monitor ever populates it, and safely defaults to `0.0` (same value as before) if not — this is honest about the current limitation instead of pretending a fabricated non-zero value is real telemetry.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_feature_extractor.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/ml_models/feature_extractor.py tests/test_feature_extractor.py
git commit -m "fix: FeatureExtractor computes real suspicious_port_count instead of hardcoded 0.0"
```

---

### Task 2: Switch `AnomalyDetector` from unsafe `pickle` to `joblib` + integrity checksum

**Files:**
- Modify: `src/ml_models/anomaly_detector.py`
- Modify: `requirements.txt`
- Create: `tests/test_anomaly_detector.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_anomaly_detector.py`:

```python
"""Unit tests for AnomalyDetector."""

import os
import tempfile
import unittest
import numpy as np

from src.ml_models.anomaly_detector import AnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector(contamination=0.1, random_state=42)
        fd, self.model_path = tempfile.mkstemp(suffix='.joblib')
        os.close(fd)
        os.remove(self.model_path)

    def tearDown(self):
        for path in (self.model_path, self.model_path + '.sha256'):
            if os.path.exists(path):
                os.remove(path)

    def test_train_requires_minimum_samples(self):
        X = np.random.rand(5, 7)
        with self.assertRaises(ValueError):
            self.detector.train(X)

    def test_train_and_predict(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)

        predictions = self.detector.predict(X)
        self.assertEqual(len(predictions), 50)

    def test_save_creates_checksum_file(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        self.assertTrue(os.path.exists(self.model_path))
        self.assertTrue(os.path.exists(self.model_path + '.sha256'))

    def test_load_succeeds_when_checksum_matches(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        new_detector = AnomalyDetector()
        new_detector.load_model(self.model_path)

        self.assertTrue(new_detector.is_trained)

    def test_load_rejects_tampered_model_file(self):
        X = np.random.rand(50, 7)
        self.detector.train(X)
        self.detector.save_model(self.model_path)

        # Tamper with the model file after the checksum was recorded
        with open(self.model_path, 'ab') as f:
            f.write(b'tampered bytes')

        new_detector = AnomalyDetector()
        with self.assertRaises(ValueError):
            new_detector.load_model(self.model_path)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_anomaly_detector.py -v`
Expected: `test_save_creates_checksum_file` and `test_load_rejects_tampered_model_file` FAIL (no checksum mechanism exists yet).

- [ ] **Step 3: Rewrite `anomaly_detector.py` to use joblib + SHA-256 checksum**

Replace the entire contents of `src/ml_models/anomaly_detector.py` with:

```python
"""ML-based anomaly detection using Isolation Forest."""

import hashlib
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """ML-based anomaly detection using Isolation Forest"""

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """Initialize anomaly detector"""
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.is_trained = False

    def train(self, X: np.ndarray) -> None:
        """Train the Isolation Forest model"""
        if X.shape[0] < 10:
            raise ValueError("Need at least 10 samples to train model")

        self.model.fit(X)
        self.is_trained = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomalies"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        return self.model.predict(X)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        return self.model.decision_function(X)

    @staticmethod
    def _compute_checksum(path: str) -> str:
        """Compute SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def save_model(self, path: str) -> None:
        """Save trained model to disk using joblib, with a SHA-256 checksum sidecar file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)

        checksum = self._compute_checksum(path)
        with open(path + '.sha256', 'w') as f:
            f.write(checksum)

    def load_model(self, path: str) -> None:
        """
        Load trained model from disk, verifying its SHA-256 checksum first.

        Raises:
            FileNotFoundError: If the model file or its checksum sidecar is missing.
            ValueError: If the file's checksum doesn't match the recorded checksum,
                indicating the model file was modified or corrupted after saving.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        checksum_path = path + '.sha256'
        if not os.path.exists(checksum_path):
            raise ValueError(
                f"Checksum file not found: {checksum_path}. "
                "Refusing to load a model with no integrity record."
            )

        with open(checksum_path, 'r') as f:
            expected_checksum = f.read().strip()

        actual_checksum = self._compute_checksum(path)
        if actual_checksum != expected_checksum:
            raise ValueError(
                f"Model file checksum mismatch for {path}. "
                "The file may have been tampered with or corrupted. Refusing to load."
            )

        self.model = joblib.load(path)
        self.is_trained = True
```

- [ ] **Step 4: Add `joblib` to requirements.txt**

In `requirements.txt`, add this line under the `# Machine learning` section:

```
joblib==1.4.2
```

- [ ] **Step 5: Install joblib and run tests**

Run: `python -m pip install joblib==1.4.2`

Run: `python -m pytest tests/test_anomaly_detector.py -v`
Expected: All PASS

- [ ] **Step 6: Handle pre-existing `.pkl` model files (migration note, not code)**

Run: `find src/ml_models/saved_models -name "*.pkl" 2>/dev/null`

If this returns any files, they were saved with the old `pickle` format and will fail to load with the new `joblib.load` call (raises a decode error, not a silent wrong-answer, so this fails loudly and safely). Since `MLIntegration._load_or_init_model` already wraps `self.trainer.load(...)` in a try/except that logs a warning and falls back to `model_trained = False` (see `src/ml_models/ml_integration.py:37-49`), any old `.pkl` file will simply be treated as "no model found" — the user will need to retrain via the dashboard's "Train ML Model" button or desktop app's ML tab. No destructive action is needed; do not delete old `.pkl` files automatically. If this repo has no such files yet, skip this step.

- [ ] **Step 7: Commit**

```bash
git add src/ml_models/anomaly_detector.py requirements.txt tests/test_anomaly_detector.py
git commit -m "fix: replace unsafe pickle model loading with joblib + SHA-256 integrity check"
```

---

### Task 3: Add international phone validation via `phonenumbers`

**Files:**
- Modify: `src/notifications/sms_service.py`
- Modify: `requirements.txt`
- Create: `tests/test_sms_service.py`

- [ ] **Step 1: Add `phonenumbers` to requirements.txt and install it**

In `requirements.txt`, add under a new `# Phone validation` section (near the Twilio line):

```
phonenumbers==8.13.40
```

Run: `python -m pip install phonenumbers==8.13.40`

- [ ] **Step 2: Write the failing tests**

Create `tests/test_sms_service.py`:

```python
"""Unit tests for SMSService phone validation."""

import unittest
from unittest.mock import patch, MagicMock

from src.notifications.sms_service import SMSService
from src.exceptions import NotificationException


def make_config():
    return {
        'account_sid': 'test_sid',
        'auth_token': 'test_token',
        'from_number': '+15551234567',
        'retry_attempts': 1,
        'retry_delay': 0,
    }


class TestSMSServicePhoneValidation(unittest.TestCase):
    def setUp(self):
        # Mock Twilio's Client so no real network calls happen and the
        # twilio package doesn't need to be installed/importable in CI.
        patcher = patch('twilio.rest.Client')
        self.addCleanup(patcher.stop)
        self.mock_client_class = patcher.start()

        self.service = SMSService(make_config())

    def test_validate_us_number_with_plus_prefix(self):
        self.assertTrue(SMSService.validate_phone('+14155552671'))

    def test_validate_uk_number(self):
        self.assertTrue(SMSService.validate_phone('+442071838750'))

    def test_validate_india_number(self):
        self.assertTrue(SMSService.validate_phone('+919876543210'))

    def test_reject_invalid_number(self):
        self.assertFalse(SMSService.validate_phone('not-a-phone-number'))

    def test_reject_too_short_number(self):
        self.assertFalse(SMSService.validate_phone('+1123'))

    def test_reject_number_missing_country_code(self):
        # phonenumbers requires a country code (E.164 format with +) to
        # unambiguously validate international numbers.
        self.assertFalse(SMSService.validate_phone('4155552671'))


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 3: Run tests to verify international ones fail**

Run: `python -m pytest tests/test_sms_service.py -v`
Expected: `test_validate_uk_number` and `test_validate_india_number` FAIL (current US-only regex rejects them). `test_reject_number_missing_country_code` may also fail since the old regex's `1?` prefix made the country code optional.

- [ ] **Step 4: Replace `validate_phone` with `phonenumbers`-based validation**

In `src/notifications/sms_service.py`, replace the imports at the top:

```python
import logging
import re
from typing import Dict, Any, List

from src.exceptions import NotificationException
```

with:

```python
import logging
from typing import Dict, Any, List

import phonenumbers

from src.exceptions import NotificationException
```

Then replace the `validate_phone` static method:

```python
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format."""
        pattern = r'^\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$'
        return bool(re.match(pattern, phone))
```

with:

```python
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """
        Validate phone number format using Google's libphonenumber (via the
        phonenumbers package), which supports international numbers.

        Numbers must be in E.164 format with a leading '+' and country code
        (e.g. '+14155552671', '+442071838750') since a bare national number
        is ambiguous without knowing which country's numbering plan applies.
        """
        try:
            parsed = phonenumbers.parse(phone, None)
            return phonenumbers.is_valid_number(parsed)
        except phonenumbers.NumberParseException:
            return False
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_sms_service.py -v`
Expected: All PASS

- [ ] **Step 6: Run the existing notification manager test suite to confirm no regression**

Run: `python -m pytest tests/test_notification_manager.py -v`
Expected: All PASS (this file doesn't test SMS directly per the original audit, but confirm no import errors from the `sms_service.py` change ripple into it).

- [ ] **Step 7: Commit**

```bash
git add src/notifications/sms_service.py requirements.txt tests/test_sms_service.py
git commit -m "fix: SMSService validates international phone numbers via phonenumbers library"
```

---

### Task 4: Implement `log_conversation` so AI assistant conversations actually persist

**Files:**
- Modify: `src/database/db_manager.py`
- Modify: `src/assistant/knowledge_base.py`
- Test: `tests/test_db_manager.py` (append), `tests/test_assistant.py` (verify no regression)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_db_manager.py` inside `TestDatabaseManager`:

```python
    def test_log_conversation_and_retrieve(self):
        self.db.log_conversation(user_id=1, query='what is ransomware', response='...', confidence=0.9)

        conversations = self.db.get_conversations_for_user(user_id=1)
        self.assertEqual(len(conversations), 1)
        self.assertEqual(conversations[0]['query'], 'what is ransomware')

    def test_get_conversations_for_user_returns_empty_list_when_none(self):
        conversations = self.db.get_conversations_for_user(user_id=999)
        self.assertEqual(conversations, [])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_db_manager.py::TestDatabaseManager::test_log_conversation_and_retrieve -v`
Expected: FAIL with `AttributeError: 'DatabaseManager' object has no attribute 'log_conversation'`

- [ ] **Step 3: Add both methods to `DatabaseManager`**

In `src/database/db_manager.py`, add these methods after `update_last_login` (added in Plan 2 Task 1):

```python
    def log_conversation(self, user_id: int, query: str, response: str, confidence: float = 1.0) -> int:
        """
        Log an AI assistant conversation turn.

        Args:
            user_id: ID of the user who asked the question
            query: The user's question
            response: The assistant's response
            confidence: Confidence score of the response (0-1)

        Returns:
            ID of the inserted conversation record
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ai_conversations (user_id, query, response, confidence)
                VALUES (?, ?, ?, ?)
            ''', (user_id, query, response, confidence))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_conversations_for_user(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent conversation history for a user.

        Args:
            user_id: User ID to fetch conversations for
            limit: Maximum number of conversations to return

        Returns:
            List of conversation dictionaries, most recent first
        """
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM ai_conversations
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            ''', (user_id, limit))
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_db_manager.py -v`
Expected: All PASS

- [ ] **Step 5: Remove the bare except in `knowledge_base.py` now that the method exists**

In `src/assistant/knowledge_base.py`, replace:

```python
    def store_conversation(self, user_id: int, query: str, response: str, confidence: float = 1.0) -> None:
        """Store conversation in database"""
        if self.db_manager:
            try:
                self.db_manager.log_conversation(user_id, query, response, confidence)
            except Exception:
                pass
```

with:

```python
    def store_conversation(self, user_id: int, query: str, response: str, confidence: float = 1.0) -> None:
        """Store conversation in database"""
        if self.db_manager:
            try:
                self.db_manager.log_conversation(user_id, query, response, confidence)
            except Exception as e:
                import logging
                logging.getLogger('securex').warning(f"Failed to store conversation: {e}")
```

- [ ] **Step 6: Run the existing assistant test suite to confirm no regression**

Run: `python -m pytest tests/test_assistant.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/database/db_manager.py src/assistant/knowledge_base.py tests/test_db_manager.py
git commit -m "feat: implement log_conversation so AI assistant history actually persists; stop swallowing save failures silently"
```

---

### Task 5: Fix bare except in `monitoring_loop` and wire up `adjust_risk_by_context` for off-hours detection

**Files:**
- Modify: `src/dashboard/app.py`

- [ ] **Step 1: Fix the bare except in `monitoring_loop`**

In `src/dashboard/app.py`, inside `monitoring_loop()`, replace:

```python
            # Also emit system metrics
            try:
                import psutil
                metrics = {
                    'cpu': psutil.cpu_percent(interval=0.5),
                    'memory': psutil.virtual_memory().percent,
                    'timestamp': datetime.now().isoformat()
                }
                socketio.emit('system_metrics', metrics)
            except:
                pass
```

with:

```python
            # Also emit system metrics
            try:
                import psutil
                metrics = {
                    'cpu': psutil.cpu_percent(interval=0.5),
                    'memory': psutil.virtual_memory().percent,
                    'timestamp': datetime.now().isoformat()
                }
                socketio.emit('system_metrics', metrics)
            except Exception as e:
                logger.debug(f"Failed to emit system metrics: {e}")
```

- [ ] **Step 2: Wire `adjust_risk_by_context` into `perform_scan()` for off-hours detection**

In `src/dashboard/app.py`, inside `perform_scan()`, replace:

```python
        if threat:
            # Step 3: Calculate risk score
            threat_with_risk = risk_scorer.calculate_risk(threat)
            
            # Step 4: Generate advisory
            advisory = advisor.generate_advisory(threat_with_risk)
```

with:

```python
        if threat:
            # Step 3: Calculate risk score
            threat_with_risk = risk_scorer.calculate_risk(threat)

            # Step 3b: Adjust for off-hours activity (10pm-6am local time is
            # more suspicious than daytime activity for the same event)
            current_hour = datetime.now().hour
            is_off_hours = current_hour >= 22 or current_hour < 6
            if is_off_hours:
                threat_with_risk = risk_scorer.adjust_risk_by_context(
                    threat_with_risk, {'off_hours': True}
                )

            # Step 4: Generate advisory
            advisory = advisor.generate_advisory(threat_with_risk)
```

- [ ] **Step 3: Verify with a syntax check**

Run: `python -c "import ast; ast.parse(open('src/dashboard/app.py').read()); print('syntax OK')"`
Expected: `syntax OK`

- [ ] **Step 4: Write a test confirming off-hours adjustment is applied**

Add a new test file `tests/test_risk_scorer.py` addition (append to the existing `TestRiskScorer` class from Plan 1 Task 8):

```python
    def test_adjust_risk_by_context_increases_score_for_off_hours(self):
        threat = {'risk_score': 0.5, 'risk_level': 'Medium'}

        adjusted = self.scorer.adjust_risk_by_context(threat, {'off_hours': True})

        self.assertGreater(adjusted['risk_score'], 0.5)
        self.assertIn('Increased: Off-hours activity', adjusted['risk_adjustments'])

    def test_adjust_risk_by_context_no_change_without_context_flags(self):
        threat = {'risk_score': 0.5, 'risk_level': 'Medium'}

        adjusted = self.scorer.adjust_risk_by_context(threat, {})

        self.assertEqual(adjusted['risk_score'], 0.5)
        self.assertEqual(adjusted['risk_adjustments'], [])
```

- [ ] **Step 5: Run the test**

Run: `python -m pytest tests/test_risk_scorer.py -v`
Expected: All PASS (including the 2 new tests, since `adjust_risk_by_context`'s implementation already existed and was correct — only the wiring into `perform_scan` was missing).

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/app.py tests/test_risk_scorer.py
git commit -m "fix: log real exceptions instead of bare except in monitoring loop; wire up off-hours risk adjustment"
```

---

### Task 6: Run full test suite and verify no regressions

**Files:** None (verification only)

- [ ] **Step 1: Run the complete test suite**

Run:
```bash
set SECRET_KEY=test-secret-for-local-run
python -m pytest tests/ -v --tb=short 2>&1 | tail -100
```
Expected: `test_feature_extractor.py`, `test_anomaly_detector.py`, `test_sms_service.py` all pass; `test_db_manager.py`, `test_risk_scorer.py`, `test_assistant.py`, `test_notification_manager.py` still pass with no new failures.

- [ ] **Step 2: Manually verify ML training end-to-end with the new joblib format**

Run:
```bash
python -c "
import numpy as np
from src.ml_models.ml_integration import MLIntegration
import os, shutil

test_path = 'data/ml_test/test_model.joblib'
if os.path.exists(os.path.dirname(test_path)):
    shutil.rmtree(os.path.dirname(test_path))

ml = MLIntegration(model_path=test_path)
events = [{'cpu_percent': float(i % 100), 'memory_percent': float((i * 2) % 100), 'num_connections': i % 10, 'num_files': i % 5} for i in range(60)]
success = ml.train_model(events)
print('Training success:', success)
print('Model stats:', ml.get_model_stats())

shutil.rmtree(os.path.dirname(test_path))
"
```
Expected: `Training success: True` and stats showing `'trained': True`.

- [ ] **Step 3: Final commit for this plan (if any uncommitted cleanup remains)**

```bash
git status
```
If clean, no action needed.

---

## Plan Complete

This plan fixes the ML pipeline's fake constant features, replaces unsafe pickle deserialization with integrity-checked joblib loading, adds real international phone validation, implements conversation persistence for the AI assistant, and wires up the previously-dead `adjust_risk_by_context` for off-hours detection. Desktop app cleanup and remaining dead-code removal are covered in **Plan 4**.
