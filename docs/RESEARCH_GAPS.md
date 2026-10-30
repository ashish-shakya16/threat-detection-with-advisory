# Research Gaps and How SecureX Addresses Them

Each claim below is matched to the code that implements it and the tests that
check it. "Limits" states what is not claimed.

| Gap | Problem | How SecureX addresses it | Where |
|---|---|---|---|
| G1 Evaluation validity | Dataset defects and biased train/test protocols inflate performance | Provides a reproducible evaluation pipeline for CIC-IDS2017 and UNSW-NB15: day-based or official splits, de-duplication, removal of cross-split duplicates and identifier columns, benign-only training, and a threshold chosen on validation data. Reports precision, recall, F1, FPR, ROC-AUC and per-category rates | `src/ml_models/dataset_evaluation.py`, `scripts/evaluate_datasets.py`, `docs/DATASET_EVALUATION.md`, `tests/test_governance.py` |
| G2 Detection-response asymmetry | Systems detect but do not evaluate response | Each detection gets a risk-based advisory and a response level (observe, alert, contain, terminate), and the outcome of every response is recorded | `src/advisory/`, `src/response/response_manager.py` |
| G3 Weak operational adaptivity | Closed-loop adaptation is rare | Continuous process and network monitoring with rule detection plus an Isolation Forest anomaly score blended into risk once a model is trained | `src/monitors/`, `src/ml_models/ml_integration.py`, `perform_scan()` |
| G4 Missing risk contextualisation | Asset criticality and exposure ignored | Risk classification (Low, Medium, High, Critical) adjusted for configured asset criticality, network exposure, privileged accounts and off-hours activity, with the reasons stored per threat | `src/risk_assessment/asset_context.py`, `risk_scorer.py` |
| G5 Explainability-autonomy mismatch | Explanations not designed around decisions | Human-readable advisories plus an AI assistant that explains why a threat was flagged, separates evidence from recommendations and flags uncertainty | `src/advisory/`, `src/assistant/` |
| G6 Robustness of the response loop | Automated response becomes an attack surface | Graduated response in which containment is only proposed. Execution requires human approval, is off by default, re-verifies the target, protects system processes, expires and is rate-limited, and suspensions can be resumed | `src/response/response_manager.py`, `docs/GOVERNANCE.md` |
| G7 Governance of delegated action | Accountability and auditability unresolved | Hash-chained audit log of logins, configuration changes, threat status changes and every response decision, with an integrity check | `src/audit/audit_log.py`, Audit Log page |

## Limits (do not overstate)

- **G1:** the pipeline is implemented and tested on synthetic fixtures only.
  Report numbers only after running it on the real datasets, and cite the report
  file. The evaluation is offline on flow features; it is not live-detection accuracy.
- **G3:** there is no drift detection or automatic retraining. The model is
  retrained manually via `POST /api/ml/train`. The gap itself (closed-loop,
  drift-triggered adaptation) is not solved.
- **G4:** asset criticality is one value per device set by the administrator,
  not an asset inventory. The multipliers are a heuristic and are not calibrated.
- **G6:** only process suspend, resume and terminate exist. No file quarantine,
  firewall blocking or network isolation.
- **G7:** the hash chain makes tampering evident but cannot prevent someone with
  database write access from rebuilding it.
