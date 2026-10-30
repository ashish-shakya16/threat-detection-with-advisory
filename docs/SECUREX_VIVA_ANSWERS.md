# SecureX Viva Questions and Answers

These answers describe the current SecureX implementation. The project should not claim benchmark results or dataset usage that has not been reproduced.

## Core Questions

### 1. What is SecureX?

SecureX is a cybersecurity threat-monitoring and advisory platform. It combines system and network monitoring, rule-based detection, Isolation Forest anomaly detection, risk scoring, SQLite logging, notifications, advisories, and web and desktop interfaces.

### 2. Why did you choose this project?

Cyberattacks are becoming more difficult to detect using fixed rules alone. This project studies how traditional security rules and machine-learning anomaly detection can work together in a practical monitoring system.

### 3. What problem does SecureX solve?

SecureX identifies suspicious system and network activity, prioritizes threats using risk scores, stores historical events, and gives users understandable security recommendations.

### 4. How is SecureX different from existing antivirus software?

Commercial antivirus products provide mature malware signatures, kernel-level protection, sandboxing, cloud intelligence, quarantine, and enterprise management. SecureX is a research and educational monitoring platform focused on process and network telemetry, configurable rules, anomaly scoring, risk prioritization, advisories, and dashboards.

### 5. Who are the target users?

The target users are students, researchers, system administrators, small organizations, and security analysts who need a local cybersecurity monitoring dashboard. It is not currently designed for large enterprise deployment.

### 6. What is hybrid threat detection?

Hybrid detection combines multiple methods. SecureX uses rules for known suspicious patterns, Isolation Forest for unusual behavior, and risk scoring to combine severity, confidence, impact, and prevalence.

### 7. What is signature-based detection?

Signature-based detection compares an event with a known pattern, such as a suspicious process name, file hash, IP address, port, path, or extension. It is fast and explainable but cannot independently detect a completely new threat.

### 8. What is Isolation Forest?

Isolation Forest is an unsupervised anomaly-detection algorithm. It randomly partitions observations. Unusual observations are isolated with fewer partitions, so shorter isolation paths indicate possible anomalies.

### 9. Why did you choose Isolation Forest?

It does not require a complete set of labelled attacks, works well with numerical features, is relatively efficient, is available in scikit-learn, and is simpler to deploy than a deep-learning model.

### 10. Can Isolation Forest detect zero-day attacks?

It may flag previously unseen behavior if that behavior differs from normal activity, but it cannot guarantee zero-day detection. An anomaly is an investigation signal, not proof of an attack.

### 11. Why do you need both ML and signatures?

Signatures are precise for known threats, while ML can identify unusual behavior not explicitly encoded in a rule. Rules are easier to explain, while ML provides broader behavioral coverage. Combining them reduces dependence on one method.

### 12. What features does the ML model use?

The current feature extractor defines CPU usage, memory usage, process count, network-connection count, suspicious-port count, file-operation count, and registry-change count. Process count currently represents one event as one process, and registry changes default to zero unless a future monitor supplies them.

### 13. What is the difference between supervised and unsupervised learning?

Supervised learning uses labelled examples, such as traffic labelled normal or malicious. Unsupervised learning uses unlabelled data and identifies structure or unusual observations. SecureX's Isolation Forest is unsupervised.

### 14. Which datasets are used in SecureX?

The current repository does not show CICIDS2017, UNSW-NB15, or KDD Cup 99 being loaded into the active training pipeline. The training code accepts SecureX event dictionaries. A model artifact exists, but its dataset provenance and benchmark results are not documented reproducibly.

### 15. What is CICIDS2017?

CICIDS2017 is a Canadian Institute for Cybersecurity network-intrusion benchmark containing benign traffic and attacks such as brute force, denial of service, port scanning, botnet activity, web attacks, and infiltration.

### 16. What is UNSW-NB15?

UNSW-NB15 is a network-security dataset containing normal traffic and several attack categories. It includes network-flow and connection features and is commonly used for intrusion-detection benchmarking.

### 17. What is KDD Cup 99?

KDD Cup 99 is a classic network-intrusion dataset based on DARPA traffic. It contains normal and attack classes such as denial of service, probe, remote-to-local, and user-to-root attacks. It has important weaknesses, including redundancy and unrealistic traffic distributions.

### 18. How do you combine all three datasets?

A proper combination would require a common feature schema, consistent categorical encoding, a shared label taxonomy, duplicate removal, missing-value handling, class-imbalance handling, and time-aware train/test splits. SecureX does not currently implement this three-dataset combination; it is a proposed evaluation method.

### 19. If you use CICIDS2017, can SecureX detect ransomware on a computer?

Not reliably. CICIDS2017 is mainly a network dataset, while ransomware detection needs endpoint and temporal features such as rapid file modification, encryption-like activity, file renaming, suspicious processes, and shadow-copy deletion. SecureX would need endpoint file monitoring and ransomware-specific data.

### 20. How will you evaluate the model?

Use precision, recall, F1-score, confusion matrix, false-positive rate, false-negative rate, PR-AUC or ROC-AUC, detection latency, CPU usage, memory usage, and per-attack results. Use time-based and cross-environment testing. The current repository has unit tests but no complete validated benchmark report.

### 21. Which threats can SecureX detect?

The configured rules cover suspicious process execution, brute-force attempts, suspicious ports, excessive CPU usage, system-file modification, excessive network connections, privilege escalation, suspicious scripts, possible data exfiltration, and memory injection. Detection depends on the necessary event data being available.

### 22. Can SecureX detect phishing?

Not directly in the current implementation. It does not currently provide a complete email, URL, webpage, sender, or browser-analysis pipeline. Phishing detection would require URL, domain, sender, language, page-structure, and threat-intelligence features.

### 23. What is a false positive?

A false positive occurs when legitimate activity is reported as malicious. For example, an authorized administrator using Nmap could trigger a suspicious-process rule.

### 24. What happens when a threat is detected?

SecureX collects the event, checks rules, creates a threat record, calculates risk, optionally enriches it with ML scoring, generates an advisory, stores the result in SQLite, sends configured notifications, and displays it on the dashboard. It does not currently quarantine or delete files automatically.

### 25. What if an attacker disables the monitoring service?

The current implementation does not provide strong self-protection or an independent watchdog. A production system should add a protected Windows service, service recovery, remote heartbeat monitoring, tamper-resistant logging, least-privilege configuration, and alerts when telemetry stops.

### 26. Why Python?

Python provides rapid development and strong libraries for cybersecurity, psutil monitoring, scikit-learn, Flask, SQLite, PyQt, testing, and deployment. Kernel-level security products would generally use lower-level languages such as C, C++, or Rust.

### 27. Why Flask and SQLite?

Flask is lightweight and suitable for a REST API and dashboard backend. SQLite is embedded, serverless, easy to deploy, and suitable for local or small deployments. A large multi-user system would use a database such as PostgreSQL.

### 28. What is RAG?

Retrieval-Augmented Generation retrieves relevant documents and supplies them to a language model before generating an answer. This can make security explanations more grounded in threat definitions, advisories, and internal documentation.

### 29. Why ChromaDB?

ChromaDB is a vector database that supports embedding-based similarity search. It could store threat definitions, advisories, MITRE ATT&CK information, and incident reports. However, the active SecureX assistant currently uses a local knowledge base and an optional OpenAI-compatible API; ChromaDB is not currently active.

### 30. What is LangChain?

LangChain is a framework for building language-model applications with prompts, retrieval, tools, memory, and agents. Older project plans mention it, but the current assistant directly uses Python requests and does not depend on LangChain.

### 31. Can the AI assistant always give correct security advice?

No. It can misunderstand events, hallucinate facts, or recommend an unsuitable action. SecureX has local fallback responses when the external AI service is unavailable. AI output should be treated as advisory and reviewed before high-impact actions.

### 32. Why build both a desktop application and a website?

The desktop application provides local monitoring and a native Windows experience. The website provides browser-based access, remote administration, API access, and future centralized management. Both use the same backend detection concepts.

### 33. Is SecureX a complete commercial antivirus replacement?

No. It does not provide kernel-level protection, mature quarantine, secure boot integration, cloud reputation, sandboxing, enterprise endpoint management, large-scale malware intelligence, or strong tamper protection.

### 34. What are the limitations of your project?

Limitations include limited endpoint file monitoring, no complete phishing detector, no guaranteed zero-day detection, no independent watchdog, incomplete dataset provenance, no complete benchmark evaluation, connection-level rather than packet-level network monitoring, AI uncertainty, SQLite scalability limits, and no automatic high-impact response.

### 35. What is the future scope?

Future work includes real file and registry monitoring, ransomware detection, phishing analysis, reproducible public-dataset evaluation, concept-drift handling, explainable ML, MITRE ATT&CK mapping, watchdog protection, tamper resistance, PostgreSQL support, YARA and VirusTotal integration, threat-intelligence feeds, cloud management, and analyst-approved automated response.

## Important Technical Viva Questions

### 36. Why Isolation Forest instead of Random Forest?

Random Forest is mainly a supervised classification algorithm and requires labelled examples. Isolation Forest is designed for anomaly detection and can learn from mostly normal data without complete labels for every attack. Random Forest could be evaluated later if a reliable labelled dataset is prepared.

### 37. How exactly are network features extracted from live traffic?

SecureX uses `psutil.net_connections(kind='inet')`. It reads local and remote addresses, remote ports, connection status, protocol information, process IDs, and process names when permitted. Rules then check suspicious ports and excessive connection counts. This is connection-level monitoring, not packet capture or deep-packet inspection.

### 38. Which dataset did you actually train on, and what are your measured results?

The repository does not document a reproducible public-dataset training run. The training code accepts SecureX event dictionaries and a model artifact exists, but there is no verified report identifying the exact training data, split, or benchmark metrics. The unit tests verify software behavior, not accuracy, precision, recall, or F1-score.

### 39. How is SecureX different from Microsoft Defender or commercial antivirus software?

Commercial products provide real-time file scanning, kernel sensors, cloud reputation, behavioral blocking, exploit protection, sandboxing, quarantine, automatic remediation, enterprise policy management, and large-scale telemetry. SecureX demonstrates local telemetry collection, configurable rules, anomaly scoring, risk classification, logging, advisories, and dashboards. It should be described as a research prototype, not an endpoint-protection replacement.

### 40. What happens if the model produces a false positive or misses a threat?

For a false positive, the event can be reviewed with its rule evidence, threshold, risk score, and context. Thresholds and training data can then be improved. If the model misses a threat, rule detection, additional telemetry, external investigation, and new training data can provide other layers of protection. Destructive actions should never depend only on an anomaly score.

## Short Final Summary

SecureX is a hybrid cybersecurity monitoring prototype. Its rules detect known patterns, while Isolation Forest highlights unusual behavior. It provides risk scoring, logging, advisories, and desktop and web interfaces. It is not a complete antivirus product, and the current code does not claim a validated public-dataset benchmark or guaranteed zero-day, ransomware, or phishing detection.

## Rubric Preparation: 50 Marks

### 1. Quantification and Completeness of Functional Specifications - 6 marks

Present SecureX as a set of measurable functions:

- Collect system-process and network-connection events.
- Apply 10 configurable detection rules.
- Extract seven ML features and calculate anomaly scores.
- Calculate a 0.0-1.0 risk score and classify risk levels.
- Store threats, events, advisories, and history in SQLite.
- Display results through the web dashboard and desktop application.
- Send optional email, SMS, and webhook notifications.
- Require authenticated access to protected dashboard APIs.

Use tests, API endpoints, configuration files, and a live demonstration as evidence. Do not claim that every configured rule is active unless the required event source exists.

### 2. Selection of Computing Framework or SDLC Model - 6 marks

Explain that SecureX follows an iterative, incremental development approach. The system was divided into modules: monitoring, detection, ML, risk assessment, advisory generation, database, API, frontend, and desktop packaging. Each module could be developed and tested separately, then integrated through the event pipeline.

This approach was appropriate because requirements evolved from a basic rule engine into a hybrid detection platform with notifications, authentication, a dashboard, and a packaged desktop client.

### 3. Use of Latest Design Tools - 6 marks

Mention the tools actually used:

- React and TypeScript for the frontend
- Vite for frontend development and production builds
- Flask and Flask-SocketIO for the backend API and real-time events
- scikit-learn for Isolation Forest
- psutil for system and network telemetry
- SQLite for local persistence
- PyQt6 and Qt WebEngine for the native desktop client
- PyInstaller for packaging
- Docker for deployment
- Pytest for automated tests

The important point is not merely naming tools; explain why each tool supports a project requirement.

### 4. Appropriateness of Design - 6 marks

The design is appropriate for a local cybersecurity prototype because it separates collection, detection, risk scoring, advice, storage, and presentation. Rules provide deterministic evidence, Isolation Forest adds anomaly detection, and risk scoring prioritizes alerts instead of treating every event equally.

SQLite and Flask keep deployment simple. The design is not claimed to be sufficient for enterprise-scale endpoint protection, kernel monitoring, or multi-tenant deployment.

### 5. Synchronization of Functionality with Design - 6 marks

Demonstrate the complete flow:

```text
System/network monitor
	-> event dictionary
	-> rule engine
	-> risk scorer and optional ML enrichment
	-> advisory and notifications
	-> SQLite database
	-> web or desktop dashboard
```

The UI should display the same threat, risk, advisory, and history concepts implemented by the backend. The desktop client embeds the same dashboard rather than implementing a separate detection engine.

### 6. Oral Communication - 5 marks

Use this structure during the presentation:

1. State the problem.
2. Explain the architecture.
3. Demonstrate one normal event and one suspicious event.
4. Explain why rules and Isolation Forest are complementary.
5. Show the alert, risk score, advisory, and stored record.
6. State limitations honestly.

Avoid saying that SecureX guarantees zero-day detection, replaces Microsoft Defender, or has benchmark accuracy that has not been measured.

### 7. Written Communication - 5 marks

Keep the report consistent with the implementation. Define technical terms before using them, label proposed work as future scope, include architecture and data-flow diagrams, describe configuration and test evidence, and separate software-test results from ML-performance results.

The strongest written claim is that SecureX demonstrates an integrated hybrid detection workflow. The weaker claims, such as public-dataset accuracy or complete ransomware detection, should be presented as future evaluation work unless experimentally verified.

### 8. Guide's Marks - 10 marks

Be prepared to explain your individual contribution and show evidence such as:

- Modules or features personally implemented
- Tests written or executed
- Design decisions and trade-offs
- Problems encountered and how they were solved
- The desktop or web demonstration
- Documentation and packaging work

A good response is specific: describe the module, the input and output, the design reason, and how it was tested. Do not claim work that cannot be demonstrated in the repository.

## One-Minute Presentation Answer

SecureX is a hybrid cybersecurity monitoring platform developed using an iterative modular approach. It collects system and network events, checks them against configurable rules, and uses Isolation Forest to identify unusual behavior. A risk-scoring layer prioritizes the results, while SQLite stores the evidence and Flask, React, and PyQt6 provide web and desktop interfaces. The design is appropriate for an educational and small-scale monitoring system because it is explainable, modular, and easy to deploy. It is not a commercial antivirus replacement, and its current limitation is that public-dataset benchmarking and complete endpoint protection still require future work.
