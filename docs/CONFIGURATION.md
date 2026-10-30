# SecureX Configuration Guide

## Configuration File

Main configuration: `config/config.yaml`

## Monitoring Settings

```yaml
monitoring:
  system_check_interval: 5        # Seconds between checks
  network_check_interval: 10
  
  system:
    enabled: true
    cpu_threshold: 90             # Alert if > 90% CPU
    memory_threshold: 85          # Alert if > 85% RAM
    suspicious_process_names:
      - "mimikatz"
      - "metasploit"
  
  network:
    enabled: true
    suspicious_ports:
      - 4444
      - 5555
    max_connections_per_process: 100
```

## Detection Settings

```yaml
detection:
  rule_based:
    enabled: true
    rules_file: "config/rules.json"
  
  ml_based:
    enabled: false
    model_path: "src/ml_models/saved_models/anomaly_detector.pkl"
    contamination: 0.1
```

## Risk Assessment

```yaml
risk_assessment:
  weights:
    severity: 0.4
    confidence: 0.3
    impact: 0.2
    prevalence: 0.1
  
  thresholds:
    low: 0.3
    medium: 0.6
    high: 0.85
```

## AI Assistant Settings

```yaml
ai:
  enabled: false                 # true = use a language model; false = offline knowledge base
  provider: "openai-compatible"  # or "huggingface", "ollama"
  api_key_env: "SECUREX_AI_API_KEY"  # name of the env var holding the key
  base_url: ""                   # optional override of the provider endpoint
  model: "gpt-4o-mini"
  temperature: 0.2
  max_tokens: 600
  timeout_seconds: 30
  rag_enabled: true              # ChromaDB + Sentence Transformers; keyword fallback otherwise
  embedding_model: "all-MiniLM-L6-v2"
  chroma_path: "data/chroma_db"
  knowledge_dir: "docs/security_knowledge"
  max_distance: 0.65             # cosine distance cut-off; larger = looser matches
```

Install optional retrieval dependencies with `pip install -r requirements-ai.txt`.
See the README's "AI Security Assistant" section for provider examples.

## Notification Settings

```yaml
notifications:
  enabled: false
  notify_on_critical: true
  notify_on_high: true
  notify_on_medium: false
  notify_on_low: false
  cooldown_seconds: 300
  recipients: []                 # trusted addresses; others are verified by email
  smtp:
    smtp_server: "smtp.gmail.com"
    smtp_port: 587               # 465 switches to implicit TLS
    sender_email_env: "SECUREX_SMTP_SENDER"
    sender_password_env: "SECUREX_SMTP_PASSWORD"
    use_tls: true
    timeout_seconds: 15
    retry_attempts: 3
    retry_delay: 2
```

The enabled flag, severities and cooldown can also be changed in Settings. Those
changes are stored in the database and override these values after a restart.

## Database Settings

```yaml
database:
  type: "sqlite"
  path: "data/db/threats.db"
  backup_enabled: true
  backup_interval: 86400
```

## Dashboard Settings

```yaml
dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 5000
  auto_refresh_interval: 10
```

## Logging Settings

```yaml
logging:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "json"
  log_to_file: true
  log_file: "data/logs/app.log"
```
