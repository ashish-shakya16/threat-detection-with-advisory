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
