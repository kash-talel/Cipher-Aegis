# Logs Directory

This directory contains Cipher Aegis system logs.

## Log Files

- **`cipher_aegis.log`**: Main application log
  - Startup/shutdown events
  - Anomaly detections
  - Errors and warnings
  - Training events

## Log Format

```
YYYY-MM-DD HH:MM:SS - logger_name - LEVEL - message
```

Example:
```
2026-01-02 01:15:00 - __main__ - INFO - Cipher Aegis startup initiated
2026-01-02 01:15:05 - __main__ - WARNING - 🚨 ANOMALY: 192.168.1.100 → 8.8.8.8 | Score: 0.853 | HIGH
```

## Log Levels

- **INFO**: Normal operation events
- **WARNING**: Anomaly detections, non-critical issues
- **ERROR**: Errors that don't stop execution
- **CRITICAL**: Fatal errors

## Log Rotation

Logs are not automatically rotated. To manage log size:

```bash
# Archive old log
mv logs/cipher_aegis.log logs/cipher_aegis_$(date +%Y%m%d).log

# Compress archive
gzip logs/cipher_aegis_*.log
```

## Viewing Logs

Real-time monitoring:
```bash
# Linux/Mac
tail -f logs/cipher_aegis.log

# Windows (PowerShell)
Get-Content logs/cipher_aegis.log -Wait -Tail 20
```

Filter by level:
```bash
# Show only warnings and errors
grep -E "WARNING|ERROR" logs/cipher_aegis.log
```
