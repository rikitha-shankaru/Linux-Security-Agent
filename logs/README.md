# Log Files

This directory contains log files from the security agent.

## Log File: security_agent.log

- **Location**: `logs/security_agent.log` (or `~/.cache/security_agent/logs/security_agent.log`)
- **Rotation**: Automatically rotated when file reaches 10 MB
- **Backups**: Keeps 5 backup files (security_agent.log.1, .log.2, etc.)
- **Format**: Detailed with timestamps, file locations, and line numbers

## What's Logged

- Agent startup/shutdown
- Syscall events (first 5 events)
- ML detection results
- High-risk alerts
- Anomaly detections
- Connection pattern detections
- Errors and exceptions (with full tracebacks)

## Viewing Logs

```bash
# View latest log
tail -f logs/security_agent.log

# Search for errors
grep ERROR logs/security_agent.log

# Search for detections
grep "HIGH RISK\|ANOMALY\|CONNECTION PATTERN" logs/security_agent.log

# View last 100 lines
tail -100 logs/security_agent.log
```

## Log Levels

- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages
- **WARNING**: Warning messages (detections, anomalies)
- **ERROR**: Error messages (with tracebacks)


