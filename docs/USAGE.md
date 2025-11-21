# Linux Security Agent - Usage Guide

> **Author**: Master's Student Research Project  
> **Note**: This is a research prototype developed for academic purposes.

## Quick Start

### Basic Usage

**Linux (Simple Agent - Recommended):**
```bash
# Run with auditd collector (most reliable)
sudo python3 core/simple_agent.py --collector auditd --threshold 30

# Run with eBPF collector
sudo python3 core/simple_agent.py --collector ebpf --threshold 30

# Run with dashboard
sudo python3 core/simple_agent.py --collector ebpf --dashboard --threshold 30
```

**Linux (Enhanced Agent - Full Features):**
```bash
# Run with dashboard
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30

# Run with specific collector
sudo python3 core/enhanced_security_agent.py --collector ebpf --dashboard

# Run with JSON output
sudo python3 core/enhanced_security_agent.py --output json --timeout 60
```

### Advanced Usage

**Training Models:**
```bash
# Train models on real system data
sudo python3 core/enhanced_security_agent.py --train-models

# Train and append to existing feature store
sudo python3 core/enhanced_security_agent.py --train-models --append

# Train then run dashboard
sudo python3 core/enhanced_security_agent.py --train-models --dashboard
```

**With Attack Testing:**
```bash
# Terminal 1: Start agent
sudo python3 core/simple_agent.py --collector ebpf --dashboard --threshold 30

# Terminal 2: Run attack simulation
python3 scripts/simulate_attacks.py
```

## Command Line Options

### Simple Agent (`core/simple_agent.py`)

| Option | Description | Default |
|--------|-------------|---------|
| `--collector` | Collector type: `ebpf` or `auditd` | `ebpf` |
| `--threshold` | Risk score threshold for alerts | 50.0 |
| `--dashboard` | Display real-time dashboard | False |

### Enhanced Agent (`core/enhanced_security_agent.py`)

| Option | Description | Default |
|--------|-------------|---------|
| `--collector` | Collector type: `ebpf` or `auditd` | `ebpf` |
| `--threshold` | Risk score threshold for alerts | 50.0 |
| `--dashboard` | Display real-time dashboard | False |
| `--output` | Output format: `console` or `json` | `console` |
| `--timeout` | Run for specified seconds then exit (0 = indefinitely) | 0 |
| `--train-models` | Train ML models on system data | False |
| `--append` | Append to existing feature store when training | False |

## Risk Scoring System

### System Call Risk Levels

- **Low Risk (1-2 points)**: Normal operations
  - `read`, `write`, `open`, `close`, `stat`, `getpid`, etc.

- **Medium Risk (3-5 points)**: Potentially suspicious
  - `fork`, `execve`, `chmod`, `chown`, `mount`, etc.

- **High Risk (8-10 points)**: Very suspicious
  - `ptrace`, `setuid`, `setgid`, `chroot`, etc.

### Risk Score Calculation

- Base score from system calls
- Time decay factor (0.95)
- Continuous updates as more syscalls are observed
- Range: 0-100

## Anomaly Detection

The anomaly detection system uses Isolation Forest to identify unusual system call patterns:

### Features Used

1. **Syscall frequency distribution**
2. **Unique syscalls ratio**
3. **High-risk syscall ratio**
4. **File operation ratio**
5. **Process control ratio**
6. **Network operation ratio**
7. **Syscall entropy**
8. **Pattern features**

### Training

- Model is automatically trained on first run
- Uses synthetic data with normal and suspicious patterns
- Model is saved and reused on subsequent runs

## Action System

### Action Thresholds

- **Warning**: 60% of main threshold
- **Freeze**: 120% of main threshold  
- **Kill**: 180% of main threshold

### Actions Taken

1. **WARN**: Send SIGUSR1 signal to process
2. **FREEZE**: Send SIGSTOP signal to freeze process
3. **KILL**: Send SIGKILL signal to terminate process
4. **LOG**: Log process information

### Safety Features

- Kill actions are disabled by default
- Frozen processes can be unfrozen
- All actions are logged
- Permission checks before taking actions

## Demo Scripts

### Running Demos

```bash
# Run normal behavior demo
cd demo
python3 normal_behavior.py

# Run suspicious behavior demo
python3 suspicious_behavior.py

# Run both demos
python3 run_demo.py
```

### What to Expect

- **Normal behavior**: Low risk scores (0-20)
- **Suspicious behavior**: High risk scores (50-100)
- **Anomaly detection**: Identifies unusual patterns

## Monitoring Examples

### Example 1: Basic Monitoring

**Linux:**
```bash
# Start monitoring
sudo python3 core/simple_agent.py --dashboard

# In another terminal, run suspicious behavior
cd demo
python3 suspicious_behavior.py
```

**macOS:**
```bash
# Start monitoring with timeout
python3 core/simple_agent.py --dashboard --timeout 60

# In another terminal, run suspicious behavior
cd demo
python3 suspicious_behavior.py
```

Expected output:
```
PID 1234: python3 (Risk: 75.2, Anomaly: -0.15)
PID 1235: bash (Risk: 82.1, Anomaly: -0.23)
```

### Example 2: JSON Output

**Linux:**
```bash
# Start with JSON output
sudo python3 core/simple_agent.py --output json
```

**macOS:**
```bash
# Start with JSON output and timeout
python3 core/simple_agent.py --output json --timeout 30
```

# Output will be in JSON format:
{
  "timestamp": "2024-01-15T10:30:00",
  "processes": [
    {
      "pid": 1234,
      "name": "python3",
      "risk_score": 75.2,
      "anomaly_score": -0.15,
      "syscall_count": 45,
      "last_update": 1705312200.0
    }
  ]
}
```

### Example 3: With Actions

```bash
# Start with actions enabled
sudo python3 core/simple_agent.py --threshold 30 --enable-kill

# Processes will be automatically:
# - Warned at risk score 18+
# - Frozen at risk score 36+
# - Killed at risk score 54+
```

## Integration Examples

### With SIEM Systems

```bash
# Output to file for SIEM ingestion
sudo python3 core/simple_agent.py --output json > /var/log/security_events.json

# Or use syslog
sudo python3 core/simple_agent.py --action-log /dev/log
```

### With Monitoring Systems

```bash
# Use with Prometheus/Grafana
sudo python3 core/simple_agent.py --output json | \
    jq -r '.processes[] | select(.risk_score > 50) | "security_risk{pid=\"\(.pid)\",name=\"\(.name)\"} \(.risk_score)"'
```

### With Alerting Systems

```bash
# Send alerts to external systems
sudo python3 core/simple_agent.py --output json | \
    jq -r '.processes[] | select(.risk_score > 80) | "ALERT: High risk process \(.name) (PID: \(.pid)) with score \(.risk_score)"'
```

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with `sudo` (Linux) or check file permissions (macOS)
2. **BCC not available**: Install BCC tools (Linux) or use macOS version
3. **No processes detected**: Check if monitoring is working
4. **High false positives**: Adjust risk thresholds
5. **NoneType errors**: Fixed in recent versions - ensure you're using the latest code
6. **Import errors**: Make sure virtual environment is activated and dependencies are installed

### Debug Mode

**Linux:**
```bash
# Run with verbose output
sudo python3 core/simple_agent.py --dashboard --threshold 10
```

**macOS:**
```bash
# Run with verbose output and timeout
python3 core/simple_agent.py --dashboard --threshold 10 --timeout 30
```

### Log Analysis

```bash
# Check action logs
tail -f /var/log/security_agent.log

# Analyze risk patterns
grep "HIGH RISK" /var/log/security_agent.log
```

## Performance Considerations

### Resource Usage

- **CPU**: Low overhead with eBPF
- **Memory**: ~50MB for monitoring
- **Disk**: Log file growth (configurable)

### Optimization

- Use eBPF for better performance
- Adjust monitoring frequency
- Limit log file size
- Use JSON output for integration

## Security Considerations

### Running as Root

- Required for eBPF and process actions
- Use with caution in production
- Consider using capabilities instead

### Action Safety

- Kill actions are dangerous
- Test in isolated environment first
- Monitor action logs carefully
- Have rollback procedures

### Data Privacy

- System call data is sensitive
- Secure log files
- Consider data retention policies
- Encrypt logs if necessary

## Best Practices

1. **Start with monitoring only** - Don't enable actions initially
2. **Test thoroughly** - Use demo scripts to validate behavior
3. **Monitor logs** - Watch for false positives
4. **Adjust thresholds** - Fine-tune based on your environment
5. **Backup systems** - Have recovery procedures ready
6. **Regular updates** - Keep the agent updated
7. **Documentation** - Document your configuration and procedures
