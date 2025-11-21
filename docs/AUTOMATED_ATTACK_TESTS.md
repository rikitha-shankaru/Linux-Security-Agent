# Automated Attack Test Suite

> **Author**: Likitha Shankar  
> **Last Updated**: November 20, 2024

## Overview

The automated attack test suite validates the security agent's ability to detect various attack patterns. It runs attack simulations and verifies that the agent correctly identifies and scores them.

## Features

- **5 Attack Types Tested**:
  1. Privilege Escalation (T1078)
  2. High-Frequency Attack (DoS pattern)
  3. Process Churn (T1055)
  4. Suspicious File Patterns (T1070)
  5. Ptrace Attempts (T1055)

- **Comprehensive Reporting**:
  - JSON test report with detailed results
  - Attack execution status
  - Detection verification
  - Risk and anomaly scores

## Usage

### Quick Start

```bash
# Run all attack tests
sudo python3 scripts/run_attack_tests.py

# Or run via unittest
sudo python3 -m pytest tests/test_automated_attacks.py -v
```

### What It Does

1. **Starts Agent**: Launches the security agent in background with eBPF collector
2. **Executes Attacks**: Runs each attack pattern sequentially
3. **Monitors Detection**: Checks if agent detects the attacks
4. **Generates Report**: Creates `attack_test_report.json` with results

## Test Results

The test suite generates a JSON report with:

```json
{
  "timestamp": 1234567890,
  "tests_run": 5,
  "failures": 0,
  "errors": 0,
  "success": true,
  "test_details": [...]
}
```

## Attack Patterns

### 1. Privilege Escalation
- **MITRE ATT&CK**: T1078
- **Syscalls**: `execve`, `chmod`, `chown`, `mount`
- **Expected Detection**: High risk score (>30), anomaly flag

### 2. High-Frequency Attack
- **Type**: DoS pattern
- **Behavior**: Rapid file operations (300+ operations)
- **Expected Detection**: Rate-based detection, high syscall frequency

### 3. Process Churn
- **MITRE ATT&CK**: T1055
- **Behavior**: Rapid process creation/termination
- **Expected Detection**: Process injection pattern detection

### 4. Suspicious File Patterns
- **MITRE ATT&CK**: T1070
- **Behavior**: Unusual file access with `chmod`/`chown`
- **Expected Detection**: File access anomaly detection

### 5. Ptrace Attempts
- **MITRE ATT&CK**: T1055
- **Behavior**: Process injection attempts via `ptrace`
- **Expected Detection**: High-risk syscall detection

## Integration with CI/CD

The test suite can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run Attack Tests
  run: |
    sudo python3 scripts/run_attack_tests.py
  continue-on-error: true
```

## Requirements

- **Root privileges** (for eBPF collector)
- **Python 3.8+**
- **Trained ML models** (in `~/.cache/security_agent/`)

## Notes

- Tests run attacks in isolated `/tmp` directories
- All test files are cleaned up after execution
- Agent runs in background process during tests
- Detection verification requires agent to be running

## Troubleshooting

**Agent not starting?**
- Ensure you have root privileges
- Check eBPF is available: `ls /sys/kernel/debug/tracing/`

**Attacks not detected?**
- Verify ML models are trained
- Check agent logs for errors
- Ensure agent has time to process (5s wait after each attack)

## Related Files

- `tests/test_automated_attacks.py` - Main test suite
- `scripts/run_attack_tests.py` - Test runner script
- `scripts/simulate_attacks.py` - Attack simulation functions
- `attack_test_report.json` - Generated test report

