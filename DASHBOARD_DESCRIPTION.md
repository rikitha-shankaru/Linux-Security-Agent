# Security Agent Dashboard - Visual Description

**Real-time TUI (Text User Interface) Dashboard**

---

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Processes: 15 | High Risk: 3 | Anomalies: 2 | C2: 0 | Scans: 0 | Syscalls: 1234 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ ℹ️  Score Information                                                │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ 📊 Score Guide:                                                      │ │
│ │                                                                       │ │
│ │ Risk Score (0-100):                                                  │ │
│ │   🟢 0-30    Normal behavior - typical system operations            │ │
│ │   🟡 30-50   Suspicious - unusual patterns detected                │ │
│ │   🔴 50-100  High Risk - potential threat, investigate immediately │ │
│ │                                                                       │ │
│ │ Anomaly Score (ML-based):                                            │ │
│ │   0.00-10.00  Normal - matches learned behavior patterns           │ │
│ │   10.00-30.00 Unusual - deviates from baseline                      │ │
│ │   30.00+      Anomalous - significant deviation, likely threat       │ │
│ │                                                                       │ │
│ │ How Scores Work:                                                     │ │
│ │   • Risk Score: Based on syscall types, frequency, patterns          │ │
│ │   • Anomaly Score: ML model detects deviations from normal           │ │
│ │   • Both scores update in real-time                                 │ │
│ │                                                                       │ │
│ │ Current Threshold: 20.0 (configurable with --threshold)            │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ 🛡️ Security Agent - Live Monitoring                                 │ │
│ ├──────┬──────────────────┬──────┬──────────┬─────────┬──────────────────────────────┬────────────┐ │
│ │ PID  │ Process          │ Risk │ Anomaly  │ Syscalls │ Recent Syscalls              │ Last Update│ │
│ ├──────┼──────────────────┼──────┼──────────┼─────────┼──────────────────────────────┼────────────┤ │
│ │ 71474│ 🟢 python3       │ 22.0 │ 39.20    │ 100     │ read, write, open, close...   │ 2s         │ │
│ │ 4973 │ 🟢 bash          │ 20.9 │ 41.10    │ 85      │ execve, fork, wait4...        │ 3s         │ │
│ │ 1901 │ 🟢 systemd       │ 18.5 │ 15.30    │ 234     │ socket, bind, listen...        │ 1s         │ │
│ │ 1234 │ ⚪ sshd          │ 12.3 │ 8.50     │ 45      │ accept, read, write...         │ 8s         │ │
│ │ 5678 │ 🟢 nginx         │ 10.2 │ 5.20     │ 567     │ accept, recv, send...          │ 1s         │ │
│ │ ...  │ ...              │ ...  │ ...      │ ...     │ ...                           │ ...        │ │
│ └──────┴──────────────────┴──────┴──────────┴─────────┴──────────────────────────────┴────────────┘ │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Dashboard Components

### 1. **Top Status Bar** (Green Border)
Shows real-time statistics:
- **Processes**: Total processes being monitored
- **High Risk**: Count of processes above threshold
- **Anomalies**: ML-detected anomalies
- **C2**: C2 beaconing detections
- **Scans**: Port scanning detections
- **Syscalls**: Total syscalls processed

### 2. **Score Information Panel** (Blue Border)
Explains what the scores mean:
- Risk Score ranges and meanings
- Anomaly Score ranges and meanings
- How scores are calculated
- Current threshold setting

### 3. **Main Monitoring Table** (Green Border)
Real-time process monitoring with columns:

| Column | Description | Color Coding |
|--------|-------------|--------------|
| **PID** | Process ID | Cyan |
| **Process** | Process name with status indicator | Green |
| **Risk** | Risk score (0-100) | Green/Yellow/Red based on value |
| **Anomaly** | ML anomaly score | Magenta |
| **Syscalls** | Total syscalls from this process | Blue |
| **Recent Syscalls** | Last 10 unique syscalls | Cyan |
| **Last Update** | Time since last syscall | Dim |

---

## Color Coding

### Process Status Indicators:
- 🟢 **Green dot**: Active (updated in last 5 seconds)
- ⚪ **White dot**: Recent (updated in last 30 seconds)
- ⚫ **Black dot**: Stale (not updated recently)

### Risk Score Colors:
- 🟢 **Green** (0-30): Normal behavior
- 🟡 **Yellow** (30-50): Suspicious
- 🔴 **Red** (50-100): High risk

### Anomaly Score Interpretation:
- **0-10**: Normal
- **10-30**: Unusual
- **30+**: Anomalous (threat)

---

## Real-Time Updates

- **Refresh Rate**: Updates every 0.5 seconds
- **Sorting**: Processes sorted by risk score (highest first)
- **Display Limit**: Top 30 processes shown
- **Auto-scroll**: New high-risk processes appear at top

---

## Example Dashboard Output

When running, you'll see:

```
🛡️  Security Agent Starting...
ℹ️  Score information will be displayed in the dashboard
📝 Log file: logs/security_agent.log

[Then the dashboard appears with live updates]
```

---

## Features

✅ **Real-time monitoring** - Updates every 0.5 seconds  
✅ **Color-coded alerts** - Visual indication of threat levels  
✅ **Process status** - Shows active/recent/stale processes  
✅ **Recent syscalls** - See what each process is doing  
✅ **Statistics** - Live counts of threats and anomalies  
✅ **Score guide** - Built-in explanation of scoring system  

---

## Screenshot

The dashboard uses the `rich` library for beautiful terminal UI with:
- Colored borders
- Formatted tables
- Status indicators
- Real-time updates

**To see it in action**:
```bash
sudo python3 core/simple_agent.py --collector ebpf --threshold 20
```

The dashboard will appear after a few seconds of startup.

---

**Last Updated**: December 5, 2024

