# Risk Score and Anomaly Score Explanation

## Quick Answers

### 1. Does Anomaly Score Reset Every Time?

**Yes, anomaly scores reset every time you restart the agent.**

- Anomaly scores are calculated **in real-time** during monitoring
- They are **NOT persisted** between agent runs
- Each time you start the agent, scores start at 0.00
- Scores are calculated fresh based on current process behavior

**What IS persisted:**
- ✅ ML models (trained models are saved to `~/.cache/security_agent/`)
- ✅ Risk scorer baselines (in memory during a run, but reset on restart)

**What is NOT persisted:**
- ❌ Anomaly scores
- ❌ Risk scores
- ❌ Process tracking data

### 2. Is the Attack Code Working?

**Yes, but there are important considerations:**

#### Attack Simulation Status:
- ✅ All attack patterns execute successfully
- ✅ They generate real syscalls (open, read, write, fork, execve, socket, etc.)
- ✅ The agent captures these syscalls via eBPF

#### Why You Might Not See High Risk Scores:

1. **Timing Issue**: Attacks must run **WHILE the agent is monitoring**
   - If you run attacks before starting the agent, they won't be detected
   - If attacks finish too quickly, the agent might miss them

2. **Process Lifetime**: Attack processes are short-lived
   - They spawn, do work, and exit quickly
   - The agent needs time to accumulate syscalls and calculate scores
   - Risk scores build up over time as more syscalls are captured

3. **Normalization**: Risk scores are normalized
   - High-frequency attacks might not immediately spike scores
   - Scores build up as the agent observes patterns over time

#### How to Test Properly:

```bash
# Terminal 1: Start agent
sudo python3 core/simple_agent.py --collector ebpf --threshold 30

# Terminal 2: Run attacks WHILE agent is running
python3 scripts/simulate_attacks.py

# Watch Terminal 1 for risk score spikes
```

---

## Score Ranges Explained

### Risk Score (0-100)

**Calculation:**
- Based on syscall types, frequencies, and behavioral patterns
- Combines: base syscall risk + behavioral deviation + anomaly weight + container adjustments

**Ranges:**
- **0-30 (Normal)**: Typical system operations
  - Examples: read, write, open, close, stat
  - Normal process behavior
  
- **30-50 (Suspicious)**: Unusual patterns detected
  - Examples: rapid file creation/deletion, unusual syscall sequences
  - Worth investigating but not necessarily malicious
  
- **50-100 (High Risk)**: Potential threat
  - Examples: privilege escalation attempts, rapid process spawning, suspicious network activity
  - Should be investigated immediately

**Default Threshold:** 30.0 (configurable with `--threshold`)

### Anomaly Score (ML-based)

**Calculation:**
- Uses ensemble ML models (Isolation Forest, One-Class SVM, DBSCAN)
- Compares current behavior to learned baseline patterns
- Detects deviations from normal behavior

**Ranges:**
- **0.00-10.00 (Normal)**: Matches learned behavior patterns
  - Process behavior is consistent with training data
  - Low deviation from baseline
  
- **10.00-30.00 (Unusual)**: Deviates from baseline
  - Process shows some unusual patterns
  - May indicate new behavior or potential issue
  
- **30.00+ (Anomalous)**: Significant deviation
  - Strong indication of anomalous behavior
  - Likely threat or unusual activity

**Note:** Anomaly scores can be negative (from ML models), but are displayed as absolute values in the dashboard.

---

## How Scores Work Together

1. **Risk Score** = Rule-based + Behavioral analysis
   - Fast, deterministic
   - Based on known patterns and syscall types
   
2. **Anomaly Score** = ML-based detection
   - Learns from training data
   - Detects unknown patterns
   
3. **Combined Detection**:
   - High Risk + High Anomaly = Strong threat signal
   - High Risk + Low Anomaly = Known suspicious pattern
   - Low Risk + High Anomaly = Unusual but not necessarily dangerous
   - Both low = Normal behavior

---

## Dashboard Display

The dashboard now shows:
- **Live process monitoring table** with PID, Process, Risk, Anomaly, Syscalls
- **Info panel** explaining score ranges (always visible)
- **Statistics** showing total processes, high risk count, anomalies, syscalls

**Color Coding:**
- 🟢 Green: Normal (Risk 0-30)
- 🟡 Yellow: Suspicious (Risk 30-50)
- 🔴 Red: High Risk (Risk 50+)

---

## Tips for Testing

1. **Start agent first**, then run attacks
2. **Let agent run for 10-30 seconds** before running attacks (to establish baselines)
3. **Run attacks slowly** (add delays) to give agent time to capture syscalls
4. **Watch the dashboard** in real-time to see scores update
5. **Check anomaly scores** - they should increase during attacks if ML models are trained

---

## Troubleshooting

**Q: Why are all risk scores low (5-15)?**
- A: Normal system processes have low risk. Run attack simulation to see spikes.

**Q: Why are anomaly scores 0.00?**
- A: ML models not trained. Run: `python3 scripts/train_with_dataset.py --file datasets/normal_behavior_dataset.json`

**Q: Attacks ran but no high risk scores?**
- A: Make sure agent is running WHILE attacks execute. Check timing.

**Q: Scores reset when I restart?**
- A: Yes, this is expected. Scores are calculated in real-time, not persisted.

