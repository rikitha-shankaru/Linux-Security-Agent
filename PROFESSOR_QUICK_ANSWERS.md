# Quick Answers for Professor - One Page Summary

## 1. Why eBPF Over auditd?

**Short Answer:**
"eBPF provides 10-100x better performance through zero-copy architecture and kernel-space execution. It enables real-time detection with < 5% CPU overhead, critical for production security monitoring."

**Technical Details:**
- **Performance**: 10-100x faster (zero-copy vs disk I/O)
- **Overhead**: < 5% CPU (vs 10-30% for auditd)
- **Latency**: Microseconds (vs milliseconds)
- **Event Rate**: 100,000+ syscalls/sec (vs ~10,000/sec)
- **Architecture**: Kernel-space execution, shared memory (vs file I/O)

**Research Basis**: "Programmable System Call Security with eBPF" (2023)

**Code**: `core/enhanced_ebpf_monitor.py` (eBPF) vs `core/collector_auditd.py` (fallback)

---

## 2. How Does ML Model Training Work?

**Short Answer:**
"Unsupervised learning: collects 500+ real syscall samples during 60-second training window, extracts 50-D features, trains ensemble of Isolation Forest + One-Class SVM + DBSCAN on normal behavior. Models learn what's normal, flag deviations as anomalies."

**Training Process:**
1. **Data Collection** (60 seconds): Collects real syscalls from kernel via eBPF
2. **Feature Extraction**: Converts to 50-D feature vectors (frequencies, entropy, patterns)
3. **Model Training**: Trains 3-model ensemble (Isolation Forest, One-Class SVM, DBSCAN)
4. **Incremental Learning**: Automatically retrains every hour with new data

**Training with Public Datasets:**
- ✅ Supports JSON format datasets
- ✅ Can load from file, URL, or directory
- ✅ Format: `{"samples": [{"syscalls": [...], "process_info": {...}}]}`

**Code**: 
- Collection: `core/enhanced_security_agent.py` - `_train_anomaly_models()`
- Training: `core/enhanced_anomaly_detector.py` - `train_models()`
- Dataset loading: `core/enhanced_anomaly_detector.py` - `load_training_data_from_file()`

---

## 3. How to Test with Actual Attacks?

**Short Answer:**
"Run safe attack simulation scripts that trigger suspicious patterns (privilege escalation attempts, high-frequency syscalls, etc.). The agent detects these in real-time, showing risk scores 50-100 and ML anomaly flags."

**Quick Test:**
```bash
# Terminal 1: Run agent
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30

# Terminal 2: Run attacks
python3 scripts/simulate_attacks.py
```

**Attack Patterns Simulated:**
1. Privilege escalation (setuid, setgid, execve)
2. High-frequency attacks (DoS pattern)
3. Suspicious file operations
4. Process churn (rapid fork/exec)
5. Network scanning
6. Ptrace attempts

**All Safe:**
- ✅ No actual privilege escalation (attempts fail)
- ✅ No destructive operations
- ✅ Only uses `/tmp`
- ✅ Limited duration

**Expected Results:**
- Risk scores: 50-100 (vs < 30 for normal)
- ML anomaly: ✅ DETECTED
- Explanations: "High proportion of risky system calls"

**Code**: `scripts/simulate_attacks.py`

---

## 📊 Summary Table

| Question | Answer |
|----------|--------|
| **Why eBPF?** | 10-100x faster, < 5% overhead, real-time |
| **Training?** | 500+ samples, 50-D features, 3-model ensemble |
| **Test Attacks?** | `scripts/simulate_attacks.py` - safe attack patterns |
| **Public Datasets?** | ✅ Supported via `scripts/train_with_dataset.py` |

---

## 🎯 Demo Script

```bash
# 1. Show normal behavior (low risk)
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
# Run: ls, cat, ps in another terminal → Risk < 30

# 2. Run attack simulation
python3 scripts/simulate_attacks.py
# → Risk spikes to 50-100, ML flags as anomalous

# 3. Point out:
#    - Real-time detection
#    - Risk score differences
#    - ML anomaly explanations
```

---

**See Also:**
- `PROFESSOR_ANSWERS.md` - Detailed answers
- `TESTING_WITH_ATTACKS.md` - Complete testing guide
- `docs/PROFESSOR_TECHNICAL_ANSWERS.md` - Technical deep dive

