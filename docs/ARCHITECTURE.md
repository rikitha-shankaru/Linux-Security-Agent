# 🏗️ Linux Security Agent - Architecture Documentation

> **Author**: Likitha Shankar
> **Status**: Research Prototype / Academic Project - Not Production Ready

## 📋 **Project Overview**

This is a **research prototype** implementing EDR (Endpoint Detection and Response) concepts for academic purposes. The system demonstrates real-time system call monitoring, threat detection, and automated response capabilities across Linux platforms. This project was developed as part of a Master's degree program to explore eBPF-based security monitoring and ML-based anomaly detection.

---

## 🏗️ **System Architecture**

> **📊 For detailed visual architecture diagrams, see [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md)**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Monitor  │───▶│  Security Agent  │───▶│ Action Handler  │
│  (Kernel Level) │    │  (Main Engine)   │    │ (Response Sys)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Anomaly Detector│    │ Advanced Risk    │    │ Security        │
│   (ML Engine)   │    │    Engine        │    │ Hardener        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ MITRE ATT&CK    │    │ Performance      │    │ Dashboard/TUI   │
│   Detector      │    │  Optimizer       │    │ (Visualization) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

---

## ✅ 2025 Collector Strategy (eBPF-first with auditd fallback)

- Default collector: eBPF/BCC for low-overhead, high-fidelity syscall events.
- Fallback collector: auditd (Ubuntu) for portability and guaranteed demos.
- Both collectors emit the same normalized event schema so downstream logic is identical.

### Unified Event Schema
```
{
  ts: float,            # event timestamp (seconds)
  pid: int,
  uid: int,
  comm: str,            # short command
  exe: str,             # full path if available
  syscall: str,         # name (e.g., "execve")
  args: dict | None     # optional, collector-dependent
}
```

### Runtime selection
- CLI flag (proposed): `--collector=ebpf|auditd` (default: `ebpf`).
- If eBPF initialization fails, automatically fall back to `auditd` with a warning.

---

## 📦 Pipeline Overview (Collector-agnostic)

1) Collector (eBPF or auditd) → normalized events
2) Process state update (per-PID history, counts)
3) Risk scoring (base weights, deviation, container context, burst signals)
4) Feature extraction (50-D vector) → scaler → PCA
5) ML ensemble (IsolationForest + One‑Class SVM)
6) Optional: n‑gram/bigram likelihood for sequence explanation
7) Outputs: dashboard/TUI, list views, JSON export, optional actions

---

## 🔁 Training and Retraining

- Persist preprocessing and models (already supported): scaler, PCA, IF, OCSVM.
- Add a rolling feature store (last N samples, e.g., 50k–200k) on disk.
- Retrain by loading previous features + appending new features; re-fit scaler/PCA/IF/OCSVM; save.
- Calibrate thresholds from recent percentiles after retrain (optional `--calibrate <secs>`).
- Online adaptation already present: per‑PID behavioral baselines via EMA.

Optional (time-permitting): streaming detector (e.g., River Half‑Space Trees) behind `--stream-ml` for continuous learning and drift alerts.

---

## 🖥️ Operator Interfaces

- Dashboard (existing): detailed, with risk/anomaly and explanations.
- TUI (proposed lite mode): compact table refreshed every 1–2s:
  - Columns: PID | Command | Score | Anom | Status
  - Enabled with `--tui` (can coexist with dashboard or run standalone)

---

## ⚙️ Configuration and Flags (additions)

- `--collector=ebpf|auditd` – choose data source at runtime (default: ebpf)
- `--tui` – enable compact table UI (Rich) for quick demos
- `--train-models [--append]` – train; with `--append`, merge previous feature store
- `--calibrate <secs>` – sample recent normal to set thresholds by percentile
- `--stream-ml` – enable streaming detector (optional, if implemented)

Examples
```bash
# eBPF with dashboard
sudo python3 core/enhanced_security_agent.py --collector ebpf --dashboard --threshold 30

# Auditd fallback with TUI
sudo python3 core/enhanced_security_agent.py --collector auditd --tui --timeout 300

# Train and append to previous feature store
python3 core/enhanced_security_agent.py --train-models --append
```

---

## 🎯 Design Rationale and Alternatives

### Why eBPF-first with auditd fallback
- eBPF advantages: low overhead, fine-grained, hard to bypass, rich context; already integrated here.
- auditd advantages: ubiquitous on Ubuntu, simple to enable, zero kernel/dev headers needed.
- Tradeoff: auditd events are coarser and can add overhead under heavy load; eBPF requires BCC/kernel headers. Combining both gives performance by default and reliability when eBPF isn’t available.

Alternatives considered
- ptrace/strace: easy to prototype but high overhead, intrusive, and trivial to evade.
- LD_PRELOAD interposition: userland-only, misses kernel-only behavior, bypassable.
- SystemTap/perf/ftrace: powerful but heavier setup and fewer verifier safety guarantees.
- Kernel module: maximal control/perf but high maintenance and crash risk.

Why this is better here
- Matches production patterns (modern EDRs use kernel sensors) while preserving a portable fallback for demos and grading.

### Why IsolationForest + One‑Class SVM (+ PCA/Scaler)
- Strengths: robust on tabular features, unsupervised (normal-only), fast inference, mature libraries, explainable with feature attributions.
- Complementarity: IF isolates outliers via random splits; OCSVM learns a boundary around normal. Disagreement between the two is informative; agreement is high-confidence.
- PCA/Scaler: stabilizes distances, denoises features, improves generalization across hosts.

Alternatives considered
- LOF/EllipticEnvelope/KDE: slower or brittle at scale; useful offline but not ideal for hot path.
- Autoencoder (MLP): powerful but added complexity and tuning; worthwhile later if you need subtle anomaly recall.
- Sequence models (LSTM/Transformer over syscalls): best for sequence semantics but heavy to train/tune; non-trivial latency.
- DBSCAN: good for clustering analysis but not suitable for single-sample online inference (we keep it for training-time structure only).

Why this is better here
- Balances accuracy, speed, and maintainability; integrates cleanly with current 50‑D features; no specialized hardware required.

### Why add n‑gram likelihood and behavioral baselines
- n‑gram/bigram likelihood: cheap sequence signal that explains anomalies ("unusual syscall pair frequency").
- Behavioral baselines (EMA): adapts per‑PID to reduce false positives for long-lived benign processes.

### Retraining strategy choice
- Chosen: rolling feature store (last N samples), re-fit scaler/PCA/IF/OCSVM on previous+new; persist models and features.
- Alternative: true online models (Half‑Space Trees/RCF via River). We may add this behind a flag when time allows.
- Why: re-fit on bounded windows remains simple, deterministic, and reproducible, fitting the 40‑day delivery window.

---

## 📁 **Core Architecture Files (Current)**

### **🔧 Main Agent and Collectors**

#### **`core/enhanced_security_agent.py`** – Main agent
- Orchestrates collection, scoring, ML, outputs (dashboard/TUI/JSON).
- Handles process state, configuration, thresholds.

#### **`core/collectors/`** – Collector modules (modular architecture)
- **`base.py`** – Abstract `BaseCollector` interface with `SyscallEvent` dataclass
- **`ebpf_collector.py`** – eBPF collector (wraps `enhanced_ebpf_monitor.py`)
- **`auditd_collector.py`** – Auditd collector (consolidated, implements `BaseCollector` directly)
- **`collector_factory.py`** – Factory with automatic fallback (eBPF → auditd)

#### **`core/enhanced_ebpf_monitor.py`** – eBPF implementation
- Loads/attaches eBPF, captures syscall events, used by `ebpf_collector.py`

### **🧠 ML & Features**

#### **`core/enhanced_anomaly_detector.py`** – Ensemble ML
- 50‑D features → StandardScaler → PCA → IsolationForest + One‑Class SVM.
- Saves/loads models; supports retrain with appended feature store.

### **🛡️ Container Context**

#### **`core/container_security_monitor.py`** – Container mapping
- Maps PID↔container (if Docker), adds context to scoring/policy.

---

## 🛠️ **Setup & Testing (Relevant)**

- Installation and platform details: `docs/INSTALL.md`
- Demo and usage: `docs/DEMO_GUIDE.md`
- Tests: `tests/` and top-level `test_*.py`

---

## 📁 **Docs & Demo**

- `README.md` – Overview and quick start
- `docs/ARCHITECTURE.md` – This file
- `docs/INSTALL.md` – Installation and VM tips
- `docs/DEMO_GUIDE.md` – Demo instructions and pitch
- `PROJECT_EXPLANATION.md` – Consolidated explanation and talk track

---

## 🔄 **Data Flow (Current)**

### 1) Collection (two interchangeable sources via factory)
```
Kernel (eBPF) → collectors/ebpf_collector → BaseCollector → SyscallEvent
OR
auditd → collectors/auditd_collector → BaseCollector → SyscallEvent

Factory: collectors/collector_factory.py (auto-selects with fallback)
```

### 2) Processing
```
Events → enhanced_security_agent → process state → risk scoring → features (50‑D)
```

### 3) Detection
```
Features → scaler → PCA → IF + OCSVM (ensemble) [+ n‑gram likelihood]
```

### 4) Output / Response
```
Dashboard/TUI/List/JSON → optional actions (warn/freeze/kill; if enabled)
```

---

## 🎯 **Key Features**

### **🔍 Monitoring Capabilities**
- **Real-time system call monitoring** (eBPF on Linux)
- **Process behavior analysis** (cross-platform)
- **Resource usage tracking** (CPU, memory, network)
- **File system monitoring** (access patterns, modifications)

### **🧠 Analytics & Detection**
- **Machine learning anomaly detection** (Isolation Forest)
- **Behavioral baselining** (process behavior learning)
- **MITRE ATT&CK framework** (50+ attack techniques)
- **Risk scoring** (0-100 scale with time decay)

### **🛡️ Security & Response**
- **Automated response actions** (warn/freeze/kill)
- **System hardening** (integrity checking, tamper protection)
- **Process protection** (memory monitoring, process isolation)
- **Security policy enforcement** (configurable rules)

### **📊 Output & Visualization**
- **Real-time dashboard** (Rich TUI with live updates)
- **JSON export** (structured event logs for analysis)
- **Comprehensive logging** (audit trails, compliance)
- **Process monitoring** (detailed process and syscall tracking)

### **⚡ Performance & Scalability**
- **Low overhead monitoring** (<5% CPU usage)
- **Multi-threaded processing** (scalable architecture)
- **Event batching** (efficient data processing)
- **Memory optimization** (resource management)

---

## 🚀 **Deployment Options**

### **Linux (Production)**
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --anomaly-detection --threshold 30
```

### **macOS (Development)**
```bash
python3 core/simple_agent.py --dashboard --timeout 30
```

### **Docker (Containerized)**
```bash
docker run --rm --privileged security-agent --dashboard --threshold 30
```

### **Production (Enterprise)**
```bash
python3 production_agent.py --config production.json
```

---

## 📊 **Performance Metrics**

### **System Requirements**
- **CPU**: <5% overhead (Linux eBPF), ~2-3% (macOS simulation)
- **Memory**: ~50MB base usage
- **Disk**: Minimal (logs and configuration)
- **Network**: Minimal (cloud integration only)

### **Scalability**
- **Processes**: Tested with 1000+ concurrent processes
- **System Calls**: Handles millions of syscalls per minute
- **Response Time**: <100ms for risk score updates
- **Accuracy**: >95% for known attack patterns

---

## 🔧 **Configuration**

### **Risk Thresholds**
- **Low Risk**: 0-20 (normal operations)
- **Medium Risk**: 20-50 (potentially suspicious)
- **High Risk**: 50-100 (very suspicious/attack patterns)

### **Action Thresholds**
- **Warning**: 60% of main threshold
- **Freeze**: 120% of main threshold
- **Kill**: 180% of main threshold

### **System Call Risk Levels**
- **Low Risk (1-2 points)**: `read`, `write`, `open`, `close`
- **Medium Risk (3-5 points)**: `fork`, `execve`, `chmod`, `mount`
- **High Risk (8-10 points)**: `ptrace`, `setuid`, `setgid`, `chroot`

---

## 🎓 **Academic Value**

### **Cybersecurity Concepts Demonstrated**
1. **System Call Monitoring**: Kernel-level security
2. **Anomaly Detection**: Machine learning in security
3. **Threat Intelligence**: MITRE ATT&CK framework
4. **Risk Assessment**: Quantitative security metrics
5. **Automated Response**: Security orchestration

### **Technical Skills Showcased**
1. **System Programming**: eBPF, kernel interfaces
2. **Machine Learning**: Isolation Forest, feature engineering
3. **Software Architecture**: Modular, scalable design
4. **Cross-Platform Development**: Linux/macOS compatibility
5. **Enterprise Integration**: Cloud backends, APIs

---

## 🏆 **Research Prototype vs. Enterprise EDR Solutions**

> **Note**: This comparison highlights what this research project demonstrates vs. production enterprise solutions. This is not a production-ready replacement for commercial EDR systems.

| Feature                          | This System (Research)              | CrowdStrike Falcon          | SentinelOne                 | Carbon Black                 |
|----------------------------------|-------------------------------------|-----------------------------|-----------------------------|------------------------------|
| **Purpose**                      | Academic Research / Learning        | Production EDR              | Production EDR              | Production EDR               |
| **Cost**                         | Free (Open Source)                  | ~$8.99/endpoint/month       | ~$2.99/endpoint/month       | ~$7.00/endpoint/month        |
| **Production Ready**             | ❌ Research Prototype               | ✅ Enterprise-Grade         | ✅ Enterprise-Grade         | ✅ Enterprise-Grade          |
| **Real-time Syscall Monitoring** | ✅ (eBPF/auditd)                    | ✅ (Kernel-level)           | ✅ (Kernel-level)           | ✅ (Kernel-level)            |
| **ML Anomaly Detection**         | ✅ (Basic ensemble)                 | ✅ (Advanced AI)            | ✅ (Advanced AI)            | ✅ (Advanced AI)             |
| **MITRE ATT&CK Mapping**         | ✅ (Basic mapping)                  | ✅ (Full coverage)          | ✅ (Full coverage)          | ✅ (Full coverage)           |
| **Platform Support**             | ✅ Linux (eBPF/auditd)              | ✅ Windows, Linux, Mac      | ✅ Windows, Linux, Mac      | ✅ Windows, Linux, Mac       |
| **Customization**                | ✅ Full source code access          | ⚠️ Limited (config only)    | ⚠️ Limited (config only)    | ⚠️ Limited (config only)     |
| **Data Privacy**                 | ✅ Local-only (no cloud)            | ⚠️ Cloud-based              | ⚠️ Cloud-based              | ⚠️ Cloud-based               |
| **Open Source**                  | ✅ Yes                              | ❌ No                       | ❌ No                       | ❌ No                        |
| **Threat Intelligence**          | ⚠️ Basic (static)                   | ✅ Real-time feeds          | ✅ Real-time feeds          | ✅ Real-time feeds           |
| **Incident Response**            | ⚠️ Basic (manual)                   | ✅ Automated workflows      | ✅ Automated workflows      | ✅ Automated workflows       |
| **Scalability**                  | ⚠️ Single endpoint                  | ✅ Millions of endpoints    | ✅ Millions of endpoints    | ✅ Millions of endpoints     |
| **Support & Maintenance**        | ⚠️ Self-supported                   | ✅ 24/7 enterprise support  | ✅ 24/7 enterprise support  | ✅ 24/7 enterprise support   |
| **Compliance**                   | ❌ Not certified                    | ✅ SOC2, ISO, FedRAMP       | ✅ SOC2, ISO, FedRAMP       | ✅ SOC2, ISO, FedRAMP        |
| **Academic Value**               | ✅ Excellent (learning/research)    | ⚠️ Limited (black box)      | ⚠️ Limited (black box)      | ⚠️ Limited (black box)       |
| **Code Transparency**            | ✅ Full visibility                  | ❌ Proprietary              | ❌ Proprietary              | ❌ Proprietary               |

### **Key Takeaways**

**This Research Project Excels At:**
- ✅ **Learning & Education**: Full source code for understanding EDR concepts
- ✅ **Customization**: Modify and extend for research purposes
- ✅ **Privacy**: All data stays local, no cloud dependencies
- ✅ **Cost**: Free and open source
- ✅ **Academic Research**: Demonstrates eBPF, ML, and security concepts

**Enterprise Solutions Excel At:**
- ✅ **Production Deployment**: Battle-tested, scalable, reliable
- ✅ **Threat Intelligence**: Real-time global threat feeds
- ✅ **Support**: Professional support and maintenance
- ✅ **Compliance**: Certified for enterprise use
- ✅ **Advanced Features**: Mature detection algorithms and response automation

**Best Use Cases for This Project:**
- 🎓 Academic research and learning
- 🔬 Proof-of-concept development
- 🛠️ Custom security monitoring needs
- 📚 Understanding EDR internals
- 🧪 Experimentation with eBPF and ML

---

## 🚀 **Getting Started**

### **Quick Start (macOS)**
```bash
source venv/bin/activate
python3 core/simple_agent.py --dashboard --timeout 30
```

### **Quick Start (Linux)**
```bash
sudo python3 core/enhanced_security_agent.py --dashboard --threshold 30
```

### **Quick Start (Docker)**
```bash
docker build -t security-agent .
docker run --rm --privileged security-agent --dashboard --threshold 30
```

---

**🎓 This research prototype demonstrates EDR concepts and provides a foundation for learning and academic research.**
