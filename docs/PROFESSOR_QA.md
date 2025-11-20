## Professor Q&A: eBPF, ML Anomaly Detection, Scoring, and Safe Malware Simulation

This guide explains how the project uses eBPF, how the ML anomaly detection is trained and decides “normal vs abnormal,” how syscall-based risk scoring works, and how to safely simulate malware-like behavior for demos without harming the system.

References to repository files are provided inline using backticks for quick navigation.

---

## 1) eBPF: How it works, why we use it, and alternatives

### How eBPF works
- Userspace loads a small, sandboxed program into the Linux kernel using the `bpf()` syscall.
- The kernel’s verifier checks safety: memory bounds, guaranteed termination, valid helper calls.
- If verified, the kernel JIT-compiles the bytecode to native machine code (fast) or interprets it.
- The program is attached to a kernel hook (e.g., syscall tracepoints, kprobes/fentry, network XDP/TC, LSM).
- Data flows between kernel and userspace through eBPF maps (hash/array/LRU), perf/ring buffers.

In this project, our eBPF layer captures system call activity and relevant process context, which the userspace agent consumes for feature extraction and anomaly detection.

Relevant files:
- `core/enhanced_ebpf_monitor.py` (collector/orchestration for syscall events)
- `core/enhanced_security_agent.py` (agent that wires collection → features → ML detection → response)

### Why eBPF for this project
- **Low overhead, high fidelity**: Observe syscalls and kernel events at the source with minimal latency.
- **Safety and agility**: Dynamic load/unload at runtime (no kernel modules), verifier reduces crash risk.
- **Precision**: Attach exactly at function entry/exit or tracepoints for rich context.
- **Production friendly**: Modern kernels support eBPF widely; tooling ecosystem (bcc/libbpf) is mature.

### Alternative approaches and tradeoffs
- **auditd/audisp**: Stable and easy; events are coarser and can be higher overhead under load.
- **ptrace/strace**: Simple prototypes; high overhead, intrusive, easier for adversaries to evade.
- **LD_PRELOAD interposition**: Userland only, bypassable, misses kernel-only activity.
- **SystemTap/perf/ftrace**: Powerful tracing; more setup, often root-heavy; fewer safety guarantees vs eBPF verifier.
- **Kernel modules**: Maximal power/perf but brittle and risky; maintenance and crash risk are high.
- **fanotify/inotify**: Great for filesystem monitoring but limited for process/network/syscall correlations.

We favor eBPF for its safety/performance balance and the precision needed for syscall-centric anomaly detection.

---

## 2) ML model training: how it learns “normal” vs “abnormal”

### Approach overview
- The detector is unsupervised and trained on normal behavior only.
- It extracts a fixed 50-dimensional feature vector from syscall sequences and process metrics.
- Preprocessing: standardization (scaler) + dimensionality reduction (PCA).
- Ensemble models: Isolation Forest and One-Class SVM are used at inference time; DBSCAN is trained for structure understanding but skipped for single-sample predictions.

Entry points:
- Feature extraction: `core/enhanced_anomaly_detector.py` → `extract_advanced_features(...)`
- Training: `core/enhanced_anomaly_detector.py` → `train_models(...)`
- Inference: `core/enhanced_anomaly_detector.py` → `detect_anomaly_ensemble(...)`

### What “normal” means
- During training, you provide samples of normal workload behavior: `(syscalls, process_info)` pairs.
- The scaler and PCA learn the distribution of these features; IF/OCSVM learn the “manifold” of normal.
- At runtime, samples that fall outside this learned region produce negative decision scores and are flagged as anomalies.

### Behavioral baselining and adaptation
- Per-PID baselines are kept in-memory and updated using an exponential moving average (EMA):
  - Syscall frequency profiles per process
  - Recent resource usage (CPU, memory)
- This reduces false positives for long-running benign services that evolve over time.

Relevant file: `core/enhanced_anomaly_detector.py` (classes `EnhancedAnomalyDetector`, `BehavioralBaseline`).

---

## 3) System call scoring: from events to risk score

### Feature engineering (50 features)
- **Frequencies**: Common syscalls (e.g., `read`, `write`, `open`, `close`, `mmap`, `fork`, `execve`).
- **Diversity**: Unique syscall ratio and entropy.
- **High-risk ratio**: Proportion of calls like `ptrace`, `mount`, `umount`, `setuid`, `setgid`, `chroot`, `reboot`.
- **Temporal proxies**: Approximate syscall rate/burstiness (real timestamps can improve this further).
- **Subsystem ratios**: Network-related vs filesystem-related syscall proportions.
- **Process metrics**: CPU percent, memory percent, number of threads (normalized).
- **Sequence structure**: Bigram frequency and repetitive pattern indicators.

Implementation: `core/enhanced_anomaly_detector.py` → `extract_advanced_features(...)`.

### Ensemble decision and risk computation
- Each model produces a prediction and a decision score:
  - Isolation Forest / One-Class SVM return `-1` for outliers and a (typically negative) decision function for anomalies.
- Majority vote decides `is_anomaly`.
- Negative decision scores are normalized and combined into an `ensemble_score`.
- Risk score is scaled to `0–100` from the normalized ensemble score.
- An explanation string is generated (e.g., “High proportion of risky system calls”).

Implementation: `core/enhanced_anomaly_detector.py` → `detect_anomaly_ensemble(...)`.

---

## 4) Safely simulating malware-like behavior (for demos)

Goal: trigger detection without harming the host.

### Safety checklist
- Run inside a VM or disposable container/namespace whenever possible.
- Use a non-root user; avoid privilege escalation attempts that could succeed.
- Avoid destructive operations: no real `mount`, `chroot`, `reboot`, filesystem changes outside `/tmp`, or credential modifications.
- Keep tests short-lived and resource-bounded; clean up temp files.

### Benign-but-suspicious patterns to trigger anomalies
- Rapid bursts of file operations in `/tmp` (open/read/write/close loops with small files).
- Brief CPU spikes and process churn (spawn/exec short helpers, then exit).
- Localhost socket open/close cycles (e.g., connect to a closed port and handle errors).
- Attempt to `ptrace` your own PID (expect `EPERM`), then continue; this raises the high-risk syscall ratio without impact.
- Repeated unusual syscall bigrams (e.g., failed `setuid` attempts followed by network calls).

### Existing demos and integration
- `demo/normal_behavior.py` and `demo/suspicious_behavior.py` provide side-by-side scenarios.
- `demo/run_demo.py` and `scripts/run_demo.sh` orchestrate full runs.
- You can add a new “safe malware simulator” that:
  - Performs 200–500 temp file ops in `/tmp`.
  - Executes short-lived subprocesses in a loop.
  - Opens/closes a localhost socket a few times.
  - Attempts `ptrace` on self and ignores the error.
  - Exits after ~5–15 seconds.

Run the agent alongside this script to show anomaly scores and explanations produced by `EnhancedAnomalyDetector` in `core/enhanced_anomaly_detector.py`.

---

## Talking points (concise answers)

- **eBPF works by** loading verified programs into the kernel that run at hooks and send structured events back to userspace with low overhead and high safety.
- **We chose eBPF** for precision, safety, and performance. Alternatives (auditd, ptrace, SystemTap, kernel modules) trade off safety, fidelity, or maintainability.
- **The ML model learns normal** from normal-only training data; IF/OCSVM model the normal manifold. Deviations (negative decision scores) are anomalies.
- **Scoring** uses engineered syscall features → scaler/PCA → model decisions → majority vote → normalized risk score (0–100) plus human-readable explanation.
- **Safe malware simulation**: use benign but suspicious patterns (bursty files, exec churn, localhost sockets, self-ptrace) in a VM/container to trigger detection without damage.

---

## Pointers for deeper review
- eBPF integration: `core/enhanced_ebpf_monitor.py`
- ML pipeline and scoring: `core/enhanced_anomaly_detector.py`
- Agent orchestration: `core/enhanced_security_agent.py`
- Demos: `demo/normal_behavior.py`, `demo/suspicious_behavior.py`, `demo/run_demo.py`
- Quick start and testing: `docs/DEMO_GUIDE.md`, `tests/run_tests.py`


