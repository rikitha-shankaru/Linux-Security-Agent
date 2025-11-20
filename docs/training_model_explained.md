# Detailed explanation: how the training model works

## Overview

The system uses unsupervised machine learning to detect anomalies. It learns normal behavior from real system activity and flags deviations.

---

## Part 1: Initial training process

### Step 1: Data collection (60 seconds)

When you run `--train-models`, the system collects real syscall data:

```python
# Location: core/enhanced_security_agent.py, _train_anomaly_models()

1. Starts 60-second collection window
2. Every 0.5 seconds, scans all monitored processes
3. For each process with 5+ syscalls:
   - Takes last 50 syscalls (recent behavior window)
   - Gets process metrics: CPU%, memory%, thread count
   - Creates training sample: (syscalls_list, process_info_dict)
4. Stops at 500 samples OR after 60 seconds
```

What gets collected:
- Real syscalls from eBPF (e.g., `['read', 'write', 'open', 'close', 'mmap', 'read', 'write', ...]`)
- Process metrics from psutil (CPU, memory, threads)
- Only from processes with enough activity (5+ syscalls)

Why 50 syscalls per sample:
- Captures short-term patterns
- Balances detail and performance
- Enough to see sequences like `open → read → write → close`

### Step 2: Baseline supplementation (if needed)

If < 50 real samples:
- Uses synthetic baseline patterns (text editor, browser, shell, file manager)
- Ensures training can proceed

If 50-100 samples:
- Mixes real + baseline data

If 100+ samples:
- Uses only real data

### Step 3: Feature extraction (50-dimensional vectors)

Each training sample `(syscalls, process_info)` is converted to a 50-feature vector:

```python
# Location: core/enhanced_anomaly_detector.py, extract_advanced_features()

Features 0-7: Common syscall frequencies (8 features)
  - Frequency of: read, write, open, close, mmap, munmap, fork, execve
  - Example: If 30% of syscalls are 'read' → feature[0] = 0.30

Feature 8: Unique syscall ratio (1 feature)
  - How diverse? unique_syscalls / total_syscalls
  - Example: 20 unique syscalls out of 50 total → 0.40

Feature 9: Syscall entropy (1 feature)
  - Information entropy: -Σ(p * log2(p))
  - Measures randomness/diversity
  - High entropy = diverse, low entropy = repetitive

Feature 10: High-risk syscall ratio (1 feature)
  - Frequency of: ptrace, mount, setuid, setgid, chroot, reboot
  - Example: 5 risky syscalls out of 50 → 0.10

Features 11-14: Temporal features (4 features)
  - Total syscalls in window
  - Estimated syscall rate (per second)
  - Average interval between syscalls
  - Max interval between syscalls

Feature 15: Network syscall ratio (1 feature)
  - Frequency of: socket, bind, listen, accept, connect, send, recv

Feature 16: File system syscall ratio (1 feature)
  - Frequency of: open, close, read, write, stat, fstat, lstat

Features 17-19: Resource usage (3 features)
  - CPU percent / 100
  - Memory percent / 100
  - Thread count / 100

Features 20-49: Advanced patterns (30 features)
  - Bigram frequencies (syscall pairs like "read_write", "open_read")
  - Sequence pattern frequencies
  - Repetitive pattern detection
```

Why 50 features:
- Captures multiple aspects (frequency, diversity, risk, patterns)
- Enough detail without overfitting
- Standardized size for all models

### Step 4: Preprocessing pipeline

Before training, features are preprocessed:

```python
# Location: core/enhanced_anomaly_detector.py, train_models()

1. StandardScaler (Normalization)
   - Converts features to mean=0, std=1
   - Why: Different scales (CPU% vs syscall count)
   - Example: CPU 50% → normalized to ~0.0

2. PCA (Dimensionality Reduction)
   - Reduces 50 features → 10 principal components
   - Why: Speeds training, removes redundancy, keeps 95%+ variance
   - Example: 50D → 10D (5x smaller, faster)
```

### Step 5: Model training (ensemble of 3 models)

Three models are trained on the preprocessed features:

#### Model 1: Isolation Forest

```python
# Algorithm: Random trees that isolate anomalies
# How it works:
1. Builds 200 random decision trees
2. Each tree randomly splits features
3. Anomalies are isolated quickly (fewer splits needed)
4. Normal data requires more splits

# Output:
- prediction: -1 (anomaly) or 1 (normal)
- decision_function: negative score = anomaly (more negative = more anomalous)
```

Why Isolation Forest:
- Fast training and inference
- Good for high-dimensional data
- Unsupervised (no labels needed)

#### Model 2: One-Class SVM

```python
# Algorithm: Learns a boundary around normal data
# How it works:
1. Maps features to high-dimensional space (RBF kernel)
2. Finds smallest sphere that contains most normal data
3. Points outside sphere = anomalies

# Output:
- prediction: -1 (anomaly) or 1 (normal)
- decision_function: distance from boundary (negative = outside = anomaly)
```

Why One-Class SVM:
- Learns a clear normal boundary
- Good for non-linear patterns
- Complements Isolation Forest

#### Model 3: DBSCAN

```python
# Algorithm: Density-based clustering
# How it works:
1. Groups similar behaviors into clusters
2. Points in dense regions = normal
3. Points in sparse regions = anomalies (noise)

# Note: Used mainly for training-time analysis
# Not used for single-sample prediction (requires batch data)
```

Why DBSCAN:
- Identifies behavior clusters
- Useful for analysis
- Not used for real-time detection

### Step 6: Model persistence

Trained models are saved to disk:

```
~/.cache/security_agent/
├── isolation_forest.pkl    # Isolation Forest model
├── one_class_svm.pkl       # One-Class SVM model
├── scaler.pkl             # Feature scaler (for normalization)
├── pca.pkl                # PCA transformer (for dimensionality reduction)
├── training_features.npy  # Feature store (for incremental retraining)
└── ngram_bigrams.json     # Bigram probabilities (for sequence analysis)
```

---

## Part 2: Inference (anomaly detection)

When monitoring, each process is analyzed:

### Step 1: Feature extraction

```python
# Same 50-feature extraction as training
features = extract_advanced_features(current_syscalls, process_info)
# Returns: numpy array of 50 floats
```

### Step 2: Preprocessing

```python
# Use SAVED scaler and PCA from training
features_scaled = scaler.transform(features)  # Normalize
features_pca = pca.transform(features_scaled)  # Reduce to 10D
```

### Step 3: Ensemble prediction

```python
# Run through both models
isolation_forest_prediction = isolation_forest.predict(features_pca)  # -1 or 1
isolation_forest_score = isolation_forest.decision_function(features_pca)  # Distance

one_class_svm_prediction = one_class_svm.predict(features_pca)  # -1 or 1
one_class_svm_score = one_class_svm.decision_function(features_pca)  # Distance

# Ensemble voting
anomaly_votes = sum([if_pred == -1, svm_pred == -1])  # Count anomalies
is_anomaly = anomaly_votes >= 1  # If 1+ models say anomaly → flag it
```

### Step 4: Score calculation

```python
# Normalize scores from both models
if_score_normalized = max(0, -isolation_forest_score / 10.0)  # Convert to 0-1
svm_score_normalized = max(0, -one_class_svm_score / 10.0)  # Convert to 0-1

# Weighted average
ensemble_score = (if_score_normalized + svm_score_normalized) / 2

# Add n-gram rarity (sequence-based anomaly)
ngram_rarity = calculate_bigram_rarity(syscalls)  # 0-1 (higher = rarer)
final_score = ensemble_score * 100 + ngram_rarity * 20  # 0-100 scale
```

### Step 5: Explanation generation

```python
# Human-readable explanation
if isolation_forest_prediction == -1:
    explanation += "Isolation Forest detected outlier behavior; "
if svm_prediction == -1:
    explanation += "One-Class SVM identified deviation from normal; "
if high_risk_ratio > 0.1:
    explanation += "High proportion of risky system calls; "
```

---

## Part 3: Incremental retraining (automatic)

The system automatically retrains models during monitoring.

### How sample collection works

```python
# Location: core/enhanced_security_agent.py, _collect_training_sample()

During monitoring, for each process:
1. Check if process is LOW RISK (risk_score < 30) ← Only normal behavior!
2. Check if process has 20+ syscalls (enough data)
3. Check if syscall_count % 50 == 0 (sample every 50 syscalls)
4. If all true:
   - Get FRESH syscalls from process dict (not stale snapshot)
   - Get current process metrics
   - Store sample in memory (max 10,000 samples)
```

Why only low-risk processes:
- Trains on normal behavior
- Avoids learning attack patterns
- Reduces false positives

### Automatic retraining loop

```python
# Location: core/enhanced_security_agent.py, _incremental_retrain_loop()

Background thread runs continuously:
1. Every 60 seconds, check:
   - Has 1 hour passed since last retrain? (configurable)
   - Do we have 100+ new samples? (configurable)
   - Are models already trained?
   
2. If all true:
   - Collect samples from memory (e.g., 150 samples)
   - Load previous feature store from disk (e.g., 5000 samples)
   - COMBINE: 5000 old + 150 new = 5150 total
   - Keep last 200,000 samples (bound memory)
   - Retrain all 3 models on combined data
   - Save updated models and feature store
   - Clear in-memory samples (start collecting again)
```

Why combine old + new:
- Models adapt to system changes
- Retains historical patterns
- Improves accuracy over time

### Feature store append process

```python
# Location: core/enhanced_anomaly_detector.py, train_models(append=True)

if append:
    prev_features = load_feature_store()  # Load from disk
    if prev_features.shape[1] == new_features.shape[1]:  # Same dimensions?
        combined = np.vstack([prev_features, new_features])  # Stack vertically
        if combined.shape[0] > 200000:  # Too many?
            combined = combined[-200000:]  # Keep last 200K
        features = combined  # Train on combined data
    else:
        # Dimension mismatch! (code changed)
        logger.error("Feature dimension mismatch - starting fresh")
        # Use only new data
```

---

## Part 4: N-gram model (sequence analysis)

In addition to ML models, there's a lightweight bigram model:

### Training bigrams

```python
# Location: core/enhanced_anomaly_detector.py, _train_bigrams_from_training()

For each training sequence:
1. Extract bigrams (pairs): "read_write", "open_read", "write_close"
2. Count frequencies: bigram_counts["read_write"] = 15
3. Calculate probabilities with add-one smoothing:
   P(write|read) = (count("read_write") + 1) / (count("read") + vocab_size)
4. Store probabilities in ngram_bigram_probs dict
```

### Using bigrams for detection

```python
# Location: core/enhanced_anomaly_detector.py, _avg_bigram_prob()

For current syscall sequence:
1. Extract bigrams: ["read_write", "write_open", "open_close"]
2. Look up probabilities: P(write|read), P(open|write), P(close|open)
3. Calculate average probability
4. Convert to rarity score: (avg_prob - reference_prob) / reference_prob
5. Higher rarity = more anomalous sequence
```

Why bigrams:
- Captures sequence patterns
- Fast to compute
- Complements ML models

---

## Summary: complete training flow

```
┌─────────────────────────────────────────────────────────┐
│ INITIAL TRAINING (Manual: --train-models)              │
├─────────────────────────────────────────────────────────┤
│ 1. Collect 60 seconds of real syscall data             │
│ 2. Extract 50 features per sample                      │
│ 3. Normalize + PCA (50D → 10D)                        │
│ 4. Train 3 models: IF, OCSVM, DBSCAN                   │
│ 5. Train bigram model                                  │
│ 6. Save models + feature store to disk                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ MONITORING (Runtime)                                    │
├─────────────────────────────────────────────────────────┤
│ 1. Capture syscalls via eBPF                           │
│ 2. Extract 50 features                                  │
│ 3. Normalize + PCA (using saved transformers)          │
│ 4. Run through IF + OCSVM                              │
│ 5. Ensemble voting + scoring                           │
│ 6. Add bigram rarity                                   │
│ 7. Return anomaly score (0-100)                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ INCREMENTAL RETRAINING (Automatic, every 1 hour)       │
├─────────────────────────────────────────────────────────┤
│ 1. Collect samples from low-risk processes             │
│ 2. Wait for 100+ samples + 1 hour                      │
│ 3. Load previous feature store from disk               │
│ 4. Combine old + new features                          │
│ 5. Retrain all 3 models                                │
│ 6. Save updated models                                  │
│ 7. Clear in-memory samples                             │
└─────────────────────────────────────────────────────────┘
```

---

## Key concepts

1. Unsupervised learning: learns normal behavior without labeled attacks
2. Ensemble approach: combines multiple models for better accuracy
3. Feature engineering: 50 features capture behavior patterns
4. Incremental learning: adapts over time automatically
5. Sequence analysis: bigrams capture syscall patterns

This enables the system to learn normal behavior and detect deviations without manual labeling.