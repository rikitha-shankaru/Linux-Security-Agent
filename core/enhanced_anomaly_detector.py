#!/usr/bin/env python3
"""
Enhanced Anomaly Detection with Unsupervised Learning
Based on recent research: U-SCAD and advanced ML techniques (2024-2025)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from collections import deque, defaultdict, Counter
import pickle
import os
import time
import random
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import warnings
warnings.filterwarnings('ignore')

@dataclass
class AnomalyResult:
    """Structured anomaly detection result"""
    pid: int
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    features: Dict[str, float]
    explanation: str
    timestamp: float
    model_used: str

@dataclass
class BehavioralBaseline:
    """Behavioral baseline for a process"""
    pid: int
    syscall_frequencies: Dict[str, float]
    temporal_patterns: Dict[str, float]
    resource_usage: Dict[str, float]
    network_patterns: Dict[str, float]
    file_access_patterns: Dict[str, float]
    last_updated: float
    sample_count: int

class EnhancedAnomalyDetector:
    """
    Enhanced anomaly detector with multiple ML algorithms and behavioral baselining
    Based on U-SCAD research and recent unsupervised learning advances
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Multiple ML models for ensemble detection
        self.isolation_forest = IsolationForest(
            contamination=self.config.get('contamination', 0.1),
            random_state=42,
            n_estimators=200,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1
        )
        
        self.one_class_svm = OneClassSVM(
            nu=self.config.get('nu', 0.1),
            kernel='rbf',
            gamma='scale',
            tol=1e-3
        )
        
        self.dbscan = DBSCAN(
            eps=self.config.get('eps', 0.5),
            min_samples=self.config.get('min_samples', 5),
            metric='euclidean'
        )
        
        # Feature preprocessing
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=self.config.get('pca_components', 10))
        
        # Model state
        self.is_fitted = False
        self.models_trained = {
            'isolation_forest': False,
            'one_class_svm': False,
            'dbscan': False
        }
        
        # Feature extraction parameters
        self.feature_window = self.config.get('feature_window', 100)
        self.syscall_history = deque(maxlen=self.feature_window)
        self.process_features = defaultdict(list)
        self.behavioral_baselines = {}  # pid -> BehavioralBaseline
        
        # Advanced feature extraction
        self.temporal_features = True
        self.network_features = True
        self.file_features = True
        self.resource_features = True
        
        # Model persistence
        # Prefer user cache directory by default
        default_dir = os.path.join(os.path.expanduser('~'), '.cache', 'security_agent')
        self.model_dir = self.config.get('model_dir', default_dir)
        os.makedirs(self.model_dir, exist_ok=True)
        self.feature_store_path = os.path.join(self.model_dir, 'training_features.npy')
        self.ngram_path = os.path.join(self.model_dir, 'ngram_bigrams.json')

        # Lightweight sequence model (bigrams)
        self.ngram_bigram_probs: Dict[str, float] = {}
        self.ngram_default_prob: float = 0.001
        self.ngram_avg_prob: float = 0.0
        
        # Performance tracking
        self.detection_stats = {
            'total_detections': 0,
            'true_positives': 0,
            'false_positives': 0,
            'model_performance': {}
        }
    
    def extract_advanced_features(self, syscalls: List[str], process_info: Dict = None) -> np.ndarray:
        """
        Extract advanced features from system call sequence and process information
        Based on U-SCAD feature extraction methodology
        """
        if not syscalls:
            return np.zeros(50)  # Return zero vector if no syscalls
        
        features = []
        
        # 1. Basic syscall frequency features - OPTIMIZED: use Counter for faster counting
        syscall_counts = Counter(syscalls)  # Faster than defaultdict (O(n) vs O(n log n))
        syscalls_len = len(syscalls)
        syscalls_len_inv = 1.0 / syscalls_len if syscalls_len > 0 else 0.0  # Cache division
        
        # Already checked at function start, but keep for safety
        
        # Common syscalls frequency - OPTIMIZED: pre-compute set for faster lookup
        common_syscalls = {'read', 'write', 'open', 'close', 'mmap', 'munmap', 'fork', 'execve'}
        features.extend([syscall_counts.get(sc, 0) * syscalls_len_inv for sc in ['read', 'write', 'open', 'close', 'mmap', 'munmap', 'fork', 'execve']])
        
        # 2. Unique syscalls ratio - OPTIMIZED: use len of Counter keys (already unique)
        unique_syscalls = len(syscall_counts)
        features.append(unique_syscalls * syscalls_len_inv)
        
        # 3. Syscall diversity (entropy) - OPTIMIZED: vectorized computation
        if syscall_counts:
            # Use numpy for faster entropy calculation
            counts_array = np.array(list(syscall_counts.values()))
            probabilities = counts_array * syscalls_len_inv
            # Vectorized entropy: -sum(p * log2(p)) for p > 0
            entropy = -np.sum(probabilities[probabilities > 0] * np.log2(probabilities[probabilities > 0]))
            features.append(entropy)
        else:
            features.append(0.0)
        
        # 4. High-risk syscall ratio - OPTIMIZED: use set intersection
        high_risk_syscalls = {'ptrace', 'mount', 'umount', 'setuid', 'setgid', 'chroot', 'reboot'}
        high_risk_count = sum(syscall_counts.get(sc, 0) for sc in high_risk_syscalls)
        features.append(high_risk_count * syscalls_len_inv if syscalls_len > 0 else 0.0)
        
        # 5. Temporal features (NOTE: Will be real when timestamps are captured)
        if self.temporal_features and len(syscalls) > 1:
            # Syscall rate (syscalls per second)
            features.append(len(syscalls))  # Total syscalls in window
            
            # Burst detection
            # TODO: Use actual timestamps from syscall events
            # For now, estimate based on syscall patterns
            # In a real implementation, we'd have timestamps from eBPF events
            features.append(len(syscalls) / 100)  # Estimate: 100 syscalls per second avg
            # Prevent division by zero
            if len(syscalls) > 0:
                features.append(1.0 / len(syscalls))  # Estimated average interval
            else:
                features.append(0.0)
            features.append(len(syscalls) * 0.1)  # Estimated max interval
        
        # 6. Network-related features - OPTIMIZED: use set for faster lookup
        if self.network_features:
            network_syscalls = {'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv'}
            network_count = sum(syscall_counts.get(sc, 0) for sc in network_syscalls)
            features.append(network_count * syscalls_len_inv if syscalls_len > 0 else 0.0)
        
        # 7. File system features - OPTIMIZED: use set for faster lookup
        if self.file_features:
            file_syscalls = {'open', 'close', 'read', 'write', 'stat', 'fstat', 'lstat'}
            file_count = sum(syscall_counts.get(sc, 0) for sc in file_syscalls)
            features.append(file_count * syscalls_len_inv if syscalls_len > 0 else 0.0)
        
        # 8. Process information features
        if process_info and self.resource_features:
            features.append(process_info.get('cpu_percent', 0) / 100.0)
            features.append(process_info.get('memory_percent', 0) / 100.0)
            features.append(process_info.get('num_threads', 1) / 100.0)
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # 9. Behavioral pattern features - OPTIMIZED: vectorized bigram generation
        if syscalls_len >= 10:
            # N-gram patterns (bigrams) - OPTIMIZED: use zip for faster generation
            bigrams = [f"{syscalls[i]}_{syscalls[i+1]}" for i in range(syscalls_len - 1)]
            bigram_counts = Counter(bigrams)  # Faster than defaultdict
            
            # Most common bigram frequency
            if bigram_counts:
                max_bigram_freq = max(bigram_counts.values()) / len(bigrams)
                features.append(max_bigram_freq)
            else:
                features.append(0.0)
        else:
            features.append(0.0)
        
        # 10. Syscall sequence patterns
        if len(syscalls) >= 5:
            # Check for repetitive patterns
            pattern_length = min(5, len(syscalls) // 2)
            patterns = []
            for i in range(len(syscalls) - pattern_length + 1):
                pattern = '_'.join(syscalls[i:i+pattern_length])
                patterns.append(pattern)
            
            pattern_counts = defaultdict(int)
            for pattern in patterns:
                pattern_counts[pattern] += 1
            
            # Most common pattern frequency
            if pattern_counts:
                max_pattern_freq = max(pattern_counts.values()) / len(patterns)
                features.append(max_pattern_freq)
            else:
                features.append(0.0)
        else:
            features.append(0.0)
        
        # Pad to fixed size
        while len(features) < 50:
            features.append(0.0)
        
        # FIXED: Validate feature count and warn if truncated
        if len(features) > 50:
            import logging
            logger = logging.getLogger('security_agent.anomaly')
            logger.warning(f"Feature vector too long ({len(features)} > 50), truncating. This may indicate a bug in feature extraction.")
        
        return np.array(features[:50])
    
    def _save_feature_store(self, features_np: np.ndarray) -> None:
        try:
            np.save(self.feature_store_path, features_np)
            print("✅ Feature store saved")
        except Exception as e:
            print(f"❌ Error saving feature store: {e}")

    def _load_feature_store(self) -> Optional[np.ndarray]:
        try:
            if os.path.exists(self.feature_store_path):
                data = np.load(self.feature_store_path)
                if isinstance(data, np.ndarray) and data.ndim == 2:
                    return data
        except Exception as e:
            print(f"❌ Error loading feature store: {e}")
        return None

    def train_models(self, training_data: List[Tuple[List[str], Dict]], append: bool = False, max_store_samples: int = 200000):
        """
        Train all ML models on normal behavior data
        
        Args:
            training_data: List of (syscalls, process_info) tuples
            append: If True, append to previous feature store (incremental learning)
            max_store_samples: Maximum samples to keep in feature store (default: 200K)
        """
        print("Training enhanced anomaly detection models...")
        
        # Extract features from training data - OPTIMIZED: direct numpy array creation
        features = np.array([self.extract_advanced_features(syscalls, process_info) 
                             for syscalls, process_info in training_data], dtype=np.float32)
        print(f"Extracted {features.shape[0]} samples with {features.shape[1]} features")

        # Merge with previous feature store if requested
        if append:
            prev = self._load_feature_store()
            if prev is not None:
                # CRITICAL: Validate feature dimensions match
                if prev.shape[1] != features.shape[1]:
                    # Feature dimension mismatch - cannot append safely
                    import logging
                    logger = logging.getLogger('security_agent.anomaly')
                    logger.error(
                        f"❌ CRITICAL: Feature dimension mismatch detected! "
                        f"Previous feature store: {prev.shape[1]} dimensions, "
                        f"New features: {features.shape[1]} dimensions. "
                        f"Previous feature store is incompatible and will be ignored. "
                        f"Starting fresh with {features.shape[0]} new samples. "
                        f"This may indicate a code change in feature extraction."
                    )
                    print(
                        f"❌ Feature dimension mismatch: prev={prev.shape[1]}, new={features.shape[1]}. "
                        f"Previous store incompatible - starting fresh."
                    )
                    # Option: Could backup old store or raise exception, but continuing with new data
                else:
                    try:
                        features = np.vstack([prev, features])
                        # Keep last N samples to bound train time/memory
                        if features.shape[0] > max_store_samples:
                            features = features[-max_store_samples:]
                        print(f"📦 Appended previous store → total {features.shape[0]} samples")
                    except Exception as e:
                        import logging
                        logger = logging.getLogger('security_agent.anomaly')
                        logger.error(f"❌ Could not append previous features: {e}", exc_info=True)
                        print(f"❌ Could not append previous features: {e}")
                        # Don't silently continue - this is a critical error
                        raise RuntimeError(f"Failed to append feature store: {e}") from e
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Apply PCA for dimensionality reduction
        features_pca = self.pca.fit_transform(features_scaled)
        
        # Train Isolation Forest
        try:
            self.isolation_forest.fit(features_pca)
            self.models_trained['isolation_forest'] = True
            print("✅ Isolation Forest trained successfully")
        except Exception as e:
            print(f"❌ Isolation Forest training failed: {e}")
        
        # Train One-Class SVM
        try:
            self.one_class_svm.fit(features_pca)
            self.models_trained['one_class_svm'] = True
            print("✅ One-Class SVM trained successfully")
        except Exception as e:
            print(f"❌ One-Class SVM training failed: {e}")
        
        # Train DBSCAN (for clustering)
        try:
            self.dbscan.fit(features_pca)
            self.models_trained['dbscan'] = True
            print("✅ DBSCAN trained successfully")
        except Exception as e:
            print(f"❌ DBSCAN training failed: {e}")
        
        self.is_fitted = True
        self._save_models()
        # Persist feature store for future appended retraining
        self._save_feature_store(features)
        # Build/update n-gram model from training data
        try:
            self._train_bigrams_from_training(training_data)
            self._save_ngram()
        except Exception as e:
            print(f"❌ N-gram training failed: {e}")
        print("🎉 All models trained and saved successfully")
    
    def _save_ngram(self) -> None:
        """Save n-gram bigram probabilities to disk"""
        try:
            ngram_payload = {
                'bigrams': self.ngram_bigram_probs,
                'default_prob': self.ngram_default_prob,
                'avg_prob': self.ngram_avg_prob,
            }
            with open(self.ngram_path, 'w') as f:
                json.dump(ngram_payload, f, indent=2)
        except Exception as e:
            print(f"❌ Error saving n-gram model: {e}")
    
    def detect_anomaly_ensemble(self, syscalls: List[str], process_info: Dict = None, pid: int = None) -> AnomalyResult:
        """
        Detect anomalies using ensemble of ML models
        """
        if not self.is_fitted:
            return AnomalyResult(
                pid=pid or 0,
                anomaly_score=0.0,
                is_anomaly=False,
                confidence=0.0,
                features={},
                explanation="Models not trained",
                timestamp=time.time(),
                model_used="none"
            )
        
        # Extract features
        features = self.extract_advanced_features(syscalls, process_info)
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        features_pca = self.pca.transform(features_scaled)
        
        # Ensemble predictions
        predictions = {}
        scores = {}
        
        # Isolation Forest
        if self.models_trained['isolation_forest']:
            try:
                if_pred = self.isolation_forest.predict(features_pca)[0]
                if_score = self.isolation_forest.decision_function(features_pca)[0]
                predictions['isolation_forest'] = if_pred == -1
                scores['isolation_forest'] = if_score
            except Exception as e:
                print(f"Isolation Forest prediction error: {e}")
        
        # One-Class SVM
        if self.models_trained['one_class_svm']:
            try:
                svm_pred = self.one_class_svm.predict(features_pca)[0]
                svm_score = self.one_class_svm.decision_function(features_pca)[0]
                predictions['one_class_svm'] = svm_pred == -1
                scores['one_class_svm'] = svm_score
            except Exception as e:
                print(f"One-Class SVM prediction error: {e}")
        
        # DBSCAN - Note: DBSCAN doesn't work well for single-sample prediction
        # We use the pre-fitted model's cluster centers to estimate distance
        if self.models_trained['dbscan']:
            try:
                # DBSCAN is not designed for single-sample predictions
                # Instead, use a distance-based approach to existing clusters
                # If we have training data stored, we could use it, but for now,
                # we'll use a simplified approach: check if point is within eps of any core sample
                # Since DBSCAN is mainly for training/baseline, skip prediction on single samples
                # and only use it during ensemble if we have batch data
                # For single samples, use isolation forest and SVM only
                pass  # Skip DBSCAN for single-sample predictions
            except Exception as e:
                pass  # Silently skip DBSCAN if it fails
        
        # Ensemble decision
        anomaly_votes = sum(predictions.values())
        total_models = len(predictions)
        
        # Weighted ensemble score
        ensemble_score = 0.0
        if scores:
            # Normalize scores and take weighted average
            normalized_scores = []
            for model, score in scores.items():
                if model == 'isolation_forest':
                    # Isolation Forest: negative scores indicate anomalies
                    normalized_scores.append(max(0, -score / 10.0))
                elif model == 'one_class_svm':
                    # One-Class SVM: negative scores indicate anomalies
                    normalized_scores.append(max(0, -score / 10.0))
                else:
                    normalized_scores.append(score)
            
            ensemble_score = np.mean(normalized_scores)
        
        # Add n-gram rarity score (0..1) where higher = more anomalous
        ngram_rarity = 0.0
        try:
            ngram_avg_p = self._avg_bigram_prob(syscalls)
            # Convert to rarity in [0,1]; if avg prob is low, rarity high
            # Use trained avg as reference; avoid div by zero
            ref = self.ngram_avg_prob or 1e-6
            ratio = max(0.0, min(1.0, (ref - ngram_avg_p) / max(ref, 1e-6)))
            ngram_rarity = ratio  # 0 normal, 1 very rare
        except Exception:
            pass

        # Final decision
        is_anomaly = anomaly_votes >= (total_models / 2) if total_models > 0 else False
        confidence = anomaly_votes / total_models if total_models > 0 else 0.0
        
        # Convert to 0-100 risk score and add bounded n-gram contribution
        risk_score = min(100, max(0, ensemble_score * 100))
        ngram_weight = float(self.config.get('ngram_weight', 0.2))  # 0..1
        risk_score = min(100.0, max(0.0, risk_score + 100.0 * ngram_weight * ngram_rarity))
        
        # Generate explanation
        explanation = self._generate_explanation(predictions, scores, features)
        
        # Update behavioral baseline
        if pid:
            self._update_behavioral_baseline(pid, syscalls, process_info)
        
        # Update statistics
        self.detection_stats['total_detections'] += 1
        if is_anomaly:
            self.detection_stats['true_positives'] += 1
        
        return AnomalyResult(
            pid=pid or 0,
            anomaly_score=risk_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            features={f"feature_{i}": float(features[i]) for i in range(len(features))},
            explanation=explanation,
            timestamp=time.time(),
            model_used=f"ensemble_{total_models}_models"
        )
    
    def _generate_explanation(self, predictions: Dict, scores: Dict, features: np.ndarray) -> str:
        """Generate human-readable explanation for anomaly detection"""
        explanations = []
        
        if predictions.get('isolation_forest', False):
            explanations.append("Isolation Forest detected outlier behavior")
        
        if predictions.get('one_class_svm', False):
            explanations.append("One-Class SVM identified deviation from normal")
        
        if predictions.get('dbscan', False):
            explanations.append("DBSCAN classified as noise/outlier")
        
        # N-gram based explanation
        if 'ngram' in scores and scores['ngram'] < 0:
            explanations.append("Unusual syscall sequence (low bigram likelihood)")

        # Feature-based explanations (indices aligned to extract_advanced_features)
        # 0..7: common syscall proportions; 8: unique ratio; 9: entropy; 10: high-risk ratio
        try:
            if len(features) > 10 and features[10] > 0.1:
                explanations.append("High proportion of risky system calls")
        except Exception:
            pass
        try:
            if len(features) > 9 and features[9] < 1.0:
                explanations.append("Low system call diversity (low entropy)")
        except Exception:
            pass
        try:
            # Temporal count proxy at index 11 (len(syscalls)); flag if very high
            if len(features) > 11 and features[11] > 100:
                explanations.append("Unusually high system call rate")
        except Exception:
            pass
        
        return "; ".join(explanations) if explanations else "Normal behavior detected"

    def _train_bigrams_from_training(self, training_data: List[Tuple[List[str], Dict]]):
        """Train bigram probabilities from training sequences with add-one smoothing"""
        from collections import Counter
        bigram_counts = Counter()
        unigram_counts = Counter()
        for syscalls, _ in training_data:
            if not syscalls or len(syscalls) < 2:
                continue
            unigram_counts.update(syscalls)
            for i in range(len(syscalls) - 1):
                bg = f"{syscalls[i]}_{syscalls[i+1]}"
                bigram_counts[bg] += 1
        vocab = max(1, len(unigram_counts))
        probs = {}
        total_bg = 0
        sum_p = 0.0
        for bg, cnt in bigram_counts.items():
            # P(b|a) ≈ count(bg)+1 / (count(a)+V)
            a = bg.split('_')[0]
            denom = unigram_counts.get(a, 0) + vocab
            p = (cnt + 1.0) / max(1.0, float(denom))
            probs[bg] = float(p)
            total_bg += 1
            sum_p += p
        self.ngram_bigram_probs = probs
        self.ngram_default_prob = 1.0 / max(1, sum(unigram_counts.values()) + vocab)
        self.ngram_avg_prob = (sum_p / max(1, total_bg)) if total_bg > 0 else 0.0

    def _avg_bigram_prob(self, syscalls: List[str]) -> float:
        if not syscalls or len(syscalls) < 2 or not self.ngram_bigram_probs:
            return self.ngram_avg_prob or 0.0
        total = 0.0
        n = 0
        for i in range(len(syscalls) - 1):
            bg = f"{syscalls[i]}_{syscalls[i+1]}"
            total += self.ngram_bigram_probs.get(bg, self.ngram_default_prob)
            n += 1
        return total / max(1, n)
    
    def _update_behavioral_baseline(self, pid: int, syscalls: List[str], process_info: Dict = None):
        """Update behavioral baseline for a process"""
        if pid not in self.behavioral_baselines:
            self.behavioral_baselines[pid] = BehavioralBaseline(
                pid=pid,
                syscall_frequencies={},
                temporal_patterns={},
                resource_usage={},
                network_patterns={},
                file_access_patterns={},
                last_updated=time.time(),
                sample_count=0
            )
        
        baseline = self.behavioral_baselines[pid]
        
        # Update syscall frequencies
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        total_syscalls = len(syscalls)
        if total_syscalls > 0:
            for syscall, count in syscall_counts.items():
                current_freq = baseline.syscall_frequencies.get(syscall, 0.0)
                new_freq = count / total_syscalls
                # Exponential moving average
                baseline.syscall_frequencies[syscall] = 0.9 * current_freq + 0.1 * new_freq
        
        # Update resource usage
        if process_info:
            baseline.resource_usage['cpu_percent'] = process_info.get('cpu_percent', 0)
            baseline.resource_usage['memory_percent'] = process_info.get('memory_percent', 0)
        
        baseline.last_updated = time.time()
        baseline.sample_count += 1
    
    def get_behavioral_baseline(self, pid: int) -> Optional[BehavioralBaseline]:
        """Get behavioral baseline for a process"""
        return self.behavioral_baselines.get(pid)
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            # Save Isolation Forest
            if self.models_trained['isolation_forest']:
                with open(os.path.join(self.model_dir, 'isolation_forest.pkl'), 'wb') as f:
                    pickle.dump(self.isolation_forest, f)
            
            # Save One-Class SVM
            if self.models_trained['one_class_svm']:
                with open(os.path.join(self.model_dir, 'one_class_svm.pkl'), 'wb') as f:
                    pickle.dump(self.one_class_svm, f)
            
            # Save scaler and PCA
            with open(os.path.join(self.model_dir, 'scaler.pkl'), 'wb') as f:
                pickle.dump(self.scaler, f)
            
            with open(os.path.join(self.model_dir, 'pca.pkl'), 'wb') as f:
                pickle.dump(self.pca, f)
            
            # Save configuration
            with open(os.path.join(self.model_dir, 'config.json'), 'w') as f:
                json.dump(self.config, f, indent=2)

            # Save n-gram model
            try:
                ngram_payload = {
                    'bigrams': self.ngram_bigram_probs,
                    'default_prob': self.ngram_default_prob,
                    'avg_prob': self.ngram_avg_prob,
                }
                with open(self.ngram_path, 'w') as f:
                    json.dump(ngram_payload, f)
            except Exception as e:
                print(f"❌ Error saving n-gram model: {e}")
            
            print("✅ Models saved successfully")
        except Exception as e:
            print(f"❌ Error saving models: {e}")
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            # Load Isolation Forest
            if_path = os.path.join(self.model_dir, 'isolation_forest.pkl')
            if os.path.exists(if_path):
                with open(if_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                self.models_trained['isolation_forest'] = True
            
            # Load One-Class SVM
            svm_path = os.path.join(self.model_dir, 'one_class_svm.pkl')
            if os.path.exists(svm_path):
                with open(svm_path, 'rb') as f:
                    self.one_class_svm = pickle.load(f)
                self.models_trained['one_class_svm'] = True
            
            # Load scaler and PCA
            scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            pca_path = os.path.join(self.model_dir, 'pca.pkl')
            if os.path.exists(pca_path):
                with open(pca_path, 'rb') as f:
                    self.pca = pickle.load(f)
            
            # Set fitted only if we have scaler, PCA and at least one model
            have_scaler = hasattr(self, 'scaler') and isinstance(self.scaler, StandardScaler)
            have_pca = hasattr(self, 'pca') and isinstance(self.pca, PCA)
            have_model = any(self.models_trained.values())
            self.is_fitted = bool(have_scaler and have_pca and have_model)
            if self.is_fitted:
                print("✅ Models loaded successfully")
            else:
                print("⚠️ Partial model load; training required before detection")

            # Load n-gram model if available
            try:
                if os.path.exists(self.ngram_path):
                    with open(self.ngram_path, 'r') as f:
                        payload = json.load(f)
                    self.ngram_bigram_probs = payload.get('bigrams', {})
                    self.ngram_default_prob = float(payload.get('default_prob', 0.001))
                    self.ngram_avg_prob = float(payload.get('avg_prob', 0.0))
            except Exception as e:
                print(f"❌ Error loading n-gram model: {e}")
        except Exception as e:
            print(f"❌ Error loading models: {e}")
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            **self.detection_stats,
            'models_trained': self.models_trained,
            'behavioral_baselines': len(self.behavioral_baselines),
            'is_fitted': self.is_fitted
        }
    
    def export_anomaly_data(self) -> Dict[str, Any]:
        """Export anomaly detection data for analysis"""
        return {
            'detection_stats': self.detection_stats,
            'behavioral_baselines': {pid: asdict(baseline) for pid, baseline in self.behavioral_baselines.items()},
            'models_trained': self.models_trained,
            'config': self.config,
            'export_timestamp': time.time()
        }
    
    def export_training_data(self, training_data: List[Tuple[List[str], Dict]], 
                            output_path: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Export training data to JSON file for sharing/backup
        
        Args:
            training_data: List of (syscalls, process_info) tuples
            output_path: Path to output JSON file
            metadata: Optional metadata dict (source, os, etc.)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            import platform
            from datetime import datetime
            
            # Prepare export data
            export_data = {
                'version': '1.0',
                'metadata': metadata or {
                    'source': platform.node(),
                    'os': platform.system(),
                    'os_version': platform.release(),
                    'collection_date': datetime.utcnow().isoformat() + 'Z',
                    'total_samples': len(training_data),
                    'feature_dimensions': 50
                },
                'samples': []
            }
            
            # Convert training data to JSON-serializable format
            for syscalls, process_info in training_data:
                sample = {
                    'syscalls': syscalls,
                    'process_info': {
                        'cpu_percent': float(process_info.get('cpu_percent', 0.0)),
                        'memory_percent': float(process_info.get('memory_percent', 0.0)),
                        'num_threads': int(process_info.get('num_threads', 1)),
                        'pid': int(process_info.get('pid', 0)) if 'pid' in process_info else None
                    }
                }
                # Add any additional metadata
                if 'process_name' in process_info:
                    sample['metadata'] = {'process_name': process_info['process_name']}
                export_data['samples'].append(sample)
            
            # Write to file
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"✅ Exported {len(training_data)} training samples to {output_path}")
            return True
        except Exception as e:
            print(f"❌ Error exporting training data: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def load_training_data_from_file(self, file_path: str) -> List[Tuple[List[str], Dict]]:
        """
        Load training data from JSON file
        
        Args:
            file_path: Path to JSON file containing training data
        
        Returns:
            List of (syscalls, process_info) tuples
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Validate format
            if not isinstance(data, dict) or 'samples' not in data:
                raise ValueError(f"Invalid training data format in {file_path}")
            
            training_data = []
            for sample in data['samples']:
                if 'syscalls' not in sample or 'process_info' not in sample:
                    continue  # Skip invalid samples
                
                syscalls = sample['syscalls']
                process_info = sample['process_info'].copy()
                
                # Ensure required fields
                if 'cpu_percent' not in process_info:
                    process_info['cpu_percent'] = 0.0
                if 'memory_percent' not in process_info:
                    process_info['memory_percent'] = 0.0
                if 'num_threads' not in process_info:
                    process_info['num_threads'] = 1
                
                training_data.append((syscalls, process_info))
            
            print(f"✅ Loaded {len(training_data)} training samples from {file_path}")
            if 'metadata' in data:
                meta = data['metadata']
                print(f"   Source: {meta.get('source', 'unknown')}, "
                      f"Date: {meta.get('collection_date', 'unknown')}")
            
            return training_data
        except Exception as e:
            print(f"❌ Error loading training data from {file_path}: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def load_training_data_from_directory(self, directory_path: str, 
                                         pattern: str = "*.json") -> List[Tuple[List[str], Dict]]:
        """
        Load training data from all matching files in a directory
        
        Args:
            directory_path: Directory containing training data files
            pattern: File pattern to match (default: "*.json")
        
        Returns:
            Combined list of (syscalls, process_info) tuples from all files
        """
        import glob
        
        training_data = []
        files = glob.glob(os.path.join(directory_path, pattern))
        
        if not files:
            print(f"⚠️ No files matching {pattern} found in {directory_path}")
            return []
        
        print(f"📂 Loading training data from {len(files)} files in {directory_path}...")
        
        for file_path in files:
            file_data = self.load_training_data_from_file(file_path)
            training_data.extend(file_data)
            print(f"   Loaded {len(file_data)} samples from {os.path.basename(file_path)}")
        
        print(f"✅ Total: {len(training_data)} samples from {len(files)} files")
        return training_data
    
    def load_training_data_from_url(self, url: str, 
                                   headers: Optional[Dict[str, str]] = None) -> List[Tuple[List[str], Dict]]:
        """
        Load training data from URL (HTTP/HTTPS)
        
        Args:
            url: URL to fetch training data from
            headers: Optional HTTP headers (for authentication, etc.)
        
        Returns:
            List of (syscalls, process_info) tuples
        """
        try:
            import requests
            
            response = requests.get(url, headers=headers or {}, timeout=30)
            response.raise_for_status()
            
            # Try parsing as JSON
            data = response.json()
            
            # If it's a direct list, wrap it
            if isinstance(data, list):
                data = {'samples': data, 'metadata': {}}
            
            # Convert to training data format
            training_data = []
            for sample in data.get('samples', []):
                if 'syscalls' not in sample or 'process_info' not in sample:
                    continue
                
                syscalls = sample['syscalls']
                process_info = sample['process_info'].copy()
                
                # Ensure required fields
                process_info.setdefault('cpu_percent', 0.0)
                process_info.setdefault('memory_percent', 0.0)
                process_info.setdefault('num_threads', 1)
                
                training_data.append((syscalls, process_info))
            
            print(f"✅ Loaded {len(training_data)} training samples from {url}")
            return training_data
        except Exception as e:
            print(f"❌ Error loading training data from URL {url}: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def merge_training_datasets(self, *datasets: List[Tuple[List[str], Dict]]) -> List[Tuple[List[str], Dict]]:
        """
        Merge multiple training datasets into one
        
        Args:
            *datasets: Variable number of training data lists
        
        Returns:
            Combined training data list
        """
        merged = []
        total_samples = 0
        
        for dataset in datasets:
            if dataset:
                merged.extend(dataset)
                total_samples += len(dataset)
        
        print(f"✅ Merged {len(datasets)} datasets into {len(merged)} total samples")
        return merged

# Example usage and testing
if __name__ == "__main__":
    # Create enhanced anomaly detector
    detector = EnhancedAnomalyDetector({
        'contamination': 0.1,
        'nu': 0.1,
        'feature_window': 100,
        'pca_components': 10
    })
    
    # Generate training data (normal behavior)
    print("Generating training data...")
    training_data = []
    for i in range(1000):
        # Normal syscall patterns
        syscalls = random.choices(
            ['read', 'write', 'open', 'close', 'mmap', 'munmap', 'fork', 'execve'],
            weights=[30, 30, 20, 20, 10, 10, 5, 5],
            k=random.randint(10, 50)
        )
        process_info = {
            'cpu_percent': random.uniform(0, 50),
            'memory_percent': random.uniform(0, 20),
            'num_threads': random.randint(1, 10)
        }
        training_data.append((syscalls, process_info))
    
    # Train models
    detector.train_models(training_data)
    
    # Test anomaly detection
    print("\nTesting anomaly detection...")
    
    # Normal behavior
    normal_syscalls = ['read', 'write', 'open', 'close', 'mmap', 'munmap']
    normal_info = {'cpu_percent': 10, 'memory_percent': 5, 'num_threads': 2}
    result = detector.detect_anomaly_ensemble(normal_syscalls, normal_info, pid=1234)
    print(f"Normal behavior: {result.is_anomaly} (score: {result.anomaly_score:.2f})")
    
    # Anomalous behavior
    anomalous_syscalls = ['ptrace', 'mount', 'setuid', 'setgid', 'chroot', 'reboot'] * 10
    anomalous_info = {'cpu_percent': 90, 'memory_percent': 80, 'num_threads': 50}
    result = detector.detect_anomaly_ensemble(anomalous_syscalls, anomalous_info, pid=5678)
    print(f"Anomalous behavior: {result.is_anomaly} (score: {result.anomaly_score:.2f})")
    print(f"Explanation: {result.explanation}")
    
    # Get statistics
    stats = detector.get_detection_stats()
    print(f"\nDetection stats: {stats}")
    
    # Export data
    export_data = detector.export_anomaly_data()
    print(f"Exported {len(export_data)} data entries")
