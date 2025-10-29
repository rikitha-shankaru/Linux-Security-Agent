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
from collections import deque, defaultdict
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
        self.model_dir = self.config.get('model_dir', '/tmp/security_agent_models')
        os.makedirs(self.model_dir, exist_ok=True)
        
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
        
        # 1. Basic syscall frequency features
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        # Early return if syscalls list is empty to prevent division by zero
        if len(syscalls) == 0:
            # Return zero-filled feature vector
            return np.zeros(50)
        
        # Common syscalls frequency
        common_syscalls = ['read', 'write', 'open', 'close', 'mmap', 'munmap', 'fork', 'execve']
        for syscall in common_syscalls:
            features.append(syscall_counts.get(syscall, 0) / len(syscalls))
        
        # 2. Unique syscalls ratio
        unique_syscalls = len(set(syscalls))
        features.append(unique_syscalls / len(syscalls))
        
        # 3. Syscall diversity (entropy)
        if len(syscall_counts) > 0:
            probabilities = [count / len(syscalls) for count in syscall_counts.values()]
            entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
            features.append(entropy)
        else:
            features.append(0.0)
        
        # 4. High-risk syscall ratio
        high_risk_syscalls = ['ptrace', 'mount', 'umount', 'setuid', 'setgid', 'chroot', 'reboot']
        high_risk_count = sum(syscall_counts.get(syscall, 0) for syscall in high_risk_syscalls)
        # Prevent division by zero
        if len(syscalls) > 0:
            features.append(high_risk_count / len(syscalls))
        else:
            features.append(0.0)
        
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
        
        # 6. Network-related features
        if self.network_features:
            network_syscalls = ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv']
            network_count = sum(syscall_counts.get(syscall, 0) for syscall in network_syscalls)
            # Prevent division by zero
            if len(syscalls) > 0:
                features.append(network_count / len(syscalls))
            else:
                features.append(0.0)
        
        # 7. File system features
        if self.file_features:
            file_syscalls = ['open', 'close', 'read', 'write', 'stat', 'fstat', 'lstat']
            file_count = sum(syscall_counts.get(syscall, 0) for syscall in file_syscalls)
            # Prevent division by zero
            if len(syscalls) > 0:
                features.append(file_count / len(syscalls))
            else:
                features.append(0.0)
        
        # 8. Process information features
        if process_info and self.resource_features:
            features.append(process_info.get('cpu_percent', 0) / 100.0)
            features.append(process_info.get('memory_percent', 0) / 100.0)
            features.append(process_info.get('num_threads', 1) / 100.0)
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # 9. Behavioral pattern features
        if len(syscalls) >= 10:
            # N-gram patterns (bigrams)
            bigrams = []
            for i in range(len(syscalls) - 1):
                bigrams.append(f"{syscalls[i]}_{syscalls[i+1]}")
            
            bigram_counts = defaultdict(int)
            for bigram in bigrams:
                bigram_counts[bigram] += 1
            
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
        
        return np.array(features[:50])
    
    def train_models(self, training_data: List[Tuple[List[str], Dict]]):
        """
        Train all ML models on normal behavior data
        """
        print("Training enhanced anomaly detection models...")
        
        # Extract features from training data
        features = []
        for syscalls, process_info in training_data:
            feature_vector = self.extract_advanced_features(syscalls, process_info)
            features.append(feature_vector)
        
        features = np.array(features)
        print(f"Extracted {features.shape[0]} samples with {features.shape[1]} features")
        
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
        print("🎉 All models trained and saved successfully")
    
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
        
        # DBSCAN
        if self.models_trained['dbscan']:
            try:
                cluster = self.dbscan.fit_predict(features_pca)[0]
                predictions['dbscan'] = cluster == -1  # -1 indicates outlier
                scores['dbscan'] = 1.0 if cluster == -1 else 0.0
            except Exception as e:
                print(f"DBSCAN prediction error: {e}")
        
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
        
        # Final decision
        is_anomaly = anomaly_votes >= (total_models / 2) if total_models > 0 else False
        confidence = anomaly_votes / total_models if total_models > 0 else 0.0
        
        # Convert to 0-100 risk score
        risk_score = min(100, max(0, ensemble_score * 100))
        
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
        
        # Feature-based explanations
        if features[3] > 0.1:  # High-risk syscall ratio
            explanations.append("High proportion of risky system calls")
        
        if features[1] < 0.1:  # Low syscall diversity
            explanations.append("Low system call diversity")
        
        if features[4] > 0.5:  # High syscall rate
            explanations.append("Unusually high system call rate")
        
        return "; ".join(explanations) if explanations else "Normal behavior detected"
    
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
            
            self.is_fitted = True
            print("✅ Models loaded successfully")
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
