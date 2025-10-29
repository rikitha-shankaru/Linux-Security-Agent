#!/usr/bin/env python3
"""
Anomaly detection module using Isolation Forest for system call patterns
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque, defaultdict
import pickle
import os
import time
import random
from typing import Dict, List, Tuple, Optional

class AnomalyDetector:
    """Anomaly detector for system call patterns using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        
        # Feature extraction parameters
        self.feature_window = 100  # Number of syscalls to consider for features
        self.syscall_history = deque(maxlen=self.feature_window)
        self.process_features = defaultdict(list)
        
        # Model persistence
        self.model_file = "/tmp/security_agent_anomaly_model.pkl"
        self.scaler_file = "/tmp/security_agent_scaler.pkl"
        
    def extract_features(self, syscalls: List[str]) -> np.ndarray:
        """Extract features from system call sequence"""
        if not syscalls:
            return np.zeros(20)  # Return zero vector if no syscalls
        
        # Feature 1: Syscall frequency distribution
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        # Feature 2: Unique syscalls ratio
        unique_ratio = len(set(syscalls)) / len(syscalls) if syscalls else 0
        
        # Feature 3: High-risk syscall ratio
        high_risk_syscalls = {'execve', 'setuid', 'setgid', 'ptrace', 'chmod', 'chown', 'mount', 'umount'}
        high_risk_count = sum(1 for syscall in syscalls if syscall in high_risk_syscalls)
        high_risk_ratio = high_risk_count / len(syscalls) if syscalls else 0
        
        # Feature 4: Medium-risk syscall ratio
        medium_risk_syscalls = {'fork', 'clone', 'vfork', 'chmod', 'chown', 'rename', 'unlink'}
        medium_risk_count = sum(1 for syscall in syscalls if syscall in medium_risk_syscalls)
        medium_risk_ratio = medium_risk_count / len(syscalls) if syscalls else 0
        
        # Feature 5: File operation ratio
        file_ops = {'open', 'close', 'read', 'write', 'stat', 'fstat', 'lstat'}
        file_op_count = sum(1 for syscall in syscalls if syscall in file_ops)
        file_op_ratio = file_op_count / len(syscalls) if syscalls else 0
        
        # Feature 6: Process control ratio
        process_ops = {'fork', 'clone', 'vfork', 'execve', 'exit', 'wait4', 'kill'}
        process_op_count = sum(1 for syscall in syscalls if syscall in process_ops)
        process_op_ratio = process_op_count / len(syscalls) if syscalls else 0
        
        # Feature 7: Network operation ratio
        network_ops = {'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv'}
        network_op_count = sum(1 for syscall in syscalls if syscall in network_ops)
        network_op_ratio = network_op_count / len(syscalls) if syscalls else 0
        
        # Feature 8: System call entropy
        syscall_entropy = self._calculate_entropy(syscalls)
        
        # Feature 9: Syscall sequence length
        sequence_length = len(syscalls)
        
        # Feature 10: Time-based features (if available)
        time_features = self._extract_time_features(syscalls)
        
        # Feature 11: Syscall pattern features
        pattern_features = self._extract_pattern_features(syscalls)
        
        # Combine all features
        features = np.array([
            unique_ratio,
            high_risk_ratio,
            medium_risk_ratio,
            file_op_ratio,
            process_op_ratio,
            network_op_ratio,
            syscall_entropy,
            sequence_length,
            *time_features,
            *pattern_features
        ])
        
        return features
    
    def _calculate_entropy(self, syscalls: List[str]) -> float:
        """Calculate entropy of system call sequence"""
        if not syscalls:
            return 0.0
        
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        total = len(syscalls)
        entropy = 0.0
        for count in syscall_counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _extract_time_features(self, syscalls: List[str]) -> List[float]:
        """Extract time-based features"""
        # For now, return dummy time features
        # In a real implementation, you'd track timestamps
        return [0.0, 0.0, 0.0]  # Placeholder for time features
    
    def _extract_pattern_features(self, syscalls: List[str]) -> List[float]:
        """Extract pattern-based features"""
        if not syscalls:
            return [0.0, 0.0, 0.0, 0.0, 0.0]
        
        # Feature 1: Repetition ratio
        unique_syscalls = set(syscalls)
        repetition_ratio = (len(syscalls) - len(unique_syscalls)) / len(syscalls)
        
        # Feature 2: Consecutive identical syscalls
        consecutive_count = 0
        max_consecutive = 0
        current_consecutive = 1
        
        for i in range(1, len(syscalls)):
            if syscalls[i] == syscalls[i-1]:
                current_consecutive += 1
            else:
                max_consecutive = max(max_consecutive, current_consecutive)
                current_consecutive = 1
        
        max_consecutive = max(max_consecutive, current_consecutive)
        consecutive_ratio = max_consecutive / len(syscalls)
        
        # Feature 3: Syscall diversity
        diversity = len(unique_syscalls) / len(syscalls)
        
        # Feature 4: Transition patterns
        transitions = defaultdict(int)
        for i in range(1, len(syscalls)):
            transition = f"{syscalls[i-1]}->{syscalls[i]}"
            transitions[transition] += 1
        
        transition_entropy = self._calculate_entropy(list(transitions.keys()))
        
        # Feature 5: Syscall frequency variance
        syscall_counts = defaultdict(int)
        for syscall in syscalls:
            syscall_counts[syscall] += 1
        
        counts = list(syscall_counts.values())
        frequency_variance = np.var(counts) if counts else 0.0
        
        return [repetition_ratio, consecutive_ratio, diversity, transition_entropy, frequency_variance]
    
    def add_syscall(self, syscall: str, pid: int):
        """Add a system call to the history"""
        self.syscall_history.append(syscall)
        
        # Extract features for this process
        if len(self.syscall_history) >= 10:  # Minimum window size
            features = self.extract_features(list(self.syscall_history))
            self.process_features[pid].append(features)
            
            # Keep only recent features
            if len(self.process_features[pid]) > 50:
                self.process_features[pid] = self.process_features[pid][-50:]
    
    def fit(self, training_data: List[List[str]]):
        """Fit the anomaly detection model"""
        print("Training anomaly detection model...")
        
        # Extract features from training data
        features_list = []
        for syscall_sequence in training_data:
            features = self.extract_features(syscall_sequence)
            features_list.append(features)
        
        if not features_list:
            print("No training data available")
            return
        
        # Convert to numpy array
        X = np.array(features_list)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit the isolation forest
        self.isolation_forest.fit(X_scaled)
        self.is_fitted = True
        
        print(f"Model trained on {len(features_list)} samples")
        
        # Save model
        self.save_model()
    
    def predict(self, syscalls: List[str]) -> Tuple[bool, float]:
        """Predict if syscall sequence is anomalous"""
        if not self.is_fitted:
            return False, 0.0
        
        # Extract features
        features = self.extract_features(syscalls)
        features = features.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict anomaly
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        
        # Get anomaly score
        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        
        return is_anomaly, anomaly_score
    
    def predict_process(self, pid: int) -> Tuple[bool, float]:
        """Predict if a process is anomalous based on its syscall history"""
        if pid not in self.process_features or not self.process_features[pid]:
            return False, 0.0
        
        # Get recent features for this process
        recent_features = self.process_features[pid][-10:]  # Last 10 feature vectors
        
        if not recent_features:
            return False, 0.0
        
        # Average the features
        avg_features = np.mean(recent_features, axis=0)
        
        # Predict anomaly
        is_anomaly, anomaly_score = self.predict([])  # Use empty list since we have features
        
        if self.is_fitted:
            features_scaled = self.scaler.transform(avg_features.reshape(1, -1))
            is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        
        return is_anomaly, anomaly_score
    
    def generate_training_data(self, num_samples: int = 1000) -> List[List[str]]:
        """Generate synthetic training data"""
        print("Generating synthetic training data...")
        
        # Define normal syscall patterns
        normal_patterns = [
            ['read', 'write', 'open', 'close'],
            ['stat', 'fstat', 'lstat', 'access'],
            ['fork', 'execve', 'wait4', 'exit'],
            ['socket', 'bind', 'listen', 'accept'],
            ['mmap', 'munmap', 'mprotect', 'brk'],
            ['getpid', 'getuid', 'getgid', 'getppid'],
            ['chdir', 'getcwd', 'fchdir'],
            ['pipe', 'dup', 'dup2', 'close'],
            ['select', 'poll', 'epoll_wait'],
            ['nanosleep', 'alarm', 'pause']
        ]
        
        # Define suspicious syscall patterns
        suspicious_patterns = [
            ['execve', 'setuid', 'chmod', 'chown'],
            ['ptrace', 'setgid', 'setreuid', 'setregid'],
            ['mount', 'umount', 'chroot', 'pivot_root'],
            ['syscall', 'sysenter', 'int80'],
            ['fork', 'execve', 'chmod', '+s'],
            ['setuid', 'setgid', 'ptrace', 'execve'],
            ['chmod', 'chown', 'setuid', 'execve'],
            ['mount', 'umount', 'chroot', 'execve'],
            ['ptrace', 'setuid', 'setgid', 'execve'],
            ['syscall', 'sysenter', 'int80', 'execve']
        ]
        
        training_data = []
        
        # Generate normal samples
        for _ in range(num_samples // 2):
            pattern = random.choice(normal_patterns)
            # Add some variation
            sequence = []
            for syscall in pattern:
                sequence.append(syscall)
                # Add some random normal syscalls
                if random.random() < 0.3:
                    sequence.append(random.choice(['read', 'write', 'open', 'close', 'stat']))
            training_data.append(sequence)
        
        # Generate suspicious samples
        for _ in range(num_samples // 2):
            pattern = random.choice(suspicious_patterns)
            # Add some variation
            sequence = []
            for syscall in pattern:
                sequence.append(syscall)
                # Add some random suspicious syscalls
                if random.random() < 0.2:
                    sequence.append(random.choice(['setuid', 'setgid', 'ptrace', 'chmod']))
            training_data.append(sequence)
        
        return training_data
    
    def save_model(self):
        """Save the trained model"""
        try:
            with open(self.model_file, 'wb') as f:
                pickle.dump(self.isolation_forest, f)
            with open(self.scaler_file, 'wb') as f:
                pickle.dump(self.scaler, f)
            print(f"Model saved to {self.model_file}")
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self):
        """Load a trained model"""
        try:
            if os.path.exists(self.model_file) and os.path.exists(self.scaler_file):
                with open(self.model_file, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                with open(self.scaler_file, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.is_fitted = True
                print(f"Model loaded from {self.model_file}")
                return True
        except Exception as e:
            print(f"Error loading model: {e}")
        return False
    
    def get_anomaly_score(self, syscalls: List[str]) -> float:
        """Get anomaly score for syscall sequence"""
        is_anomaly, score = self.predict(syscalls)
        return score
    
    def get_process_anomaly_score(self, pid: int) -> float:
        """Get anomaly score for a process"""
        is_anomaly, score = self.predict_process(pid)
        return score


# Example usage and testing
if __name__ == "__main__":
    import random
    
    # Create anomaly detector
    detector = AnomalyDetector()
    
    # Generate training data
    training_data = detector.generate_training_data(1000)
    
    # Train the model
    detector.fit(training_data)
    
    # Test with normal syscalls
    normal_syscalls = ['read', 'write', 'open', 'close', 'stat', 'fstat']
    is_anomaly, score = detector.predict(normal_syscalls)
    print(f"Normal syscalls - Anomaly: {is_anomaly}, Score: {score:.3f}")
    
    # Test with suspicious syscalls
    suspicious_syscalls = ['execve', 'setuid', 'chmod', 'ptrace', 'chown']
    is_anomaly, score = detector.predict(suspicious_syscalls)
    print(f"Suspicious syscalls - Anomaly: {is_anomaly}, Score: {score:.3f}")
    
    print("Anomaly detection model ready!")
