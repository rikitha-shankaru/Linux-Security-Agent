#!/usr/bin/env python3
"""
Incremental Model Retraining System
Automatically collects normal behavior samples and retrains models periodically
Author: Likitha Shankar
"""

import threading
import time
import logging
from typing import List, Tuple, Dict, Optional
from collections import deque
import numpy as np
from pathlib import Path
import json


class IncrementalTrainer:
    """
    Manages automatic incremental retraining of anomaly detection models
    Collects normal behavior samples and triggers retraining periodically
    """
    
    def __init__(self, anomaly_detector, config: Dict = None):
        """
        Initialize incremental trainer
        
        Args:
            anomaly_detector: EnhancedAnomalyDetector instance
            config: Configuration dictionary
        """
        self.detector = anomaly_detector
        self.config = config or {}
        
        # Training parameters
        self.retrain_interval = self.config.get('retrain_interval', 3600)  # 1 hour default
        self.min_samples_for_retrain = self.config.get('min_samples_for_retrain', 100)
        self.max_buffer_size = self.config.get('max_buffer_size', 1000)
        self.anomaly_score_threshold = self.config.get('anomaly_score_threshold', 30.0)
        
        # Sample buffer for normal behavior
        self.normal_samples_buffer: deque = deque(maxlen=self.max_buffer_size)
        self.buffer_lock = threading.Lock()
        
        # Retraining control
        self.retraining_enabled = True
        self.retrain_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Statistics
        self.stats = {
            'total_samples_collected': 0,
            'retraining_count': 0,
            'last_retrain_time': 0,
            'samples_in_buffer': 0,
            'retraining_errors': 0
        }
        
        self.logger = logging.getLogger('security_agent.incremental_trainer')
        
        # Save/load state
        self.state_file = Path(self.detector.model_dir) / 'incremental_trainer_state.json'
    
    def start(self):
        """Start the incremental training thread"""
        if self.retrain_thread and self.retrain_thread.is_alive():
            self.logger.warning("Incremental trainer already running")
            return
        
        self.stop_event.clear()
        self.retrain_thread = threading.Thread(
            target=self._retrain_loop,
            daemon=True,
            name="IncrementalTrainer"
        )
        self.retrain_thread.start()
        self.logger.info(f"Incremental trainer started (interval: {self.retrain_interval}s)")
    
    def stop(self):
        """Stop the incremental training thread"""
        self.stop_event.set()
        if self.retrain_thread:
            self.retrain_thread.join(timeout=5.0)
        self.logger.info("Incremental trainer stopped")
    
    def add_sample(self, syscalls: List[str], process_info: Dict, anomaly_score: float):
        """
        Add a sample to the buffer if it appears to be normal behavior
        
        Args:
            syscalls: List of system calls
            process_info: Process information dictionary
            anomaly_score: Anomaly score from detector
        """
        # Only collect samples that appear to be normal
        if anomaly_score < self.anomaly_score_threshold:
            with self.buffer_lock:
                self.normal_samples_buffer.append((syscalls, process_info))
                self.stats['total_samples_collected'] += 1
                self.stats['samples_in_buffer'] = len(self.normal_samples_buffer)
    
    def _retrain_loop(self):
        """Background thread that periodically retrains models"""
        while not self.stop_event.is_set():
            try:
                # Wait for retrain interval
                if self.stop_event.wait(timeout=self.retrain_interval):
                    break
                
                # Check if we have enough samples
                with self.buffer_lock:
                    sample_count = len(self.normal_samples_buffer)
                
                if sample_count >= self.min_samples_for_retrain:
                    self.logger.info(f"Starting incremental retraining with {sample_count} samples...")
                    success = self._perform_retrain()
                    
                    if success:
                        self.logger.info("✅ Incremental retraining completed successfully")
                    else:
                        self.logger.warning("⚠️ Incremental retraining failed")
                else:
                    self.logger.debug(
                        f"Skipping retrain: only {sample_count}/{self.min_samples_for_retrain} samples"
                    )
            
            except Exception as e:
                self.logger.error(f"Error in retrain loop: {e}", exc_info=True)
                self.stats['retraining_errors'] += 1
    
    def _perform_retrain(self) -> bool:
        """
        Perform the actual retraining with buffered samples
        
        Returns:
            True if retraining succeeded, False otherwise
        """
        try:
            # Get samples from buffer
            with self.buffer_lock:
                training_samples = list(self.normal_samples_buffer)
            
            if not training_samples:
                return False
            
            # Retrain models with append=True for incremental learning
            self.detector.train_models(training_samples, append=True)
            
            # Update statistics
            self.stats['retraining_count'] += 1
            self.stats['last_retrain_time'] = time.time()
            
            # Clear buffer after successful retraining
            with self.buffer_lock:
                self.normal_samples_buffer.clear()
                self.stats['samples_in_buffer'] = 0
            
            # Save state
            self._save_state()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Retraining failed: {e}", exc_info=True)
            self.stats['retraining_errors'] += 1
            return False
    
    def trigger_retrain_now(self) -> bool:
        """
        Manually trigger an immediate retraining
        
        Returns:
            True if retraining succeeded, False otherwise
        """
        with self.buffer_lock:
            sample_count = len(self.normal_samples_buffer)
        
        if sample_count < self.min_samples_for_retrain:
            self.logger.warning(
                f"Not enough samples for retraining: {sample_count}/{self.min_samples_for_retrain}"
            )
            return False
        
        self.logger.info(f"Manual retraining triggered with {sample_count} samples")
        return self._perform_retrain()
    
    def get_stats(self) -> Dict:
        """Get training statistics"""
        with self.buffer_lock:
            self.stats['samples_in_buffer'] = len(self.normal_samples_buffer)
        
        stats = self.stats.copy()
        
        # Add time since last retrain
        if stats['last_retrain_time'] > 0:
            stats['time_since_last_retrain'] = time.time() - stats['last_retrain_time']
        else:
            stats['time_since_last_retrain'] = None
        
        return stats
    
    def _save_state(self):
        """Save trainer state to disk"""
        try:
            state = {
                'stats': self.stats,
                'timestamp': time.time()
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
    
    def _load_state(self):
        """Load trainer state from disk"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                
                self.stats.update(state.get('stats', {}))
                self.logger.info("Loaded previous trainer state")
        
        except Exception as e:
            self.logger.error(f"Failed to load state: {e}")
    
    def configure(self, **kwargs):
        """
        Update configuration parameters
        
        Args:
            retrain_interval: Seconds between retraining attempts
            min_samples_for_retrain: Minimum samples needed to trigger retrain
            max_buffer_size: Maximum samples to keep in buffer
            anomaly_score_threshold: Threshold below which samples are considered normal
        """
        if 'retrain_interval' in kwargs:
            self.retrain_interval = kwargs['retrain_interval']
        
        if 'min_samples_for_retrain' in kwargs:
            self.min_samples_for_retrain = kwargs['min_samples_for_retrain']
        
        if 'max_buffer_size' in kwargs:
            self.max_buffer_size = kwargs['max_buffer_size']
            # Update deque maxlen
            with self.buffer_lock:
                old_samples = list(self.normal_samples_buffer)
                self.normal_samples_buffer = deque(old_samples, maxlen=self.max_buffer_size)
        
        if 'anomaly_score_threshold' in kwargs:
            self.anomaly_score_threshold = kwargs['anomaly_score_threshold']
        
        self.logger.info(f"Configuration updated: {kwargs}")


class AdaptiveThresholdManager:
    """
    Manages adaptive anomaly detection thresholds based on observed behavior
    Adjusts thresholds dynamically to reduce false positives while maintaining detection rate
    """
    
    def __init__(self, initial_threshold: float = 30.0, config: Dict = None):
        """
        Initialize adaptive threshold manager
        
        Args:
            initial_threshold: Starting anomaly score threshold
            config: Configuration dictionary
        """
        self.config = config or {}
        self.current_threshold = initial_threshold
        
        # Adaptation parameters
        self.min_threshold = self.config.get('min_threshold', 10.0)
        self.max_threshold = self.config.get('max_threshold', 70.0)
        self.adaptation_rate = self.config.get('adaptation_rate', 0.1)
        self.target_false_positive_rate = self.config.get('target_fp_rate', 0.05)
        
        # Statistics tracking
        self.recent_scores = deque(maxlen=1000)
        self.false_positive_count = 0
        self.true_positive_count = 0
        self.total_detections = 0
        
        self.logger = logging.getLogger('security_agent.adaptive_threshold')
    
    def update(self, anomaly_score: float, was_false_positive: bool = False):
        """
        Update threshold based on new detection
        
        Args:
            anomaly_score: Anomaly score from detector
            was_false_positive: Whether this detection was a false positive
        """
        self.recent_scores.append(anomaly_score)
        
        if anomaly_score >= self.current_threshold:
            self.total_detections += 1
            
            if was_false_positive:
                self.false_positive_count += 1
            else:
                self.true_positive_count += 1
        
        # Adjust threshold if we have enough data
        if self.total_detections >= 20:
            current_fp_rate = self.false_positive_count / self.total_detections
            
            if current_fp_rate > self.target_false_positive_rate:
                # Too many false positives - increase threshold
                adjustment = self.adaptation_rate * (current_fp_rate - self.target_false_positive_rate)
                self.current_threshold = min(
                    self.max_threshold,
                    self.current_threshold + adjustment
                )
                self.logger.info(f"Increased threshold to {self.current_threshold:.2f} (FP rate: {current_fp_rate:.2%})")
            
            elif current_fp_rate < self.target_false_positive_rate * 0.5:
                # Very low false positives - can decrease threshold for better detection
                adjustment = self.adaptation_rate * 0.5
                self.current_threshold = max(
                    self.min_threshold,
                    self.current_threshold - adjustment
                )
                self.logger.info(f"Decreased threshold to {self.current_threshold:.2f} (FP rate: {current_fp_rate:.2%})")
    
    def get_threshold(self) -> float:
        """Get current adaptive threshold"""
        return self.current_threshold
    
    def get_stats(self) -> Dict:
        """Get threshold adaptation statistics"""
        fp_rate = (self.false_positive_count / self.total_detections 
                   if self.total_detections > 0 else 0.0)
        
        return {
            'current_threshold': self.current_threshold,
            'false_positive_rate': fp_rate,
            'total_detections': self.total_detections,
            'false_positives': self.false_positive_count,
            'true_positives': self.true_positive_count,
            'recent_scores_count': len(self.recent_scores),
            'avg_recent_score': float(np.mean(self.recent_scores)) if self.recent_scores else 0.0
        }

