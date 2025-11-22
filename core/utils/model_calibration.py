#!/usr/bin/env python3
"""
Model Calibration and Confidence Intervals
Calibrates ensemble predictions and calculates confidence intervals
Author: Likitha Shankar
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import LogisticRegression
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class CalibratedPrediction:
    """Calibrated prediction with confidence intervals"""
    raw_score: float
    calibrated_score: float
    confidence_interval_lower: float
    confidence_interval_upper: float
    confidence_level: float  # e.g., 0.95 for 95% CI
    calibrated_probability: float  # Calibrated probability of anomaly


class ModelCalibrator:
    """Calibrates ensemble model predictions and calculates confidence intervals"""
    
    def __init__(self):
        self.iso_regressor: Optional[IsotonicRegression] = None
        self.log_regressor: Optional[LogisticRegression] = None
        self.is_calibrated = False
        self.calibration_data: List[Tuple[float, float]] = []  # (raw_score, true_label)
        
    def calibrate(self, raw_scores: np.ndarray, true_labels: np.ndarray,
                 method: str = 'isotonic') -> bool:
        """
        Calibrate model predictions using calibration data
        
        Args:
            raw_scores: Raw anomaly scores from ensemble
            true_labels: True labels (1 for anomaly, 0 for normal)
            method: Calibration method ('isotonic' or 'platt')
            
        Returns:
            True if calibration successful
        """
        if not SKLEARN_AVAILABLE:
            return False
        
        if len(raw_scores) < 10:
            return False  # Need minimum samples for calibration
        
        try:
            if method == 'isotonic':
                self.iso_regressor = IsotonicRegression(out_of_bounds='clip')
                self.iso_regressor.fit(raw_scores, true_labels)
                self.is_calibrated = True
            elif method == 'platt':
                self.log_regressor = LogisticRegression()
                # Reshape for sklearn
                X = raw_scores.reshape(-1, 1)
                self.log_regressor.fit(X, true_labels)
                self.is_calibrated = True
            else:
                return False
            
            # Store calibration data
            self.calibration_data = list(zip(raw_scores, true_labels))
            return True
        except Exception as e:
            print(f"⚠️  Calibration failed: {e}")
            return False
    
    def predict_calibrated(self, raw_score: float, 
                          confidence_level: float = 0.95) -> CalibratedPrediction:
        """
        Get calibrated prediction with confidence intervals
        
        Args:
            raw_score: Raw anomaly score from ensemble
            confidence_level: Confidence level for intervals (default: 0.95)
            
        Returns:
            CalibratedPrediction with calibrated score and confidence intervals
        """
        if not self.is_calibrated:
            # Return uncalibrated with simple confidence intervals
            return self._uncalibrated_prediction(raw_score, confidence_level)
        
        # Get calibrated probability
        if self.iso_regressor:
            calibrated_prob = float(self.iso_regressor.predict([raw_score])[0])
        elif self.log_regressor:
            calibrated_prob = float(self.log_regressor.predict_proba([[raw_score]])[0][1])
        else:
            calibrated_prob = raw_score / 100.0  # Fallback: normalize to [0,1]
        
        # Calculate confidence intervals using bootstrap or empirical distribution
        ci_lower, ci_upper = self._calculate_confidence_interval(
            raw_score, calibrated_prob, confidence_level
        )
        
        return CalibratedPrediction(
            raw_score=raw_score,
            calibrated_score=calibrated_prob * 100.0,  # Convert back to 0-100 scale
            confidence_interval_lower=ci_lower,
            confidence_interval_upper=ci_upper,
            confidence_level=confidence_level,
            calibrated_probability=calibrated_prob
        )
    
    def _calculate_confidence_interval(self, raw_score: float, calibrated_prob: float,
                                      confidence_level: float) -> Tuple[float, float]:
        """
        Calculate confidence intervals for prediction
        
        Uses empirical distribution from calibration data if available,
        otherwise uses heuristic based on score magnitude
        """
        if not self.calibration_data:
            # No calibration data - use heuristic
            return self._heuristic_confidence_interval(raw_score, confidence_level)
        
        # Use empirical distribution from calibration data
        # Find similar scores and use their distribution
        similar_scores = [
            (score, label) for score, label in self.calibration_data
            if abs(score - raw_score) < 10.0  # Within 10 points
        ]
        
        if len(similar_scores) >= 5:
            # Use bootstrap on similar scores
            scores_array = np.array([s[0] for s in similar_scores])
            mean_score = np.mean(scores_array)
            std_score = np.std(scores_array)
            
            # Calculate CI using t-distribution approximation
            from scipy import stats
            try:
                t_critical = stats.t.ppf((1 + confidence_level) / 2, len(similar_scores) - 1)
                margin = t_critical * std_score / np.sqrt(len(similar_scores))
                ci_lower = max(0.0, mean_score - margin)
                ci_upper = min(100.0, mean_score + margin)
                return (ci_lower, ci_upper)
            except:
                pass
        
        # Fallback to heuristic
        return self._heuristic_confidence_interval(raw_score, confidence_level)
    
    def _heuristic_confidence_interval(self, raw_score: float,
                                       confidence_level: float) -> Tuple[float, float]:
        """Heuristic confidence intervals based on score magnitude"""
        # Higher scores have wider intervals (more uncertainty at extremes)
        # Lower scores have narrower intervals (more certain about normal)
        
        if raw_score < 20:
            # Low scores: narrow interval (±5%)
            margin = 5.0
        elif raw_score < 50:
            # Medium scores: moderate interval (±10%)
            margin = 10.0
        else:
            # High scores: wider interval (±15%)
            margin = 15.0
        
        # Adjust for confidence level
        try:
            from scipy import stats
            z_critical = stats.norm.ppf((1 + confidence_level) / 2)
            margin *= (z_critical / 1.96)  # Scale from 95% to desired level
        except ImportError:
            # Fallback: use 1.96 for 95% CI
            margin *= (1.96 / 1.96) if confidence_level == 0.95 else 1.0
        
        ci_lower = max(0.0, raw_score - margin)
        ci_upper = min(100.0, raw_score + margin)
        
        return (ci_lower, ci_upper)
    
    def _uncalibrated_prediction(self, raw_score: float,
                                confidence_level: float) -> CalibratedPrediction:
        """Return uncalibrated prediction with simple confidence intervals"""
        ci_lower, ci_upper = self._heuristic_confidence_interval(raw_score, confidence_level)
        
        return CalibratedPrediction(
            raw_score=raw_score,
            calibrated_score=raw_score,  # No calibration
            confidence_interval_lower=ci_lower,
            confidence_interval_upper=ci_upper,
            confidence_level=confidence_level,
            calibrated_probability=raw_score / 100.0
        )
    
    def evaluate_calibration(self, raw_scores: np.ndarray, true_labels: np.ndarray) -> Dict[str, float]:
        """
        Evaluate calibration quality using Brier score and ECE (Expected Calibration Error)
        
        Args:
            raw_scores: Raw anomaly scores
            true_labels: True labels (1 for anomaly, 0 for normal)
            
        Returns:
            Dictionary with calibration metrics
        """
        if not self.is_calibrated:
            return {'brier_score': 1.0, 'ece': 1.0, 'calibrated': False}
        
        # Get calibrated probabilities
        calibrated_probs = []
        for score in raw_scores:
            pred = self.predict_calibrated(score)
            calibrated_probs.append(pred.calibrated_probability)
        
        calibrated_probs = np.array(calibrated_probs)
        
        # Brier score (lower is better)
        brier_score = np.mean((calibrated_probs - true_labels) ** 2)
        
        # Expected Calibration Error (ECE)
        n_bins = 10
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        ece = 0.0
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            # Find samples in this bin
            in_bin = (calibrated_probs > bin_lower) & (calibrated_probs <= bin_upper)
            prop_in_bin = in_bin.mean()
            
            if prop_in_bin > 0:
                accuracy_in_bin = true_labels[in_bin].mean()
                avg_confidence_in_bin = calibrated_probs[in_bin].mean()
                ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
        
        return {
            'brier_score': float(brier_score),
            'ece': float(ece),
            'calibrated': True,
            'n_samples': len(raw_scores)
        }


def calculate_ensemble_confidence(ensemble_scores: Dict[str, float],
                                 ensemble_predictions: Dict[str, bool]) -> float:
    """
    Calculate confidence from ensemble voting
    
    Args:
        ensemble_scores: Dictionary of model_name -> score
        ensemble_predictions: Dictionary of model_name -> is_anomaly (bool)
        
    Returns:
        Confidence score [0.0, 1.0]
    """
    if not ensemble_predictions:
        return 0.0
    
    # Simple voting confidence
    total_models = len(ensemble_predictions)
    anomaly_votes = sum(1 for pred in ensemble_predictions.values() if pred)
    confidence = anomaly_votes / total_models if total_models > 0 else 0.0
    
    # Weight by score agreement
    if ensemble_scores:
        scores = list(ensemble_scores.values())
        score_std = np.std(scores)
        score_agreement = 1.0 / (1.0 + score_std)  # Higher agreement = lower std
        
        # Combine voting confidence with score agreement
        confidence = 0.7 * confidence + 0.3 * score_agreement
    
    return min(1.0, max(0.0, confidence))


def calculate_prediction_interval(score: float, n_samples: int = 100,
                                  confidence_level: float = 0.95) -> Tuple[float, float]:
    """
    Calculate prediction interval for anomaly score
    
    Args:
        score: Anomaly score
        n_samples: Number of samples used (for uncertainty estimation)
        confidence_level: Confidence level (default: 0.95)
        
    Returns:
        (lower_bound, upper_bound) tuple
    """
    # Uncertainty decreases with more samples
    uncertainty_factor = 1.0 / np.sqrt(n_samples) if n_samples > 0 else 1.0
    
    # Higher scores have more uncertainty
    base_uncertainty = score * 0.1 * uncertainty_factor
    
    # Calculate margin
    try:
        from scipy import stats
        z_critical = stats.norm.ppf((1 + confidence_level) / 2)
    except ImportError:
        # Fallback: use 1.96 for 95% CI
        z_critical = 1.96 if confidence_level == 0.95 else 2.0
    
    margin = base_uncertainty * z_critical
    
    lower = max(0.0, score - margin)
    upper = min(100.0, score + margin)
    
    return (lower, upper)

