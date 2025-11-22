#!/usr/bin/env python3
"""
Feature Importance Analyzer
Analyzes the importance of 50-D feature engineering for anomaly detection
Author: Likitha Shankar
"""

import numpy as np
import json
import os
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.inspection import permutation_importance
    from sklearn.decomposition import PCA
    import pandas as pd
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class FeatureImportanceReport:
    """Feature importance analysis report"""
    feature_names: List[str]
    isolation_forest_importance: Dict[str, float]
    permutation_importance: Dict[str, float]
    pca_variance_explained: Dict[str, float]
    feature_correlations: Dict[str, Dict[str, float]]
    top_features: List[Tuple[str, float]]
    dimensionality_analysis: Dict[str, Any]
    recommendations: List[str]


class FeatureImportanceAnalyzer:
    """Analyzes feature importance for 50-D feature engineering"""
    
    # Feature names corresponding to the 50-D feature vector
    FEATURE_NAMES = [
        # 0-7: Common syscall frequencies (8 features)
        'freq_read', 'freq_write', 'freq_open', 'freq_close',
        'freq_mmap', 'freq_munmap', 'freq_fork', 'freq_execve',
        # 8: Unique syscalls ratio
        'unique_ratio',
        # 9-18: High-risk syscall frequencies (10 features)
        'freq_ptrace', 'freq_mount', 'freq_umount', 'freq_chmod',
        'freq_chown', 'freq_setuid', 'freq_setgid', 'freq_socket',
        'freq_connect', 'freq_bind',
        # 19-28: Temporal features (10 features)
        'temporal_entropy', 'temporal_variance', 'temporal_mean_interval',
        'temporal_max_interval', 'temporal_min_interval', 'temporal_std',
        'temporal_trend', 'temporal_burst_count', 'temporal_idle_count',
        'temporal_pattern_score',
        # 29-38: Network features (10 features)
        'network_socket_ratio', 'network_connect_ratio', 'network_send_ratio',
        'network_recv_ratio', 'network_bind_ratio', 'network_listen_ratio',
        'network_accept_ratio', 'network_close_ratio', 'network_activity_score',
        'network_pattern_diversity',
        # 39-42: Resource usage features (4 features)
        'cpu_percent', 'memory_percent', 'num_threads', 'resource_utilization',
        # 43-49: Additional features (7 features)
        'syscall_sequence_length', 'syscall_diversity', 'syscall_entropy',
        'syscall_repetition', 'syscall_complexity', 'syscall_pattern_score',
        'syscall_anomaly_indicator'
    ]
    
    def __init__(self):
        self.report: Optional[FeatureImportanceReport] = None
        
    def analyze_features(self, training_data: List[Tuple[List[str], Dict]],
                        detector) -> FeatureImportanceReport:
        """
        Analyze feature importance from training data
        
        Args:
            training_data: List of (syscalls, process_info) tuples
            detector: EnhancedAnomalyDetector instance with extract_advanced_features method
            
        Returns:
            FeatureImportanceReport with analysis results
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for feature importance analysis")
        
        # Extract features
        print("📊 Extracting features from training data...")
        features = np.array([
            detector.extract_advanced_features(syscalls, process_info)
            for syscalls, process_info in training_data
        ], dtype=np.float32)
        
        print(f"✅ Extracted {features.shape[0]} samples with {features.shape[1]} features")
        
        # Verify feature count
        if features.shape[1] != 50:
            print(f"⚠️  Warning: Expected 50 features, got {features.shape[1]}")
        
        # Standardize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Train models for importance analysis
        print("🧠 Training models for importance analysis...")
        
        # Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        iso_forest.fit(features_scaled)
        
        # One-Class SVM
        oc_svm = OneClassSVM(nu=0.1, kernel='rbf', gamma='scale')
        oc_svm.fit(features_scaled)
        
        # Get feature importances
        print("📈 Calculating feature importances...")
        
        # Isolation Forest feature importance (from feature_importances_)
        iso_importance = {}
        if hasattr(iso_forest, 'feature_importances_'):
            iso_importances = iso_forest.feature_importances_
            for i, name in enumerate(self.FEATURE_NAMES[:len(iso_importances)]):
                iso_importance[name] = float(iso_importances[i])
        else:
            # Fallback: use permutation importance with custom scorer
            def iso_scorer(estimator, X, y):
                scores = estimator.decision_function(X)
                return np.mean(scores)
            
            perm_importance = permutation_importance(
                iso_forest, features_scaled[:min(1000, len(features_scaled))],
                features_scaled[:min(1000, len(features_scaled))],
                n_repeats=10, random_state=42, n_jobs=-1, scoring=iso_scorer
            )
            for i, name in enumerate(self.FEATURE_NAMES[:len(perm_importance.importances_mean)]):
                iso_importance[name] = float(perm_importance.importances_mean[i])
        
        # Permutation importance (more reliable)
        # For unsupervised models, use decision_function as scoring
        print("   Computing permutation importance...")
        def iso_forest_scorer(estimator, X, y):
            """Custom scorer for Isolation Forest using decision function"""
            scores = estimator.decision_function(X)
            return np.mean(scores)  # Higher is better (more normal)
        
        perm_importance_iso = permutation_importance(
            iso_forest, features_scaled[:min(500, len(features_scaled))],
            features_scaled[:min(500, len(features_scaled))],
            n_repeats=5, random_state=42, n_jobs=-1, scoring=iso_forest_scorer
        )
        
        perm_importance_dict = {}
        for i, name in enumerate(self.FEATURE_NAMES[:len(perm_importance_iso.importances_mean)]):
            perm_importance_dict[name] = float(perm_importance_iso.importances_mean[i])
        
        # PCA variance explained
        print("   Computing PCA variance explained...")
        pca = PCA(n_components=min(50, features_scaled.shape[1]))
        pca.fit(features_scaled)
        
        pca_variance = {}
        cumulative_variance = 0.0
        for i, (var, name) in enumerate(zip(pca.explained_variance_ratio_, self.FEATURE_NAMES)):
            pca_variance[name] = float(var)
            cumulative_variance += var
            if i < 10:  # Track top 10
                pca_variance[f'{name}_cumulative'] = float(cumulative_variance)
        
        # Feature correlations (top correlations)
        print("   Computing feature correlations...")
        feature_df = pd.DataFrame(features_scaled, columns=self.FEATURE_NAMES[:features_scaled.shape[1]])
        correlations = feature_df.corr().to_dict()
        
        # Get top features by importance
        top_features = sorted(
            [(name, perm_importance_dict.get(name, 0.0)) for name in self.FEATURE_NAMES],
            key=lambda x: x[1],
            reverse=True
        )[:20]  # Top 20
        
        # Dimensionality analysis
        print("   Analyzing dimensionality...")
        dimensionality_analysis = self._analyze_dimensionality(features_scaled, pca)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            iso_importance, perm_importance_dict, pca_variance, dimensionality_analysis
        )
        
        # Create report
        self.report = FeatureImportanceReport(
            feature_names=self.FEATURE_NAMES,
            isolation_forest_importance=iso_importance,
            permutation_importance=perm_importance_dict,
            pca_variance_explained=pca_variance,
            feature_correlations=correlations,
            top_features=top_features,
            dimensionality_analysis=dimensionality_analysis,
            recommendations=recommendations
        )
        
        return self.report
    
    def _analyze_dimensionality(self, features: np.ndarray, pca: PCA) -> Dict[str, Any]:
        """Analyze if 50 dimensions is optimal"""
        # Calculate variance explained by different numbers of components
        n_components_to_test = [5, 10, 15, 20, 25, 30, 40, 50]
        variance_explained = {}
        
        for n_comp in n_components_to_test:
            if n_comp <= features.shape[1]:
                pca_test = PCA(n_components=n_comp)
                pca_test.fit(features)
                variance_explained[n_comp] = float(np.sum(pca_test.explained_variance_ratio_))
        
        # Find optimal number (95% variance threshold)
        optimal_n = None
        for n_comp, var in sorted(variance_explained.items()):
            if var >= 0.95:
                optimal_n = n_comp
                break
        
        return {
            'variance_by_components': variance_explained,
            'optimal_components_95pct': optimal_n,
            'current_components': 50,
            'variance_explained_50': variance_explained.get(50, 0.0),
            'is_optimal': optimal_n == 50 if optimal_n else False
        }
    
    def _generate_recommendations(self, iso_importance: Dict, perm_importance: Dict,
                                 pca_variance: Dict, dim_analysis: Dict) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        # Check if 50-D is optimal
        optimal_n = dim_analysis.get('optimal_components_95pct')
        if optimal_n and optimal_n < 50:
            recommendations.append(
                f"Consider reducing dimensions to {optimal_n} (explains 95% variance, current: 50)"
            )
        elif optimal_n and optimal_n > 50:
            recommendations.append(
                f"Consider increasing dimensions to {optimal_n} for better variance coverage"
            )
        else:
            recommendations.append("50 dimensions appears optimal for 95% variance coverage")
        
        # Check for low-importance features
        low_importance = [
            name for name, imp in perm_importance.items()
            if imp < 0.01 and name in self.FEATURE_NAMES
        ]
        if low_importance:
            recommendations.append(
                f"Consider removing or combining {len(low_importance)} low-importance features: "
                f"{', '.join(low_importance[:5])}"
            )
        
        # Check variance explained
        var_50 = dim_analysis.get('variance_explained_50', 0.0)
        if var_50 < 0.90:
            recommendations.append(
                f"50 dimensions explain only {var_50:.1%} variance. Consider adding more features."
            )
        elif var_50 > 0.99:
            recommendations.append(
                f"50 dimensions explain {var_50:.1%} variance. May be over-engineered."
            )
        
        return recommendations
    
    def print_report(self, report: Optional[FeatureImportanceReport] = None):
        """Print formatted feature importance report"""
        if report is None:
            report = self.report
        
        if report is None:
            print("❌ No report available")
            return
        
        print("\n" + "=" * 70)
        print("📊 Feature Importance Analysis Report")
        print("=" * 70)
        
        # Dimensionality analysis
        dim_analysis = report.dimensionality_analysis
        print(f"\n📐 Dimensionality Analysis:")
        print(f"   Current Dimensions: 50")
        if dim_analysis.get('optimal_components_95pct'):
            print(f"   Optimal (95% variance): {dim_analysis['optimal_components_95pct']} dimensions")
            print(f"   Variance Explained (50-D): {dim_analysis.get('variance_explained_50', 0.0):.2%}")
            if dim_analysis.get('is_optimal'):
                print(f"   ✅ 50 dimensions is optimal!")
            else:
                print(f"   ⚠️  Consider adjusting dimensions")
        
        # Top features
        print(f"\n🏆 Top 20 Most Important Features:")
        for i, (name, importance) in enumerate(report.top_features[:20], 1):
            print(f"   {i:2d}. {name:30s} {importance:8.4f}")
        
        # Feature categories
        print(f"\n📊 Feature Importance by Category:")
        categories = {
            'Common Syscalls (0-7)': report.top_features[:8],
            'High-Risk Syscalls (9-18)': [f for f in report.top_features if 'freq_ptrace' in f[0] or 'freq_mount' in f[0] or 'freq_chmod' in f[0]][:10],
            'Temporal (19-28)': [f for f in report.top_features if 'temporal' in f[0]],
            'Network (29-38)': [f for f in report.top_features if 'network' in f[0]],
            'Resource (39-42)': [f for f in report.top_features if 'cpu' in f[0] or 'memory' in f[0] or 'thread' in f[0]],
        }
        
        for category, features in categories.items():
            if features:
                avg_importance = np.mean([f[1] for f in features])
                print(f"   {category:30s} Avg: {avg_importance:.4f}")
        
        # Recommendations
        if report.recommendations:
            print(f"\n💡 Recommendations:")
            for rec in report.recommendations:
                print(f"   - {rec}")
        
        print("\n" + "=" * 70)
    
    def export_report(self, report: Optional[FeatureImportanceReport] = None,
                     output_path: str = "feature_importance_report.json"):
        """Export report to JSON"""
        if report is None:
            report = self.report
        
        if report is None:
            print("❌ No report to export")
            return False
        
        try:
            report_dict = asdict(report)
            with open(output_path, 'w') as f:
                json.dump(report_dict, f, indent=2)
            print(f"✅ Feature importance report exported to {output_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to export report: {e}")
            return False

