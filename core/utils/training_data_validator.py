#!/usr/bin/env python3
"""
Training Data Quality Validator
Validates training data quality, detects outliers, and generates quality reports
Author: Likitha Shankar
"""

import json
import os
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


@dataclass
class DataQualityReport:
    """Comprehensive data quality report"""
    total_samples: int
    valid_samples: int
    invalid_samples: int
    duplicate_samples: int
    missing_fields: Dict[str, int]
    outlier_samples: int
    quality_score: float  # 0.0 to 1.0
    warnings: List[str]
    errors: List[str]
    statistics: Dict[str, Any]
    recommendations: List[str]


class TrainingDataValidator:
    """Validates training data quality for ML models"""
    
    def __init__(self):
        self.report: Optional[DataQualityReport] = None
        
    def validate_file(self, file_path: str) -> DataQualityReport:
        """
        Validate training data from a JSON file
        
        Args:
            file_path: Path to JSON training data file
            
        Returns:
            DataQualityReport with validation results
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            return DataQualityReport(
                total_samples=0,
                valid_samples=0,
                invalid_samples=0,
                duplicate_samples=0,
                missing_fields={},
                outlier_samples=0,
                quality_score=0.0,
                warnings=[],
                errors=[f"Failed to load file: {e}"],
                statistics={},
                recommendations=["Fix file format or file path"]
            )
        
        return self.validate_data(data)
    
    def validate_data(self, data: Dict[str, Any]) -> DataQualityReport:
        """
        Validate training data structure
        
        Args:
            data: Training data dictionary with 'samples' and optional 'metadata'
            
        Returns:
            DataQualityReport with validation results
        """
        errors = []
        warnings = []
        statistics = {}
        recommendations = []
        
        # Check basic structure
        if not isinstance(data, dict):
            errors.append("Data must be a dictionary")
            return self._create_error_report(errors)
        
        if 'samples' not in data:
            errors.append("Missing 'samples' field")
            return self._create_error_report(errors)
        
        samples = data.get('samples', [])
        if not isinstance(samples, list):
            errors.append("'samples' must be a list")
            return self._create_error_report(errors)
        
        total_samples = len(samples)
        if total_samples == 0:
            errors.append("No samples found in dataset")
            return self._create_error_report(errors)
        
        # Validate each sample
        valid_samples = []
        invalid_samples = []
        missing_fields = defaultdict(int)
        syscall_lengths = []
        cpu_values = []
        memory_values = []
        thread_counts = []
        all_syscalls = []
        sample_hashes = set()
        duplicate_samples = 0
        
        for idx, sample in enumerate(samples):
            if not isinstance(sample, dict):
                invalid_samples.append(idx)
                missing_fields['sample_structure'] += 1
                continue
            
            # Check required fields
            if 'syscalls' not in sample:
                invalid_samples.append(idx)
                missing_fields['syscalls'] += 1
                continue
            
            if 'process_info' not in sample:
                invalid_samples.append(idx)
                missing_fields['process_info'] += 1
                continue
            
            syscalls = sample['syscalls']
            process_info = sample['process_info']
            
            # Validate syscalls
            if not isinstance(syscalls, list):
                invalid_samples.append(idx)
                missing_fields['syscalls_type'] += 1
                continue
            
            if len(syscalls) == 0:
                warnings.append(f"Sample {idx}: Empty syscall list")
                continue
            
            # Validate process_info
            if not isinstance(process_info, dict):
                invalid_samples.append(idx)
                missing_fields['process_info_type'] += 1
                continue
            
            # Check for required process_info fields
            cpu = process_info.get('cpu_percent', 0.0)
            memory = process_info.get('memory_percent', 0.0)
            threads = process_info.get('num_threads', 1)
            
            # Validate numeric ranges
            if not isinstance(cpu, (int, float)) or cpu < 0 or cpu > 100:
                warnings.append(f"Sample {idx}: Invalid cpu_percent: {cpu}")
                cpu = max(0.0, min(100.0, float(cpu) if isinstance(cpu, (int, float)) else 0.0))
            
            if not isinstance(memory, (int, float)) or memory < 0 or memory > 100:
                warnings.append(f"Sample {idx}: Invalid memory_percent: {memory}")
                memory = max(0.0, min(100.0, float(memory) if isinstance(memory, (int, float)) else 0.0))
            
            if not isinstance(threads, int) or threads < 1:
                warnings.append(f"Sample {idx}: Invalid num_threads: {threads}")
                threads = max(1, int(threads) if isinstance(threads, (int, float)) else 1)
            
            # Check for duplicates (simple hash-based)
            sample_hash = hash(tuple(sorted(syscalls)) + tuple(sorted(process_info.items())))
            if sample_hash in sample_hashes:
                duplicate_samples += 1
            else:
                sample_hashes.add(sample_hash)
            
            # Collect statistics
            valid_samples.append(sample)
            syscall_lengths.append(len(syscalls))
            cpu_values.append(cpu)
            memory_values.append(memory)
            thread_counts.append(threads)
            all_syscalls.extend(syscalls)
        
        # Calculate statistics
        statistics = {
            'syscall_length': {
                'mean': float(np.mean(syscall_lengths)) if syscall_lengths else 0.0,
                'std': float(np.std(syscall_lengths)) if syscall_lengths else 0.0,
                'min': int(np.min(syscall_lengths)) if syscall_lengths else 0,
                'max': int(np.max(syscall_lengths)) if syscall_lengths else 0,
                'median': float(np.median(syscall_lengths)) if syscall_lengths else 0.0
            },
            'cpu_percent': {
                'mean': float(np.mean(cpu_values)) if cpu_values else 0.0,
                'std': float(np.std(cpu_values)) if cpu_values else 0.0,
                'min': float(np.min(cpu_values)) if cpu_values else 0.0,
                'max': float(np.max(cpu_values)) if cpu_values else 0.0,
                'median': float(np.median(cpu_values)) if cpu_values else 0.0
            },
            'memory_percent': {
                'mean': float(np.mean(memory_values)) if memory_values else 0.0,
                'std': float(np.std(memory_values)) if memory_values else 0.0,
                'min': float(np.min(memory_values)) if memory_values else 0.0,
                'max': float(np.max(memory_values)) if memory_values else 0.0,
                'median': float(np.median(memory_values)) if memory_values else 0.0
            },
            'num_threads': {
                'mean': float(np.mean(thread_counts)) if thread_counts else 0.0,
                'std': float(np.std(thread_counts)) if thread_counts else 0.0,
                'min': int(np.min(thread_counts)) if thread_counts else 1,
                'max': int(np.max(thread_counts)) if thread_counts else 1,
                'median': float(np.median(thread_counts)) if thread_counts else 1.0
            },
            'unique_syscalls': len(set(all_syscalls)),
            'total_syscalls': len(all_syscalls),
            'most_common_syscalls': dict(Counter(all_syscalls).most_common(10))
        }
        
        # Detect outliers using statistical methods
        outlier_samples = self._detect_outliers(
            valid_samples, syscall_lengths, cpu_values, memory_values, thread_counts
        )
        
        # Calculate quality score (0.0 to 1.0)
        quality_score = self._calculate_quality_score(
            total_samples, len(valid_samples), len(invalid_samples),
            duplicate_samples, outlier_samples, len(warnings), len(errors)
        )
        
        # Generate recommendations
        if len(invalid_samples) > 0:
            recommendations.append(f"Remove or fix {len(invalid_samples)} invalid samples")
        
        if duplicate_samples > total_samples * 0.1:  # More than 10% duplicates
            recommendations.append(f"High duplicate rate ({duplicate_samples}/{total_samples}). Consider deduplication.")
        
        if outlier_samples > total_samples * 0.05:  # More than 5% outliers
            recommendations.append(f"High outlier rate ({outlier_samples}/{total_samples}). Review data collection.")
        
        if len(valid_samples) < 100:
            recommendations.append("Low sample count. Consider collecting more training data.")
        
        if statistics['syscall_length']['mean'] < 3:
            recommendations.append("Average syscall sequence length is very short. Consider longer sequences.")
        
        if statistics['unique_syscalls'] < 20:
            recommendations.append("Low syscall diversity. Consider more varied training data.")
        
        # Create report
        self.report = DataQualityReport(
            total_samples=total_samples,
            valid_samples=len(valid_samples),
            invalid_samples=len(invalid_samples),
            duplicate_samples=duplicate_samples,
            missing_fields=dict(missing_fields),
            outlier_samples=outlier_samples,
            quality_score=quality_score,
            warnings=warnings[:50],  # Limit to first 50 warnings
            errors=errors,
            statistics=statistics,
            recommendations=recommendations
        )
        
        return self.report
    
    def _detect_outliers(self, samples: List[Dict], syscall_lengths: List[int],
                        cpu_values: List[float], memory_values: List[float],
                        thread_counts: List[int]) -> int:
        """Detect statistical outliers in training data"""
        if len(samples) < 10:
            return 0  # Too few samples for outlier detection
        
        outlier_count = 0
        
        # Use IQR method for outlier detection
        def iqr_outliers(values: List[float]) -> set:
            if len(values) < 4:
                return set()
            q1 = np.percentile(values, 25)
            q3 = np.percentile(values, 75)
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            return {i for i, v in enumerate(values) if v < lower_bound or v > upper_bound}
        
        # Detect outliers in each dimension
        length_outliers = iqr_outliers(syscall_lengths)
        cpu_outliers = iqr_outliers(cpu_values)
        memory_outliers = iqr_outliers(memory_values)
        thread_outliers = iqr_outliers(thread_counts)
        
        # Count unique outlier samples
        all_outliers = length_outliers | cpu_outliers | memory_outliers | thread_outliers
        outlier_count = len(all_outliers)
        
        # Use Isolation Forest if available for multivariate outlier detection
        if SKLEARN_AVAILABLE and len(samples) >= 20:
            try:
                # Create feature matrix
                features = np.array([
                    [syscall_lengths[i], cpu_values[i], memory_values[i], thread_counts[i]]
                    for i in range(len(samples))
                ])
                
                # Standardize
                scaler = StandardScaler()
                features_scaled = scaler.fit_transform(features)
                
                # Detect outliers
                iso_forest = IsolationForest(contamination=0.1, random_state=42)
                outlier_labels = iso_forest.fit_predict(features_scaled)
                
                # Count outliers (label == -1)
                ml_outlier_count = np.sum(outlier_labels == -1)
                
                # Use the more conservative estimate
                outlier_count = min(outlier_count, ml_outlier_count)
            except Exception:
                pass  # Fall back to IQR method
        
        return outlier_count
    
    def _calculate_quality_score(self, total: int, valid: int, invalid: int,
                                 duplicates: int, outliers: int,
                                 warnings_count: int, errors_count: int) -> float:
        """Calculate overall quality score (0.0 to 1.0)"""
        if total == 0:
            return 0.0
        
        # Base score from validity
        validity_score = valid / total if total > 0 else 0.0
        
        # Penalize duplicates
        duplicate_penalty = min(0.2, duplicates / total * 2.0)
        
        # Penalize outliers
        outlier_penalty = min(0.2, outliers / total * 2.0)
        
        # Penalize warnings/errors
        warning_penalty = min(0.1, warnings_count / total * 0.1)
        error_penalty = min(0.3, errors_count * 0.1)
        
        # Calculate final score
        score = validity_score * (1.0 - duplicate_penalty - outlier_penalty - warning_penalty - error_penalty)
        return max(0.0, min(1.0, score))
    
    def _create_error_report(self, errors: List[str]) -> DataQualityReport:
        """Create a report with only errors"""
        return DataQualityReport(
            total_samples=0,
            valid_samples=0,
            invalid_samples=0,
            duplicate_samples=0,
            missing_fields={},
            outlier_samples=0,
            quality_score=0.0,
            warnings=[],
            errors=errors,
            statistics={},
            recommendations=["Fix errors before proceeding"]
        )
    
    def print_report(self, report: Optional[DataQualityReport] = None):
        """Print a formatted quality report"""
        if report is None:
            report = self.report
        
        if report is None:
            print("❌ No report available")
            return
        
        print("\n" + "=" * 70)
        print("📊 Training Data Quality Report")
        print("=" * 70)
        
        print(f"\n📈 Overall Quality Score: {report.quality_score:.2%}")
        
        print(f"\n📋 Sample Statistics:")
        print(f"   Total Samples: {report.total_samples}")
        print(f"   Valid Samples: {report.valid_samples} ({report.valid_samples/report.total_samples*100:.1f}%)")
        print(f"   Invalid Samples: {report.invalid_samples}")
        print(f"   Duplicate Samples: {report.duplicate_samples}")
        print(f"   Outlier Samples: {report.outlier_samples}")
        
        if report.missing_fields:
            print(f"\n⚠️  Missing Fields:")
            for field, count in report.missing_fields.items():
                print(f"   {field}: {count}")
        
        if report.statistics:
            stats = report.statistics
            print(f"\n📊 Data Statistics:")
            print(f"   Syscall Length: mean={stats['syscall_length']['mean']:.1f}, "
                  f"std={stats['syscall_length']['std']:.1f}, "
                  f"range=[{stats['syscall_length']['min']}-{stats['syscall_length']['max']}]")
            print(f"   CPU %: mean={stats['cpu_percent']['mean']:.2f}, "
                  f"std={stats['cpu_percent']['std']:.2f}")
            print(f"   Memory %: mean={stats['memory_percent']['mean']:.2f}, "
                  f"std={stats['memory_percent']['std']:.2f}")
            print(f"   Threads: mean={stats['num_threads']['mean']:.1f}, "
                  f"range=[{stats['num_threads']['min']}-{stats['num_threads']['max']}]")
            print(f"   Unique Syscalls: {stats['unique_syscalls']}")
            print(f"   Total Syscalls: {stats['total_syscalls']}")
            if stats.get('most_common_syscalls'):
                print(f"   Top Syscalls: {', '.join(list(stats['most_common_syscalls'].keys())[:5])}")
        
        if report.warnings:
            print(f"\n⚠️  Warnings ({len(report.warnings)}):")
            for warning in report.warnings[:10]:  # Show first 10
                print(f"   - {warning}")
            if len(report.warnings) > 10:
                print(f"   ... and {len(report.warnings) - 10} more")
        
        if report.errors:
            print(f"\n❌ Errors ({len(report.errors)}):")
            for error in report.errors:
                print(f"   - {error}")
        
        if report.recommendations:
            print(f"\n💡 Recommendations:")
            for rec in report.recommendations:
                print(f"   - {rec}")
        
        print("\n" + "=" * 70)
    
    def export_report(self, report: Optional[DataQualityReport] = None, 
                     output_path: str = "training_data_quality_report.json"):
        """Export quality report to JSON file"""
        if report is None:
            report = self.report
        
        if report is None:
            print("❌ No report to export")
            return False
        
        try:
            # Convert to dict (dataclass.asdict handles nested structures)
            report_dict = asdict(report)
            
            with open(output_path, 'w') as f:
                json.dump(report_dict, f, indent=2)
            
            print(f"✅ Quality report exported to {output_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to export report: {e}")
            return False

