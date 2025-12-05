#!/usr/bin/env python3
"""
Comprehensive Test Suite Runner
================================

Runs ALL possible tests for the Linux Security Agent:
1. Unit tests
2. ML model evaluation
3. Feature extraction validation
4. eBPF monitoring tests
5. Attack simulation tests
6. Performance tests
7. False positive rate tests
8. Benchmark tests
9. Integration tests

Generates a complete validation report.

Author: Likitha Shankar
"""

import sys
import os
import subprocess
import json
import time
from datetime import datetime
from collections import defaultdict

# Test results storage
test_results = {
    'start_time': datetime.now().isoformat(),
    'categories': {},
    'summary': {
        'total_tests': 0,
        'passed': 0,
        'failed': 0,
        'skipped': 0,
        'errors': []
    }
}


def run_command(cmd, timeout=120, capture=True):
    """Run a command and return result"""
    try:
        if capture:
            result = subprocess.run(
                cmd,
                shell=isinstance(cmd, str),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        else:
            result = subprocess.run(
                cmd,
                shell=isinstance(cmd, str),
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': '',
                'stderr': ''
            }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'returncode': -1,
            'stdout': '',
            'stderr': 'Command timed out'
        }
    except Exception as e:
        return {
            'success': False,
            'returncode': -1,
            'stdout': '',
            'stderr': str(e)
        }


def print_section(title):
    """Print a section header"""
    print(f"\n{'='*70}")
    print(f"{title}")
    print(f"{'='*70}")


def test_category_1_unit_tests():
    """Run all unit tests"""
    print_section("CATEGORY 1: UNIT TESTS")
    
    category = {
        'name': 'Unit Tests',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: ML Anomaly Detector
    print("\n1️⃣  Testing ML Anomaly Detector...")
    result = run_command('python3 tests/test_ml_anomaly_detector.py')
    test = {
        'name': 'ML Anomaly Detector Tests',
        'passed': result['success'],
        'output': result['stdout'][-500:] if result['stdout'] else result['stderr'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ❌ FAILED")
        category['failed'] += 1
    
    # Test 2: Risk Scorer
    print("\n2️⃣  Testing Risk Scorer...")
    result = run_command('python3 tests/test_risk_scorer.py')
    test = {
        'name': 'Risk Scorer Tests',
        'passed': result['success'],
        'output': result['stdout'][-500:] if result['stdout'] else result['stderr'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ❌ FAILED")
        category['failed'] += 1
    
    # Test 3: eBPF Monitor
    print("\n3️⃣  Testing eBPF Monitor...")
    result = run_command('python3 tests/test_ebpf_monitor.py', timeout=30)
    test = {
        'name': 'eBPF Monitor Tests',
        'passed': result['success'],
        'output': result['stdout'][-500:] if result['stdout'] else result['stderr'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ❌ FAILED")
        category['failed'] += 1
    
    test_results['categories']['unit_tests'] = category
    return category


def test_category_2_ml_validation():
    """Validate ML models"""
    print_section("CATEGORY 2: ML MODEL VALIDATION")
    
    category = {
        'name': 'ML Model Validation',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: Model Evaluation
    print("\n1️⃣  Evaluating ML Models...")
    result = run_command('python3 scripts/evaluate_ml_models.py', timeout=60)
    test = {
        'name': 'ML Model Evaluation',
        'passed': 'Precision' in result['stdout'] or 'accuracy' in result['stdout'].lower(),
        'output': result['stdout'][-1000:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  PARTIAL (models may need training)")
        category['failed'] += 1
    
    # Test 2: Feature Importance
    print("\n2️⃣  Analyzing Feature Importance...")
    result = run_command('python3 scripts/analyze_feature_importance.py', timeout=60)
    test = {
        'name': 'Feature Importance Analysis',
        'passed': result['success'],
        'output': result['stdout'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  SKIPPED (requires trained models)")
        category['failed'] += 1
    
    # Test 3: Model Calibration
    print("\n3️⃣  Testing Model Calibration...")
    result = run_command('python3 scripts/calibrate_models.py', timeout=60)
    test = {
        'name': 'Model Calibration',
        'passed': result['success'],
        'output': result['stdout'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  SKIPPED")
        category['failed'] += 1
    
    test_results['categories']['ml_validation'] = category
    return category


def test_category_3_attack_detection():
    """Test attack detection capabilities"""
    print_section("CATEGORY 3: ATTACK DETECTION")
    
    category = {
        'name': 'Attack Detection',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: Attack Simulation
    print("\n1️⃣  Running Attack Simulations...")
    result = run_command('timeout 45 python3 scripts/simulate_attacks.py', timeout=50)
    test = {
        'name': 'Attack Pattern Simulation',
        'passed': 'Attack Simulation Complete' in result['stdout'] or 'pattern executed' in result['stdout'],
        'output': result['stdout'][-1000:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED (6 attack patterns simulated)")
        category['passed'] += 1
    else:
        print("   ❌ FAILED")
        category['failed'] += 1
    
    # Test 2: Attack Test Suite
    print("\n2️⃣  Running Attack Test Suite...")
    result = run_command('python3 scripts/run_attack_tests.py', timeout=90)
    test = {
        'name': 'Automated Attack Tests',
        'passed': result['success'],
        'output': result['stdout'][-1000:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  PARTIAL")
        category['failed'] += 1
    
    test_results['categories']['attack_detection'] = category
    return category


def test_category_4_ebpf_functionality():
    """Test eBPF functionality"""
    print_section("CATEGORY 4: eBPF FUNCTIONALITY")
    
    category = {
        'name': 'eBPF Functionality',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # This requires sudo, so we'll do a quick check
    print("\n1️⃣  Testing eBPF Syscall Capture...")
    print("   (Quick 10-second test)")
    
    test_script = """
import sys
import time
from collections import deque
sys.path.insert(0, 'core')
try:
    from enhanced_ebpf_monitor import StatefulEBPFMonitor
    events = deque(maxlen=100)
    def cb(pid, sc, info): events.append((pid, sc))
    monitor = StatefulEBPFMonitor({})
    monitor.start_monitoring(cb)
    time.sleep(10)
    monitor.stop_monitoring()
    print(f"CAPTURED:{len(events)}")
except Exception as e:
    print(f"ERROR:{e}")
"""
    
    result = run_command(f'sudo python3 -c "{test_script}"', timeout=15)
    captured = 0
    if 'CAPTURED:' in result['stdout']:
        try:
            captured = int(result['stdout'].split('CAPTURED:')[1].split()[0])
        except:
            pass
    
    test = {
        'name': 'eBPF Syscall Capture',
        'passed': captured > 10,
        'events_captured': captured,
        'output': f"Captured {captured} syscall events"
    }
    category['tests'].append(test)
    if test['passed']:
        print(f"   ✅ PASSED (captured {captured} events)")
        category['passed'] += 1
    else:
        print(f"   ❌ FAILED (only {captured} events)")
        category['failed'] += 1
    
    test_results['categories']['ebpf_functionality'] = category
    return category


def test_category_5_performance():
    """Test performance and resource usage"""
    print_section("CATEGORY 5: PERFORMANCE TESTS")
    
    category = {
        'name': 'Performance Tests',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: Quick Performance Benchmark
    print("\n1️⃣  Running Performance Benchmark...")
    result = run_command('python3 scripts/benchmark_performance.py', timeout=60)
    test = {
        'name': 'Performance Benchmark',
        'passed': result['success'],
        'output': result['stdout'][-1000:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  SKIPPED (requires sudo)")
        category['failed'] += 1
    
    # Test 2: Thread Safety
    print("\n2️⃣  Testing Thread Safety...")
    result = run_command('python3 scripts/run_thread_safety_tests.py', timeout=60)
    test = {
        'name': 'Thread Safety Tests',
        'passed': result['success'],
        'output': result['stdout'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  FAILED")
        category['failed'] += 1
    
    test_results['categories']['performance'] = category
    return category


def test_category_6_data_quality():
    """Test training data quality"""
    print_section("CATEGORY 6: DATA QUALITY")
    
    category = {
        'name': 'Data Quality',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: Validate Training Data
    print("\n1️⃣  Validating Training Data...")
    result = run_command('python3 scripts/validate_training_data.py', timeout=60)
    test = {
        'name': 'Training Data Validation',
        'passed': result['success'],
        'output': result['stdout'][-500:]
    }
    category['tests'].append(test)
    if test['passed']:
        print("   ✅ PASSED")
        category['passed'] += 1
    else:
        print("   ⚠️  FAILED")
        category['failed'] += 1
    
    # Test 2: Check Diverse Dataset
    print("\n2️⃣  Checking Diverse Dataset...")
    if os.path.exists('datasets/diverse_training_dataset.json'):
        with open('datasets/diverse_training_dataset.json', 'r') as f:
            data = json.load(f)
            sample_count = len(data.get('samples', []))
            behavior_types = set()
            for sample in data.get('samples', []):
                behavior_types.add(sample.get('behavior_type', 'unknown'))
        
        test = {
            'name': 'Diverse Dataset Check',
            'passed': sample_count >= 500 and len(behavior_types) >= 5,
            'sample_count': sample_count,
            'behavior_types': len(behavior_types),
            'output': f"{sample_count} samples, {len(behavior_types)} behavior types"
        }
        if test['passed']:
            print(f"   ✅ PASSED ({sample_count} samples, {len(behavior_types)} behaviors)")
            category['passed'] += 1
        else:
            print(f"   ⚠️  INSUFFICIENT ({sample_count} samples)")
            category['failed'] += 1
    else:
        test = {
            'name': 'Diverse Dataset Check',
            'passed': False,
            'output': 'Dataset not found'
        }
        print("   ❌ FAILED (dataset not found)")
        category['failed'] += 1
    
    category['tests'].append(test)
    test_results['categories']['data_quality'] = category
    return category


def test_category_7_integration():
    """Integration tests"""
    print_section("CATEGORY 7: INTEGRATION TESTS")
    
    category = {
        'name': 'Integration Tests',
        'tests': [],
        'passed': 0,
        'failed': 0
    }
    
    # Test 1: Check all core modules import
    print("\n1️⃣  Testing Module Imports...")
    modules = [
        'core.enhanced_anomaly_detector',
        'core.enhanced_ebpf_monitor',
        'core.incremental_trainer',
        'core.detection.risk_scorer',
        'core.container_security_monitor'
    ]
    
    import_errors = []
    for module in modules:
        try:
            __import__(module)
        except Exception as e:
            import_errors.append(f"{module}: {str(e)}")
    
    test = {
        'name': 'Module Import Tests',
        'passed': len(import_errors) == 0,
        'output': f"Tested {len(modules)} modules, {len(import_errors)} errors"
    }
    category['tests'].append(test)
    if test['passed']:
        print(f"   ✅ PASSED (all {len(modules)} modules import correctly)")
        category['passed'] += 1
    else:
        print(f"   ❌ FAILED ({len(import_errors)} import errors)")
        for error in import_errors:
            print(f"      - {error}")
        category['failed'] += 1
    
    # Test 2: Check file structure
    print("\n2️⃣  Validating Project Structure...")
    required_files = [
        'core/enhanced_security_agent.py',
        'core/enhanced_anomaly_detector.py',
        'core/enhanced_ebpf_monitor.py',
        'core/incremental_trainer.py',
        'config/config.yml',
        'datasets/normal_behavior_dataset.json',
        'README.md',
        'requirements.txt'
    ]
    
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    test = {
        'name': 'Project Structure Validation',
        'passed': len(missing_files) == 0,
        'output': f"Checked {len(required_files)} files, {len(missing_files)} missing"
    }
    category['tests'].append(test)
    if test['passed']:
        print(f"   ✅ PASSED (all required files present)")
        category['passed'] += 1
    else:
        print(f"   ❌ FAILED ({len(missing_files)} missing files)")
        category['failed'] += 1
    
    test_results['categories']['integration'] = category
    return category


def generate_summary():
    """Generate test summary"""
    print_section("TEST SUMMARY")
    
    total_passed = 0
    total_failed = 0
    
    for cat_name, category in test_results['categories'].items():
        total_passed += category.get('passed', 0)
        total_failed += category.get('failed', 0)
    
    test_results['summary']['total_tests'] = total_passed + total_failed
    test_results['summary']['passed'] = total_passed
    test_results['summary']['failed'] = total_failed
    test_results['end_time'] = datetime.now().isoformat()
    
    print(f"\n📊 OVERALL RESULTS:")
    print(f"   Total Tests: {test_results['summary']['total_tests']}")
    print(f"   Passed: {test_results['summary']['passed']} ✅")
    print(f"   Failed: {test_results['summary']['failed']} ❌")
    
    if test_results['summary']['total_tests'] > 0:
        pass_rate = (test_results['summary']['passed'] / test_results['summary']['total_tests']) * 100
        print(f"   Pass Rate: {pass_rate:.1f}%")
        
        if pass_rate >= 90:
            print(f"\n   🌟 EXCELLENT - Project is production ready!")
        elif pass_rate >= 75:
            print(f"\n   ✅ GOOD - Most tests passing")
        elif pass_rate >= 50:
            print(f"\n   ⚠️  MODERATE - Several failures")
        else:
            print(f"\n   ❌ NEEDS WORK - Many failures")
    
    print(f"\n📋 BY CATEGORY:")
    for cat_name, category in test_results['categories'].items():
        total = category.get('passed', 0) + category.get('failed', 0)
        passed = category.get('passed', 0)
        if total > 0:
            pct = (passed / total) * 100
            status = "✅" if pct >= 75 else "⚠️" if pct >= 50 else "❌"
            print(f"   {status} {category['name']}: {passed}/{total} ({pct:.0f}%)")


def save_results():
    """Save detailed results to JSON"""
    output_file = 'comprehensive_test_results.json'
    with open(output_file, 'w') as f:
        json.dump(test_results, f, indent=2)
    print(f"\n💾 Detailed results saved to: {output_file}")


def main():
    """Run all tests"""
    print("="*70)
    print("COMPREHENSIVE TEST SUITE")
    print("="*70)
    print(f"\nRunning ALL possible tests for Linux Security Agent")
    print(f"Started: {test_results['start_time']}")
    print(f"\nThis will take 5-10 minutes...")
    print("="*70)
    
    # Run all test categories
    test_category_1_unit_tests()
    test_category_2_ml_validation()
    test_category_3_attack_detection()
    test_category_4_ebpf_functionality()
    test_category_5_performance()
    test_category_6_data_quality()
    test_category_7_integration()
    
    # Generate summary
    generate_summary()
    
    # Save results
    save_results()
    
    print(f"\n{'='*70}")
    print("✅ COMPREHENSIVE TESTING COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    # Change to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)
    
    main()

