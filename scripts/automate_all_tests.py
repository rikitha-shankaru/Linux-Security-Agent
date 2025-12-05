#!/usr/bin/env python3
"""
Complete Automation Script for Linux Security Agent
====================================================

This script automates the ENTIRE testing and execution workflow:
1. Pre-flight checks (dependencies, permissions, ML models)
2. Unit tests (pytest)
3. Start agent in background
4. Health check and verification
5. Run all attack simulations
6. Monitor detections in real-time
7. Generate comprehensive report
8. Cleanup and shutdown

Usage:
    sudo python3 scripts/automate_all_tests.py [--keep-agent] [--no-unit-tests]

Author: Likitha Shankar
"""

import os
import sys
import time
import subprocess
import signal
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Global state
agent_process = None
results = {
    'timestamp': datetime.now().isoformat(),
    'preflight': {},
    'unit_tests': {},
    'agent': {},
    'attacks': {},
    'detections': {},
    'summary': {}
}

def print_header(text, color=BLUE):
    """Print a formatted header"""
    print(f"\n{color}{BOLD}{'='*80}{RESET}")
    print(f"{color}{BOLD}{text:^80}{RESET}")
    print(f"{color}{BOLD}{'='*80}{RESET}\n")

def print_section(text, color=CYAN):
    """Print a section header"""
    print(f"\n{color}{'─'*80}{RESET}")
    print(f"{color}{BOLD}{text}{RESET}")
    print(f"{color}{'─'*80}{RESET}\n")

def print_status(message, status="info"):
    """Print a status message with icon"""
    icons = {
        "success": f"{GREEN}✅{RESET}",
        "error": f"{RED}❌{RESET}",
        "warning": f"{YELLOW}⚠️{RESET}",
        "info": f"{BLUE}ℹ️{RESET}",
        "running": f"{CYAN}🔄{RESET}"
    }
    icon = icons.get(status, "•")
    print(f"{icon} {message}")

def run_command(cmd, timeout=60, background=False, capture_output=True):
    """Run a command and return result"""
    try:
        if background:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            return process
        else:
            result = subprocess.run(
                cmd,
                shell=True,
                timeout=timeout,
                capture_output=capture_output,
                text=True
            )
            return {
                'stdout': result.stdout if capture_output else '',
                'stderr': result.stderr if capture_output else '',
                'returncode': result.returncode,
                'success': result.returncode == 0
            }
    except subprocess.TimeoutExpired:
        return {'stdout': '', 'stderr': 'Timeout', 'returncode': -1, 'success': False}
    except Exception as e:
        return {'stdout': '', 'stderr': str(e), 'returncode': -1, 'success': False}

def preflight_checks():
    """Run pre-flight checks"""
    print_header("🔍 PRE-FLIGHT CHECKS")
    
    checks = {
        'python_version': False,
        'dependencies': False,
        'ebpf_support': False,
        'ml_models': False,
        'permissions': False,
        'log_directory': False
    }
    
    # Check Python version
    print_status("Checking Python version...", "info")
    python_version = sys.version_info
    if python_version.major == 3 and python_version.minor >= 8:
        print_status(f"Python {python_version.major}.{python_version.minor}.{python_version.micro} ✓", "success")
        checks['python_version'] = True
    else:
        print_status(f"Python {python_version.major}.{python_version.minor} - Need 3.8+", "error")
    
    # Check dependencies
    print_status("Checking dependencies...", "info")
    required_packages = ['bcc', 'numpy', 'scikit-learn', 'psutil', 'rich', 'pyyaml']
    missing = []
    for package in required_packages:
        result = run_command(f"python3 -c 'import {package}'", timeout=5)
        if not result['success']:
            missing.append(package)
    
    if not missing:
        print_status("All dependencies installed ✓", "success")
        checks['dependencies'] = True
    else:
        print_status(f"Missing packages: {', '.join(missing)}", "error")
    
    # Check eBPF support
    print_status("Checking eBPF support...", "info")
    result = run_command("lsmod | grep bpf", timeout=5)
    if result['success'] or 'bpf' in result['stdout'].lower():
        print_status("eBPF support available ✓", "success")
        checks['ebpf_support'] = True
    else:
        print_status("eBPF support not detected (may still work)", "warning")
        checks['ebpf_support'] = False
    
    # Check ML models
    print_status("Checking ML models...", "info")
    model_paths = [
        Path.home() / ".cache" / "security_agent" / "isolation_forest.pkl",
        Path.home() / ".cache" / "security_agent" / "one_class_svm.pkl",
        Path("/root/.cache/security_agent/isolation_forest.pkl"),
        Path("/root/.cache/security_agent/one_class_svm.pkl")
    ]
    
    models_found = any(p.exists() for p in model_paths)
    if models_found:
        print_status("ML models found ✓", "success")
        checks['ml_models'] = True
    else:
        print_status("ML models not found - agent will work without ML", "warning")
        checks['ml_models'] = False
    
    # Check permissions
    print_status("Checking permissions...", "info")
    if os.geteuid() == 0:
        print_status("Running as root ✓", "success")
        checks['permissions'] = True
    else:
        print_status("Not running as root - agent needs sudo", "warning")
        checks['permissions'] = False
    
    # Check log directory
    print_status("Checking log directory...", "info")
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    if log_dir.exists():
        print_status(f"Log directory ready: {log_dir.absolute()} ✓", "success")
        checks['log_directory'] = True
    else:
        print_status("Failed to create log directory", "error")
    
    results['preflight'] = checks
    all_passed = all(checks.values())
    
    if all_passed:
        print_status("All pre-flight checks passed!", "success")
    else:
        print_status("Some pre-flight checks failed - continuing anyway", "warning")
    
    return all_passed

def run_unit_tests():
    """Run unit tests"""
    print_header("🧪 UNIT TESTS")
    
    print_status("Running pytest...", "running")
    result = run_command("python3 -m pytest tests/ -v --tb=short", timeout=120)
    
    test_results = {
        'executed': True,
        'success': result['success'],
        'output': result['stdout'][-2000:] if len(result['stdout']) > 2000 else result['stdout']
    }
    
    if result['success']:
        print_status("All unit tests passed ✓", "success")
    else:
        print_status("Some unit tests failed", "error")
        print(f"{YELLOW}{result['stderr'][-500:]}{RESET}")
    
    results['unit_tests'] = test_results
    return result['success']

def start_agent():
    """Start the security agent"""
    print_header("🚀 STARTING SECURITY AGENT")
    
    global agent_process
    
    # Kill any existing agents
    print_status("Cleaning up existing agents...", "info")
    run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
    time.sleep(2)
    
    # Clear old log file
    log_file = Path("logs/security_agent.log")
    if log_file.exists():
        log_file.unlink()
    
    # Start agent in headless mode (no dashboard blinking)
    print_status("Starting agent with eBPF collector (headless mode)...", "running")
    agent_cmd = "sudo python3 core/simple_agent.py --collector ebpf --threshold 20 --headless"
    agent_process = run_command(agent_cmd, background=True, capture_output=False)
    
    if agent_process:
        print_status(f"Agent started (PID: {agent_process.pid})", "success")
        results['agent']['started'] = True
        results['agent']['pid'] = agent_process.pid
        
        # Wait for initialization
        print_status("Waiting for agent initialization (15 seconds)...", "info")
        time.sleep(15)
        
        # Health check
        return verify_agent_health()
    else:
        print_status("Failed to start agent", "error")
        results['agent']['started'] = False
        return False

def verify_agent_health():
    """Verify agent is running and capturing events"""
    print_section("Agent Health Check")
    
    log_file = Path("logs/security_agent.log")
    health = {
        'log_file_exists': False,
        'log_growing': False,
        'startup_confirmed': False,
        'events_captured': False,
        'ml_loaded': False
    }
    
    # Check log file
    if log_file.exists():
        health['log_file_exists'] = True
        print_status("Log file exists ✓", "success")
        
        # Check if log is growing
        initial_size = log_file.stat().st_size
        time.sleep(5)
        final_size = log_file.stat().st_size
        
        if final_size > initial_size:
            health['log_growing'] = True
            print_status("Log file is growing (events being captured) ✓", "success")
        else:
            print_status("Log file not growing - agent may not be capturing events", "warning")
        
        # Check log content
        with open(log_file, 'r') as f:
            content = f.read()
            
            if "Agent started successfully" in content or "Agent PID:" in content:
                health['startup_confirmed'] = True
                print_status("Agent startup confirmed in logs ✓", "success")
            
            if "HIGH RISK DETECTED" in content or "ANOMALY DETECTED" in content or "SCORE UPDATE" in content:
                health['events_captured'] = True
                print_status("Events being processed ✓", "success")
            
            if "Loaded pre-trained ML models" in content or "ML models loaded" in content:
                health['ml_loaded'] = True
                print_status("ML models loaded ✓", "success")
            else:
                print_status("ML models not loaded (agent will work without ML)", "warning")
    else:
        print_status("Log file not found", "error")
    
    results['agent']['health'] = health
    return health['log_file_exists'] and health['log_growing']

def run_attack_simulations():
    """Run all attack simulations"""
    print_header("🔴 ATTACK SIMULATIONS")
    
    attacks = [
        ("Privilege Escalation", "T1078", ["HIGH RISK DETECTED", "ANOMALY DETECTED", "setuid", "execve"]),
        ("High-Frequency Attack", "DoS", ["HIGH RISK DETECTED", "ANOMALY DETECTED", "high frequency"]),
        ("Suspicious File Patterns", "T1070", ["HIGH RISK DETECTED", "ANOMALY DETECTED", "chmod", "chown"]),
        ("Process Churn", "T1055", ["HIGH RISK DETECTED", "ANOMALY DETECTED", "fork", "execve"]),
        ("Network Scanning", "T1046", ["CONNECTION PATTERN", "PORT_SCANNING", "socket", "connect"]),
        ("Ptrace Attempts", "T1055", ["HIGH RISK DETECTED", "ANOMALY DETECTED", "ptrace"]),
    ]
    
    log_file = Path("logs/security_agent.log")
    
    for attack_name, attack_type, detection_patterns in attacks:
        print_section(f"Attack: {attack_name} ({attack_type})")
        
        # Get initial log state
        initial_log_content = ""
        if log_file.exists():
            with open(log_file, 'r') as f:
                initial_log_content = f.read()
        
        # Run attack
        print_status(f"Executing {attack_name}...", "running")
        attack_func_name = attack_name.lower().replace(' ', '_').replace('-', '_')
        attack_func_name = f"simulate_{attack_func_name}"
        
        attack_result = run_command(
            f"python3 -c \"import sys; sys.path.insert(0, 'scripts'); from simulate_attacks import {attack_func_name}; {attack_func_name}()\"",
            timeout=30
        )
        
        # Wait for detection
        print_status("Waiting for detection (8 seconds)...", "info")
        time.sleep(8)
        
        # Check for detections
        detections_found = {}
        if log_file.exists():
            with open(log_file, 'r') as f:
                current_log = f.read()
                new_log = current_log[len(initial_log_content):]
                
                for pattern in detection_patterns:
                    if pattern in new_log:
                        detections_found[pattern] = True
                        print_status(f"Detected: {pattern}", "success")
        
        attack_result_data = {
            'type': attack_type,
            'executed': attack_result['success'],
            'detections': list(detections_found.keys()),
            'detected': len(detections_found) > 0
        }
        
        results['attacks'][attack_name] = attack_result_data
        
        if attack_result_data['detected']:
            print_status(f"{attack_name} DETECTED ✓", "success")
        else:
            print_status(f"{attack_name} not clearly detected", "warning")
        
        time.sleep(3)  # Pause between attacks
    
    return results['attacks']

def analyze_detections():
    """Analyze all detections from logs"""
    print_header("📊 DETECTION ANALYSIS")
    
    log_file = Path("logs/security_agent.log")
    
    if not log_file.exists():
        print_status("Log file not found", "error")
        return {}
    
    with open(log_file, 'r') as f:
        content = f.read()
    
    analysis = {
        'total_lines': len(content.split('\n')),
        'high_risk_detections': content.count('HIGH RISK DETECTED'),
        'anomaly_detections': content.count('ANOMALY DETECTED'),
        'connection_patterns': content.count('CONNECTION PATTERN'),
        'c2_beacons': content.count('C2_BEACONING'),
        'port_scans': content.count('PORT_SCANNING'),
        'ml_results': content.count('ML RESULT'),
        'score_updates': content.count('SCORE UPDATE'),
        'errors': content.count('ERROR') + content.count('❌'),
        'warnings': content.count('WARNING') + content.count('⚠️'),
    }
    
    print_status("Log Analysis Results:", "info")
    print(f"  Total log lines: {analysis['total_lines']}")
    print(f"  High risk detections: {analysis['high_risk_detections']}")
    print(f"  Anomaly detections: {analysis['anomaly_detections']}")
    print(f"  Connection patterns: {analysis['connection_patterns']}")
    print(f"  C2 beacons: {analysis['c2_beacons']}")
    print(f"  Port scans: {analysis['port_scans']}")
    print(f"  Score updates: {analysis['score_updates']}")
    print(f"  Errors: {analysis['errors']}")
    print(f"  Warnings: {analysis['warnings']}")
    
    results['detections'] = analysis
    return analysis

def generate_report():
    """Generate comprehensive test report"""
    print_header("📋 GENERATING REPORT")
    
    # Calculate summary
    attacks_detected = sum(1 for a in results['attacks'].values() if a.get('detected', False))
    total_attacks = len(results['attacks'])
    detection_rate = (attacks_detected / total_attacks * 100) if total_attacks > 0 else 0
    
    results['summary'] = {
        'preflight_passed': all(results['preflight'].values()),
        'unit_tests_passed': results['unit_tests'].get('success', False),
        'agent_running': results['agent'].get('started', False),
        'agent_healthy': results['agent'].get('health', {}).get('log_growing', False),
        'total_attacks': total_attacks,
        'attacks_detected': attacks_detected,
        'detection_rate': f"{detection_rate:.1f}%",
        'total_detections': results['detections'].get('high_risk_detections', 0) + results['detections'].get('anomaly_detections', 0),
        'timestamp': results['timestamp']
    }
    
    # Print summary
    print_section("Test Summary")
    print(f"{BOLD}Pre-flight Checks:{RESET} {'✅ Passed' if results['summary']['preflight_passed'] else '❌ Failed'}")
    print(f"{BOLD}Unit Tests:{RESET} {'✅ Passed' if results['summary']['unit_tests_passed'] else '❌ Failed'}")
    print(f"{BOLD}Agent Status:{RESET} {'✅ Running' if results['summary']['agent_running'] else '❌ Not running'}")
    print(f"{BOLD}Agent Health:{RESET} {'✅ Healthy' if results['summary']['agent_healthy'] else '⚠️  Issues detected'}")
    print(f"{BOLD}Total Attacks:{RESET} {total_attacks}")
    print(f"{BOLD}Attacks Detected:{RESET} {attacks_detected}")
    print(f"{BOLD}Detection Rate:{RESET} {results['summary']['detection_rate']}")
    print(f"{BOLD}Total Detections:{RESET} {results['summary']['total_detections']}")
    
    # Save JSON report
    report_file = Path("automated_test_report.json")
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print_status(f"Report saved to: {report_file.absolute()}", "success")
    
    # Generate text report
    text_report = Path("automated_test_report.txt")
    with open(text_report, 'w') as f:
        f.write("="*80 + "\n")
        f.write("AUTOMATED TEST REPORT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Timestamp: {results['timestamp']}\n\n")
        f.write("SUMMARY\n")
        f.write("-"*80 + "\n")
        for key, value in results['summary'].items():
            f.write(f"{key}: {value}\n")
        f.write("\n" + "="*80 + "\n")
        f.write("DETAILED RESULTS\n")
        f.write("="*80 + "\n\n")
        f.write(json.dumps(results, indent=2))
    
    print_status(f"Text report saved to: {text_report.absolute()}", "success")
    
    return results['summary']

def cleanup(keep_agent=False):
    """Cleanup and stop agent"""
    print_header("🧹 CLEANUP")
    
    global agent_process
    
    if keep_agent:
        print_status("Keeping agent running (--keep-agent flag)", "info")
        print_status(f"Agent PID: {agent_process.pid if agent_process else 'N/A'}", "info")
        print_status("To stop manually: sudo pkill -9 -f 'simple_agent.py'", "info")
        return
    
    print_status("Stopping agent...", "running")
    
    if agent_process:
        try:
            os.killpg(os.getpgid(agent_process.pid), signal.SIGTERM)
            time.sleep(2)
            os.killpg(os.getpgid(agent_process.pid), signal.SIGKILL)
        except:
            pass
    
    # Force kill any remaining
    run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
    time.sleep(2)
    
    print_status("Agent stopped ✓", "success")

def main():
    """Main execution"""
    parser = argparse.ArgumentParser(description='Automate all tests and agent execution')
    parser.add_argument('--keep-agent', action='store_true', help='Keep agent running after tests')
    parser.add_argument('--no-unit-tests', action='store_true', help='Skip unit tests')
    args = parser.parse_args()
    
    try:
        # Change to project directory
        script_dir = Path(__file__).parent.parent
        os.chdir(script_dir)
        
        print_header("🛡️  LINUX SECURITY AGENT - AUTOMATED TESTING", MAGENTA)
        print(f"{YELLOW}This will run comprehensive tests and attack simulations{RESET}")
        print(f"{YELLOW}Make sure you're running this on a VM or isolated environment{RESET}\n")
        
        # Step 1: Pre-flight checks
        preflight_checks()
        time.sleep(1)
        
        # Step 2: Unit tests (optional)
        if not args.no_unit_tests:
            run_unit_tests()
            time.sleep(1)
        else:
            print_status("Skipping unit tests (--no-unit-tests flag)", "info")
            results['unit_tests'] = {'executed': False, 'skipped': True}
        
        # Step 3: Start agent
        if not start_agent():
            print_status("Agent failed to start - aborting", "error")
            cleanup()
            return 1
        
        # Step 4: Run attack simulations
        run_attack_simulations()
        time.sleep(2)
        
        # Step 5: Analyze detections
        analyze_detections()
        time.sleep(1)
        
        # Step 6: Generate report
        summary = generate_report()
        
        # Step 7: Cleanup
        cleanup(keep_agent=args.keep_agent)
        
        # Final status
        print_header("✅ AUTOMATION COMPLETE", GREEN)
        
        if summary['detection_rate'] != '0.0%':
            print_status("Tests completed successfully!", "success")
            return 0
        else:
            print_status("Tests completed but no detections found", "warning")
            return 1
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠️  Automation interrupted by user{RESET}")
        cleanup()
        return 1
    except Exception as e:
        print(f"\n{RED}❌ Automation failed: {e}{RESET}")
        import traceback
        traceback.print_exc()
        cleanup()
        return 1

if __name__ == "__main__":
    sys.exit(main())

