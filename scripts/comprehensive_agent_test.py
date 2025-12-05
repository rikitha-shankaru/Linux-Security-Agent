#!/usr/bin/env python3
"""
Comprehensive Agent Test - Run agent and test all attack detections
This script:
1. Starts the agent in background
2. Runs all attack simulations
3. Monitors logs for detections
4. Verifies all attack types are detected
5. Generates a comprehensive report
"""

import os
import sys
import time
import subprocess
import signal
import json
from pathlib import Path
from datetime import datetime

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}{text:^70}{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")

def print_section(text):
    print(f"\n{CYAN}{'─'*70}{RESET}")
    print(f"{CYAN}{text}{RESET}")
    print(f"{CYAN}{'─'*70}{RESET}\n")

def run_command(cmd, timeout=30, background=False):
    """Run a command and return output"""
    try:
        if background:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            return process
        else:
            result = subprocess.run(
                cmd,
                shell=True,
                timeout=timeout,
                capture_output=True,
                text=True
            )
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'success': result.returncode == 0
            }
    except subprocess.TimeoutExpired:
        return {'stdout': '', 'stderr': 'Timeout', 'returncode': -1, 'success': False}
    except Exception as e:
        return {'stdout': '', 'stderr': str(e), 'returncode': -1, 'success': False}

def check_log_for_patterns(log_file, patterns, timeout=10):
    """Check log file for specific patterns"""
    detections = {}
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    for pattern_name, pattern in patterns.items():
                        if pattern in content:
                            detections[pattern_name] = True
        except Exception as e:
            pass
        time.sleep(0.5)
    
    return detections

def main():
    print_header("🛡️  COMPREHENSIVE AGENT TEST")
    print(f"{YELLOW}This will test the agent with all attack types{RESET}")
    print(f"{YELLOW}Make sure you're running this on a VM or isolated environment{RESET}\n")
    
    # Change to project directory
    script_dir = Path(__file__).parent.parent
    os.chdir(script_dir)
    
    # Results storage
    results = {
        'timestamp': datetime.now().isoformat(),
        'agent_started': False,
        'health_check': False,
        'attacks': {},
        'detections': {},
        'log_analysis': {},
        'summary': {}
    }
    
    # Step 1: Kill any existing agents
    print_section("Step 1: Cleaning up existing agents")
    print("Killing any existing agent processes...")
    run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
    time.sleep(2)
    print(f"{GREEN}✅ Cleanup complete{RESET}")
    
    # Step 2: Check log file location
    log_file = Path("logs/security_agent.log")
    if not log_file.exists():
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch()
    
    print(f"\nLog file: {log_file.absolute()}")
    
    # Step 3: Start agent in background
    print_section("Step 2: Starting Security Agent")
    print("Starting agent with eBPF collector...")
    
    agent_cmd = "sudo python3 core/simple_agent.py --collector ebpf --threshold 20"
    agent_process = run_command(agent_cmd, background=True)
    
    if agent_process:
        print(f"{GREEN}✅ Agent started (PID: {agent_process.pid}){RESET}")
        results['agent_started'] = True
        results['agent_pid'] = agent_process.pid
    else:
        print(f"{RED}❌ Failed to start agent{RESET}")
        return results
    
    # Wait for agent to initialize
    print("Waiting for agent to initialize (10 seconds)...")
    time.sleep(10)
    
    # Step 4: Health check - verify events are being captured
    print_section("Step 3: Health Check")
    print("Checking if agent is capturing events...")
    
    initial_log_size = log_file.stat().st_size if log_file.exists() else 0
    time.sleep(5)
    final_log_size = log_file.stat().st_size if log_file.exists() else 0
    
    if final_log_size > initial_log_size:
        print(f"{GREEN}✅ Agent is capturing events (log file growing){RESET}")
        results['health_check'] = True
    else:
        print(f"{YELLOW}⚠️  Warning: Log file not growing - agent may not be capturing events{RESET}")
        results['health_check'] = False
    
    # Check log for startup messages
    if log_file.exists():
        with open(log_file, 'r') as f:
            log_content = f.read()
            if "Agent started successfully" in log_content:
                print(f"{GREEN}✅ Agent startup confirmed in logs{RESET}")
            if "Health check passed" in log_content:
                print(f"{GREEN}✅ Agent health check passed{RESET}")
            if "Loaded pre-trained ML models" in log_content:
                print(f"{GREEN}✅ ML models loaded{RESET}")
            else:
                print(f"{YELLOW}⚠️  ML models not loaded - agent will work without ML{RESET}")
    
    # Step 5: Run attack simulations
    print_section("Step 4: Running Attack Simulations")
    
    attacks = [
        ("Privilege Escalation", "T1078", ["HIGH RISK DETECTED", "Privilege", "setuid", "execve"]),
        ("High-Frequency Attack", "DoS", ["HIGH RISK DETECTED", "high frequency", "rapid"]),
        ("Suspicious File Patterns", "T1070", ["HIGH RISK DETECTED", "chmod", "chown", "suspicious"]),
        ("Process Churn", "T1055", ["HIGH RISK DETECTED", "process", "fork", "execve"]),
        ("Network Scanning", "T1046", ["CONNECTION PATTERN", "PORT_SCANNING", "socket", "connect"]),
        ("Ptrace Attempts", "T1055", ["HIGH RISK DETECTED", "ptrace", "process"]),
    ]
    
    for attack_name, attack_type, detection_patterns in attacks:
        print(f"\n{YELLOW}🔴 Running: {attack_name} ({attack_type}){RESET}")
        
        # Clear log markers before attack
        initial_log_content = ""
        if log_file.exists():
            with open(log_file, 'r') as f:
                initial_log_content = f.read()
        
        # Run attack simulation - call the specific function
        attack_func_name = attack_name.lower().replace(' ', '_').replace('-', '_')
        attack_result = run_command(
            f"python3 -c \"import sys; sys.path.insert(0, 'scripts'); from simulate_attacks import {attack_func_name}; {attack_func_name}()\"",
            timeout=30
        )
        
        # Wait for detection
        print(f"   Waiting for detection (5 seconds)...")
        time.sleep(5)
        
        # Check log for detections
        detections_found = {}
        if log_file.exists():
            with open(log_file, 'r') as f:
                current_log = f.read()
                new_log = current_log[len(initial_log_content):]
                
                for pattern in detection_patterns:
                    if pattern in new_log:
                        detections_found[pattern] = True
                        print(f"   {GREEN}✅ Detected: {pattern}{RESET}")
        
        results['attacks'][attack_name] = {
            'type': attack_type,
            'executed': attack_result['success'],
            'detections': detections_found,
            'detected': len(detections_found) > 0
        }
        
        if len(detections_found) > 0:
            print(f"   {GREEN}✅ {attack_name} DETECTED{RESET}")
        else:
            print(f"   {YELLOW}⚠️  {attack_name} not clearly detected in logs{RESET}")
        
        time.sleep(2)  # Pause between attacks
    
    # Step 6: Analyze log file
    print_section("Step 5: Log File Analysis")
    
    if log_file.exists():
        with open(log_file, 'r') as f:
            log_content = f.read()
        
        # Count various log entries
        results['log_analysis'] = {
            'total_lines': len(log_content.split('\n')),
            'high_risk_detections': log_content.count('HIGH RISK DETECTED'),
            'anomaly_detections': log_content.count('ANOMALY DETECTED'),
            'connection_patterns': log_content.count('CONNECTION PATTERN'),
            'c2_beacons': log_content.count('C2_BEACONING'),
            'port_scans': log_content.count('PORT_SCANNING'),
            'ml_results': log_content.count('ML RESULT'),
            'errors': log_content.count('ERROR') + log_content.count('❌'),
            'warnings': log_content.count('WARNING') + log_content.count('⚠️'),
        }
        
        print(f"Log file analysis:")
        print(f"  Total lines: {results['log_analysis']['total_lines']}")
        print(f"  High risk detections: {results['log_analysis']['high_risk_detections']}")
        print(f"  Anomaly detections: {results['log_analysis']['anomaly_detections']}")
        print(f"  Connection patterns: {results['log_analysis']['connection_patterns']}")
        print(f"  C2 beacons: {results['log_analysis']['c2_beacons']}")
        print(f"  Port scans: {results['log_analysis']['port_scans']}")
        print(f"  ML results: {results['log_analysis']['ml_results']}")
        print(f"  Errors: {results['log_analysis']['errors']}")
        print(f"  Warnings: {results['log_analysis']['warnings']}")
    
    # Step 7: Summary
    print_section("Step 6: Test Summary")
    
    attacks_detected = sum(1 for a in results['attacks'].values() if a.get('detected', False))
    total_attacks = len(results['attacks'])
    
    results['summary'] = {
        'agent_started': results['agent_started'],
        'health_check_passed': results['health_check'],
        'total_attacks': total_attacks,
        'attacks_detected': attacks_detected,
        'detection_rate': f"{(attacks_detected/total_attacks*100):.1f}%" if total_attacks > 0 else "0%"
    }
    
    print(f"Agent Status: {'✅ Running' if results['agent_started'] else '❌ Not running'}")
    print(f"Health Check: {'✅ Passed' if results['health_check'] else '⚠️  Warning'}")
    print(f"Attacks Executed: {total_attacks}")
    print(f"Attacks Detected: {attacks_detected}")
    print(f"Detection Rate: {results['summary']['detection_rate']}")
    
    # Step 8: Stop agent
    print_section("Step 7: Stopping Agent")
    print("Stopping agent...")
    
    if 'agent_pid' in results:
        try:
            os.killpg(os.getpgid(agent_process.pid), signal.SIGTERM)
            time.sleep(2)
            os.killpg(os.getpgid(agent_process.pid), signal.SIGKILL)
        except:
            run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
    
    print(f"{GREEN}✅ Agent stopped{RESET}")
    
    # Save results
    results_file = Path("comprehensive_test_results.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n{GREEN}✅ Test complete! Results saved to: {results_file}{RESET}")
    print(f"\n{YELLOW}To view the full log file:{RESET}")
    print(f"  tail -f {log_file.absolute()}")
    
    return results

if __name__ == "__main__":
    try:
        results = main()
        sys.exit(0 if results['summary'].get('detection_rate', '0%') != '0%' else 1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠️  Test interrupted by user{RESET}")
        run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}❌ Test failed: {e}{RESET}")
        import traceback
        traceback.print_exc()
        run_command("sudo pkill -9 -f 'simple_agent.py'", timeout=5)
        sys.exit(1)

