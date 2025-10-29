# 📚 Legacy Components - Basic Linux Security Agent

This folder contains the **original/basic components** of the Linux Security Agent. These are kept for comparison, learning, and backward compatibility.

## 📁 Files

### **Core Legacy Components**
- **`security_agent.py`** - Basic Linux security agent with eBPF
- **`security_agent_mac.py`** - macOS-compatible version with simulation
- **`anomaly_detector.py`** - Simple Isolation Forest implementation
- **`ebpf_monitor.py`** - Standard eBPF monitoring
- **`action_handler.py`** - Basic automated response system

### **Additional Legacy Components**
- **`advanced_risk_engine.py`** - Advanced risk scoring engine
- **`cloud_backend.py`** - Cloud backend integration
- **`cloud_server.py`** - Cloud server implementation
- **`mitre_attack_detector.py`** - MITRE ATT&CK detection
- **`performance_optimizer.py`** - Performance optimization
- **`production_agent.py`** - Production orchestrator
- **`security_hardener.py`** - Security hardening utilities

## 🎯 Usage

### **Basic Usage (Legacy Version)**
```bash
# Linux (with eBPF)
sudo python3 legacy/security_agent.py --dashboard

# macOS (simulation mode)
python3 legacy/security_agent_mac.py --dashboard --timeout 30
```

## 📊 Performance Metrics (Legacy)

- **Detection Accuracy**: ~85%
- **False Positive Rate**: ~15%
- **CPU Overhead**: 2-3%
- **Response Time**: <50ms
- **Scalability**: 1,000+ processes

## 🎓 When to Use Legacy Components

### **✅ Ideal For:**
- **Learning and Education** - Understanding basic security monitoring
- **Resource-Constrained Environments** - Limited CPU/memory
- **Simple Deployments** - Basic security monitoring needs
- **Prototyping** - Quick proof-of-concept development
- **Legacy Systems** - Older hardware or software constraints
- **Development/Testing** - Non-production environments

### **❌ Not Recommended For:**
- Production deployments requiring high security
- Enterprise environments with advanced threat detection needs
- Containerized systems and cloud-native deployments
- High-value targets requiring comprehensive protection

## 🔄 Migration Path

To migrate from legacy to enhanced components:
1. Start with legacy components for learning
2. Gradually adopt enhanced components
3. Use both versions in different environments
4. Refer to `../research/CODE_COMPARISON_ANALYSIS.md` for detailed comparison

## 📚 Educational Value

These components are excellent for:
- Understanding basic security monitoring concepts
- Learning eBPF and system call monitoring
- Prototyping and experimentation
- Teaching cybersecurity fundamentals
- Comparing with enhanced implementations
