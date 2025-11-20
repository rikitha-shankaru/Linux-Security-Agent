# 🔧 Scripts - Linux Security Agent

This folder contains automation scripts, setup utilities, and helper scripts for the Linux Security Agent project.

## 📁 Files

### **Main Scripts**
- **`run_agent.sh`** - Main script to run the security agent
- **`run_demo.sh`** - Demo execution script
- **`run_on_mac.sh`** - macOS-specific run script
- **`practice_demo.sh`** - Practice demo script for presentations
- **`docker_demo.sh`** - Docker-based demo script
- **`setup_linux_vm.sh`** - Automated Linux VM setup script
- **`check_dependencies.py`** - Dependency checking utility
- **`quick_demo.sh`** - Quick demo script
- **`quick_test.sh`** - Quick test script
- **`trigger_activity.sh`** - Script to trigger system activity for testing

## 🎯 Usage

### **Running the Security Agent**
```bash
# Run enhanced security agent
./scripts/run_agent.sh

# Run on macOS
./scripts/run_on_mac.sh

# Run demo
./scripts/run_demo.sh
```

### **Demo Scripts**
```bash
# Practice demo for presentations
./scripts/practice_demo.sh

# Docker-based demo
./scripts/docker_demo.sh
```

### **Setup Scripts**
```bash
# Automated Linux VM setup
./scripts/setup_linux_vm.sh
```

## 🔧 Script Details

### **`run_agent.sh`**
- **Purpose**: Main script to run the security agent
- **Features**: 
  - Checks for dependencies
  - Activates virtual environment
  - Runs enhanced security agent
  - Handles error cases
- **Usage**: `./scripts/run_agent.sh`

### **`run_demo.sh`**
- **Purpose**: Demo execution script
- **Features**:
  - Sets up demo environment
  - Runs security agent with demo settings
  - Shows example output
- **Usage**: `./scripts/run_demo.sh`

### **`run_on_mac.sh`**
- **Purpose**: macOS-specific run script
- **Features**:
  - Handles macOS-specific requirements
  - Uses macOS-compatible components
  - No root privileges required
- **Usage**: `./scripts/run_on_mac.sh`

### **`practice_demo.sh`**
- **Purpose**: Practice demo for presentations
- **Features**:
  - Automated demo sequence
  - Talking points and explanations
  - Professional presentation format
- **Usage**: `./scripts/practice_demo.sh`

### **`docker_demo.sh`**
- **Purpose**: Docker-based demo script
- **Features**:
  - Containerized demo environment
  - Isolated testing environment
  - Easy cleanup and reset
- **Usage**: `./scripts/docker_demo.sh`

### **`setup_linux_vm.sh`**
- **Purpose**: Automated Linux VM setup
- **Features**:
  - Installs all dependencies
  - Configures system settings
  - Sets up security agent
  - Validates installation
- **Usage**: `./scripts/setup_linux_vm.sh`

## 🚀 Quick Start

### **For Enhanced Version**
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run enhanced security agent
./scripts/run_agent.sh

# Run demo
./scripts/run_demo.sh
```

### **For macOS**
```bash
# Run on macOS
./scripts/run_on_mac.sh

# Practice demo
./scripts/practice_demo.sh
```

### **For VM Setup**
```bash
# Automated VM setup
./scripts/setup_linux_vm.sh
```

## 🔧 Customization

### **Modifying Scripts**
- Edit script files to customize behavior
- Add your own parameters and options
- Modify paths and configurations as needed
- Test changes before using in production

### **Adding New Scripts**
- Follow existing script patterns
- Include error handling and logging
- Add usage instructions and help
- Test thoroughly before committing

## 📊 Script Features

### **Common Features**
- **Error Handling**: Comprehensive error checking and reporting
- **Logging**: Detailed logging for debugging and monitoring
- **Configuration**: Configurable parameters and options
- **Validation**: Input validation and dependency checking
- **Cleanup**: Proper cleanup and resource management

### **Platform Support**
- **Linux**: Full support with eBPF capabilities
- **macOS**: Simulation mode with psutil
- **Docker**: Containerized execution environment
- **VM**: Virtual machine setup and configuration

## 🎓 Educational Value

### **For Learning**
- Study script patterns and best practices
- Understand automation and deployment
- Learn system administration techniques
- Practice shell scripting and automation

### **For Teaching**
- Use scripts for classroom demonstrations
- Show automation and deployment concepts
- Demonstrate system administration tasks
- Practice presentation and demo skills

## 🔧 Troubleshooting

### **Common Issues**
- **Permission Denied**: Make scripts executable with `chmod +x`
- **Dependencies Missing**: Check and install required packages
- **Path Issues**: Verify script paths and file locations
- **Environment Issues**: Check virtual environment activation

### **Debugging**
- Enable verbose logging in scripts
- Check script output and error messages
- Validate system requirements and dependencies
- Test scripts in isolated environments

## 📚 Related Documentation

### **Setup Guides**
- `../docs/INSTALL.md` - Installation instructions
- `../docs/LINUX_SETUP_GUIDE.md` - Linux setup guide
- `../docs/MACOS_GUIDE.md` - macOS setup guide

### **Usage Guides**
- `../docs/USAGE.md` - Usage instructions
- `../docs/DEMO_GUIDE.md` - Demo guide
- `../docs/ENHANCED_INTEGRATION_GUIDE.md` - Integration guide

### **Configuration**
- `../config/` - Configuration files and setup
- `../requirements.txt` - Python dependencies
- `../README.md` - Main project documentation

These scripts provide automation and convenience for running, testing, and deploying the Linux Security Agent project.
