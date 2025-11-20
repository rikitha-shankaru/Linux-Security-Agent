# ⚙️ Configuration - Linux Security Agent

This folder contains configuration files, setup scripts, and deployment configurations for the Linux Security Agent project.

## 📁 Files

### **Setup Scripts**
- **`setup_local.py`** - Local environment setup script
- **`setup_macos.py`** - macOS-specific setup script
- **`setup.py`** - Main setup and installation script

### **Docker Configuration**
- **`docker-compose.yml`** - Docker Compose configuration
- **`Dockerfile`** - Main Docker container definition
- **`Dockerfile.alternative`** - Alternative Docker configuration

## 🎯 Usage

### **Setup and Installation**
```bash
# Local setup
python3 config/setup_local.py

# macOS setup
python3 config/setup_macos.py

# Main setup
python3 config/setup.py
```

### **Docker Deployment**
```bash
# Build Docker image
docker build -f config/Dockerfile -t security-agent .

# Run with Docker Compose
docker-compose -f config/docker-compose.yml up

# Run container
docker run --rm --privileged security-agent
```

## 🔧 Configuration Details

### **`setup_local.py`**
- **Purpose**: Local environment setup and configuration
- **Features**:
  - Virtual environment creation and activation
  - Dependency installation and validation
  - System configuration and optimization
  - Environment validation and testing
- **Usage**: `python3 config/setup_local.py [options]`

### **`setup_macos.py`**
- **Purpose**: macOS-specific setup and configuration
- **Features**:
  - macOS-specific dependency installation
  - System configuration for macOS
  - Compatibility testing and validation
  - Performance optimization for macOS
- **Usage**: `python3 config/setup_macos.py [options]`

### **`setup.py`**
- **Purpose**: Main setup and installation script
- **Features**:
  - Comprehensive system setup
  - Dependency management and installation
  - Configuration validation and testing
  - System optimization and tuning
- **Usage**: `python3 config/setup.py [options]`

### **`docker-compose.yml`**
- **Purpose**: Docker Compose configuration for containerized deployment
- **Features**:
  - Multi-container orchestration
  - Service configuration and networking
  - Volume mounting and persistence
  - Environment variable management
- **Usage**: `docker-compose -f config/docker-compose.yml up`

### **`Dockerfile`**
- **Purpose**: Main Docker container definition
- **Features**:
  - Base image configuration
  - Dependency installation
  - Application setup and configuration
  - Security hardening and optimization
- **Usage**: `docker build -f config/Dockerfile -t security-agent .`

### **`Dockerfile.alternative`**
- **Purpose**: Alternative Docker configuration
- **Features**:
  - Alternative base image
  - Different dependency configuration
  - Alternative security settings
  - Performance optimization options
- **Usage**: `docker build -f config/Dockerfile.alternative -t security-agent-alt .`

## 🚀 Configuration Options

### **Setup Options**
```bash
# Setup with options
python3 config/setup.py --verbose
python3 config/setup.py --force
python3 config/setup.py --clean
python3 config/setup.py --validate
```

### **Docker Options**
```bash
# Docker build options
docker build -f config/Dockerfile -t security-agent --build-arg VERSION=latest .

# Docker run options
docker run --rm --privileged -v /var/log:/var/log:rw security-agent
```

### **Environment Variables**
```bash
# Environment configuration
export SECURITY_AGENT_CONFIG=/path/to/config
export SECURITY_AGENT_LOG_LEVEL=INFO
export SECURITY_AGENT_OUTPUT_FORMAT=json
```

## 🔧 Configuration Management

### **Configuration Files**
```python
# Configuration structure
CONFIG = {
    'general': {
        'log_level': 'INFO',
        'output_format': 'console',
        'timeout': 0,
    },
    'enhanced_ebpf': {
        'batch_size': 1000,
        'max_processes': 10000,
        'stateful_tracking': True,
    },
    'enhanced_anomaly_detection': {
        'contamination': 0.1,
        'nu': 0.1,
        'feature_window': 100,
    },
    'container_security': {
        'docker_enabled': True,
        'cross_container_blocking': True,
    },
}
```

### **Configuration Validation**
```python
# Configuration validation
def validate_config(config):
    """Validate configuration parameters"""
    # Validation logic
    pass

def load_config(config_file):
    """Load configuration from file"""
    # Configuration loading
    pass
```

## 🎓 Configuration Best Practices

### **Setup Best Practices**
- **Automated Setup**: Use automated setup scripts
- **Environment Isolation**: Use virtual environments
- **Dependency Management**: Manage dependencies carefully
- **Configuration Validation**: Validate all configurations
- **Error Handling**: Handle setup errors gracefully

### **Docker Best Practices**
- **Security**: Use security-hardened base images
- **Optimization**: Optimize image size and performance
- **Networking**: Configure networking properly
- **Persistence**: Handle data persistence correctly
- **Monitoring**: Include monitoring and logging

## 🔧 Troubleshooting

### **Setup Issues**
- **Dependencies**: Check and install required dependencies
- **Permissions**: Verify file permissions and access rights
- **Environment**: Check environment configuration and setup
- **Validation**: Run configuration validation and testing

### **Docker Issues**
- **Build Errors**: Check Dockerfile syntax and dependencies
- **Runtime Errors**: Check container logs and configuration
- **Network Issues**: Verify networking and port configuration
- **Volume Issues**: Check volume mounting and permissions

## 📚 Related Documentation

### **Setup Guides**
- `../docs/INSTALL.md` - Installation instructions
- `../docs/LINUX_SETUP_GUIDE.md` - Linux setup guide
- `../docs/MACOS_GUIDE.md` - macOS setup guide

### **Usage Guides**
- `../docs/USAGE.md` - Usage instructions
- `../docs/ENHANCED_INTEGRATION_GUIDE.md` - Integration guide
- `../docs/DEMO_GUIDE.md` - Demo and testing guide

### **Development**
- `../core/README.md` - Core components documentation
- `../legacy/README.md` - Legacy components documentation
- `../scripts/README.md` - Automation scripts

## 🎯 Configuration Strategy

### **Environment-Specific Configuration**
- **Development**: Development-specific settings and configurations
- **Testing**: Test environment configurations and settings
- **Production**: Production-ready configurations and optimizations
- **Docker**: Containerized deployment configurations

### **Configuration Management**
- **Version Control**: Track configuration changes
- **Validation**: Validate configurations before deployment
- **Backup**: Backup important configurations
- **Documentation**: Document configuration options and settings

These configuration files and scripts provide comprehensive setup, deployment, and configuration management for the Linux Security Agent project.
