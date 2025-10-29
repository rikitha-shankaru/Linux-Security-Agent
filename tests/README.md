# 🧪 Tests - Linux Security Agent

This folder contains testing utilities, validation scripts, and test suites for the Linux Security Agent project.

## 📁 Files

### **Test Scripts**
- **`run_tests.py`** - Main test runner and validation script
- **`test_ebpf.py`** - eBPF functionality testing script

## 🎯 Usage

### **Running Tests**
```bash
# Run all tests
python3 tests/run_tests.py

# Run eBPF tests
python3 tests/test_ebpf.py

# Run with verbose output
python3 tests/run_tests.py --verbose
```

### **Test Categories**
```bash
# Run specific test categories
python3 tests/run_tests.py --category unit
python3 tests/run_tests.py --category integration
python3 tests/run_tests.py --category performance
```

## 🔧 Test Details

### **`run_tests.py`**
- **Purpose**: Main test runner and validation script
- **Features**:
  - Unit tests for all components
  - Integration tests for system functionality
  - Performance benchmarks and validation
  - Error handling and edge case testing
  - Test reporting and results analysis
- **Usage**: `python3 tests/run_tests.py [options]`

### **`test_ebpf.py`**
- **Purpose**: eBPF functionality testing
- **Features**:
  - eBPF program compilation and loading
  - System call monitoring validation
  - Performance testing and benchmarking
  - Error handling and recovery testing
  - Compatibility testing across systems
- **Usage**: `python3 tests/test_ebpf.py [options]`

## 🚀 Test Categories

### **Unit Tests**
- **Component Testing**: Individual component functionality
- **Function Testing**: Specific function validation
- **Edge Cases**: Boundary conditions and error cases
- **Mock Testing**: Isolated component testing

### **Integration Tests**
- **System Integration**: End-to-end system testing
- **Component Interaction**: Inter-component communication
- **Data Flow**: Data processing and transformation
- **Error Propagation**: Error handling across components

### **Performance Tests**
- **Benchmarking**: Performance measurement and validation
- **Load Testing**: High-load scenario testing
- **Memory Testing**: Memory usage and leak detection
- **CPU Testing**: CPU usage and optimization validation

### **Security Tests**
- **Threat Detection**: Security threat detection validation
- **Anomaly Detection**: ML model accuracy testing
- **Policy Enforcement**: Security policy validation
- **Container Security**: Container security testing

## 📊 Test Results

### **Expected Results**
- **Unit Tests**: 100% pass rate
- **Integration Tests**: 95%+ pass rate
- **Performance Tests**: Within acceptable thresholds
- **Security Tests**: High detection accuracy

### **Test Metrics**
- **Coverage**: Code coverage percentage
- **Accuracy**: Detection accuracy metrics
- **Performance**: CPU and memory usage
- **Reliability**: System stability and consistency

## 🔧 Test Configuration

### **Test Parameters**
```python
# Test configuration
TEST_CONFIG = {
    'timeout': 30,  # Test timeout in seconds
    'verbose': False,  # Verbose output
    'categories': ['unit', 'integration', 'performance'],
    'coverage': True,  # Enable coverage reporting
    'benchmarks': True,  # Enable benchmarking
}
```

### **Environment Setup**
```bash
# Install test dependencies
pip install pytest coverage pytest-cov

# Run tests with coverage
python3 tests/run_tests.py --coverage

# Generate coverage report
coverage html
```

## 🎓 Test Development

### **Adding New Tests**
```python
# Test template
def test_component_functionality():
    """Test component functionality"""
    # Setup
    component = Component()
    
    # Test
    result = component.function()
    
    # Assert
    assert result is not None
    assert result.status == 'success'
```

### **Test Best Practices**
- **Isolation**: Tests should be independent and isolated
- **Deterministic**: Tests should produce consistent results
- **Comprehensive**: Cover all code paths and edge cases
- **Fast**: Tests should run quickly for frequent execution
- **Clear**: Test names and assertions should be clear and descriptive

## 🔧 Troubleshooting

### **Common Issues**
- **Test Failures**: Check test output and error messages
- **Environment Issues**: Verify test environment setup
- **Dependencies**: Ensure all test dependencies are installed
- **Permissions**: Check file permissions and access rights

### **Debugging**
- **Verbose Output**: Use `--verbose` flag for detailed output
- **Single Test**: Run individual tests for focused debugging
- **Log Analysis**: Check test logs for detailed error information
- **Environment Validation**: Verify test environment configuration

## 📚 Related Documentation

### **Testing Guides**
- `../docs/USAGE.md` - Usage instructions and examples
- `../docs/ENHANCED_INTEGRATION_GUIDE.md` - Integration testing
- `../docs/DEMO_GUIDE.md` - Demo and validation testing

### **Development**
- `../core/README.md` - Core components documentation
- `../legacy/README.md` - Legacy components documentation
- `../scripts/README.md` - Automation and testing scripts

### **Configuration**
- `../config/` - Configuration files and setup
- `../requirements.txt` - Python dependencies
- `../README.md` - Main project documentation

## 🎯 Test Strategy

### **Continuous Testing**
- **Automated Testing**: Run tests automatically on code changes
- **Regression Testing**: Prevent regression of existing functionality
- **Performance Monitoring**: Monitor performance metrics over time
- **Security Validation**: Continuous security testing and validation

### **Test Coverage**
- **Code Coverage**: Aim for 90%+ code coverage
- **Function Coverage**: Test all public functions and methods
- **Edge Case Coverage**: Test boundary conditions and error cases
- **Integration Coverage**: Test all component interactions

These tests ensure the reliability, performance, and security of the Linux Security Agent project.
