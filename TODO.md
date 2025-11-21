# TODO List - Remaining Implementation Tasks

> **Author**: Likitha Shankar  
> **Last Updated**: November 20, 2024  
> **Status**: Research Prototype - Priority items for enhancement

This document tracks remaining tasks and improvements for the Linux Security Agent project.

---

## 🔴 Critical Priority (For Production Readiness)

### Security & Authentication
- [ ] **Add authentication/authorization for agent operations**
  - **Priority**: High (for production)
  - **Research Priority**: Low (not needed for academic demo)
  - **Effort**: 1-2 weeks
  - **Details**: Add API keys, HMAC signatures, or local socket permissions
  - **Location**: All components

- [ ] **Add encryption for sensitive data storage**
  - **Priority**: Medium (for production)
  - **Research Priority**: Low
  - **Effort**: 3-5 days
  - **Details**: Encrypt risk scores, training data, model files in `~/.cache/security_agent/`
  - **Current**: Files have secure permissions (0o700) but not encrypted

- [ ] **Implement container policy enforcement**
  - **Priority**: Medium
  - **Research Priority**: Low
  - **Effort**: 1 week
  - **Details**: Currently detection only, add blocking/isolation capabilities
  - **Location**: `core/container_security_monitor.py`

---

## 🟡 High Priority (For Research Enhancement)

### Testing & Validation
- [ ] **Add comprehensive integration tests**
  - **Priority**: High (strengthens academic presentation)
  - **Effort**: 1-2 weeks
  - **Details**: Full pipeline tests (collector → risk scoring → ML detection → dashboard)
  - **Current**: Basic unit tests exist, integration tests limited

- [ ] **Create performance benchmark suite**
  - **Priority**: High (validates performance claims)
  - **Effort**: 1 week
  - **Details**: Validate "<5% CPU overhead", "1000+ processes" claims
  - **Current**: Performance claims unverified

- [ ] **Add automated attack simulation test suite**
  - **Priority**: High (demonstrates detection capabilities)
  - **Effort**: 1 week
  - **Details**: Integrate `scripts/simulate_attacks.py` into test framework
  - **Current**: Scripts exist but not automated in CI/CD

- [ ] **Add ML model evaluation metrics**
  - **Priority**: High (strengthens ML claims)
  - **Effort**: 1 week
  - **Details**: Precision, recall, F1, confusion matrices, ROC AUC
  - **Current**: Models work but accuracy not quantified

---

## 🟢 Medium Priority (Enhancements)

### Code Quality
- [ ] **Replace remaining silent error handling**
  - **Priority**: Medium
  - **Effort**: 3-5 days
  - **Details**: Replace remaining `try/except: pass` with proper logging
  - **Current**: Improved but not comprehensive

- [ ] **Move hardcoded values to config**
  - **Priority**: Low
  - **Effort**: 2-3 days
  - **Details**: `MAX_VALID_PID`, `STALE_PROCESS_TIMEOUT`, etc.
  - **Current**: Most values in config, some remain hardcoded

- [ ] **Add thread safety stress testing**
  - **Priority**: Medium
  - **Effort**: 1 week
  - **Details**: Audit shared state, test race conditions
  - **Current**: Uses locks but not stress-tested

### ML Improvements
- [ ] **Validate training data quality**
  - **Priority**: Medium
  - **Effort**: 1-2 weeks
  - **Details**: Add data validation, outlier detection, ground truth labels
  - **Current**: Models train but no quality checks

- [ ] **Validate 50-D feature engineering as optimal**
  - **Priority**: Low
  - **Effort**: 1-2 weeks
  - **Details**: Feature importance analysis, dimensionality reduction validation
  - **Current**: 50-D features not validated

- [ ] **Add model calibration and confidence intervals**
  - **Priority**: Low
  - **Effort**: 3-5 days
  - **Details**: Calibrate ensemble voting, add confidence intervals
  - **Current**: Basic ensemble without calibration

### Documentation
- [ ] **Add visual architecture diagrams**
  - **Priority**: Low (nice to have for presentation)
  - **Effort**: 1 week
  - **Details**: Visual diagrams, data flow diagrams
  - **Current**: Architecture documented in text

- [ ] **Decide on Platform API integration**
  - **Priority**: Low
  - **Effort**: 1-2 weeks (if integrating)
  - **Details**: Integrate `_platform-api-stash/` or remove and document decision
  - **Current**: Stashed code exists but not integrated

---

## 📊 Summary by Category

### Security (3 items)
- Authentication/authorization
- Encryption
- Container policy enforcement

### Testing (4 items)
- Integration tests
- Performance benchmarks
- Automated attack tests
- ML evaluation metrics

### Code Quality (3 items)
- Error handling improvements
- Config management
- Thread safety testing

### ML/Detection (3 items)
- Training data validation
- Feature engineering validation
- Model calibration

### Documentation (2 items)
- Architecture diagrams
- Platform API decision

---

## 🎯 Recommended Priority for Research Project

### For Academic Presentation (High Priority)
1. **ML Evaluation Metrics** (1 week) - Strengthen ML claims
2. **Performance Benchmarks** (1 week) - Validate performance claims
3. **Automated Attack Tests** (1 week) - Demonstrate detection capabilities

### For Production Readiness (If Pursued)
1. **Authentication/Authorization** (1-2 weeks)
2. **Comprehensive Testing** (2-3 weeks)
3. **Encryption** (3-5 days)
4. **Thread Safety Validation** (1 week)

---

## ✅ Recently Completed (Not in TODO)

These items have been completed and don't need to be tracked:

- ✅ Risk scores storage (moved from `/tmp` to `~/.cache/security_agent/` with secure permissions)
- ✅ Memory management (automatic cleanup using `deque(maxlen=50)`)
- ✅ Error handling improvements (replaced many bare `except:` clauses)
- ✅ Documentation accuracy (updated to reflect "Research Prototype" status)
- ✅ Modular architecture (refactored into organized modules)
- ✅ Collector factory pattern (centralized collector selection)
- ✅ Anomaly score integration (fixed to properly affect risk scores)
- ✅ Attack simulation scripts (added `scripts/simulate_attacks.py`)
- ✅ Dashboard improvements (better UI, fixed blinking, status indicators)

---

## 📈 Progress Tracking

**Total Remaining Tasks**: 15  
**Critical Priority**: 3  
**High Priority**: 4  
**Medium Priority**: 8

**Estimated Effort for Research Enhancement**: 2-3 weeks (metrics, benchmarks, tests)  
**Estimated Effort for Production Readiness**: 6-8 weeks

---

## 🔗 Related Documentation

- **Gap Analysis**: `docs/GAP_ANALYSIS.md` - Detailed gap analysis
- **Project Status**: `PROJECT_STATUS.md` - Current state and classification
- **Architecture**: `docs/ARCHITECTURE.md` - System design

---

**Note**: This is a research prototype. Many items are acceptable for academic demonstration. Focus should be on demonstrating concepts (eBPF, ML anomaly detection, container security) rather than production-grade features.

