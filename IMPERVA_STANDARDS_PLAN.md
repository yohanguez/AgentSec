# Imperva Conference Standards - Implementation Plan

## Executive Summary

Comparison with reference repository (thalesgroup/shadowai-watch) reveals gaps in testing, CI/CD, and documentation that must be addressed before conference presentation.

## Current State Analysis

### AgentSec (Current)
- **Test Coverage**: ~6% (342 lines of tests / 5,862 lines of code)
- **Test Files**: 7 test files, 28 test functions
- **CI/CD**: ❌ None
- **Pre-commit Hooks**: ❌ None
- **Build System**: ❌ No Makefile
- **Code Quality**: Configured (black, ruff, mypy) but not enforced
- **Documentation**: 
  - ✅ README.md
  - ✅ TESTING_GUIDE.md
  - ❌ SECURITY.md
  - ❌ CODE_OF_CONDUCT.md
  - ❌ CONTRIBUTING.md (incomplete)
  - ❌ LICENSE file

### shadowai-watch (Reference Standard)
- **Test Coverage**: Extensive (25 test files, comprehensive coverage)
- **CI/CD**: ✅ GitHub Actions with 2-job pipeline
  - Job 1: Verify, test, build wheel, upload artifacts
  - Job 2: Compile sources, verify checksums
- **Pre-commit Hooks**: ✅ Git pre-push hook with full pipeline
- **Build System**: ✅ Makefile (all, build, test, verify, wheel, hooks, clean)
- **Code Quality**: Enforced via CI and hooks
- **Documentation**:
  - ✅ README.md with badges
  - ✅ SECURITY.md (vulnerability reporting, policies)
  - ✅ CODE_OF_CONDUCT.md (Contributor Covenant)
  - ✅ CONTRIBUTING.md
  - ✅ LICENSE (Apache-2.0)
  - ✅ docs/ folder with technical documentation

## Gap Analysis & Priority

### 🔴 Critical (Required for Conference)

#### 1. Legal & Compliance
- **LICENSE file**: Apache-2.0 or Imperva-approved license
- **SECURITY.md**: Vulnerability disclosure policy with Imperva contact
- **CODE_OF_CONDUCT.md**: Professional conduct standards

#### 2. Quality Assurance
- **GitHub Actions CI/CD**: Automated testing on every push/PR
- **Test Coverage**: Minimum 80% coverage (industry standard)
- **Pre-commit Hooks**: Prevent bad commits from entering repo

### 🟡 High Priority (Professional Standards)

#### 3. Build Infrastructure
- **Makefile**: Standardized commands (test, lint, build, clean)
- **pytest-cov configuration**: Coverage reporting and thresholds

#### 4. Documentation
- **CONTRIBUTING.md**: Detailed contribution guidelines
- **README badges**: CI status, coverage, quality indicators

### 🟢 Medium Priority (Nice to Have)

#### 5. Extended Testing
- **Integration tests**: CLI command testing
- **Coverage reports**: HTML reports for review

## Detailed Implementation Plan

### Phase 1: Legal & Compliance (Week 1)
**Priority**: CRITICAL - Cannot present without these

```
1. Add LICENSE file (Apache-2.0)
   - Review with Imperva legal if needed
   - Add copyright header template

2. Create SECURITY.md
   - Supported versions table
   - Vulnerability reporting: security@imperva.com (or appropriate contact)
   - Disclosure policy
   - Known security gaps

3. Add CODE_OF_CONDUCT.md
   - Contributor Covenant 2.1
   - Imperva contact for violations
   - Enforcement guidelines
```

### Phase 2: CI/CD Pipeline (Week 1-2)
**Priority**: CRITICAL - Demonstrates professional engineering

```
4. Create .github/workflows/ci.yml
   Jobs:
   a) code-quality:
      - black --check (formatting)
      - ruff check (linting)
      - mypy (type checking)
   
   b) test:
      - pytest with coverage
      - Upload coverage to Codecov/Coveralls
      - Fail if coverage < 80%
   
   c) build:
      - Build wheel package
      - Upload artifact
      - Test package installation

5. Add pre-commit hooks
   - .pre-commit-config.yaml
   - tools/install_hooks.py
   - Update CONTRIBUTING.md with setup instructions
```

### Phase 3: Test Coverage (Week 2-3)
**Priority**: CRITICAL - Core quality metric

```
6. Expand unit tests to 80%+ coverage
   Current: 28 tests, 342 lines
   Target: 100+ tests, 2000+ lines

   Priority modules:
   - agentsec/analyzers/* (langgraph, crewai, autogen, n8n)
   - agentsec/audit/* (capability detection, AST analysis)
   - agentsec/report/* (HTML/JSON generation)
   - agentsec/server/* (FastAPI endpoints)
   - agentsec/cli/* (command interface)

7. Add integration tests
   - CLI command testing (scan, serve, monitor)
   - End-to-end workflow analysis
   - Report generation validation

8. Configure pytest-cov
   - Update pytest.ini with coverage settings
   - Add pytest-cov to dev dependencies
   - Set minimum coverage threshold (80%)
```

### Phase 4: Build Infrastructure (Week 3)
**Priority**: HIGH - Professional polish

```
9. Create Makefile
   Targets:
   - install: pip install -e ".[all]"
   - test: pytest with coverage
   - lint: black + ruff + mypy
   - build: lint + test + wheel
   - hooks: install pre-commit hooks
   - clean: remove artifacts
   - all: build (default)

10. Update pyproject.toml
    - Add pytest-cov to dev dependencies
    - Configure black/ruff/mypy strict settings
    - Add coverage settings
```

### Phase 5: Documentation (Week 3-4)
**Priority**: HIGH - User and contributor experience

```
11. Enhance CONTRIBUTING.md
    - Setup instructions (clone, install, hooks)
    - Development workflow
    - Coding standards (black 100 chars, ruff rules)
    - Testing requirements (80% coverage)
    - PR checklist
    - Commit message format
    - Issue management

12. Add README badges
    - CI/CD status
    - Code coverage
    - License
    - Python versions supported
    - Documentation link

13. Update README.md
    - Add "For Developers" section
    - Link to CONTRIBUTING.md
    - Link to SECURITY.md
    - Add "Tested on" section
```

### Phase 6: Final Polish (Week 4)
**Priority**: MEDIUM - Conference presentation polish

```
14. Enhance .gitignore
    - Coverage reports (htmlcov/, .coverage)
    - Build artifacts (dist/, build/, *.egg-info)
    - IDE files (.vscode/, .idea/)
    - Cache directories (__pycache__, .pytest_cache/)

15. Add docs/ folder
    - ARCHITECTURE.md (system design)
    - API.md (server API documentation)
    - EXAMPLES.md (usage examples)

16. Create CHANGELOG.md
    - Version history
    - Release notes format
```

## Success Metrics

### Before Conference Checklist

- [ ] LICENSE file present (Apache-2.0)
- [ ] SECURITY.md with Imperva contact
- [ ] CODE_OF_CONDUCT.md present
- [ ] CONTRIBUTING.md complete
- [ ] GitHub Actions CI passing all checks
- [ ] Test coverage ≥ 80%
- [ ] Pre-commit hooks installed and working
- [ ] Makefile with standard targets
- [ ] README with badges (all green)
- [ ] No security vulnerabilities in dependencies
- [ ] Code formatted (black), linted (ruff), typed (mypy)
- [ ] All tests passing
- [ ] Wheel package builds successfully
- [ ] Documentation up to date

## Reference Implementation Examples

### CI/CD Pipeline Structure (from shadowai-watch)
```yaml
name: Build
on: [push, pull_request]

jobs:
  verify-and-test:
    runs-on: ubuntu-latest
    steps:
      - checkout
      - setup-python (3.10, 3.11, 3.12)
      - install dependencies
      - run linting (black, ruff, mypy)
      - run tests with coverage
      - build wheel
      - upload artifacts

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - bandit security scan
      - safety check dependencies
      - upload results
```

### Makefile Structure (from shadowai-watch)
```makefile
PYTHON ?= python3

all: build

build: lint test wheel

lint:
	$(PYTHON) -m black --check .
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy agentsec

test:
	$(PYTHON) -m pytest --cov=agentsec --cov-report=html tests/

wheel:
	$(PYTHON) -m pip wheel --no-deps -w dist .

hooks:
	$(PYTHON) tools/install_hooks.py

clean:
	rm -rf dist build *.egg-info htmlcov .coverage
	find . -name '__pycache__' -exec rm -rf {} +
```

### Pre-commit Hook Structure
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        args: [--line-length=100]

  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: v0.1.9
    hooks:
      - id: ruff
        args: [--fix]

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.8.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
```

## Timeline Estimate

- **Phase 1 (Legal)**: 1-2 days
- **Phase 2 (CI/CD)**: 2-3 days
- **Phase 3 (Testing)**: 5-7 days (most effort)
- **Phase 4 (Build)**: 1-2 days
- **Phase 5 (Docs)**: 2-3 days
- **Phase 6 (Polish)**: 1-2 days

**Total**: 2-3 weeks of focused work

## Immediate Next Steps

1. **Confirm with Imperva legal**: License type and security contact email
2. **Start with Phase 1**: Legal compliance documents (cannot present without)
3. **Run in parallel**: CI/CD setup while writing tests
4. **Continuous validation**: Each phase should result in working, tested code

## Questions for Imperva

1. What license should be used? (Apache-2.0, MIT, proprietary?)
2. What email/contact for security vulnerability reports?
3. Any specific compliance requirements beyond standard OSS practices?
4. Code review required before public release?
5. Can we use public GitHub Actions or need self-hosted runners?
6. Any restricted dependencies or security scanning requirements?

---

**Status**: Ready for implementation
**Owner**: [Your Name]
**Conference Date**: [Date]
**Review Required**: Yes (Imperva legal and security teams)
