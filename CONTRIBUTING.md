# Contributing to AgentSec

Thank you for your interest in contributing to AgentSec! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Format](#commit-message-format)
- [Issue Management](#issue-management)

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@imperva.com.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- pip and setuptools

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AgentSec.git
   cd AgentSec
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/yohanguez/AgentSec.git
   ```

## Development Setup

### 1. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
# Install package in editable mode with all extras
make install

# Or manually:
pip install -e ".[all]"
pip install pytest pytest-cov black ruff mypy pre-commit
```

### 3. Install Pre-commit Hooks

Pre-commit hooks automatically check code quality before each commit:

```bash
make hooks

# Or manually:
python tools/install_hooks.py
```

This installs hooks that will:
- Format code with black
- Lint with ruff
- Type check with mypy
- Check for trailing whitespace
- Validate YAML/JSON syntax
- Detect large files and private keys

### 4. Verify Setup

```bash
# Run tests
make test

# Run linting
make lint

# Run demo
make demo
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feat/your-feature-name
# or for bug fixes:
git checkout -b fix/bug-description
```

Branch naming conventions:
- `feat/feature-name` - New features
- `fix/bug-name` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions or updates

### 2. Make Your Changes

- Write clear, concise code
- Follow the coding standards (see below)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
make test

# Run specific test file
pytest tests/test_models.py

# Run with coverage report
pytest --cov=agentsec --cov-report=html
```

### 4. Format and Lint

```bash
# Auto-format code
make format

# Check code quality
make lint
```

### 5. Commit Your Changes

Follow the commit message format (see below):

```bash
git add .
git commit -m "feat: add support for new framework"
```

### 6. Push and Create Pull Request

```bash
git push origin feat/your-feature-name
```

Then create a pull request on GitHub.

## Coding Standards

### Python Style

We follow PEP 8 with some modifications:

- **Line length**: 100 characters (enforced by black)
- **Formatter**: black with `--line-length 100`
- **Linter**: ruff
- **Type hints**: mypy (encouraged but not strictly required)

### Code Formatting

```bash
# Format all code
black --line-length 100 .

# Or use make:
make format
```

### Linting

```bash
# Check for issues
ruff check .

# Auto-fix issues
ruff check --fix .
```

### Type Checking

```bash
# Type check with mypy
mypy agentsec --ignore-missing-imports
```

### Import Organization

- Standard library imports first
- Third-party imports second
- Local application imports third
- Alphabetically sorted within each group

Example:
```python
import os
from pathlib import Path

from pydantic import BaseModel
import typer

from agentsec.models import Graph
from agentsec.audit import Auditor
```

### Docstrings

Use Google-style docstrings for public APIs:

```python
def analyze_workflow(input_dir: Path) -> Graph:
    """Analyze a workflow directory and return a graph.

    Args:
        input_dir: Path to the workflow directory

    Returns:
        A Graph object representing the analyzed workflow

    Raises:
        ValueError: If the directory doesn't contain valid workflow files
    """
    pass
```

## Testing Requirements

### Test Coverage

- **Minimum coverage**: 80% for new code
- **Target coverage**: 90% for critical modules
- Tests must pass before merging

### Writing Tests

1. Place tests in the `tests/` directory
2. Name test files `test_*.py`
3. Name test functions `test_*`
4. Use pytest fixtures for common setup

Example test structure:
```python
import pytest
from agentsec.models import Graph, Node

def test_graph_creation():
    """Test that a graph can be created with nodes."""
    graph = Graph(nodes=[])
    assert len(graph.nodes) == 0

def test_add_node():
    """Test adding a node to a graph."""
    graph = Graph(nodes=[])
    node = Node(id="test", type="agent", name="Test Agent")
    graph.nodes.append(node)
    assert len(graph.nodes) == 1
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
pytest tests/test_models.py

# Run specific test function
pytest tests/test_models.py::test_graph_creation

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=agentsec --cov-report=html
```

## Pull Request Process

### Before Submitting

- [ ] All tests pass (`make test`)
- [ ] Code is formatted (`make format`)
- [ ] Code passes linting (`make lint`)
- [ ] Coverage meets requirements (80%+)
- [ ] Documentation is updated
- [ ] Commit messages follow format
- [ ] Branch is up to date with main

### PR Checklist

Your pull request should:

1. **Have a clear title** - Use conventional commit format
2. **Include a description** - Explain what and why
3. **Reference issues** - Link related issues with "Fixes #123"
4. **Include tests** - Add tests for new functionality
5. **Update documentation** - Update README or docs if needed
6. **Pass CI checks** - All GitHub Actions must pass

### PR Template

```markdown
## Description
Brief description of the changes

## Motivation
Why are these changes needed?

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
How has this been tested?

## Related Issues
Fixes #123
Related to #456

## Checklist
- [ ] Tests pass
- [ ] Code is formatted
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

### Review Process

1. Maintainers will review your PR within 1-2 weeks
2. Address review feedback by pushing new commits
3. Once approved, a maintainer will merge your PR

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code restructuring without behavior change
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates

### Examples

```
feat(analyzers): add support for LlamaIndex framework

Implement analyzer for LlamaIndex workflows with agent detection
and capability mapping.

Fixes #123
```

```
fix(audit): correct capability detection for custom tools

AST visitor was not handling nested function calls properly.
Now correctly identifies shell_exec in nested contexts.
```

```
docs: update installation instructions

Add pip install instructions and troubleshooting section.
```

## Issue Management

### Creating Issues

Use issue templates when available:

- **Bug Report**: For reporting bugs
- **Feature Request**: For proposing new features
- **Question**: For asking questions

### Issue Labels

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `priority:high` - High priority
- `priority:low` - Low priority

### Claiming Issues

Comment on an issue to claim it before starting work:

> I'd like to work on this issue. I plan to implement X by doing Y.

## Development Tips

### Useful Make Targets

```bash
make install    # Install dependencies
make test       # Run tests
make lint       # Check code quality
make format     # Auto-format code
make build      # Full build pipeline
make hooks      # Install git hooks
make clean      # Remove artifacts
make demo       # Run demo analysis
make help       # Show all targets
```

### Debugging

```bash
# Run tests with debugging output
pytest -v -s tests/

# Run specific test with pdb
pytest --pdb tests/test_models.py::test_graph_creation

# Generate coverage report
pytest --cov=agentsec --cov-report=html
open htmlcov/index.html
```

### Working with Workflows

Test your changes with the demo workflows:

```bash
# Analyze demo workflow
agentsec scan langgraph -i demo/autoops -o test-report.html

# Run with debug logging
agentsec --debug scan langgraph -i demo/autoops -o test-report.html
```

## Questions?

- **Documentation**: Check the [README](README.md)
- **Security**: See [SECURITY.md](SECURITY.md)
- **Issues**: Search [existing issues](https://github.com/yohanguez/AgentSec/issues)
- **Discussion**: Open a new issue for questions

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to AgentSec!
