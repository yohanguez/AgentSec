#!/usr/bin/env python3
"""
Install git pre-commit hooks for AgentSec development.

This script sets up pre-commit hooks that run code quality checks
before each commit, helping maintain code standards.
"""

import os
import subprocess
import sys
from pathlib import Path


def main():
    """Install pre-commit hooks."""
    repo_root = Path(__file__).parent.parent
    os.chdir(repo_root)

    print("Installing pre-commit hooks for AgentSec...")

    # Check if we're in a git repository
    if not (repo_root / ".git").exists():
        print("Error: Not in a git repository", file=sys.stderr)
        return 1

    # Check if pre-commit is installed
    try:
        subprocess.run(
            ["pre-commit", "--version"],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("pre-commit is not installed. Installing...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pre-commit"],
            check=True,
        )

    # Install the hooks
    print("Installing pre-commit hooks...")
    result = subprocess.run(
        ["pre-commit", "install"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Error installing hooks: {result.stderr}", file=sys.stderr)
        return 1

    print("✓ Pre-commit hooks installed successfully!")
    print("\nThe following checks will run before each commit:")
    print("  • Code formatting (black)")
    print("  • Linting (ruff)")
    print("  • Type checking (mypy)")
    print("  • Trailing whitespace removal")
    print("  • YAML/JSON syntax validation")
    print("  • Large file detection")
    print("  • Private key detection")
    print("\nTo run hooks manually: pre-commit run --all-files")
    print("To bypass hooks (NOT recommended): git commit --no-verify")

    return 0


if __name__ == "__main__":
    sys.exit(main())
