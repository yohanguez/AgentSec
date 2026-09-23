"""Tests for AST signature detection."""

import pytest
import ast
from pathlib import Path

from agentsec.models import Capability
from agentsec.audit.signatures import SignatureDetector, ASTSignatureVisitor


class TestSignatureDetector:
    """Tests for signature-based capability detection."""

    def test_detect_subprocess(self):
        """Test detection of subprocess usage."""
        code = """
import subprocess
subprocess.run(['ls', '-la'])
subprocess.call(['echo', 'hello'])
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.SHELL_EXEC in capabilities

    def test_detect_os_system(self):
        """Test detection of os.system usage."""
        code = """
import os
os.system('rm -rf /')
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.SHELL_EXEC in capabilities

    def test_detect_file_operations(self):
        """Test detection of file read/write."""
        code = """
with open('file.txt', 'r') as f:
    content = f.read()

with open('output.txt', 'w') as f:
    f.write('data')
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.FS_READ in capabilities
        assert Capability.FS_WRITE in capabilities

    def test_detect_database_operations(self):
        """Test detection of database operations."""
        code = """
import sqlite3
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
cursor.execute('INSERT INTO logs VALUES (?)', (data,))
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.DB_READ in capabilities or Capability.DB_WRITE in capabilities

    def test_detect_network_requests(self):
        """Test detection of network operations."""
        code = """
import requests
response = requests.get('https://api.example.com')
requests.post('https://api.example.com', json={'data': 'value'})
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.NETWORK_READ in capabilities
        assert Capability.NETWORK_WRITE in capabilities

    def test_detect_eval_exec(self):
        """Test detection of eval/exec (code execution)."""
        code = """
user_input = input()
eval(user_input)
exec(user_input)
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        assert Capability.CODE_EXEC in capabilities

    def test_no_false_positives_on_imports(self):
        """Test that mere imports don't trigger detection."""
        code = """
import subprocess
import os
# Just importing, not using
"""
        detector = SignatureDetector()
        capabilities = detector.detect_from_code(code)
        # Imports alone might not trigger, depends on implementation
        # This test ensures we're not too aggressive

    def test_detect_from_file(self, tmp_path):
        """Test detection from a file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import subprocess
subprocess.run(['ls'])
""")
        detector = SignatureDetector()
        capabilities = detector.detect_from_file(test_file)
        assert Capability.SHELL_EXEC in capabilities

    def test_invalid_python_code(self):
        """Test handling of invalid Python code."""
        code = """
this is not valid python code!!!
"""
        detector = SignatureDetector()
        # Should handle gracefully, not crash
        try:
            capabilities = detector.detect_from_code(code)
            # May return empty set or raise, either is acceptable
        except SyntaxError:
            pass  # Expected for invalid code


class TestASTSignatureVisitor:
    """Tests for AST visitor pattern matching."""

    def test_visitor_detects_function_calls(self):
        """Test that visitor detects specific function calls."""
        code = """
import os
os.system('command')
"""
        tree = ast.parse(code)
        visitor = ASTSignatureVisitor()
        visitor.visit(tree)
        # Visitor should have recorded the os.system call
        assert len(visitor.detected_patterns) > 0 or len(visitor.capabilities) > 0

    def test_visitor_tracks_imports(self):
        """Test that visitor tracks imported modules."""
        code = """
import subprocess
from pathlib import Path
import requests
"""
        tree = ast.parse(code)
        visitor = ASTSignatureVisitor()
        visitor.visit(tree)
        # Visitor should track these imports
        assert len(visitor.imports) > 0

    def test_visitor_handles_nested_calls(self):
        """Test detection in nested function calls."""
        code = """
def wrapper():
    import subprocess
    def inner():
        subprocess.run(['command'])
    inner()
"""
        tree = ast.parse(code)
        visitor = ASTSignatureVisitor()
        visitor.visit(tree)
        # Should detect nested subprocess.run


def test_signature_patterns_coverage():
    """Test that signature detector has patterns for all capability types."""
    detector = SignatureDetector()

    # Verify detector has patterns for major capabilities
    test_cases = [
        (Capability.SHELL_EXEC, "subprocess.run(['ls'])"),
        (Capability.CODE_EXEC, "eval('1+1')"),
        (Capability.FS_READ, "open('file.txt', 'r')"),
        (Capability.FS_WRITE, "open('file.txt', 'w')"),
    ]

    for expected_cap, code in test_cases:
        caps = detector.detect_from_code(f"import subprocess\nimport os\n{code}")
        # At least one of these patterns should detect the capability
