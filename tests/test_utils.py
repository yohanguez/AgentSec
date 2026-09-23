"""Tests for utility modules."""

import pytest
import ast
from pathlib import Path

from agentsec.utils.ast_utils import (
    extract_function_calls,
    extract_imports,
    find_nodes_by_type,
    parse_python_file,
)
from agentsec.utils.file_utils import (
    find_python_files,
    find_json_files,
    read_file_safe,
)


class TestASTUtils:
    """Tests for AST utility functions."""

    def test_parse_python_file(self, tmp_path):
        """Test parsing a Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
def hello():
    print("Hello, World!")
""")
        tree = parse_python_file(test_file)
        assert tree is not None
        assert isinstance(tree, ast.Module)

    def test_parse_invalid_python(self, tmp_path):
        """Test parsing invalid Python code."""
        test_file = tmp_path / "invalid.py"
        test_file.write_text("this is not valid python !!!")

        # Should handle gracefully
        try:
            tree = parse_python_file(test_file)
            # May return None or raise
        except SyntaxError:
            pass  # Expected

    def test_extract_imports(self):
        """Test extracting import statements."""
        code = """
import os
import sys
from pathlib import Path
from typing import List, Dict
"""
        tree = ast.parse(code)
        imports = extract_imports(tree)

        assert "os" in imports
        assert "sys" in imports
        assert "pathlib" in imports or "Path" in imports

    def test_extract_function_calls(self):
        """Test extracting function calls."""
        code = """
import subprocess
subprocess.run(['ls'])
subprocess.call(['echo', 'hello'])
print("done")
"""
        tree = ast.parse(code)
        calls = extract_function_calls(tree)

        # Should find subprocess calls
        assert any("subprocess" in call or "run" in call for call in calls)

    def test_find_nodes_by_type(self):
        """Test finding nodes by AST type."""
        code = """
x = 1
y = 2
z = x + y
"""
        tree = ast.parse(code)
        assigns = find_nodes_by_type(tree, ast.Assign)

        assert len(assigns) >= 3  # Three assignments

    def test_find_function_definitions(self):
        """Test finding function definitions."""
        code = """
def func1():
    pass

def func2(x, y):
    return x + y

class MyClass:
    def method(self):
        pass
"""
        tree = ast.parse(code)
        funcs = find_nodes_by_type(tree, ast.FunctionDef)

        assert len(funcs) >= 2  # At least func1 and func2

    def test_find_class_definitions(self):
        """Test finding class definitions."""
        code = """
class Class1:
    pass

class Class2:
    def method(self):
        pass
"""
        tree = ast.parse(code)
        classes = find_nodes_by_type(tree, ast.ClassDef)

        assert len(classes) == 2


class TestFileUtils:
    """Tests for file utility functions."""

    def test_find_python_files(self, tmp_path):
        """Test finding Python files in directory."""
        # Create test files
        (tmp_path / "file1.py").write_text("# Python file 1")
        (tmp_path / "file2.py").write_text("# Python file 2")
        (tmp_path / "readme.txt").write_text("Not Python")

        python_files = find_python_files(tmp_path)

        assert len(python_files) >= 2
        assert all(f.suffix == ".py" for f in python_files)

    def test_find_python_files_recursive(self, tmp_path):
        """Test finding Python files recursively."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "root.py").write_text("# Root")
        (subdir / "nested.py").write_text("# Nested")

        python_files = find_python_files(tmp_path, recursive=True)

        # Should find both files
        assert len(python_files) >= 2

    def test_find_json_files(self, tmp_path):
        """Test finding JSON files in directory."""
        (tmp_path / "data.json").write_text('{"key": "value"}')
        (tmp_path / "config.json").write_text('{}')
        (tmp_path / "file.txt").write_text("Not JSON")

        json_files = find_json_files(tmp_path)

        assert len(json_files) >= 2
        assert all(f.suffix == ".json" for f in json_files)

    def test_read_file_safe(self, tmp_path):
        """Test safe file reading."""
        test_file = tmp_path / "test.txt"
        test_content = "Hello, World!"
        test_file.write_text(test_content)

        content = read_file_safe(test_file)

        assert content == test_content

    def test_read_file_safe_nonexistent(self, tmp_path):
        """Test reading nonexistent file."""
        nonexistent = tmp_path / "does_not_exist.txt"

        # Should handle gracefully
        try:
            content = read_file_safe(nonexistent)
            # May return None or empty string
        except (FileNotFoundError, IOError):
            pass  # Expected

    def test_read_file_safe_encoding(self, tmp_path):
        """Test reading file with different encoding."""
        test_file = tmp_path / "utf8.txt"
        test_file.write_text("Hello 世界", encoding="utf-8")

        content = read_file_safe(test_file, encoding="utf-8")

        assert "世界" in content

    def test_find_files_empty_directory(self, tmp_path):
        """Test finding files in empty directory."""
        python_files = find_python_files(tmp_path)
        json_files = find_json_files(tmp_path)

        assert len(python_files) == 0
        assert len(json_files) == 0

    def test_find_files_with_pattern(self, tmp_path):
        """Test finding files with specific pattern."""
        (tmp_path / "test_one.py").write_text("#")
        (tmp_path / "test_two.py").write_text("#")
        (tmp_path / "main.py").write_text("#")

        # Find all Python files
        all_files = find_python_files(tmp_path)
        assert len(all_files) == 3

        # Could filter by pattern
        test_files = [f for f in all_files if f.name.startswith("test_")]
        assert len(test_files) == 2

    def test_path_operations(self, tmp_path):
        """Test various Path operations."""
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()
        test_file = test_dir / "file.py"
        test_file.write_text("# Test")

        # Check path properties
        assert test_dir.exists()
        assert test_dir.is_dir()
        assert test_file.exists()
        assert test_file.is_file()
        assert test_file.parent == test_dir

    def test_glob_patterns(self, tmp_path):
        """Test glob pattern matching."""
        (tmp_path / "file1.py").write_text("#")
        (tmp_path / "file2.py").write_text("#")
        (tmp_path / "test.txt").write_text("#")

        # Find with glob
        py_files = list(tmp_path.glob("*.py"))
        assert len(py_files) == 2

        all_files = list(tmp_path.glob("*"))
        assert len(all_files) == 3