import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def parse_python_file(file_path: Path) -> Optional[ast.AST]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return ast.parse(content, filename=str(file_path))
    except Exception as e:
        # Log warning but continue
        print(f"Warning: Failed to parse {file_path}: {e}")
        return None


def find_function_calls(tree: ast.AST, function_names: List[str]) -> List[ast.Call]:
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _get_function_name(node.func)
            if func_name in function_names:
                calls.append(node)
    return calls


def find_class_instantiations(tree: ast.AST, class_names: List[str]) -> List[ast.Call]:
    instantiations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in class_names:
                instantiations.append(node)
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in class_names:
                    instantiations.append(node)
    return instantiations


def extract_string_argument(call_node: ast.Call, arg_name: str) -> Optional[str]:
    for keyword in call_node.keywords:
        if keyword.arg == arg_name:
            if isinstance(keyword.value, ast.Constant):
                return str(keyword.value.value)
            elif isinstance(keyword.value, ast.Str):  # Python 3.7 compatibility
                return keyword.value.s
    return None


def find_imports(tree: ast.AST) -> Set[str]:
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for alias in node.names:
                    imports.add(f"{node.module}.{alias.name}")
                    imports.add(alias.name)
    return imports


def _get_function_name(func_node: ast.expr) -> Optional[str]:
    if isinstance(func_node, ast.Name):
        return func_node.id
    elif isinstance(func_node, ast.Attribute):
        return func_node.attr
    return None


def extract_dict_argument(call_node: ast.Call, arg_name: str) -> Optional[Dict[str, Any]]:
    for keyword in call_node.keywords:
        if keyword.arg == arg_name:
            if isinstance(keyword.value, ast.Dict):
                return _parse_dict_ast(keyword.value)
    return None


def _parse_dict_ast(dict_node: ast.Dict) -> Dict[str, Any]:
    result = {}
    for key, value in zip(dict_node.keys, dict_node.values):
        if isinstance(key, ast.Constant):
            key_str = str(key.value)
        elif isinstance(key, ast.Str):
            key_str = key.s
        else:
            continue

        if isinstance(value, ast.Constant):
            result[key_str] = value.value
        elif isinstance(value, ast.Str):
            result[key_str] = value.s
        elif isinstance(value, ast.Num):
            result[key_str] = value.n
    return result
