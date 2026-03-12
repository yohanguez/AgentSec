from pathlib import Path
from typing import List


def find_python_files(directory: Path) -> List[Path]:
    return list(directory.rglob("*.py"))


def find_yaml_files(directory: Path) -> List[Path]:
    yaml_files = list(directory.rglob("*.yaml"))
    yaml_files.extend(directory.rglob("*.yml"))
    return yaml_files


def find_json_files(directory: Path) -> List[Path]:
    return list(directory.rglob("*.json"))
