from abc import ABC, abstractmethod
from pathlib import Path

from agentsec.models import GraphDefinition


class BaseAnalyzer(ABC):
    def __init__(self, input_dir: Path):
        self.input_dir = input_dir

    @abstractmethod
    def analyze(self) -> GraphDefinition:
        pass

    @property
    @abstractmethod
    def framework_name(self) -> str:
        pass
