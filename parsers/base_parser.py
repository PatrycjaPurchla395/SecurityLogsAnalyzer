from typing import Optional
from abc import ABC, abstractmethod

from models.events import Event


class LogParser(ABC):
    """Abstract base class for log parsers."""

    @abstractmethod
    def parse(self, line: str) -> Optional[Event]:
        raise NotImplementedError
