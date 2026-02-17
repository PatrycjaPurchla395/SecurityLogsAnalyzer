import os
from typing import Type, Dict, List, Iterator, Optional
from datetime import datetime

from models.events import Event
from parsers.auth_parser import AuthLogParser
from parsers.base_parser import LogParser
from parsers.webservice_parser import WebServerLogParser


class ParserRegistry:
    """
    Responsible for selecting the correct parser
    based on filename patterns.
    """

    def __init__(self, year: Optional[int] = None) -> None:
        self.year = year
        self.registry: Dict[str, Type[LogParser]] = {
            "webserver": WebServerLogParser,
            "auth": AuthLogParser,
        }

    def get_parser_for_file(self, filepath: str) -> LogParser:
        filename = os.path.basename(filepath).lower()

        for pattern, parser_cls in self.registry.items():
            if pattern in filename:
                if parser_cls == AuthLogParser:
                    return parser_cls(year=self.year)
                return parser_cls()

        raise ValueError(f"No parser registered for file: {filepath}")


class EventStream:
    """
    Streams events from multiple files.
    Each file is associated with exactly one parser.
    """

    def __init__(self, files: List[str]) -> None:
        self.files = files
        self.year = self._detect_year()
        self.parser_registry = ParserRegistry(year=self.year)

    def _detect_year(self) -> int:
        """Detect year from webserver logs if available"""
        for path in self.files:
            if "webserver" in os.path.basename(path).lower():
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if "[" in line and "/" in line:
                                match = line.split("[")[1].split("]")[0]
                                dt = datetime.strptime(match, "%d/%b/%Y:%H:%M:%S %z")
                                return dt.year
                except:
                    pass
        return datetime.utcnow().year

    def stream(self) -> Iterator[Event]:

        for path in self.files:
            parser = self.parser_registry.get_parser_for_file(path)

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    event = parser.parse(line)
                    if event:
                        yield event
