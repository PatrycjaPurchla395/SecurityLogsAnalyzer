from datetime import datetime
import re
from typing import Optional

from models.events import Event
from parsers.base_parser import LogParser


class WebServerLogParser(LogParser):

    WEB_REGEX = re.compile(
        r'(?P<ip>\S+) .* \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) .*" '
        r'(?P<status>\d{3})'
    )

    def parse(self, line: str) -> Optional[Event]:
        match = self.WEB_REGEX.search(line)
        if not match:
            return None
        try:
            ts = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
            return Event(
                timestamp=ts,
                source="web",
                ip=match.group("ip"),
                user=None,
                action=f"{match.group('method')} {match.group('path')}",
                status=int(match.group("status")),
                raw=line.strip()
            )
        except Exception as e:
            print(e.args)
            return None
