from datetime import datetime, timezone
import re
from typing import Optional

from models.events import Event
from parsers.base_parser import LogParser


class AuthLogParser(LogParser):

    AUTH_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+'
        r'sshd\[\d+\]:\s+(?P<message>.*)'
    )

    SUDO_REGEX = re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+\S+\s+'
        r'sudo:\s+(?P<user>\w+)\s+.*COMMAND=(?P<command>.*)'
    )

    def __init__(self, year: Optional[int] = None) -> None:
        self.current_year = year or datetime.utcnow().year

    def can_parse(self, line: str) -> bool:
        return "sshd" in line or "sudo:" in line

    def parse(self, line: str) -> Optional[Event]:

        # Handle sudo entries
        if "sudo:" in line:
            match = self.SUDO_REGEX.search(line)
            if not match:
                return None

            ts = datetime.strptime(
                f"{self.current_year} {match.group('month')} "
                f"{match.group('day')} {match.group('time')}",
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)

            return Event(
                timestamp=ts,
                source="auth",
                ip=None,
                user=match.group("user"),
                action=f"SUDO {match.group('command')}",
                status=None,
                raw=line.strip()
            )

        # Handle SSH entries
        match = self.AUTH_REGEX.search(line)
        if not match:
            return None

        ts = datetime.strptime(
            f"{self.current_year} {match.group('month')} "
            f"{match.group('day')} {match.group('time')}",
            "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)

        message = match.group("message")
        ip_match = re.search(r'from (\S+)', message)

        return Event(
            timestamp=ts,
            source="auth",
            ip=ip_match.group(1) if ip_match else None,
            user=None,
            action=message,
            status=None,
            raw=line.strip()
        )

