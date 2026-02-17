from collections import defaultdict
from typing import Dict, List, Tuple, Any

from models.events import Event

try:
    from config import FAILED_LOGIN_THRESHOLD, SUSPICIOUS_WEB_PATTERNS
except ImportError:
    FAILED_LOGIN_THRESHOLD = 3
    SUSPICIOUS_WEB_PATTERNS = ["../", "UNION", "DROP", "/admin", ".env"]


class DetectionEngine:

    def __init__(self, config: Dict[str, int] = None) -> None:
        self.config = config or {"failed_login_threshold": FAILED_LOGIN_THRESHOLD}
        self.failed_ssh: Dict[str, List[Event]] = defaultdict(list)
        self.failed_web: Dict[str, List[Event]] = defaultdict(list)
        self.suspicious_events: List[Event] = []
        self.findings: List[Dict[str, Any]] = []
        self.suspicious_patterns: List[str] = SUSPICIOUS_WEB_PATTERNS

    def process(self, event: Event) -> None:

        if event.source == "auth" and "Failed password" in event.action:
            self.failed_ssh[event.ip].append(event)

        if event.source == "web" and event.status == 401:
            self.failed_web[event.ip].append(event)

        if event.source == "web":
            if any(p.lower() in event.action.lower() for p in self.suspicious_patterns):
                self.suspicious_events.append(event)
                self.findings.append({
                    "type": "Web Attack Attempt",
                    "ip": event.ip,
                    "time": str(event.timestamp),
                    "detail": event.action
                })

    def finalize(self) -> Tuple[List[Dict[str, Any]], List[Event]]:

        for ip, events in self.failed_ssh.items():
            if len(events) >= self.config["failed_login_threshold"]:
                self.suspicious_events.extend(events)
                self.findings.append({
                    "type": "SSH Brute Force",
                    "ip": ip,
                    "count": len(events),
                    "times": [str(e.timestamp) for e in events[:3]]
                })

        for ip, events in self.failed_web.items():
            if len(events) >= self.config["failed_login_threshold"]:
                self.suspicious_events.extend(events)
                self.findings.append({
                    "type": "Web Login Brute Force",
                    "ip": ip,
                    "count": len(events),
                    "times": [str(e.timestamp) for e in events[:3]]
                })

        return self.findings, self.suspicious_events

