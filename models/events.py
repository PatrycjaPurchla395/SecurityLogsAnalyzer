import datetime
from typing import Optional
from dataclasses import dataclass


@dataclass
class Event:
    timestamp: datetime
    source: str
    ip: Optional[str]
    user: Optional[str]
    action: str
    status: Optional[int]
    raw: str