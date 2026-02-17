from collections import defaultdict
from typing import List, Dict, Any

from models.events import Event


class CorrelationEngine:

    def correlate(self, suspicious_events: List[Event]) -> List[Dict[str, Any]]:
        correlations: List[Dict[str, Any]] = []

        by_ip_time: Dict[tuple, List[Event]] = defaultdict(list)
        
        for event in suspicious_events:
            if not event.ip:
                continue
            key = (event.ip, event.timestamp)
            by_ip_time[key].append(event)
        
        for (ip, ts), events in by_ip_time.items():
            sources = {e.source for e in events}
            
            if len(sources) > 1:
                correlations.append({
                    "ip": ip,
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "sources": sorted(sources),
                    "events": [
                        {
                            "source": e.source,
                            "action": e.action
                        }
                        for e in events
                    ],
                    "threat": f"Coordinated attack: Same IP ({ip}) performing suspicious activities across multiple services ({', '.join(sorted(sources))}) at the same time"
                })
        
        return correlations

