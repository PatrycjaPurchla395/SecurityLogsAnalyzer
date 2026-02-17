import json
from collections import defaultdict
from typing import List, Dict, Any, Set

try:
    from config import SEVERITY_CRITICAL_THRESHOLD, SEVERITY_HIGH_THRESHOLD
except ImportError:
    SEVERITY_CRITICAL_THRESHOLD = 3
    SEVERITY_HIGH_THRESHOLD = 1


class ReportGenerator:

    def generate(self, findings: List[Dict[str, Any]], correlations: List[Dict[str, Any]], output_path: str) -> None:
        
        threat_analysis = self._analyze_threats(findings, correlations)
        
        report = {
            "summary": {
                "total_findings": len(findings),
                "total_correlations": len(correlations),
                "critical_ips": list(threat_analysis["critical_ips"])
            },
            "findings": findings,
            "correlations": correlations,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
    
    def _analyze_threats(self, findings: List[Dict[str, Any]], correlations: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        critical_ips: Set[str] = set()

        ip_correlations: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for corr in correlations:
            ip_correlations[corr["ip"]].append(corr)
        
        for ip, corrs in ip_correlations.items():
            critical_ips.add(ip)
            
            sources = set()
            for c in corrs:
                sources.update(c["sources"])
    
        
        return {
            "critical_ips": critical_ips,
        }