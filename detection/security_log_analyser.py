from typing import List

from detection.corelation import CorrelationEngine
from detection.detection_engine import DetectionEngine
from detection.event_stream import EventStream
from detection.raport_generator import ReportGenerator


class SecurityLogAnalyzer:

    DEFAULT_CONFIG = {
        "failed_login_threshold": 3
    }

    def __init__(self, files: List[str], output: str) -> None:
        self.files = files
        self.output = output

        self.detector = DetectionEngine(self.DEFAULT_CONFIG)
        self.correlator = CorrelationEngine()
        self.reporter = ReportGenerator()

    def run(self) -> None:
        stream = EventStream(self.files)

        for event in stream.stream():
            self.detector.process(event)

        findings, suspicious_events = self.detector.finalize()

        correlations = self.correlator.correlate(suspicious_events)

        self.reporter.generate(findings, correlations, self.output)

        print(f"Report written to {self.output}")
