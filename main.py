import argparse

from detection.security_log_analyser import SecurityLogAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()
    analyzer = SecurityLogAnalyzer(args.files, args.output)
    analyzer.run()


if __name__ == "__main__":
    main()