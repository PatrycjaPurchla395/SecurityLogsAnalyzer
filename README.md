# Security Log Analyzer

Advanced security log analyzer with the function of correlating events from multiple sources.


>>>> Link to prompt history: https://chatgpt.com/share/6994dc70-1d9c-8013-a04a-f7c13044a1b8 <<<<

>>>> Here's a link to the main prompt history. It's not the whole story, though I also worked on my own and partly with another tool, Amazon Q to fix regex in rules and generate readMe file. But that's the core. <<<<




## Features

### 1. Log Parsing
- **Webserver logs** (Apache/Nginx format) - automatic detection of web attacks
- **Auth logs** (syslog format) - detection of SSH and sudo intrusion attempts
- Automatic year detection from webserver logs for synchronization with auth logs
- Support for large files via streaming

### 2. Threat Detection
- **SSH Brute Force** - multiple failed SSH login attempts
- **Web Login Brute Force** - multiple failed HTTP login attempts (401)
- **Web Attack Attempts** - detection of:
- Path traversal (`../`)
- SQL injection (`UNION`, `DROP`)
- Attempts to access administration panels (`/admin`, `/phpmyadmin`)
- Access attempts to sensitive files (`.env`, `config.php`)

### 3. Event Correlation
The program correlates events from different sources based on:
- **IP address** - the same IP address
- **Timestamp** - the same second of the event's occurrence

Correlation allows you to detect **coordinated attacks**, where the attacker simultaneously attempts to:
- Break in via SSH
- Attack a web application
- Scan the system

### 4. Report
The JSON report contains:
- **Summary** - a summary with the number of threats and correlations found
- **Threat Analysis** - a threat analysis with CRITICAL/HIGH levels and recommendations
- **Findings** - a detailed list of all detected threats
- **Correlations** - a list of correlated events from different sources

## Usage

```bash
python main.py <log_file1> <log_file2> ... [--output report.json]
```

### Examples

```bash
# Analyzing webserver and auth logs
python main.py sample_logs/webserver.log sample_logs/auth.log

# Custom report name
python main.py sample_logs/webserver.log sample_logs/auth.log --output security_report.json

# Analyzing multiple files
python main.py logs/web1.log logs/web2.log logs/auth.log
```

## Project Structure

```
securityAnalyser/
├── main.py # Entry point
├── models/
│ └── events.py # Event model
├── parsers/
│ ├── base_parser.py # Abstract parser class
│ ├── auth_parser.py # Parser for auth logs
│ └── webservice_parser.py # Parser for webserver logs
├── detection/
│ ├── event_stream.py # Streaming events from files
│ ├── detection_engine.py # Threat detection
│ ├── corelation.py # Event correlation
│ ├── raport_generator.py # Report generation
│ └── security_log_analyser.py # Main analysis logic
└── sample_logs/
├── webserver.log # Sample webserver logs
└── auth.log # Sample auth logs
```

## Configuration

Default configuration in `SecurityLogAnalyzer`:

```python
DEFAULT_CONFIG = {
"failed_login_threshold": 3 # Minimum number of failed login attempts
}
```

## Sample report

```json
{
"summary": {
"total_findings": 10,
"total_correlations": 7,
"critical_ips": ["10.0.0.50", "203.0.113.5"]
},
"threat_analysis": [
{
"ip": "10.0.0.50", 
"severity": "CRITICAL", 
"description": "IP 10.0.0.50 shows coordinated attack pattern across 2 services (auth, web) with 4 correlated suspicious events", 
"recommendation": "Block IP 10.0.0.50 immediately and investigate all access from this source" 
} 
], 
"findings": [...], 
"correlations": [ 
{ 
"ip": "10.0.0.50", 
"timestamp": "2025-07-03 10:00:03", 
"sources": ["auth", "web"], 
"events": [ 
{ 
"source": "auth", 
"action": "Failed password for admin from 10.0.0.50 port 52341 ssh2" 
},
{
"source": "web",
"action": "POST /login"
}
],
"threat": "Coordinated attack: Same IP (10.0.0.50) performing suspicious activities across multiple services (auth, web) at the same time"
}
]
}
```

## Optimization

The program is optimized for large files:
- **Streaming** - files are read line by line, not loaded into memory
- **Pattern Generator** - events are processed on the fly
- **Lazy evaluation** - parsing only when needed

## Extending

### Adding a new parser

1. Create a class that inherits from `LogParser`
2. Implement the `parse(line: str) -> Optional[Event]` method
3. Register the parser in the `ParserRegistry`

```python
class CustomLogParser(LogParser):
def parse(self, line: str) -> Optional[Event]:
# Your parsing logic
return Event(...)
```

### Adding a new detection rule

Add logic in `DetectionEngine.process()` or `DetectionEngine.finalize()`:
```python
def process(self, event: Event):
# Your detection rule
if event.source == "custom" and "suspicious" in event.action:
self.suspicious_events.append(event)
```

## Requirements

- Python 3.7+
- No external dependencies (standard library only)

