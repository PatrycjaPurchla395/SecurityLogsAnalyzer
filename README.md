# Security Log Analyzer

Zaawansowany analizator logów bezpieczeństwa z funkcją korelacji zdarzeń z wielu źródeł.

## Funkcjonalności

### 1. Parsowanie logów
- **Webserver logs** (Apache/Nginx format) - automatyczne wykrywanie ataków web
- **Auth logs** (syslog format) - wykrywanie prób włamania SSH i sudo
- Automatyczne wykrywanie roku z logów webserver dla synchronizacji z auth logs
- Obsługa dużych plików poprzez streaming

### 2. Wykrywanie zagrożeń
- **SSH Brute Force** - wielokrotne nieudane próby logowania SSH
- **Web Login Brute Force** - wielokrotne nieudane próby logowania HTTP (401)
- **Web Attack Attempts** - wykrywanie:
  - Path traversal (`../`)
  - SQL Injection (`UNION`, `DROP`)
  - Próby dostępu do paneli administracyjnych (`/admin`, `/phpmyadmin`)
  - Próby dostępu do wrażliwych plików (`.env`, `config.php`)

### 3. Korelacja zdarzeń
Program koreluje zdarzenia z różnych źródeł na podstawie:
- **IP address** - ten sam adres IP
- **Timestamp** - ta sama sekunda wystąpienia zdarzenia

Korelacja pozwala wykryć **skoordynowane ataki**, gdzie atakujący jednocześnie próbuje:
- Włamać się przez SSH
- Atakować aplikację webową
- Skanować system

### 4. Raport
Raport JSON zawiera:
- **Summary** - podsumowanie z liczbą znalezionych zagrożeń i korelacji
- **Threat Analysis** - analiza zagrożeń z poziomami CRITICAL/HIGH i rekomendacjami
- **Findings** - szczegółowa lista wszystkich wykrytych zagrożeń
- **Correlations** - lista skorelowanych zdarzeń z różnych źródeł

## Użycie

```bash
python main.py <log_file1> <log_file2> ... [--output report.json]
```

### Przykłady

```bash
# Analiza logów webserver i auth
python main.py sample_logs/webserver.log sample_logs/auth.log

# Własna nazwa raportu
python main.py sample_logs/webserver.log sample_logs/auth.log --output security_report.json

# Analiza wielu plików
python main.py logs/web1.log logs/web2.log logs/auth.log
```

## Struktura projektu

```
securityAnalyser/
├── main.py                          # Punkt wejścia
├── models/
│   └── events.py                    # Model Event
├── parsers/
│   ├── base_parser.py               # Abstrakcyjna klasa parsera
│   ├── auth_parser.py               # Parser dla auth logs
│   └── webservice_parser.py         # Parser dla webserver logs
├── detection/
│   ├── event_stream.py              # Streaming zdarzeń z plików
│   ├── detection_engine.py          # Wykrywanie zagrożeń
│   ├── corelation.py                # Korelacja zdarzeń
│   ├── raport_generator.py          # Generowanie raportu
│   └── security_log_analyser.py     # Główna logika analizy
└── sample_logs/
    ├── webserver.log                # Przykładowe logi webserver
    └── auth.log                     # Przykładowe logi auth
```

## Konfiguracja

Domyślna konfiguracja w `SecurityLogAnalyzer`:

```python
DEFAULT_CONFIG = {
    "failed_login_threshold": 3  # Minimalna liczba nieudanych prób logowania
}
```

## Przykładowy raport

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

## Optymalizacja

Program jest zoptymalizowany pod kątem dużych plików:
- **Streaming** - pliki są czytane linia po linii, nie ładowane do pamięci
- **Generator pattern** - zdarzenia są przetwarzane w locie
- **Lazy evaluation** - parsowanie tylko gdy potrzebne

## Rozszerzanie

### Dodanie nowego parsera

1. Utwórz klasę dziedziczącą po `LogParser`
2. Zaimplementuj metodę `parse(line: str) -> Optional[Event]`
3. Zarejestruj parser w `ParserRegistry`

```python
class CustomLogParser(LogParser):
    def parse(self, line: str) -> Optional[Event]:
        # Twoja logika parsowania
        return Event(...)
```

### Dodanie nowej reguły wykrywania

Dodaj logikę w `DetectionEngine.process()` lub `DetectionEngine.finalize()`:

```python
def process(self, event: Event):
    # Twoja reguła wykrywania
    if event.source == "custom" and "suspicious" in event.action:
        self.suspicious_events.append(event)
```

## Wymagania

- Python 3.7+
- Brak zewnętrznych zależności (tylko standardowa biblioteka)
