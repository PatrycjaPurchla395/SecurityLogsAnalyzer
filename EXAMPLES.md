# Przykłady użycia Security Log Analyzer

## Przykład 1: Podstawowa analiza

```bash
python main.py sample_logs/webserver.log sample_logs/auth.log
```

### Wykryte zagrożenia:

#### 1. IP 10.0.0.50 - Skoordynowany atak brute force
**Severity:** CRITICAL

**Opis:**
- 4 nieudane próby logowania SSH (10:00:03-10:00:06)
- 4 nieudane próby logowania web (10:00:03-10:00:06)
- **Korelacja:** Te same timestampy w obu źródłach!

**Interpretacja:**
Atakujący jednocześnie próbuje włamać się przez SSH i aplikację webową, co wskazuje na zautomatyzowany, skoordynowany atak.

**Rekomendacja:**
Natychmiastowo zablokować IP 10.0.0.50 i zbadać wszystkie próby dostępu z tego źródła.

---

#### 2. IP 203.0.113.5 - Skoordynowany atak na wiele usług
**Severity:** CRITICAL

**Opis:**
- 3 nieudane próby logowania SSH z różnymi użytkownikami (test, root, ubuntu)
- Próby dostępu do panelu administracyjnego (/admin, /admin/, /admin/config)
- Próba path traversal (/admin/../../../etc/passwd)
- **Korelacja:** 3 zdarzenia w tym samym czasie w obu źródłach!

**Interpretacja:**
Zaawansowany atak łączący:
1. Brute force SSH z popularnymi nazwami użytkowników
2. Skanowanie paneli administracyjnych
3. Próba path traversal

**Rekomendacja:**
Natychmiastowo zablokować IP 203.0.113.5. To zaawansowany atakujący próbujący wielu wektorów ataku jednocześnie.

---

#### 3. IP 172.16.0.20 - Skanowanie aplikacji
**Severity:** HIGH

**Opis:**
- Szybkie skanowanie popularnych ścieżek administracyjnych
- Próby dostępu do: /admin, /phpmyadmin, /wp-admin, /administrator, /.env, /config.php

**Interpretacja:**
Automatyczne skanowanie w poszukiwaniu znanych paneli administracyjnych i wrażliwych plików konfiguracyjnych.

**Rekomendacja:**
Zablokować IP 172.16.0.20 i sprawdzić czy nie ma innych podobnych skanowań.

---

## Przykład 2: Analiza z własną nazwą raportu

```bash
python main.py sample_logs/webserver.log sample_logs/auth.log --output incident_report_2025_07_03.json
```

## Przykład 3: Analiza wielu plików

```bash
python main.py logs/web_server1.log logs/web_server2.log logs/auth.log logs/auth_backup.log
```

## Interpretacja korelacji

### Co oznacza korelacja?

Korelacja występuje gdy:
1. **Ten sam IP** pojawia się w różnych logach
2. **W tej samej sekundzie** (dokładny timestamp)
3. **Z podejrzaną aktywnością** w obu źródłach

### Dlaczego korelacja jest ważna?

1. **Wykrywa skoordynowane ataki** - atakujący używa wielu wektorów jednocześnie
2. **Potwierdza złośliwe intencje** - przypadkowe błędy nie występują jednocześnie w wielu systemach
3. **Priorytetyzuje zagrożenia** - skorelowane ataki są bardziej niebezpieczne

### Przykład korelacji z raportu:

```json
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
```

**Interpretacja:**
W sekundzie 10:00:03, IP 10.0.0.50:
- Próbował zalogować się przez SSH (nieudane)
- Próbował zalogować się przez web (nieudane)

To nie jest przypadek - to zautomatyzowany atak próbujący wielu metod jednocześnie.

## Statystyki z przykładowych logów

- **Całkowita liczba zdarzeń:** 33 linie w webserver.log + 12 linii w auth.log = 45 linii
- **Wykryte zagrożenia:** 10
- **Korelacje:** 7
- **Krytyczne IP:** 2 (10.0.0.50, 203.0.113.5)
- **Czas analizy:** < 1 sekunda

## Akcje po analizie

1. **Natychmiastowe:**
   - Zablokuj IP z sekcji "critical_ips"
   - Sprawdź czy ataki nadal trwają

2. **Krótkoterminowe:**
   - Przeanalizuj wszystkie logi z ostatnich 24h dla tych IP
   - Sprawdź czy ataki były skuteczne
   - Zmień hasła dla kont, które były celem ataków

3. **Długoterminowe:**
   - Wdróż rate limiting
   - Rozważ fail2ban lub podobne narzędzie
   - Ukryj panele administracyjne za VPN
   - Wyłącz niepotrzebne usługi
