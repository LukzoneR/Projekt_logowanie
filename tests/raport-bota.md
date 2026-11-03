# Raport z symulacji bota

- Data: 3.11.2026, 14:43:14
- Cel: http://localhost:3000
- User-Agent bota: `BotSimulator/1.0 (test bezpieczenstwa Projekt_logowanie)`
- Wynik: **9/10** zabezpieczeń zadziałało

| # | Atak bota | Zabezpieczenie | Wynik | Szczegóły |
|---|---|---|---|---|
| 1 | Bot wypełnia wszystkie pola formularza (z poprawnym hasłem) | Pułapka na boty (honeypot) | **ZADZIAŁAŁO** | HTTP 401 "Login lub hasło niepoprawne" - logowanie odrzucone mimo poprawnego hasła, komunikat nie zdradza wykrycia |
| 2 | Bot wysyła żądanie do API bez tokenu reCAPTCHA (z poprawnym hasłem) | Google reCAPTCHA - wymagany token | **ZADZIAŁAŁO** | HTTP 400 "Wymagane jest potwierdzenie reCAPTCHA." |
| 3 | Bot używa ponownie tego samego tokenu reCAPTCHA | Jednorazowość tokenu reCAPTCHA | **ZADZIAŁAŁO** | 1. użycie: HTTP 401 "Login lub hasło niepoprawne"; 2. użycie: HTTP 400 "Wyzwanie reCAPTCHA zostało już wykorzystane. Zaznacz pole ponownie." |
| 4 | Bot podaje wymyślony (nowy) token reCAPTCHA | Google reCAPTCHA - weryfikacja tokenu w Google | **NIE ZADZIAŁAŁO** | Token zaakceptowany: serwer działa na TESTOWYCH kluczach Google, które przepuszczają każdy token. Ustaw prawdziwe klucze w .env. |
| 5 | Bot sprawdza, które loginy istnieją (porównanie odpowiedzi) | Jednakowy komunikat błędu logowania | **ZADZIAŁAŁO** | istniejący "pracownik2": HTTP 401 "Login lub hasło niepoprawne" (108 ms); nieistniejący: HTTP 401 "Login lub hasło niepoprawne" (99 ms) |
| 6 | Brute force hasła konta "pracownik2" (słownik 8 haseł) | Limit błędnych logowań (5 prób, blokada 15 min) | **ZADZIAŁAŁO** | konto zablokowane po 4. próbie bota (wliczając wcześniejszą próbę z testu enumeracji); poprawne hasło w trakcie blokady: HTTP 423 "Przekroczono limit błędnych logowań. Konto jest tymczasowo zablokowane, pozostało 15 min." |
| 7 | Bot sprawdza istnienie loginu po tym, czy konto się blokuje | Blokada także dla nieistniejących loginów | **ZADZIAŁAŁO** | nieistniejący login zablokowany po 5. próbie - tak samo jak prawdziwe konto |
| 8 | Bot pobiera zrzut bazy z /backup/db_backup_2026-10-28.sql | Canarytoken: fałszywy zrzut bazy | **ZADZIAŁAŁO** | alert "wysoki" zarejestrowany (IP ::1) |
| 9 | Bot loguje się danymi ze zrzutu (backup_admin) | Canarytoken: konto-pułapka | **ZADZIAŁAŁO** | HTTP 401 "Login lub hasło niepoprawne"; alert "krytyczny": Logowanie na konto-pułapkę "backup_admin" POPRAWNYM hasłem - dane z przynęty zostały wykradzione i użyte. |
| 10 | Bot omija logowanie i wywołuje API administratora (brak / sfałszowana sesja) | Weryfikacja sesji (sessionMiddleware) | **ZADZIAŁAŁO** | bez sesji: HTTP 401 "Brak aktywnej sesji. Zaloguj się ponownie."; sfałszowany token: HTTP 401 "Nieprawidłowa lub unieważniona sesja." |
