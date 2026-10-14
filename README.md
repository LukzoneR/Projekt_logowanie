# System Uwierzytelniania, Sesji i Kontroli Dostępu RBAC (Moduł 1)

Projekt aplikacji webowej realizujący mechanizmy identyfikacji, uwierzytelniania, autoryzacji opartej na rolach (RBAC), zarządzania sesjami oraz bezpiecznej polityki haseł. Aplikacja stanowi bazę architektoniczną dla kolejnych modułów (Moduł 2 i Moduł 3).

---

## 1. Wariant Projektowy: Wariant 5

Zgodnie z wytycznymi wariantu 5 zaimplementowano:
* **Minimalna długość hasła**: domyślnie **12 znaków** (zgodnie z aktualnymi zaleceniami NIST SP 800-63B-4).
* **Dodatkowa reguła polityki haseł**: Sprawdzanie haseł w bazie wycieków **Have I Been Pwned - Pwned Passwords API** z zachowaniem pełnej **k-anonimowości** (do zewnętrznego API wysyłanych jest wyłącznie 5 pierwszych znaków skrótu SHA-1; pełne hasło ani pełny hash nigdy nie opuszczają serwera). Możliwość włączania i wyłączania tej reguły przez administratora.
* **Liczba użytkowników testowych**: dokładnie **6 użytkowników** odzwierciedlających różne stany i role.
* **Role**: **Administrator**, **Pracownik**, **Gość**.
* **Hasło jednorazowe**: **14 znaków alfanumerycznych** (`[A-Za-z0-9]`), ważne przez **24 godziny**.

---

## 2. Podstawy Teoretyczne i Realizacja Zabezpieczeń

1. **Identyfikacja, Uwierzytelnianie, Autoryzacja**:
   * *Identyfikacja*: podanie unikalnego loginu.
   * *Uwierzytelnianie*: weryfikacja tożsamości poprzez sprawdzenie hasła lub hasła jednorazowego przy użyciu kryptograficznego hashowania z solą.
   * *Autoryzacja*: model RBAC – uprawnienia (`admin:access`, `users:manage`, `policy:manage`, `employee:access`, `guest:access`) przypisane do ról, a role przypisane do użytkowników.

2. **Przechowywanie haseł**:
   * Hasła przechowywane są **wyłącznie jako hash z solą** obliczony wolnym, dedykowanym do haseł algorytmem **bcrypt** (funkcja kosztu = 10).
   * Brak stosowania przestarzałych i podatnych funkcji skrótu (MD5, SHA-1/256 do przechowywania).

3. **Wytyczne NIST (SP 800-63B-4)**:
   * Priorytet ma długość hasła (min. 12 znaków), bez narzucania sztucznych reguł złożoności (brak wymuszania wielkich liter/cyfr, które prowadzą do przewidywalnych wzorców).
   * Weryfikacja hasła z bazą skompromitowanych haseł (Have I Been Pwned).
   * Historia haseł uniemożliwia ponowne użycie wcześniej wykorzystanych haseł.

4. **Ochrona przed wyliczaniem loginów (User Enumeration)**:
   * W przypadku błędnego loginu lub błędnego hasła aplikacja zwraca **identyczny komunikat**: `Login lub hasło niepoprawne`.
   * W przypadku nieistniejącego loginu serwer wykonuje symulowane porównanie hasza (*dummy compare*), co chroni przed atakami czasowymi (*timing attacks*).

5. **Obsługa sesji i bezczynności**:
   * Sesja identyfikowana jest bezpiecznym, kryptograficznie losowanym tokenem (32 bajty hex).
   * Śledzenie czasu ostatniej aktywności (`lastActivity`).
   * Automatyczne wygaszanie sesji po okresie bezczynności (konfigurowalnym w panelu administratora) zarówno po stronie serwera, jak i klienta.
   * Natychmiastowe unieważnienie sesji przy wylogowaniu ręcznym oraz przy zablokowaniu/usunięciu konta.

6. **Pierwsze logowanie i hasła jednorazowe**:
   * Nadawane przy tworzeniu konta lub resecie hasła przez administratora (14 znaków alfanumerycznych, 24h ważności).
   * Przy pierwszym logowaniu wymuszana jest zmiana hasła na nowe, spełniające politykę bezpieczeństwa i wprowadzone dwukrotnie. Do momentu zmiany hasła użytkownik ma zablokowany dostęp do pozostałych zasobów.

---

## 3. Konta Testowe (6 użytkowników)

Aplikacja posiada wstępnie zdefiniowaną bazę 6 użytkowników testowych:

| Login | Hasło początkowe | Rola | Status / Cel testu |
| :--- | :--- | :--- | :--- |
| **admin** | `Admin12345678!` | Administrator | Stałe konto administratora (pełne uprawnienia, panel admina) |
| **pracownik1** | `Prac1234Temp01` | Pracownik | Hasło jednorazowe (14 znaków, 24h) – **wymusza pierwsze logowanie** |
| **pracownik2** | `Pracownik2026!` | Pracownik | Aktywne konto pracownika (dostęp do strefy pracownika i gościa) |
| **gosc1** | `GoscHaslo2026!` | Gość | Aktywne konto gościa (dostęp do strefy gościa) |
| **gosc2** | `GoscTemp123456` | Gość | Hasło jednorazowe (14 znaków, 24h) – **wymusza pierwsze logowanie dla roli Gość** |
| **zablokowany** | `Zablokowane12!` | Gość | Konto zablokowane – **test blokady dostępu** |

> **Wskazówka:** Na ekranie logowania znajduje się wygodna tabela z przyciskami **„Użyj”**, które automatycznie uzupełniają formularz logowania wybranym kontem testowym.

---

## 4. Architektura i Struktura Katalogów

Kod aplikacji został zaprojektowany modularnie z myślą o rozbudowie w kolejnych modułach:

```
Projekt_logowanie/
├── package.json              # Zależności (express, bcryptjs) oraz skrypty
├── README.md                 # Dokumentacja projektu
├── test_flows.js             # Automatyczny zestaw testów integracyjnych (24 asercje)
├── src/
│   ├── config/
│   │   └── config.js         # Domyślne parametry polityki haseł i sesji
│   ├── data/
│   │   ├── seedData.js       # Definicje 6 początkowych kont testowych
│   │   └── database.js       # Warstwa persystencji danych (JSON file store)
│   ├── services/
│   │   ├── authService.js    # Uwierzytelnianie, haszowanie bcrypt, polityka haseł, HIBP k-anonimowość
│   │   ├── sessionService.js # Cykl życia sesji, timeout bezczynności, unieważnianie
│   │   └── rbacService.js    # Definicja ról (Administrator, Pracownik, Gość) i uprawnień
│   ├── middleware/
│   │   ├── sessionMiddleware.js # Weryfikacja aktywności i tokena sesji
│   │   └── rbacMiddleware.js    # Autoryzacja uprawnień i wymóg zmiany hasła
│   ├── routes/
│   │   ├── authRoutes.js     # Endpointy logowania, wylogowania, zmiany hasła, me
│   │   ├── adminRoutes.js    # Panel administratora (użytkownicy, polityka, reset)
│   │   └── resourceRoutes.js # Chronione zasoby ról (strefa pracownika, strefa gościa)
│   └── server.js             # Konfiguracja serwera Express i obsługa plików statycznych
└── public/
    ├── index.html            # Struktura interfejsu webowego
    ├── css/
    │   └── style.css         # Zwięzłe, przejrzyste i proste style CSS
    └── js/
        └── app.js            # Logika klienta (SPA, timer bezczynności, obsługa ról)
```

---

## 5. Uruchomienie Aplikacji

### Wymagania:
* Node.js (wersja 18+)
* npm

### Krok 1: Instalacja zależności
```bash
npm install
```

### Krok 2: Uruchomienie serwera
```bash
npm start
```
Serwer uruchomi się pod adresem: [http://localhost:3000](http://localhost:3000).

### Krok 3: Uruchomienie automatycznych testów weryfikacyjnych
W osobnym terminalu można wykonać pełny zestaw 24 testów:
```bash
node test_flows.js
```

---

## 6. Przewodnik po Funkcjonalnościach

1. **Logowanie (`admin`)**:
   * Przejdź do [http://localhost:3000](http://localhost:3000).
   * Kliknij przycisk „Użyj” przy koncie `admin` i kliknij **Zaloguj się**.
   * Dostępne zakładki: *Mój Profil*, *Panel Administratora*, *Strefa Pracownika*, *Strefa Gościa*, *Zmiana hasła*.

2. **Panel Administratora**:
   * **Zarządzanie użytkownikami**: zmiana roli w locie, blokowanie/odblokowywanie, reset hasła na 14-znakowe jednorazowe, usuwanie (konto stałego admina jest zabezpieczone przed usunięciem i zablokowaniem).
   * **Dodanie użytkownika**: wpisanie loginu i roli – system automatycznie generuje 14-znakowe hasło jednorazowe ważne przez 24 godziny.
   * **Polityka haseł**: zmiana minimalnej długości hasła, włączanie/wyłączanie sprawdzania w Have I Been Pwned, zmiana ważności hasła oraz zmiana czasu bezczynności sesji.
   * **Przycisk „Zresetuj do 6 kont testowych”**: pozwala w każdej chwili przywrócić stan początkowy.

3. **Test Pierwszego Logowania (`pracownik1` lub `gosc2`)**:
   * Zaloguj się kontem `pracownik1` (hasło: `Prac1234Temp01`).
   * Aplikacja natychmiast wyświetli ekran: **„Wymuszona zmiana hasła przy pierwszym logowaniu!”**.
   * Próba podania hasła krótszego niż 12 znaków zostanie odrzucona.
   * Próba podania hasła skompromitowanego (np. `password12345`) zostanie odrzucona przez Have I Been Pwned API.
   * Po podaniu bezpiecznego hasła użytkownik uzyskuje pełny dostęp do systemu.

4. **Test Kontroli Dostępu (RBAC)**:
   * Zaloguj się jako `pracownik2`: brak widoczności i brak uprawnień do Panelu Administratora (próba wywołania API kończy się kodem 403 Forbidden).
   * Zaloguj się jako `gosc1`: dostęp wyłącznie do Strefy Gościa; brak dostępu do Strefy Pracownika oraz Panelu Administratora.

5. **Test Wygaśnięcia Sesji (Bezczynność)**:
   * W nagłówku widoczny jest licznik czasu bezczynności (np. `⏱️ Bezczynność: 14:58`).
   * W Panelu Administratora można zmniejszyć czas bezczynności np. do 1 minuty do celów szybkiej prezentacji.
   * Brak ruchu myszą i klawiaturą przez ten czas spowoduje automatyczne wylogowanie z komunikatem: *„Sesja wygasła z powodu bezczynności.”*.
