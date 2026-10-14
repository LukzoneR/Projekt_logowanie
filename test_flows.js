// Skrypt testujący wszystkie wymagania i scenariusze (Wariant 5)

async function runTests() {
  const BASE_URL = 'http://localhost:3000';
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  [FAIL] ${message}`);
      failed++;
    }
  }
  // Reset bazy przed testami, aby zapewnić idempotencję
  const adminLogin = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'Admin12345678!' })
  });
  const adminData = await adminLogin.json();
  if (adminData.sessionId) {
    await fetch(`${BASE_URL}/api/admin/reset-database`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminData.sessionId}` }
    });
    await fetch(`${BASE_URL}/api/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminData.sessionId}` }
    });
  }

  console.log('--- TEST 1: Niepoprawne logowanie (niezdradzanie istnienia loginu) ---');
  // 1a. Nieistniejący użytkownik
  let res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'non_existent_user_999', password: 'randomPassword123!' })
  });
  let data = await res.json();
  assert(res.status === 401, 'Status 401 dla nieistniejącego użytkownika');
  assert(data.message === 'Login lub hasło niepoprawne', 'Komunikat: "Login lub hasło niepoprawne"');

  // 1b. Istniejący użytkownik ze złym hasłem
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'WrongPassword999!' })
  });
  data = await res.json();
  assert(res.status === 401, 'Status 401 dla złego hasła');
  assert(data.message === 'Login lub hasło niepoprawne', 'Identyczny komunikat błędu: "Login lub hasło niepoprawne"');

  console.log('\n--- TEST 2: Zablokowane konto ---');
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'zablokowany', password: 'Zablokowane12!' })
  });
  data = await res.json();
  assert(!data.success && data.message.includes('zablokowane'), 'Logowanie zablokowanego użytkownika jest odrzucane');

  console.log('\n--- TEST 3: Logowanie Administratora i weryfikacja RBAC ---');
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'Admin12345678!' })
  });
  data = await res.json();
  assert(res.status === 200 && data.success && data.sessionId, 'Logowanie admina udane');
  const adminToken = data.sessionId;

  // Admin sprawdza panel użytkowników
  res = await fetch(`${BASE_URL}/api/admin/users`, {
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  data = await res.json();
  assert(res.status === 200 && data.users.length >= 6, 'Admin ma dostęp do listy użytkowników (min. 6)');

  // Admin sprawdza strefę pracownika
  res = await fetch(`${BASE_URL}/api/resources/employee/data`, {
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  assert(res.status === 200, 'Admin ma dostęp do strefy pracownika');

  console.log('\n--- TEST 4: Logowanie Pracownika i RBAC ---');
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'pracownik2', password: 'Pracownik2026!' })
  });
  data = await res.json();
  const pracownikToken = data.sessionId;

  // Pracownik próbuje wejść do strefy pracownika
  res = await fetch(`${BASE_URL}/api/resources/employee/data`, {
    headers: { 'Authorization': `Bearer ${pracownikToken}` }
  });
  assert(res.status === 200, 'Pracownik ma dostęp do strefy pracownika');

  // Pracownik próbuje wejść do panelu admina
  res = await fetch(`${BASE_URL}/api/admin/users`, {
    headers: { 'Authorization': `Bearer ${pracownikToken}` }
  });
  assert(res.status === 403, 'Pracownik NIE ma dostępu do panelu admina (403 Forbidden)');

  console.log('\n--- TEST 5: Logowanie Gościa i RBAC ---');
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'gosc1', password: 'GoscHaslo2026!' })
  });
  data = await res.json();
  const goscToken = data.sessionId;

  // Gość w strefie gościa
  res = await fetch(`${BASE_URL}/api/resources/guest/data`, {
    headers: { 'Authorization': `Bearer ${goscToken}` }
  });
  assert(res.status === 200, 'Gość ma dostęp do strefy gościa');

  // Gość próbuje wejść do strefy pracownika
  res = await fetch(`${BASE_URL}/api/resources/employee/data`, {
    headers: { 'Authorization': `Bearer ${goscToken}` }
  });
  assert(res.status === 403, 'Gość NIE ma dostępu do strefy pracownika (403 Forbidden)');

  console.log('\n--- TEST 6: Pierwsze logowanie (wymuszona zmiana hasła) ---');
  res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'pracownik1', password: 'Prac1234Temp01' })
  });
  data = await res.json();
  assert(data.user.mustChangePassword === true, 'Konto pracownik1 ma flagę mustChangePassword = true');
  const tempToken = data.sessionId;

  // Próba dostępu do zasobów przed zmianą hasła
  res = await fetch(`${BASE_URL}/api/resources/employee/data`, {
    headers: { 'Authorization': `Bearer ${tempToken}` }
  });
  assert(res.status === 403, 'Dostęp do zasobów zablokowany dopóki hasło nie zostanie zmienione (403)');

  // Próba zmiany na za krótkie hasło (< 12 znaków)
  res = await fetch(`${BASE_URL}/api/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tempToken}` },
    body: JSON.stringify({ newPassword: 'Krotkie1!', confirmPassword: 'Krotkie1!' })
  });
  data = await res.json();
  assert(!data.success && data.errors[0].includes('12 znaków'), 'Odrzucenie hasła krótszego niż 12 znaków');

  // Próba zmiany na hasło z bazy wycieków (Have I Been Pwned)
  console.log('  Sprawdzanie API Have I Been Pwned dla hasła "password12345"...');
  res = await fetch(`${BASE_URL}/api/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tempToken}` },
    body: JSON.stringify({ newPassword: 'password12345', confirmPassword: 'password12345' })
  });
  data = await res.json();
  assert(!data.success && data.errors.some(e => e.includes('Have I Been Pwned')), 'Odrzucenie hasła z bazy wycieków HIBP (Wariant 5)');

  // Poprawna zmiana hasła (bezpieczne, min. 12 znaków)
  const validNewPass = 'BezpieczneNoweHasloPracownika2026!';
  res = await fetch(`${BASE_URL}/api/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tempToken}` },
    body: JSON.stringify({ newPassword: validNewPass, confirmPassword: validNewPass })
  });
  data = await res.json();
  assert(data.success === true, 'Pomyślna zmiana hasła przy pierwszym logowaniu');

  // Po zmianie hasła zasoby są odblokowane
  res = await fetch(`${BASE_URL}/api/resources/employee/data`, {
    headers: { 'Authorization': `Bearer ${tempToken}` }
  });
  assert(res.status === 200, 'Po zmianie hasła użytkownik ma pełny dostęp do swoich uprawnień');

  console.log('\n--- TEST 7: Historia haseł (nowe hasło musi różnić się od poprzednich) ---');
  res = await fetch(`${BASE_URL}/api/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tempToken}` },
    body: JSON.stringify({
      oldPassword: validNewPass,
      newPassword: validNewPass,
      confirmPassword: validNewPass
    })
  });
  data = await res.json();
  assert(!data.success && data.errors.some(e => e.includes('poprzednio używane')), 'Odrzucenie ponownego użycia tego samego hasła (historia haseł)');

  console.log('\n--- TEST 8: Nadawanie hasła jednorazowego przez admina (14 znaków, 24h) ---');
  const testNewUser = 'nowy_pracownik_' + Date.now();
  res = await fetch(`${BASE_URL}/api/admin/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminToken}` },
    body: JSON.stringify({ username: testNewUser, role: 'Pracownik' })
  });
  data = await res.json();
  assert(res.status === 201 && data.temporaryPassword, 'Utworzono użytkownika z hasłem jednorazowym');
  assert(data.temporaryPassword.length === 14, `Hasło jednorazowe ma 14 znaków (długość: ${data.temporaryPassword.length})`);
  assert(/^[A-Za-z0-9]{14}$/.test(data.temporaryPassword), 'Hasło jednorazowe jest alfanumeryczne');

  console.log('\n--- TEST 9: Wylogowanie ręczne i unieważnienie sesji ---');
  res = await fetch(`${BASE_URL}/api/logout`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  assert(res.status === 200, 'Wylogowanie admina udane');

  // Próba użycia unieważnionej sesji
  res = await fetch(`${BASE_URL}/api/me`, {
    headers: { 'Authorization': `Bearer ${adminToken}` }
  });
  assert(res.status === 401, 'Unieważniona sesja zwraca 401 Unauthorized');

  // Reset bazy po testach, aby pozostawić czyste 6 kont testowych
  const cleanupLogin = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'Admin12345678!' })
  });
  const cleanupData = await cleanupLogin.json();
  if (cleanupData.sessionId) {
    await fetch(`${BASE_URL}/api/admin/reset-database`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${cleanupData.sessionId}` }
    });
    await fetch(`${BASE_URL}/api/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${cleanupData.sessionId}` }
    });
  }

  console.log(`\n===========================================`);
  console.log(`PODSUMOWANIE TESTÓW: ${passed} zdanych, ${failed} niezdanych`);
  console.log(`===========================================`);
}

runTests().catch(console.error);
