/**
 * Symulacja bota atakującego formularz logowania własnej aplikacji.
 *
 * Bot przechodzi kolejne etapy typowego ataku (od naiwnego wypełniania formularza,
 * przez brute force i enumerację loginów, po użycie danych z wykradzionego zrzutu bazy)
 * i sprawdza, które zabezpieczenia aplikacji zadziałały.
 *
 * Uruchomienie (serwer musi działać):  npm run test:bot
 * Inny adres serwera:                  $env:BASE_URL="http://localhost:3999"; npm run test:bot
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
// Nagłówki HTTP muszą być w ASCII - bez polskich znaków
const BOT_USER_AGENT = 'BotSimulator/1.0 (test bezpieczenstwa Projekt_logowanie)';
const REPORT_PATH = path.join(__dirname, 'raport-bota.md');
const GOOGLE_TEST_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';

// Konta testowe z seedData.js
const ADMIN = { username: 'admin', password: 'Admin12345678!' };
const VICTIM = { username: 'pracownik2', password: 'Pracownik2026!' };
const HONEYPOT_VICTIM = { username: 'gosc1', password: 'GoscHaslo2026!' };
const NONEXISTENT_LOGIN = 'nieistniejacy_' + crypto.randomBytes(3).toString('hex');

const PASSWORD_DICTIONARY = ['123456', 'password', 'qwerty123', 'Haslo123!', 'Pracownik2025!', 'admin1', 'zaq1@WSX', 'Welcome2026!'];

const results = [];

// --- Narzędzia HTTP ---

async function request(method, urlPath, { body, token, headers = {} } = {}) {
  const started = Date.now();
  const res = await fetch(BASE_URL + urlPath, {
    method,
    headers: {
      'User-Agent': BOT_USER_AGENT,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = text; }
  return { status: res.status, data, ms: Date.now() - started };
}

// Bot "rozwiązuje" reCAPTCHA podając wymyślony token (nowy przy każdej próbie)
function fakeCaptchaToken() {
  return 'bot-' + crypto.randomBytes(12).toString('hex');
}

function login(username, password, { website = '', recaptchaToken = fakeCaptchaToken() } = {}) {
  const body = { username, password, website };
  if (recaptchaToken !== null) body.recaptchaToken = recaptchaToken;
  return request('POST', '/api/login', { body });
}

function describe(res) {
  const msg = typeof res.data === 'object' ? (res.data.message || res.data.error || '') : '';
  return `HTTP ${res.status}${msg ? ` "${msg}"` : ''}`;
}

function record({ id, attack, defense, passed, details, info = false }) {
  results.push({ id, attack, defense, status: info ? 'INFO' : (passed ? 'ZADZIAŁAŁO' : 'NIE ZADZIAŁAŁO'), details });
  const icon = info ? 'i' : (passed ? '+' : '!');
  console.log(`[${icon}] ${id}. ${attack} -> ${defense}: ${info ? 'INFO' : (passed ? 'ZADZIAŁAŁO' : 'NIE ZADZIAŁAŁO')}`);
  console.log(`      ${details}`);
}

// --- Przygotowanie: sesja administratora do odczytu polityki, alertów i sprzątania ---

async function getAdminSession() {
  const res = await login(ADMIN.username, ADMIN.password);
  if (res.status !== 200 || !res.data.sessionId) {
    throw new Error(`Nie udało się zalogować jako admin (${describe(res)}). ` +
      'Sprawdź, czy serwer działa, konto admin nie jest zablokowane i jest dostęp do Google reCAPTCHA.');
  }
  return res.data.sessionId;
}

// --- Scenariusze ataku ---

async function testHoneypot() {
  // Naiwny bot wypełnia każde pole formularza, łącznie z ukrytym "website".
  // Używamy POPRAWNEGO hasła: jeśli mimo to logowanie się nie uda, zablokowała je pułapka.
  const res = await login(HONEYPOT_VICTIM.username, HONEYPOT_VICTIM.password, { website: 'http://tanie-leki.example' });
  record({
    id: 1,
    attack: 'Bot wypełnia wszystkie pola formularza (z poprawnym hasłem)',
    defense: 'Pułapka na boty (honeypot)',
    passed: res.status !== 200 && !res.data.sessionId,
    details: `${describe(res)} - ${res.status === 200 ? 'bot zalogował się!' : 'logowanie odrzucone mimo poprawnego hasła, komunikat nie zdradza wykrycia'}`
  });
}

async function testMissingCaptcha() {
  // Bot wysyła żądania prosto do API, bez rozwiązywania reCAPTCHA
  const res = await login(HONEYPOT_VICTIM.username, HONEYPOT_VICTIM.password, { recaptchaToken: null });
  record({
    id: 2,
    attack: 'Bot wysyła żądanie do API bez tokenu reCAPTCHA (z poprawnym hasłem)',
    defense: 'Google reCAPTCHA - wymagany token',
    passed: res.status === 400 && !res.data.sessionId,
    details: describe(res)
  });
}

async function testCaptchaReplay() {
  // Bot raz zdobywa token (np. od człowieka z "farmy captcha") i próbuje używać go wielokrotnie
  const token = fakeCaptchaToken();
  const first = await login(NONEXISTENT_LOGIN, 'zle-haslo-1', { recaptchaToken: token });
  const second = await login(NONEXISTENT_LOGIN, 'zle-haslo-2', { recaptchaToken: token });
  record({
    id: 3,
    attack: 'Bot używa ponownie tego samego tokenu reCAPTCHA',
    defense: 'Jednorazowość tokenu reCAPTCHA',
    passed: second.status === 400,
    details: `1. użycie: ${describe(first)}; 2. użycie: ${describe(second)}`
  });
}

async function testFakeCaptchaAccepted() {
  const captchaConfig = await request('GET', '/api/recaptcha-config');
  const usingTestKeys = captchaConfig.data.siteKey === GOOGLE_TEST_SITE_KEY;

  const res = await login(HONEYPOT_VICTIM.username, HONEYPOT_VICTIM.password);
  const accepted = res.status === 200 && !!res.data.sessionId;
  if (accepted) await request('POST', '/api/logout', { token: res.data.sessionId });

  let details = describe(res);
  if (accepted) {
    details = usingTestKeys
      ? 'Token zaakceptowany: serwer działa na TESTOWYCH kluczach Google, które przepuszczają każdy token. Ustaw prawdziwe klucze w .env.'
      : 'Token zaakceptowany mimo kluczy produkcyjnych - sprawdź weryfikację reCAPTCHA na serwerze!';
  }

  record({
    id: 4,
    attack: 'Bot podaje wymyślony (nowy) token reCAPTCHA',
    defense: 'Google reCAPTCHA - weryfikacja tokenu w Google',
    passed: !accepted,
    details
  });
}

async function testUserEnumeration() {
  const existing = await login(VICTIM.username, 'zle-haslo-enum');
  const missing = await login(NONEXISTENT_LOGIN + 'x', 'zle-haslo-enum');
  const sameAnswer = existing.status === missing.status &&
    JSON.stringify(existing.data) === JSON.stringify(missing.data);
  record({
    id: 5,
    attack: 'Bot sprawdza, które loginy istnieją (porównanie odpowiedzi)',
    defense: 'Jednakowy komunikat błędu logowania',
    passed: sameAnswer,
    details: `istniejący "${VICTIM.username}": ${describe(existing)} (${existing.ms} ms); ` +
      `nieistniejący: ${describe(missing)} (${missing.ms} ms)`
  });
}

async function testBruteForce(maxAttempts) {
  if (maxAttempts === 0) {
    record({ id: 6, attack: 'Brute force hasła istniejącego konta', defense: 'Limit błędnych logowań', passed: false,
      details: 'Limit błędnych logowań jest wyłączony w polityce (0) - bot może zgadywać bez końca.' });
    return;
  }

  let lockedAfter = null;
  let attempts = 0;
  for (const pw of PASSWORD_DICTIONARY.concat(PASSWORD_DICTIONARY)) {
    attempts++;
    const res = await login(VICTIM.username, pw);
    if (res.status === 423) { lockedAfter = attempts; break; }
    if (attempts > maxAttempts + 2) break;
  }

  // Najważniejsze: w trakcie blokady nawet POPRAWNE hasło nie może wpuścić bota
  const correct = await login(VICTIM.username, VICTIM.password);
  if (correct.data && correct.data.sessionId) await request('POST', '/api/logout', { token: correct.data.sessionId });

  record({
    id: 6,
    attack: `Brute force hasła konta "${VICTIM.username}" (słownik ${PASSWORD_DICTIONARY.length} haseł)`,
    defense: `Limit błędnych logowań (${maxAttempts} prób, blokada 15 min)`,
    passed: lockedAfter !== null && correct.status === 423,
    details: (lockedAfter !== null
      ? `konto zablokowane po ${lockedAfter}. próbie bota (wliczając wcześniejszą próbę z testu enumeracji)`
      : `brak blokady po ${attempts} próbach`) +
      `; poprawne hasło w trakcie blokady: ${describe(correct)}`
  });
}

async function testPhantomLockout(maxAttempts) {
  if (maxAttempts === 0) return;
  const login_ = NONEXISTENT_LOGIN + 'phantom';
  let lockedAfter = null;
  for (let i = 1; i <= maxAttempts + 1; i++) {
    const res = await login(login_, PASSWORD_DICTIONARY[i % PASSWORD_DICTIONARY.length]);
    if (res.status === 423) { lockedAfter = i; break; }
  }
  record({
    id: 7,
    attack: 'Bot sprawdza istnienie loginu po tym, czy konto się blokuje',
    defense: 'Blokada także dla nieistniejących loginów',
    passed: lockedAfter === maxAttempts,
    details: lockedAfter
      ? `nieistniejący login zablokowany po ${lockedAfter}. próbie - tak samo jak prawdziwe konto`
      : 'nieistniejący login nigdy się nie zablokował - bot może odróżnić prawdziwe konta'
  });
}

async function testStolenCredentials(adminToken, since) {
  // Rekonesans: robots.txt -> /backup/ -> zrzut bazy -> dane logowania -> próba logowania
  const robots = await request('GET', '/robots.txt');
  const hiddenDirs = String(robots.data).match(/Disallow:\s*(\S+)/g) || [];
  const backupDir = hiddenDirs.map(l => l.split(/\s+/)[1]).find(p => p.includes('backup'));

  const listing = backupDir ? await request('GET', backupDir) : null;
  const dumpFile = listing ? (String(listing.data).match(/href="([^"]+\.sql)"/) || [])[1] : null;
  const dump = dumpFile ? await request('GET', backupDir + dumpFile) : null;
  const creds = dump ? String(dump.data).match(/login:\s*(\S+)\s+haslo:\s*(\S+)/) : null;

  if (!creds) {
    record({ id: 8, attack: 'Bot szuka wycieku danych (robots.txt, /backup/)', defense: 'Canarytokens', passed: false,
      details: 'Bot nie dotarł do przynęty - sprawdź robots.txt i trasy /backup/.' });
    return;
  }

  const res = await login(creds[1], creds[2]);

  const alertsRes = await request('GET', '/api/admin/canary-alerts', { token: adminToken });
  const botAlerts = (alertsRes.data.alerts || []).filter(a => a.userAgent === BOT_USER_AGENT && a.triggeredAt >= since);
  const dumpAlert = botAlerts.find(a => a.tokenId.startsWith('ct_dbdump'));
  const honeyAlert = botAlerts.find(a => a.tokenId.startsWith('ct_honey'));

  record({
    id: 8,
    attack: `Bot pobiera zrzut bazy z ${backupDir}${dumpFile}`,
    defense: 'Canarytoken: fałszywy zrzut bazy',
    passed: !!dumpAlert,
    details: dumpAlert ? `alert "${dumpAlert.severity}" zarejestrowany (IP ${dumpAlert.ip})` : 'brak alertu'
  });
  record({
    id: 9,
    attack: `Bot loguje się danymi ze zrzutu (${creds[1]})`,
    defense: 'Canarytoken: konto-pułapka',
    passed: !!honeyAlert && !res.data.sessionId,
    details: `${describe(res)}; ` + (honeyAlert ? `alert "${honeyAlert.severity}": ${honeyAlert.description}` : 'brak alertu')
  });
}

async function testAccessWithoutSession() {
  const none = await request('GET', '/api/admin/users');
  const forged = await request('GET', '/api/admin/users', { token: crypto.randomBytes(32).toString('hex') });
  record({
    id: 10,
    attack: 'Bot omija logowanie i wywołuje API administratora (brak / sfałszowana sesja)',
    defense: 'Weryfikacja sesji (sessionMiddleware)',
    passed: none.status === 401 && forged.status === 401,
    details: `bez sesji: ${describe(none)}; sfałszowany token: ${describe(forged)}`
  });
}

// --- Sprzątanie: konto ofiary brute force nie powinno zostać zablokowane po teście ---

async function cleanup(adminToken) {
  const users = await request('GET', '/api/admin/users', { token: adminToken });
  const victim = (users.data.users || []).find(u => u.username === VICTIM.username);
  if (victim) await request('PUT', `/api/admin/users/${victim.id}/unlock`, { token: adminToken });
  await request('POST', '/api/logout', { token: adminToken });
}

// --- Raport ---

function writeReport(startedAt) {
  const counted = results.filter(r => r.status !== 'INFO');
  const ok = counted.filter(r => r.status === 'ZADZIAŁAŁO').length;
  const escape = s => String(s).replace(/\|/g, '\\|');

  const lines = [
    '# Raport z symulacji bota',
    '',
    `- Data: ${startedAt.toLocaleString('pl-PL')}`,
    `- Cel: ${BASE_URL}`,
    `- User-Agent bota: \`${BOT_USER_AGENT}\``,
    `- Wynik: **${ok}/${counted.length}** zabezpieczeń zadziałało`,
    '',
    '| # | Atak bota | Zabezpieczenie | Wynik | Szczegóły |',
    '|---|---|---|---|---|',
    ...results.map(r => `| ${r.id} | ${escape(r.attack)} | ${escape(r.defense)} | **${r.status}** | ${escape(r.details)} |`),
    ''
  ];
  fs.writeFileSync(REPORT_PATH, lines.join('\n'), 'utf-8');

  console.log('\n================ ZESTAWIENIE ================');
  console.table(results.map(r => ({ '#': r.id, 'Zabezpieczenie': r.defense, 'Wynik': r.status })));
  console.log(`Zadziałało: ${ok}/${counted.length}`);
  console.log(`Raport zapisano: ${REPORT_PATH}`);
}

async function main() {
  const startedAt = new Date();
  console.log(`Symulacja bota -> ${BASE_URL}\n`);

  const adminToken = await getAdminSession();
  const policy = await request('GET', '/api/admin/policy', { token: adminToken });
  const maxAttempts = policy.data.config?.maxFailedLoginAttempts ?? 5;

  try {
    await testHoneypot();
    await testMissingCaptcha();
    await testCaptchaReplay();
    await testFakeCaptchaAccepted();
    await testUserEnumeration();
    await testBruteForce(maxAttempts);
    await testPhantomLockout(maxAttempts);
    await testStolenCredentials(adminToken, startedAt.toISOString());
    await testAccessWithoutSession();
  } finally {
    await cleanup(adminToken);
  }

  writeReport(startedAt);
}

main().catch(err => {
  console.error('Symulacja przerwana:', err.message);
  process.exit(1);
});
