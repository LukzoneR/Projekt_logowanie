const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Dziennik zdarzeń bezpieczeństwa (audit log)
 * Każdy wpis: użytkownik, data i czas, adres IP, akcja, opis, wynik (sukces/błąd)
 *
 * Ochrona dziennika: rejestrowania nie można wyłączyć (brak przełącznika w konfiguracji),
 * a moduł udostępnia wyłącznie dopisywanie i odczyt - nie ma operacji edycji ani usuwania wpisów.
 */

const DATA_DIR = path.join(__dirname, '..', 'data');
const AUDIT_LOG_FILE = 'audit_log.json';
const AUDIT_LOG_PATH = path.join(DATA_DIR, AUDIT_LOG_FILE);
// Integralność (wariant 5): SHA-256 całego pliku dziennika, zapisywany po każdym wpisie w osobnym pliku
const HASH_PATH = path.join(DATA_DIR, 'audit_log.sha256.json');
const MAX_FIELD_LENGTH = 100;
// Powtórne przeglądanie dziennika z tymi samymi filtrami (np. stronicowanie, odświeżanie) nie tworzy nowych wpisów
const VIEW_LOG_WINDOW_MS = 5 * 60 * 1000;

const ACTIONS = Object.freeze({
  LOGIN: 'Logowanie',
  LOGOUT: 'Wylogowanie',
  ACCOUNT_LOCKOUT: 'Blokada konta (limit prób)',
  ACCOUNT_UNLOCK: 'Zdjęcie blokady czasowej',
  PASSWORD_CHANGE: 'Zmiana hasła',
  PASSWORD_RESET: 'Reset hasła przez administratora',
  USER_CREATE: 'Utworzenie użytkownika',
  USER_BLOCK: 'Zablokowanie użytkownika',
  USER_UNBLOCK: 'Odblokowanie użytkownika',
  USER_DELETE: 'Usunięcie użytkownika',
  ROLE_CHANGE: 'Zmiana roli',
  SETTINGS_CHANGE: 'Zmiana ustawień',
  DATABASE_RESET: 'Reset bazy danych',
  ACCESS_DENIED: 'Odmowa dostępu',
  HONEY_ACCOUNT: 'Użycie konta-pułapki',
  CANARY_DB_DUMP: 'Pobranie zrzutu-przynęty',
  AUDIT_VIEW: 'Przeglądanie dziennika zdarzeń',
  AUDIT_EXPORT: 'Eksport dziennika zdarzeń',
  AUDIT_MODIFY_DENIED: 'Próba edycji/usunięcia wpisów dziennika',
  INTEGRITY_CHECK: 'Weryfikacja integralności dziennika',
  INTEGRITY_VIOLATION: 'Naruszenie integralności dziennika',
  INTEGRITY_ACK: 'Potwierdzenie incydentu integralności'
});

const RESULTS = Object.freeze({
  SUCCESS: 'sukces',
  FAILURE: 'błąd'
});

const ANONYMOUS = 'anonim';

function loadEntries() {
  try {
    const parsed = JSON.parse(fs.readFileSync(AUDIT_LOG_PATH, 'utf-8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

// --- Integralność dziennika ---

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function readLogBytes() {
  try {
    return fs.readFileSync(AUDIT_LOG_PATH);
  } catch (e) {
    return null;
  }
}

function readHashRecord() {
  try {
    return JSON.parse(fs.readFileSync(HASH_PATH, 'utf-8'));
  } catch (e) {
    return null;
  }
}

function writeHashRecord(record) {
  fs.writeFileSync(HASH_PATH, JSON.stringify(record, null, 2), 'utf-8');
}

function buildHashRecord(logBytes, entriesCount, previous) {
  const now = new Date().toISOString();
  return {
    algorithm: 'SHA-256',
    file: AUDIT_LOG_FILE,
    sha256: logBytes ? sha256(logBytes) : null,
    entries: entriesCount,
    updatedAt: now,
    initializedAt: (previous && previous.initializedAt) || now,
    incidents: (previous && previous.incidents) || []
  };
}

function countEntries(logBytes) {
  try {
    const parsed = JSON.parse(logBytes.toString('utf-8'));
    return Array.isArray(parsed) ? parsed.length : null;
  } catch (e) {
    return null;
  }
}

// Brak pliku sumy przy starcie oznacza pierwsze uruchomienie mechanizmu;
// zniknięcie pliku w trakcie działania serwera jest traktowane jako ingerencja
let hashRecordExpected = false;

(function initIntegrity() {
  if (readHashRecord()) {
    hashRecordExpected = true;
    return;
  }
  const logBytes = readLogBytes();
  if (logBytes) {
    writeHashRecord(buildHashRecord(logBytes, countEntries(logBytes) ?? 0, null));
    hashRecordExpected = true;
    console.log('Dziennik zdarzeń: zainicjowano sumę kontrolną SHA-256 istniejącego pliku dziennika.');
  }
})();

function describeTampering(record, logBytes, entriesNow) {
  if (!record) {
    return 'Usunięto plik sumy kontrolnej dziennika - nie można potwierdzić, że dziennik nie był modyfikowany.';
  }
  if (!logBytes) {
    return `Plik dziennika został usunięty (oczekiwano ${record.entries} wpisów).`;
  }
  if (entriesNow === null) {
    return 'Plik dziennika jest uszkodzony (niepoprawny JSON) - treść została zmieniona poza aplikacją.';
  }
  if (entriesNow < record.entries) {
    return `Usunięto wpisy z dziennika: było ${record.entries}, jest ${entriesNow} (brakuje ${record.entries - entriesNow}).`;
  }
  if (entriesNow > record.entries) {
    return `Dopisano wpisy poza aplikacją: było ${record.entries}, jest ${entriesNow} (+${entriesNow - record.entries}).`;
  }
  return `Zmieniono treść wpisów - liczba wpisów bez zmian (${entriesNow}), ale suma SHA-256 pliku się nie zgadza.`;
}

function evidenceTimestamp() {
  return new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
}

/**
 * Porównuje bieżący SHA-256 pliku dziennika z zapisanym. Przy niezgodności utrwala incydent,
 * zachowuje kopię zmienionego pliku jako dowód i przyjmuje bieżący stan jako nową bazę,
 * aby kolejne zapisy nie zatarły śladu ingerencji.
 * @param {string} detectedBy - kontekst wykrycia (np. 'weryfikacja', 'zapis zdarzenia')
 * @returns {{ incident: Object|null, record: Object }}
 */
function detectTampering(detectedBy) {
  const record = readHashRecord();
  const logBytes = readLogBytes();

  if (!record && !hashRecordExpected) {
    const initial = buildHashRecord(logBytes, logBytes ? (countEntries(logBytes) ?? 0) : 0, null);
    writeHashRecord(initial);
    hashRecordExpected = true;
    return { incident: null, record: initial };
  }

  const actualHash = logBytes ? sha256(logBytes) : null;
  if (record && record.sha256 === actualHash) {
    return { incident: null, record };
  }

  const entriesNow = logBytes ? countEntries(logBytes) : 0;
  let evidenceFile = null;
  if (logBytes) {
    evidenceFile = `audit_log.tampered-${evidenceTimestamp()}.json`;
    fs.writeFileSync(path.join(DATA_DIR, evidenceFile), logBytes);
  }

  const incident = {
    id: 'inc_' + crypto.randomBytes(6).toString('hex'),
    detectedAt: new Date().toISOString(),
    detectedBy,
    description: describeTampering(record, logBytes, entriesNow),
    expectedHash: record ? record.sha256 : null,
    actualHash,
    expectedEntries: record ? record.entries : null,
    actualEntries: entriesNow,
    evidenceFile,
    acknowledgedAt: null,
    acknowledgedBy: null
  };

  const rebased = buildHashRecord(logBytes, entriesNow ?? 0, record);
  rebased.incidents = [...rebased.incidents, incident];
  writeHashRecord(rebased);
  hashRecordExpected = true;

  console.warn(`!!! INTEGRALNOŚĆ DZIENNIKA NARUSZONA (${detectedBy}): ${incident.description}`);
  return { incident, record: rebased };
}

// Dziennik nie jest przycinany ani rotowany - aplikacja nigdy nie usuwa wpisów
function saveEntries(entries) {
  const content = Buffer.from(JSON.stringify(entries, null, 2), 'utf-8');
  fs.writeFileSync(AUDIT_LOG_PATH, content);
  writeHashRecord(buildHashRecord(content, entries.length, readHashRecord()));
  hashRecordExpected = true;
}

function appendEntry(entry) {
  const entries = loadEntries();
  entries.push(entry);
  saveEntries(entries);
}

function getRequestIp(req) {
  const ip = (req && (req.ip || (req.socket && req.socket.remoteAddress))) || 'nieznany';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function truncate(value, max = MAX_FIELD_LENGTH) {
  const str = String(value ?? '');
  return str.length > max ? str.slice(0, max) + '…' : str;
}

/**
 * Zapisuje zdarzenie w dzienniku
 * @param {Object} req - żądanie HTTP (źródło IP i zalogowanego użytkownika)
 * @param {Object} entry
 * @param {string} entry.action - klucz z ACTIONS
 * @param {boolean} entry.success
 * @param {string} entry.description
 * @param {string} [entry.username] - nadpisuje użytkownika z sesji (np. login podany przy logowaniu)
 */
function buildEntry(req, { action, success, description, username }) {
  if (!ACTIONS[action]) {
    throw new Error(`Nieznana akcja dziennika zdarzeń: ${action}`);
  }

  const actor = username !== undefined && username !== null && String(username).trim() !== ''
    ? String(username).trim()
    : (req && req.user ? req.user.username : ANONYMOUS);

  return {
    id: 'evt_' + crypto.randomBytes(6).toString('hex'),
    timestamp: new Date().toISOString(),
    username: truncate(actor),
    ip: getRequestIp(req),
    action,
    description: truncate(description, 500),
    result: success ? RESULTS.SUCCESS : RESULTS.FAILURE
  };
}

function buildViolationEntry(req, incident) {
  return buildEntry(req, {
    action: 'INTEGRITY_VIOLATION',
    success: false,
    username: 'system',
    description: `${incident.description} Wykryto podczas: ${incident.detectedBy}. Incydent ${incident.id}` +
      (incident.evidenceFile ? `, kopia zmienionego pliku: ${incident.evidenceFile}.` : '.')
  });
}

function log(req, fields) {
  const entry = buildEntry(req, fields);

  try {
    // Kontrola przed zapisem: inaczej nowy wpis przeliczyłby sumę i zatarł ślad ingerencji
    const { incident } = detectTampering('zapis zdarzenia');
    if (incident) appendEntry(buildViolationEntry(req, incident));
    appendEntry(entry);
  } catch (err) {
    console.error('Dziennik zdarzeń: nie udało się zapisać wpisu:', err.message);
  }
  return entry;
}

const lastViewLogged = new Map();

/**
 * Rejestruje przeglądanie dziennika przez administratora
 * @param {string} filtersDescription - opis aktywnych filtrów
 * @param {number} total - liczba pasujących wpisów
 */
function logView(req, filtersDescription, total) {
  const now = Date.now();
  const key = `${req && req.user ? req.user.username : ANONYMOUS}|${filtersDescription}`;
  if (now - (lastViewLogged.get(key) || 0) < VIEW_LOG_WINDOW_MS) return;

  for (const [k, ts] of lastViewLogged) {
    if (now - ts >= VIEW_LOG_WINDOW_MS) lastViewLogged.delete(k);
  }
  lastViewLogged.set(key, now);

  log(req, {
    action: 'AUDIT_VIEW',
    success: true,
    description: `Przeglądanie dziennika ${filtersDescription}, liczba pasujących wpisów: ${total}.`
  });
}

function getUnacknowledgedIncidents(record) {
  return ((record && record.incidents) || []).filter(i => !i.acknowledgedAt);
}

/**
 * Weryfikacja integralności całego dziennika uruchamiana przez administratora
 */
function verifyIntegrity(req) {
  const { incident, record } = detectTampering('weryfikacja uruchomiona przez administratora');
  if (incident) appendEntry(buildViolationEntry(req, incident));

  const openIncidents = getUnacknowledgedIncidents(record);
  const intact = openIncidents.length === 0;
  const result = {
    intact,
    checkedAt: new Date().toISOString(),
    algorithm: 'SHA-256',
    hashFile: path.basename(HASH_PATH),
    currentHash: record.sha256,
    entries: record.entries,
    initializedAt: record.initializedAt,
    newlyDetected: !!incident,
    incidents: openIncidents,
    acknowledgedCount: (record.incidents || []).length - openIncidents.length
  };

  log(req, {
    action: 'INTEGRITY_CHECK',
    success: intact,
    description: intact
      ? `Dziennik nienaruszony: SHA-256 pliku zgodny z zapisaną sumą (${record.entries} wpisów).`
      : `Wykryto ingerencję w dziennik - niepotwierdzonych incydentów: ${openIncidents.length}.`
  });
  return result;
}

/**
 * Potwierdzenie (zamknięcie) incydentów przez administratora po ich wyjaśnieniu
 */
function acknowledgeIncidents(req) {
  const record = readHashRecord();
  const open = getUnacknowledgedIncidents(record);
  if (open.length === 0) return 0;

  const now = new Date().toISOString();
  const by = req && req.user ? req.user.username : ANONYMOUS;
  record.incidents = record.incidents.map(i => i.acknowledgedAt ? i : { ...i, acknowledgedAt: now, acknowledgedBy: by });
  writeHashRecord(record);

  log(req, {
    action: 'INTEGRITY_ACK',
    success: true,
    description: `Potwierdzono incydenty integralności: ${open.map(i => i.id).join(', ')}.`
  });
  return open.length;
}

/**
 * Zwraca wpisy (od najnowszych) z opcjonalnym filtrowaniem i stronicowaniem
 * @param {string} [filters.user] - dokładna nazwa użytkownika (bez rozróżniania wielkości liter)
 * @param {string} [filters.query] - fragment użytkownika, IP lub opisu
 * @param {number|null} [filters.limit] - null zwraca wszystkie pasujące wpisy
 */
function getEntries({ action, result, user, query, from, to, limit = 200, offset = 0 } = {}) {
  const fromMs = from ? new Date(from).getTime() : null;
  const toMs = to ? new Date(to).getTime() : null;
  const q = query ? String(query).toLowerCase() : '';
  const userName = user ? String(user).trim().toLowerCase() : '';

  const filtered = loadEntries().filter(e => {
    if (action && e.action !== action) return false;
    if (result && e.result !== result) return false;
    if (userName && String(e.username).toLowerCase() !== userName) return false;
    const ts = new Date(e.timestamp).getTime();
    if (fromMs !== null && !Number.isNaN(fromMs) && ts < fromMs) return false;
    if (toMs !== null && !Number.isNaN(toMs) && ts > toMs) return false;
    if (q && ![e.username, e.ip, e.description].some(v => String(v).toLowerCase().includes(q))) return false;
    return true;
  }).reverse();

  return {
    total: filtered.length,
    entries: limit === null ? filtered.slice(offset) : filtered.slice(offset, offset + limit)
  };
}

/**
 * Lista nazw użytkowników występujących w dzienniku (do podpowiedzi filtra)
 */
function getUsernames() {
  const names = new Map();
  for (const e of loadEntries()) {
    const key = String(e.username).toLowerCase();
    if (!names.has(key)) names.set(key, e.username);
  }
  return [...names.values()].sort((a, b) => a.localeCompare(b, 'pl'));
}

function formatTimestamp(iso) {
  const d = new Date(iso);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// Wartości zaczynające się od =, +, -, @ arkusz potraktowałby jako formułę (CSV injection)
function toCsvCell(value) {
  let str = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(str)) str = "'" + str;
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Buduje plik eksportu dziennika
 * @param {Object[]} entries
 * @param {'csv'|'json'} format
 * @returns {{ content: string, mimeType: string, fileName: string }}
 */
function buildExport(entries, format) {
  const fileName = `dziennik_zdarzen_${formatTimestamp(new Date().toISOString()).replace(/[: ]/g, '-')}.${format === 'json' ? 'json' : 'csv'}`;

  if (format === 'json') {
    const rows = entries.map(e => ({
      timestamp: e.timestamp,
      username: e.username,
      ip: e.ip,
      action: e.action,
      actionLabel: ACTIONS[e.action] || e.action,
      description: e.description,
      result: e.result
    }));
    return {
      content: JSON.stringify({ exportedAt: new Date().toISOString(), count: rows.length, entries: rows }, null, 2),
      mimeType: 'application/json; charset=utf-8',
      fileName
    };
  }

  const header = ['Data i czas', 'Użytkownik', 'Adres IP', 'Akcja', 'Opis', 'Wynik'];
  const rows = entries.map(e => [
    formatTimestamp(e.timestamp),
    e.username,
    e.ip,
    ACTIONS[e.action] || e.action,
    e.description,
    e.result
  ]);
  // BOM i średnik jako separator - poprawne otwieranie w polskim Excelu
  const csv = [header, ...rows].map(row => row.map(toCsvCell).join(';')).join('\r\n');
  return {
    content: '\uFEFF' + csv,
    mimeType: 'text/csv; charset=utf-8',
    fileName
  };
}

/**
 * Podsumowanie zdarzeń z ostatnich N godzin (liczba wpisów wg akcji i wyniku)
 */
function getSummary(hours = 24) {
  const since = Date.now() - hours * 60 * 60 * 1000;
  const summary = {};
  for (const e of loadEntries()) {
    if (new Date(e.timestamp).getTime() < since) continue;
    const bucket = summary[e.action] || (summary[e.action] = { sukces: 0, 'błąd': 0 });
    bucket[e.result] = (bucket[e.result] || 0) + 1;
  }
  return summary;
}

// Zamrożone API: innym modułom nie da się podmienić log() (np. na pustą funkcję) ani dodać operacji usuwania
module.exports = Object.freeze({
  ACTIONS,
  RESULTS,
  log,
  logView,
  getEntries,
  getUsernames,
  getSummary,
  buildExport,
  verifyIntegrity,
  acknowledgeIncidents
});
