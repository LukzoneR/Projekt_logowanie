const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Dziennik zdarzeń bezpieczeństwa (audit log)
 * Każdy wpis: użytkownik, data i czas, adres IP, akcja, opis, wynik (sukces/błąd)
 */

const AUDIT_LOG_PATH = path.join(__dirname, '..', 'data', 'audit_log.json');
const MAX_STORED_ENTRIES = 5000;
const MAX_FIELD_LENGTH = 100;

const ACTIONS = {
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
  AUDIT_EXPORT: 'Eksport dziennika zdarzeń'
};

const RESULTS = {
  SUCCESS: 'sukces',
  FAILURE: 'błąd'
};

const ANONYMOUS = 'anonim';

function loadEntries() {
  try {
    return JSON.parse(fs.readFileSync(AUDIT_LOG_PATH, 'utf-8'));
  } catch (e) {
    return [];
  }
}

function saveEntries(entries) {
  fs.writeFileSync(AUDIT_LOG_PATH, JSON.stringify(entries.slice(-MAX_STORED_ENTRIES), null, 2), 'utf-8');
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
function log(req, { action, success, description, username }) {
  if (!ACTIONS[action]) {
    throw new Error(`Nieznana akcja dziennika zdarzeń: ${action}`);
  }

  const actor = username !== undefined && username !== null && String(username).trim() !== ''
    ? String(username).trim()
    : (req && req.user ? req.user.username : ANONYMOUS);

  const entry = {
    id: 'evt_' + crypto.randomBytes(6).toString('hex'),
    timestamp: new Date().toISOString(),
    username: truncate(actor),
    ip: getRequestIp(req),
    action,
    description: truncate(description, 500),
    result: success ? RESULTS.SUCCESS : RESULTS.FAILURE
  };

  try {
    const entries = loadEntries();
    entries.push(entry);
    saveEntries(entries);
  } catch (err) {
    console.error('Dziennik zdarzeń: nie udało się zapisać wpisu:', err.message);
  }
  return entry;
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

module.exports = {
  ACTIONS,
  RESULTS,
  log,
  getEntries,
  getUsernames,
  getSummary,
  buildExport
};
