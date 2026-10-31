const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../data/database');

// Hash dummy do ochrony przed atakami czasowymi (timing attacks)
const DUMMY_HASH = bcrypt.hashSync('DummyPassword123!', 10);

const GENERIC_LOGIN_ERROR = 'Login lub hasło niepoprawne';

/**
 * Liczniki błędnych prób dla NIEISTNIEJĄCYCH loginów (tylko w pamięci).
 * Dzięki temu nieistniejący login również "blokuje się" po przekroczeniu limitu,
 * a ekran blokady nie zdradza atakującemu, czy dane konto istnieje.
 */
const phantomLockouts = new Map();
const PHANTOM_MAX_ENTRIES = 10000;

/**
 * Zwraca parametry polityki blokady z konfiguracji
 */
function getLockoutPolicy(config) {
  const maxAttempts = Number.isInteger(config.maxFailedLoginAttempts) ? config.maxFailedLoginAttempts : 5;
  const durationMinutes = config.lockoutDurationMinutes || 15;
  return {
    enabled: maxAttempts > 0,
    maxAttempts,
    durationMs: durationMinutes * 60 * 1000
  };
}

/**
 * Buduje odpowiedź o aktywnej blokadzie czasowej konta
 */
function buildLockedResult(lockedUntilMs) {
  const remainingSeconds = Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 1000));
  const minutes = Math.ceil(remainingSeconds / 60);
  return {
    success: false,
    locked: true,
    lockedUntil: new Date(lockedUntilMs).toISOString(),
    remainingSeconds,
    message: `Przekroczono limit błędnych logowań. Konto jest tymczasowo zablokowane, pozostało ${minutes} min.`
  };
}

/**
 * Obsługa licznika dla nieistniejącego loginu (zachowanie identyczne jak dla istniejącego konta)
 */
function registerPhantomFailure(username, policy) {
  if (!policy.enabled) return { success: false, message: GENERIC_LOGIN_ERROR };

  const key = String(username || '').toLowerCase();
  if (phantomLockouts.size > PHANTOM_MAX_ENTRIES) phantomLockouts.clear();

  const entry = phantomLockouts.get(key) || { attempts: 0, lockedUntil: 0 };
  entry.attempts += 1;

  if (entry.attempts >= policy.maxAttempts) {
    entry.attempts = 0;
    entry.lockedUntil = Date.now() + policy.durationMs;
    phantomLockouts.set(key, entry);
    return buildLockedResult(entry.lockedUntil);
  }

  phantomLockouts.set(key, entry);
  return { success: false, message: GENERIC_LOGIN_ERROR };
}

function getPhantomLock(username) {
  const entry = phantomLockouts.get(String(username || '').toLowerCase());
  if (entry && entry.lockedUntil > Date.now()) return entry.lockedUntil;
  return null;
}

/**
 * Czyści liczniki fantomowe (np. przy resecie bazy)
 */
function clearPhantomLockouts() {
  phantomLockouts.clear();
}

/**
 * Generuje hasło jednorazowe zgodnie z Wariantem 5:
 * 14 znaków alfanumerycznych, losowane kryptograficznie
 */
function generateTemporaryPassword(length = 14) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

/**
 * Sprawdza hasło w bazie wycieków Have I Been Pwned (Pwned Passwords API)
 * Wariant 5: k-anonimowość - wysyłamy TYLKO 5 pierwszych znaków skrótu SHA-1
 * Serwer HIBP nigdy nie poznaje pełnego hasła ani pełnego hasza!
 * @param {string} password 
 * @returns {Promise<{ isPwned: boolean, count: number, apiError?: boolean }>}
 */
async function checkHaveIBeenPwned(password) {
  try {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'User-Agent': 'ProjektLogowanie-Wariant5' },
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      console.warn('Ostrzeżenie: API HIBP zwróciło status', response.status);
      return { isPwned: false, count: 0, apiError: true };
    }

    const text = await response.text();
    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const [hashSuffix, countStr] = line.split(':');
      if (hashSuffix && hashSuffix.trim().toUpperCase() === suffix) {
        return { isPwned: true, count: parseInt(countStr, 10) || 1 };
      }
    }

    return { isPwned: false, count: 0 };
  } catch (err) {
    console.warn('Ostrzeżenie: Nie udało się połączyć z API HIBP (np. brak sieci):', err.message);
    return { isPwned: false, count: 0, apiError: true };
  }
}

/**
 * Sprawdza, czy nowe hasło było już używane (historia haseł)
 */
function isPasswordInHistory(newPassword, passwordHistory = []) {
  for (const oldHash of passwordHistory) {
    if (bcrypt.compareSync(newPassword, oldHash)) {
      return true;
    }
  }
  return false;
}

/**
 * Waliduje hasło pod kątem polityki bezpieczeństwa:
 * - Długość minimalna (Wariant 5: domyślnie min. 12 znaków, NIST SP 800-63B-4)
 * - Brak w bazie wycieków HIBP (Wariant 5, jeśli włączone)
 * - Różnica od poprzednich haseł (historia)
 */
async function validatePasswordPolicy(newPassword, user, config) {
  const errors = [];

  // 1. Sprawdzenie długości (NIST SP 800-63B-4: liczy się długość, nie złożoność)
  const minLength = config.minPasswordLength || 12;
  if (!newPassword || newPassword.length < minLength) {
    errors.push(`Hasło musi mieć co najmniej ${minLength} znaków (aktualna polityka NIST).`);
  }

  // 2. Sprawdzenie historii haseł
  if (user && user.passwordHistory && user.passwordHistory.length > 0) {
    if (isPasswordInHistory(newPassword, user.passwordHistory)) {
      errors.push('Nowe hasło nie może być takie samo jak poprzednio używane hasła.');
    }
  }

  // 3. Sprawdzenie wycieków HIBP (Wariant 5)
  if (config.checkHaveIBeenPwned && newPassword && newPassword.length >= minLength) {
    const hibpResult = await checkHaveIBeenPwned(newPassword);
    if (hibpResult.isPwned) {
      errors.push(`Hasło znajduje się w bazie znanych wycieków danych Have I Been Pwned (${hibpResult.count.toLocaleString()} wystąpień). Wybierz inne, bezpieczne hasło.`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Uwierzytelnianie użytkownika
 * Zgodnie z zasadą: "Komunikat błędu logowania nie może zdradzać, czy dany login istnieje."
 */
async function authenticateUser(username, password) {
  const user = db.getUserByUsername(username);
  const policy = getLockoutPolicy(db.getConfig());

  // Zabezpieczenie przed atakami czasowymi (timing attack)
  // Gdy użytkownik nie istnieje, i tak wykonujemy bcrypt.compareSync
  if (!user) {
    const phantomLock = policy.enabled ? getPhantomLock(username) : null;
    if (phantomLock) {
      return buildLockedResult(phantomLock);
    }
    bcrypt.compareSync(password || '', DUMMY_HASH);
    return registerPhantomFailure(username, policy);
  }

  // Limit błędnych logowań: aktywna blokada czasowa sprawdzana PRZED weryfikacją hasła,
  // aby w trakcie blokady nie dało się kontynuować zgadywania hasła
  const lockedUntilMs = user.lockedUntil ? new Date(user.lockedUntil).getTime() : 0;
  if (policy.enabled && lockedUntilMs > Date.now()) {
    return buildLockedResult(lockedUntilMs);
  }

  // Weryfikacja hasła przez bcrypt
  const isPasswordValid = bcrypt.compareSync(password || '', user.passwordHash);

  if (!isPasswordValid) {
    if (!policy.enabled) {
      return { success: false, message: GENERIC_LOGIN_ERROR };
    }

    // Po wygaśnięciu poprzedniej blokady licznik liczony jest od zera
    const previousAttempts = lockedUntilMs ? 0 : (user.failedLoginAttempts || 0);
    const attempts = previousAttempts + 1;

    if (attempts >= policy.maxAttempts) {
      const newLockedUntil = Date.now() + policy.durationMs;
      db.updateUser(user.id, {
        failedLoginAttempts: 0,
        lockedUntil: new Date(newLockedUntil).toISOString()
      });
      return buildLockedResult(newLockedUntil);
    }

    db.updateUser(user.id, { failedLoginAttempts: attempts, lockedUntil: null });
    return { success: false, message: GENERIC_LOGIN_ERROR };
  }

  // Poprawne hasło: zerowanie licznika błędnych prób
  if (user.failedLoginAttempts || user.lockedUntil) {
    db.updateUser(user.id, { failedLoginAttempts: 0, lockedUntil: null });
  }

  // Sprawdzenie blokady konta (dopiero po poprawnym uwierzytelnieniu, aby nie zdradzać istnienia loginu atakującemu)
  if (user.isBlocked) {
    return {
      success: false,
      message: 'Konto jest zablokowane. Skontaktuj się z administratorem.'
    };
  }

  // Sprawdzenie ważności hasła jednorazowego (24h)
  if (user.mustChangePassword && user.temporaryPasswordExpiresAt) {
    const expiresAt = new Date(user.temporaryPasswordExpiresAt).getTime();
    if (Date.now() > expiresAt) {
      return {
        success: false,
        message: 'Hasło jednorazowe wygasło (ważność 24 h). Skontaktuj się z administratorem.'
      };
    }
  }

  // Sprawdzenie ważności hasła w dniach (jeśli polityka określa termin ważności)
  const config = db.getConfig();
  if (config.passwordValidityDays && config.passwordValidityDays > 0 && user.passwordChangedAt && !user.mustChangePassword) {
    const changedAt = new Date(user.passwordChangedAt).getTime();
    const maxAgeMs = config.passwordValidityDays * 24 * 60 * 60 * 1000;
    if (Date.now() - changedAt > maxAgeMs) {
      // Wymuszenie zmiany hasła po upływie okresu ważności
      db.updateUser(user.id, { mustChangePassword: true });
      user.mustChangePassword = true;
    }
  }

  return {
    success: true,
    user
  };
}

/**
 * Zmiana hasła użytkownika
 */
async function changePassword({ userId, oldPassword, newPassword, confirmPassword, isFirstLogin = false }) {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, errors: ['Użytkownik nie istnieje.'] };
  }

  // Sprawdzenie zgodności podwójnie wprowadzonego hasła
  if (!newPassword || newPassword !== confirmPassword) {
    return { success: false, errors: ['Nowe hasła nie są identyczne.'] };
  }

  // Przy zwykłej zmianie hasła wymagana jest weryfikacja starego hasła
  if (!isFirstLogin) {
    if (!oldPassword || !bcrypt.compareSync(oldPassword, user.passwordHash)) {
      return { success: false, errors: ['Dotychczasowe hasło jest niepoprawne.'] };
    }
  }

  // Walidacja nowego hasła z polityką
  const config = db.getConfig();
  const policyCheck = await validatePasswordPolicy(newPassword, user, config);
  if (!policyCheck.valid) {
    return { success: false, errors: policyCheck.errors };
  }

  // Wyliczenie nowego hasza z solą (bcrypt)
  const newHash = bcrypt.hashSync(newPassword, 10);
  const now = new Date().toISOString();

  // Aktualizacja historii haseł (zapamiętujemy ostatnie 5 hashy)
  const history = [...(user.passwordHistory || []), newHash].slice(-5);

  db.updateUser(user.id, {
    passwordHash: newHash,
    passwordHistory: history,
    mustChangePassword: false,
    temporaryPasswordExpiresAt: null,
    passwordChangedAt: now
  });

  return { success: true };
}

module.exports = {
  generateTemporaryPassword,
  checkHaveIBeenPwned,
  validatePasswordPolicy,
  authenticateUser,
  changePassword,
  clearPhantomLockouts
};
