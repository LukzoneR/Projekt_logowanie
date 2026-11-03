const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../data/database');
const { RECAPTCHA_SECRET_KEY } = require('../config/config');

// Pamięć podręczna zużytych tokenów
const usedRecaptchaTokens = new Map();
const RECAPTCHA_TOKEN_TTL_MS = 2 * 60 * 1000;

function cleanExpiredRecaptchaTokens() {
  const now = Date.now();
  for (const [token, expiry] of usedRecaptchaTokens.entries()) {
    if (expiry <= now) {
      usedRecaptchaTokens.delete(token);
    }
  }
}

/**
 * Weryfikacja tokenu Google reCAPTCHA
 * @param {string} token
 * @returns {Promise<{ success: boolean, message?: string }>}
 */
async function verifyRecaptcha(token) {
  if (!token || typeof token !== 'string' || !token.trim()) {
    return {
      success: false,
      message: 'Wymagane jest potwierdzenie reCAPTCHA.'
    };
  }

  const cleanToken = token.trim();

  cleanExpiredRecaptchaTokens();
  if (usedRecaptchaTokens.has(cleanToken)) {
    return {
      success: false,
      message: 'Wyzwanie reCAPTCHA zostało już wykorzystane. Zaznacz pole ponownie.'
    };
  }

  try {
    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET_KEY);
    params.append('response', cleanToken);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!response.ok) {
      console.warn('Ostrzeżenie: Serwer Google reCAPTCHA zwrócił kod', response.status);
      return {
        success: false,
        message: 'Błąd weryfikacji reCAPTCHA. Spróbuj ponownie.'
      };
    }

    const data = await response.json();
    if (data.success) {
      usedRecaptchaTokens.set(cleanToken, Date.now() + RECAPTCHA_TOKEN_TTL_MS);
      return { success: true };
    }

    const errorCodes = data['error-codes'] || [];
    if (errorCodes.includes('timeout-or-duplicate')) {
      return {
        success: false,
        message: 'Wyzwanie reCAPTCHA wygasło lub zostało już wykorzystane. Rozwiąż test ponownie.'
      };
    }

    return {
      success: false,
      message: 'Weryfikacja reCAPTCHA nie powiodła się. Zaznacz pole ponownie.'
    };
  } catch (err) {
    console.error('Błąd połączenia z Google reCAPTCHA:', err.message);
    return {
      success: false,
      message: 'Błąd połączenia z serwerem reCAPTCHA.'
    };
  }
}

// Hash dummy do ochrony przed atakami czasowymi
const DUMMY_HASH = bcrypt.hashSync('DummyPassword123!', 10);

const GENERIC_LOGIN_ERROR = 'Login lub hasło niepoprawne';

/**
 * Liczniki błędnych prób dla NIEISTNIEJĄCYCH loginów
 */
const phantomLockouts = new Map();
const PHANTOM_MAX_ENTRIES = 10000;

/**
 * Zwraca parametry polityki blokady
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
 * Buduje odpowiedź o aktywnej blokadzie
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
 * Obsługa licznika dla nieistniejącego loginu
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
 * Czyści liczniki fantomowe
 */
function clearPhantomLockouts() {
  phantomLockouts.clear();
}

/**
 * Generuje hasło jednorazowe
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
 * Sprawdza hasło w bazie wycieków Have I Been Pwned
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
 * Sprawdza, czy nowe hasło było już używane
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
 * - Długość minimalna
 * - Brak w bazie wycieków HIBP
 * - Różnica od poprzednich haseł
 */
async function validatePasswordPolicy(newPassword, user, config) {
  const errors = [];

  // 1. Sprawdzenie długości
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

  // 3. Sprawdzenie wycieków HIBP
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
 */
async function authenticateUser(username, password) {
  const user = db.getUserByUsername(username);
  const policy = getLockoutPolicy(db.getConfig());

  // Zabezpieczenie przed atakami czasowymi
  // Gdy użytkownik nie istnieje, i tak wykonujemy bcrypt.compareSync
  if (!user) {
    const phantomLock = policy.enabled ? getPhantomLock(username) : null;
    if (phantomLock) {
      return buildLockedResult(phantomLock);
    }
    bcrypt.compareSync(password || '', DUMMY_HASH);
    return registerPhantomFailure(username, policy);
  }

  // Limit błędnych logowań: aktywna blokada czasowa sprawdzana PRZED weryfikacją hasła
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

  // Sprawdzenie blokady konta
  if (user.isBlocked) {
    return {
      success: false,
      message: 'Konto jest zablokowane. Skontaktuj się z administratorem.'
    };
  }

  // Sprawdzenie ważności hasła jednorazowego
  if (user.mustChangePassword && user.temporaryPasswordExpiresAt) {
    const expiresAt = new Date(user.temporaryPasswordExpiresAt).getTime();
    if (Date.now() > expiresAt) {
      return {
        success: false,
        message: 'Hasło jednorazowe wygasło (ważność 24 h). Skontaktuj się z administratorem.'
      };
    }
  }

  // Sprawdzenie ważności hasła w dniach
  const config = db.getConfig();
  if (config.passwordValidityDays && config.passwordValidityDays > 0 && user.passwordChangedAt && !user.mustChangePassword) {
    const changedAt = new Date(user.passwordChangedAt).getTime();
    const maxAgeMs = config.passwordValidityDays * 24 * 60 * 60 * 1000;
    if (Date.now() - changedAt > maxAgeMs) {
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

  // Sprawdzenie zgodności wprowadzonego hasła
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

  // Wyliczenie nowego hasza z solą
  const newHash = bcrypt.hashSync(newPassword, 10);
  const now = new Date().toISOString();

  // Aktualizacja historii haseł
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
  clearPhantomLockouts,
  verifyRecaptcha
};
