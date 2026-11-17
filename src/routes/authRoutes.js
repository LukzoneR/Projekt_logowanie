const express = require('express');
const router = express.Router();
const authService = require('../services/authService');
const canaryService = require('../services/canaryService');
const sessionService = require('../services/sessionService');
const auditService = require('../services/auditService');
const sessionMiddleware = require('../middleware/sessionMiddleware');
const db = require('../data/database');
const { getRolePermissions } = require('../services/rbacService');
const { RAW_TEST_USERS } = require('../data/seedData');
const { RECAPTCHA_SITE_KEY } = require('../config/config');

const { LOGIN_FAILURE_REASONS } = authService;

function formatAttempts(result) {
  return result.attempts && result.maxAttempts ? ` (próba ${result.attempts}/${result.maxAttempts})` : '';
}

/**
 * Opis nieudanego logowania do dziennika zdarzeń
 */
function describeLoginFailure(result) {
  const remainingMinutes = Math.ceil((result.remainingSeconds || 0) / 60);
  const target = result.unknownUser ? 'nieistniejący login' : 'konto istniejące';
  switch (result.reason) {
    case LOGIN_FAILURE_REASONS.UNKNOWN_USER:
      return `Nieistniejący login${formatAttempts(result)}.`;
    case LOGIN_FAILURE_REASONS.BAD_PASSWORD:
      return `Błędne hasło${formatAttempts(result)}.`;
    case LOGIN_FAILURE_REASONS.LOCKED:
      return `Próba logowania podczas aktywnej blokady czasowej (${target}, pozostało ${remainingMinutes} min).`;
    case LOGIN_FAILURE_REASONS.LOCKOUT_TRIGGERED:
      return `Błędne dane logowania - przekroczono limit prób (${target})${formatAttempts(result)}.`;
    case LOGIN_FAILURE_REASONS.ACCOUNT_BLOCKED:
      return 'Poprawne hasło, ale konto jest zablokowane przez administratora.';
    case LOGIN_FAILURE_REASONS.TEMP_PASSWORD_EXPIRED:
      return 'Poprawne hasło jednorazowe, ale jego ważność (24 h) wygasła.';
    default:
      return result.message || 'Nieudane logowanie.';
  }
}

/**
 * GET /api/recaptcha-config
 * Publiczny klucz witryny reCAPTCHA dla frontendu
 */
router.get('/recaptcha-config', (req, res) => {
  res.json({ siteKey: RECAPTCHA_SITE_KEY });
});

/**
 * POST /api/login
 * Logowanie użytkownika
 */ 
router.post('/login', async (req, res) => {
  const { username, password, website, recaptchaToken } = req.body;

  // Canarytoken: konto-pułapka. Alert wyzwalany jest przed pozostałymi sprawdzeniami,
  // a dalsza obsługa przebiega jak dla nieistniejącego loginu.
  if (canaryService.isHoneyAccount(username)) {
    const alert = canaryService.handleHoneyAccountLogin(req, password);
    auditService.log(req, {
      action: 'HONEY_ACCOUNT',
      success: false,
      username,
      description: `${alert.description} Alert ${alert.id}, waga: ${alert.severity}.`
    });
  }

  const loginName = typeof username === 'string' ? username : '';

  // Pułapka na boty (honeypot): wypełnione ukryte pole oznacza bota.
  // Zwracamy ogólny komunikat, aby nie zdradzać mechanizmu wykrywania.
  if (typeof website === 'string' ? website.trim() !== '' : website != null) {
    console.warn(`Pułapka na boty: odrzucono próbę logowania (login: "${username}", IP: ${req.ip})`);
    auditService.log(req, {
      action: 'LOGIN',
      success: false,
      username: loginName,
      description: 'Odrzucono: wypełnione ukryte pole formularza (pułapka na boty).'
    });
    return res.status(401).json({
      success: false,
      message: 'Login lub hasło niepoprawne'
    });
  }

  // Weryfikacja Google reCAPTCHA przy logowaniu
  const captchaCheck = await authService.verifyRecaptcha(recaptchaToken);
  if (!captchaCheck.success) {
    auditService.log(req, {
      action: 'LOGIN',
      success: false,
      username: loginName,
      description: `Nieudana weryfikacja reCAPTCHA: ${captchaCheck.message}`
    });
    return res.status(400).json({
      success: false,
      message: captchaCheck.message
    });
  }

  if (!username || !password) {
    auditService.log(req, {
      action: 'LOGIN',
      success: false,
      username: loginName,
      description: 'Brak loginu lub hasła w żądaniu.'
    });
    return res.status(400).json({
      success: false,
      message: 'Login lub hasło niepoprawne'
    });
  }

  const result = await authService.authenticateUser(username, password);

  if (!result.success) {
    auditService.log(req, {
      action: 'LOGIN',
      success: false,
      username: loginName,
      description: describeLoginFailure(result)
    });

    if (result.reason === LOGIN_FAILURE_REASONS.LOCKOUT_TRIGGERED) {
      const lockMinutes = Math.ceil(result.remainingSeconds / 60);
      auditService.log(req, {
        action: 'ACCOUNT_LOCKOUT',
        success: true,
        username: loginName,
        description: result.unknownUser
          ? `Czasowa blokada nieistniejącego loginu na ${lockMinutes} min po przekroczeniu limitu błędnych prób.`
          : `Konto zablokowane czasowo na ${lockMinutes} min (do ${new Date(result.lockedUntil).toLocaleString('pl-PL')}) po przekroczeniu limitu błędnych prób.`
      });
    }

    // Limit błędnych logowań: konto czasowo zablokowane
    if (result.locked) {
      res.setHeader('Retry-After', String(result.remainingSeconds));
      return res.status(423).json({
        success: false,
        error: 'ACCOUNT_LOCKED',
        message: result.message,
        lockedUntil: result.lockedUntil,
        remainingSeconds: result.remainingSeconds
      });
    }

    return res.status(401).json({
      success: false,
      message: result.message
    });
  }

  const user = result.user;
  const session = sessionService.createSession(user);

  let loginNote = '';
  if (result.passwordExpired) {
    loginNote = ' Hasło wygasło - wymuszono zmianę hasła.';
  } else if (user.mustChangePassword) {
    loginNote = ' Wymagana zmiana hasła (hasło jednorazowe).';
  }
  auditService.log(req, {
    action: 'LOGIN',
    success: true,
    username: user.username,
    description: `Zalogowano pomyślnie (rola: ${user.role}).${loginNote}`
  });

  res.json({
    success: true,
    sessionId: session.id,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      mustChangePassword: user.mustChangePassword,
      isPermanentAdmin: user.isPermanentAdmin
    }
  });
});

/**
 * POST /api/logout
 * Wylogowanie ręczne
 */
router.post('/logout', sessionMiddleware, (req, res) => {
  sessionService.destroySession(req.sessionId);
  const byInactivity = req.body && req.body.reason === 'inactivity';
  auditService.log(req, {
    action: 'LOGOUT',
    success: true,
    description: byInactivity
      ? 'Automatyczne wylogowanie z powodu bezczynności (zgłoszone przez przeglądarkę).'
      : 'Wylogowanie ręczne.'
  });
  res.json({
    success: true,
    message: 'Wylogowano pomyślnie.'
  });
});

/**
 * GET /api/me
 * Pobranie informacji o zalogowanym użytkowniku i aktualnej sesji
 */
router.get('/me', sessionMiddleware, (req, res) => {
  const user = req.user;
  const config = db.getConfig();

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      permissions: getRolePermissions(user.role),
      mustChangePassword: user.mustChangePassword,
      passwordChangedAt: user.passwordChangedAt,
      isPermanentAdmin: user.isPermanentAdmin
    },
    sessionTimeoutMinutes: config.sessionInactivityTimeoutMinutes
  });
});

/**
 * POST /api/change-password
 * Zmiana hasła
 */
router.post('/change-password', sessionMiddleware, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword, recaptchaToken } = req.body;

  // Weryfikacja Google reCAPTCHA przy zmianie hasła
  const isFirstLogin = req.user.mustChangePassword;
  const changeKind = isFirstLogin ? 'Wymuszona zmiana hasła' : 'Zmiana hasła';

  const captchaCheck = await authService.verifyRecaptcha(recaptchaToken);
  if (!captchaCheck.success) {
    auditService.log(req, {
      action: 'PASSWORD_CHANGE',
      success: false,
      description: `${changeKind} odrzucona - nieudana weryfikacja reCAPTCHA: ${captchaCheck.message}`
    });
    return res.status(400).json({
      success: false,
      errors: [captchaCheck.message]
    });
  }

  const result = await authService.changePassword({
    userId: req.user.id,
    oldPassword,
    newPassword,
    confirmPassword,
    isFirstLogin
  });

  if (!result.success) {
    auditService.log(req, {
      action: 'PASSWORD_CHANGE',
      success: false,
      description: `${changeKind} nieudana: ${result.errors.join(' ')}`
    });
    return res.status(400).json({
      success: false,
      errors: result.errors
    });
  }

  // Aktualizacja stanu sesji po pomyślnej zmianie hasła
  sessionService.updateSession(req.sessionId, { mustChangePassword: false });
  auditService.log(req, {
    action: 'PASSWORD_CHANGE',
    success: true,
    description: isFirstLogin
      ? 'Ustawiono nowe hasło w miejsce hasła jednorazowego/wygasłego.'
      : 'Hasło zostało zmienione przez użytkownika.'
  });

  res.json({
    success: true,
    message: 'Hasło zostało pomyślnie zmienione.'
  });
});

/**
 * GET /api/test-accounts
 * Informacja o 6 kontach testowych i wariancie
 */
router.get('/test-accounts', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  const dbUsers = db.getUsers();

  const accounts = dbUsers.map(liveUser => {
    const rawMatch = RAW_TEST_USERS.find(r => r.username.toLowerCase() === liveUser.username.toLowerCase());
    const displayPassword = rawMatch ? rawMatch.rawPassword : '••••••••••••';
    return {
      id: liveUser.id,
      username: liveUser.username,
      password: displayPassword,
      role: liveUser.role,
      mustChangePassword: liveUser.mustChangePassword,
      isBlocked: liveUser.isBlocked,
      description: rawMatch ? rawMatch.description : 'Użytkownik utworzony przez administratora'
    };
  });

  res.json({
    variant: 5,
    rules: {
      minPasswordLength: 12,
      checkHaveIBeenPwned: 'Sprawdzanie w bazie wycieków HIBP (k-anonimowość SHA-1)',
      roles: ['Administrator', 'Pracownik', 'Gość'],
      oneTimePassword: '14 znaków alfanumerycznych, ważne 24 h'
    },
    accounts
  });
});

/**
 * POST /api/reset-database
 * Reset bazy danych do 6 początkowych kont testowych
 */
router.post('/reset-database', (req, res) => {
  const data = db.resetToInitial();
  authService.clearPhantomLockouts();
  auditService.log(req, {
    action: 'DATABASE_RESET',
    success: true,
    description: `Reset bazy do ${data.users.length} kont początkowych przez publiczny endpoint (bez uwierzytelnienia).`
  });
  res.json({
    success: true,
    message: 'Baza danych została zresetowana do 6 użytkowników początkowych.',
    usersCount: data.users.length
  });
});

module.exports = router;

