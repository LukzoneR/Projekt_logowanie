const express = require('express');
const router = express.Router();
const authService = require('../services/authService');
const canaryService = require('../services/canaryService');
const sessionService = require('../services/sessionService');
const sessionMiddleware = require('../middleware/sessionMiddleware');
const db = require('../data/database');
const { getRolePermissions } = require('../services/rbacService');
const { RAW_TEST_USERS } = require('../data/seedData');
const { RECAPTCHA_SITE_KEY } = require('../config/config');

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
    canaryService.handleHoneyAccountLogin(req, password);
  }

  // Pułapka na boty (honeypot): wypełnione ukryte pole oznacza bota.
  // Zwracamy ogólny komunikat, aby nie zdradzać mechanizmu wykrywania.
  if (typeof website === 'string' ? website.trim() !== '' : website != null) {
    console.warn(`Pułapka na boty: odrzucono próbę logowania (login: "${username}", IP: ${req.ip})`);
    return res.status(401).json({
      success: false,
      message: 'Login lub hasło niepoprawne'
    });
  }

  // Weryfikacja Google reCAPTCHA przy logowaniu
  const captchaCheck = await authService.verifyRecaptcha(recaptchaToken);
  if (!captchaCheck.success) {
    return res.status(400).json({
      success: false,
      message: captchaCheck.message
    });
  }

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Login lub hasło niepoprawne'
    });
  }

  const result = await authService.authenticateUser(username, password);

  if (!result.success) {
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
  const captchaCheck = await authService.verifyRecaptcha(recaptchaToken);
  if (!captchaCheck.success) {
    return res.status(400).json({
      success: false,
      errors: [captchaCheck.message]
    });
  }

  const isFirstLogin = req.user.mustChangePassword;

  const result = await authService.changePassword({
    userId: req.user.id,
    oldPassword,
    newPassword,
    confirmPassword,
    isFirstLogin
  });

  if (!result.success) {
    return res.status(400).json({
      success: false,
      errors: result.errors
    });
  }

  // Aktualizacja stanu sesji po pomyślnej zmianie hasła
  sessionService.updateSession(req.sessionId, { mustChangePassword: false });

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
  res.json({
    success: true,
    message: 'Baza danych została zresetowana do 6 użytkowników początkowych.',
    usersCount: data.users.length
  });
});

module.exports = router;

