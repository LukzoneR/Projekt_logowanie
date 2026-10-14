const express = require('express');
const router = express.Router();
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const sessionMiddleware = require('../middleware/sessionMiddleware');
const db = require('../data/database');
const { getRolePermissions } = require('../services/rbacService');
const { RAW_TEST_USERS } = require('../data/seedData');

/**
 * POST /api/login
 * Logowanie użytkownika
 * Zabezpieczone: jednakowy komunikat błędu "Login lub hasło niepoprawne"
 */
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Login lub hasło niepoprawne'
    });
  }

  const result = await authService.authenticateUser(username, password);

  if (!result.success) {
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
 * Wylogowanie ręczne - natychmiastowe unieważnienie sesji
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
 * Zmiana hasła (zarówno przy pierwszym logowaniu, jak i regularna zmiana)
 */
router.post('/change-password', sessionMiddleware, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
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
 * Informacja o 6 kontach testowych i wariancie (ściągawka ułatwiająca testowanie)
 */
router.get('/test-accounts', (req, res) => {
  res.json({
    variant: 5,
    rules: {
      minPasswordLength: 12,
      checkHaveIBeenPwned: 'Sprawdzanie w bazie wycieków HIBP (k-anonimowość SHA-1)',
      roles: ['Administrator', 'Pracownik', 'Gość'],
      oneTimePassword: '14 znaków alfanumerycznych, ważne 24 h'
    },
    accounts: RAW_TEST_USERS.map(u => ({
      username: u.username,
      password: u.rawPassword,
      role: u.role,
      mustChangePassword: u.mustChangePassword,
      isBlocked: u.isBlocked,
      description: u.description
    }))
  });
});

module.exports = router;
