const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../data/database');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const sessionMiddleware = require('../middleware/sessionMiddleware');
const { requirePermission, requirePasswordChanged } = require('../middleware/rbacMiddleware');
const { PERMISSIONS, ROLES } = require('../services/rbacService');

// Wszystkie trasy w tym pliku wymagają uwierzytelnionej sesji oraz braku wymogu zmiany hasła
router.use(sessionMiddleware);
router.use(requirePasswordChanged);

/**
 * GET /api/admin/users
 * Lista użytkowników dla administratora (bez hashy haseł)
 */
router.get('/users', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const users = db.getUsers().map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    isBlocked: !!u.isBlocked,
    mustChangePassword: !!u.mustChangePassword,
    temporaryPasswordExpiresAt: u.temporaryPasswordExpiresAt,
    passwordChangedAt: u.passwordChangedAt,
    createdAt: u.createdAt,
    isPermanentAdmin: !!u.isPermanentAdmin
  }));

  res.json({ success: true, users });
});

/**
 * POST /api/admin/users
 * Dodanie nowego użytkownika przez administratora
 * Generuje hasło jednorazowe (14 znaków alfanumerycznych, ważne 24h)
 */
router.post('/users', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const { username, role } = req.body;

  if (!username || !username.trim()) {
    return res.status(400).json({ success: false, message: 'Nazwa użytkownika jest wymagana.' });
  }

  const validRoles = [ROLES.ADMINISTRATOR, ROLES.PRACOWNIK, ROLES.GOSC];
  if (!role || !validRoles.includes(role)) {
    return res.status(400).json({ success: false, message: 'Nieprawidłowa rola użytkownika.' });
  }

  // Sprawdzenie unikalności loginu
  const existing = db.getUserByUsername(username.trim());
  if (existing) {
    return res.status(400).json({ success: false, message: 'Użytkownik o takim loginie już istnieje.' });
  }

  // Generowanie hasła jednorazowego: 14 znaków alfanumerycznych, ważne 24h (Wariant 5)
  const tempPassword = authService.generateTemporaryPassword(14);
  const passwordHash = bcrypt.hashSync(tempPassword, 10);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const newUser = db.createUser({
    username: username.trim(),
    role,
    passwordHash,
    passwordHistory: [passwordHash],
    mustChangePassword: true,
    temporaryPasswordExpiresAt: expiresAt,
    isBlocked: false,
    isPermanentAdmin: false
  });

  res.status(201).json({
    success: true,
    message: 'Użytkownik został pomyślnie utworzony.',
    user: {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      mustChangePassword: newUser.mustChangePassword,
      temporaryPasswordExpiresAt: newUser.temporaryPasswordExpiresAt
    },
    // Hasło jednorazowe zwracane jest tylko raz administratorowi, aby mógł je przekazać
    temporaryPassword: tempPassword
  });
});

/**
 * PUT /api/admin/users/:id/role
 * Zmiana roli użytkownika
 */
router.put('/users/:id/role', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const { role } = req.body;
  const user = db.getUserById(req.params.id);

  if (!user) {
    return res.status(404).json({ success: false, message: 'Użytkownik nie istnieje.' });
  }

  if (user.isPermanentAdmin && role !== ROLES.ADMINISTRATOR) {
    return res.status(400).json({ success: false, message: 'Nie można zmienić roli stałego administratora.' });
  }

  const validRoles = [ROLES.ADMINISTRATOR, ROLES.PRACOWNIK, ROLES.GOSC];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ success: false, message: 'Nieprawidłowa rola.' });
  }

  const updated = db.updateUser(user.id, { role });
  res.json({ success: true, message: 'Rola została zaktualizowana.', user: { id: updated.id, username: updated.username, role: updated.role } });
});

/**
 * PUT /api/admin/users/:id/block
 * Zablokowanie lub odblokowanie użytkownika
 */
router.put('/users/:id/block', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return res.status(404).json({ success: false, message: 'Użytkownik nie istnieje.' });
  }

  if (user.isPermanentAdmin) {
    return res.status(400).json({ success: false, message: 'Nie można zablokować stałego konta administratora.' });
  }

  const newBlockState = !user.isBlocked;
  db.updateUser(user.id, { isBlocked: newBlockState });

  // Jeśli zablokowano, natychmiast usuwamy aktywne sesje użytkownika
  if (newBlockState) {
    sessionService.destroyUserSessions(user.id);
  }

  res.json({
    success: true,
    message: newBlockState ? 'Użytkownik został zablokowany.' : 'Użytkownik został odblokowany.',
    isBlocked: newBlockState
  });
});

/**
 * POST /api/admin/users/:id/reset-password
 * Reset hasła - nadanie nowego hasła jednorazowego (14 znaków, ważne 24h)
 */
router.post('/users/:id/reset-password', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return res.status(404).json({ success: false, message: 'Użytkownik nie istnieje.' });
  }

  const tempPassword = authService.generateTemporaryPassword(14);
  const passwordHash = bcrypt.hashSync(tempPassword, 10);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.updateUser(user.id, {
    passwordHash,
    mustChangePassword: true,
    temporaryPasswordExpiresAt: expiresAt
  });

  // Unieważnienie aktywnych sesji tego użytkownika
  sessionService.destroyUserSessions(user.id);

  res.json({
    success: true,
    message: 'Wygenerowano nowe hasło jednorazowe.',
    temporaryPassword: tempPassword,
    expiresAt
  });
});

/**
 * DELETE /api/admin/users/:id
 * Usunięcie użytkownika
 */
router.delete('/users/:id', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return res.status(404).json({ success: false, message: 'Użytkownik nie istnieje.' });
  }

  if (user.isPermanentAdmin) {
    return res.status(400).json({ success: false, message: 'Nie można usunąć stałego konta administratora.' });
  }

  sessionService.destroyUserSessions(user.id);
  db.deleteUser(user.id);

  res.json({ success: true, message: 'Użytkownik został pomyślnie usunięty.' });
});

/**
 * GET /api/admin/policy
 * Pobranie aktualnej konfiguracji polityki haseł i sesji
 */
router.get('/policy', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const config = db.getConfig();
  res.json({ success: true, config });
});

/**
 * PUT /api/admin/policy
 * Aktualizacja polityki haseł i sesji
 */
router.put('/policy', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const {
    minPasswordLength,
    checkHaveIBeenPwned,
    passwordValidityDays,
    sessionInactivityTimeoutMinutes
  } = req.body;

  const updates = {};

  if (typeof minPasswordLength === 'number' && minPasswordLength >= 6) {
    updates.minPasswordLength = minPasswordLength;
  }

  if (typeof checkHaveIBeenPwned === 'boolean') {
    updates.checkHaveIBeenPwned = checkHaveIBeenPwned;
  }

  if (typeof passwordValidityDays === 'number' && passwordValidityDays >= 0) {
    updates.passwordValidityDays = passwordValidityDays;
  }

  if (typeof sessionInactivityTimeoutMinutes === 'number' && sessionInactivityTimeoutMinutes >= 1) {
    updates.sessionInactivityTimeoutMinutes = sessionInactivityTimeoutMinutes;
  }

  const updatedConfig = db.updateConfig(updates);
  res.json({
    success: true,
    message: 'Polityka bezpieczeństwa została zaktualizowana.',
    config: updatedConfig
  });
});

/**
 * POST /api/admin/reset-database
 * Reset bazy do 6 początkowych użytkowników (do łatwych ponownych testów)
 */
router.post('/reset-database', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  const data = db.resetToInitial();
  res.json({
    success: true,
    message: 'Baza danych została zresetowana do 6 użytkowników początkowych.',
    usersCount: data.users.length
  });
});

module.exports = router;
