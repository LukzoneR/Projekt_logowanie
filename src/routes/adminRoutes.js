const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../data/database');
const authService = require('../services/authService');
const canaryService = require('../services/canaryService');
const sessionService = require('../services/sessionService');
const auditService = require('../services/auditService');
const sessionMiddleware = require('../middleware/sessionMiddleware');
const { requirePermission, requirePasswordChanged } = require('../middleware/rbacMiddleware');
const { PERMISSIONS, ROLES } = require('../services/rbacService');

router.use(sessionMiddleware);
router.use(requirePasswordChanged);

/**
 * Wysyła odpowiedź błędu i zapisuje nieudaną operację w dzienniku zdarzeń
 */
function failWithAudit(req, res, status, action, message, context = '') {
  auditService.log(req, {
    action,
    success: false,
    description: context ? `${context}: ${message}` : message
  });
  return res.status(status).json({ success: false, message });
}

/**
 * GET /api/admin/users
 * Lista użytkowników dla administratora
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
    isPermanentAdmin: !!u.isPermanentAdmin,
    failedLoginAttempts: u.failedLoginAttempts || 0,
    lockedUntil: u.lockedUntil && new Date(u.lockedUntil).getTime() > Date.now() ? u.lockedUntil : null
  }));

  res.json({ success: true, users });
});

/**
 * POST /api/admin/users
 * Dodanie nowego użytkownika przez administratora
 * Generuje hasło jednorazowe 
 */
router.post('/users', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const { username, role } = req.body;
  const context = `Tworzenie użytkownika "${typeof username === 'string' ? username.trim() : ''}"`;

  if (!username || !username.trim()) {
    return failWithAudit(req, res, 400, 'USER_CREATE', 'Nazwa użytkownika jest wymagana.', 'Tworzenie użytkownika');
  }

  const validRoles = [ROLES.ADMINISTRATOR, ROLES.PRACOWNIK, ROLES.GOSC];
  if (!role || !validRoles.includes(role)) {
    return failWithAudit(req, res, 400, 'USER_CREATE', 'Nieprawidłowa rola użytkownika.', context);
  }

  // Sprawdzenie unikalności loginu
  const existing = db.getUserByUsername(username.trim());
  if (existing || canaryService.isHoneyAccount(username)) {
    return failWithAudit(req, res, 400, 'USER_CREATE', 'Użytkownik o takim loginie już istnieje.', context);
  }

  // Generowanie hasła jednorazowego
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
    isPermanentAdmin: false,
    failedLoginAttempts: 0,
    lockedUntil: null
  });

  auditService.log(req, {
    action: 'USER_CREATE',
    success: true,
    description: `Utworzono użytkownika "${newUser.username}" z rolą ${newUser.role}; nadano hasło jednorazowe ważne 24 h.`
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
    return failWithAudit(req, res, 404, 'ROLE_CHANGE', 'Użytkownik nie istnieje.', `Zmiana roli (id: ${req.params.id})`);
  }

  const context = `Zmiana roli użytkownika "${user.username}" z ${user.role} na ${role}`;

  if (user.isPermanentAdmin && role !== ROLES.ADMINISTRATOR) {
    return failWithAudit(req, res, 400, 'ROLE_CHANGE', 'Nie można zmienić roli stałego administratora.', context);
  }

  const validRoles = [ROLES.ADMINISTRATOR, ROLES.PRACOWNIK, ROLES.GOSC];
  if (!validRoles.includes(role)) {
    return failWithAudit(req, res, 400, 'ROLE_CHANGE', 'Nieprawidłowa rola.', context);
  }

  const previousRole = user.role;
  const updated = db.updateUser(user.id, { role });
  auditService.log(req, {
    action: 'ROLE_CHANGE',
    success: true,
    description: `Zmieniono rolę użytkownika "${user.username}": ${previousRole} → ${updated.role}.`
  });
  res.json({ success: true, message: 'Rola została zaktualizowana.', user: { id: updated.id, username: updated.username, role: updated.role } });
});

/**
 * PUT /api/admin/users/:id/block
 * Zablokowanie lub odblokowanie użytkownika
 */
router.put('/users/:id/block', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return failWithAudit(req, res, 404, 'USER_BLOCK', 'Użytkownik nie istnieje.', `Zmiana blokady (id: ${req.params.id})`);
  }

  if (user.isPermanentAdmin) {
    return failWithAudit(req, res, 400, 'USER_BLOCK', 'Nie można zablokować stałego konta administratora.', `Blokowanie użytkownika "${user.username}"`);
  }

  const newBlockState = !user.isBlocked;
  const blockUpdates = { isBlocked: newBlockState };
  if (!newBlockState) {
    blockUpdates.failedLoginAttempts = 0;
    blockUpdates.lockedUntil = null;
  }
  db.updateUser(user.id, blockUpdates);

  if (newBlockState) {
    sessionService.destroyUserSessions(user.id);
  }

  auditService.log(req, {
    action: newBlockState ? 'USER_BLOCK' : 'USER_UNBLOCK',
    success: true,
    description: newBlockState
      ? `Zablokowano użytkownika "${user.username}"; jego aktywne sesje zostały unieważnione.`
      : `Odblokowano użytkownika "${user.username}"; wyzerowano licznik błędnych logowań.`
  });

  res.json({
    success: true,
    message: newBlockState ? 'Użytkownik został zablokowany.' : 'Użytkownik został odblokowany.',
    isBlocked: newBlockState
  });
});

/**
 * PUT /api/admin/users/:id/unlock
 * Zdjęcie czasowej blokady
 */
router.put('/users/:id/unlock', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return failWithAudit(req, res, 404, 'ACCOUNT_UNLOCK', 'Użytkownik nie istnieje.', `Zdjęcie blokady czasowej (id: ${req.params.id})`);
  }

  db.updateUser(user.id, { failedLoginAttempts: 0, lockedUntil: null });

  auditService.log(req, {
    action: 'ACCOUNT_UNLOCK',
    success: true,
    description: `Zdjęto czasową blokadę konta "${user.username}" przed jej wygaśnięciem.`
  });

  res.json({
    success: true,
    message: `Zdjęto czasową blokadę konta "${user.username}".`
  });
});

/**
 * POST /api/admin/users/:id/reset-password
 * Reset hasła - nadanie nowego hasła jednorazowego
 */
router.post('/users/:id/reset-password', requirePermission(PERMISSIONS.USERS_MANAGE), (req, res) => {
  const user = db.getUserById(req.params.id);

  if (!user) {
    return failWithAudit(req, res, 404, 'PASSWORD_RESET', 'Użytkownik nie istnieje.', `Reset hasła (id: ${req.params.id})`);
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

  auditService.log(req, {
    action: 'PASSWORD_RESET',
    success: true,
    description: `Nadano nowe hasło jednorazowe użytkownikowi "${user.username}" (ważne 24 h); jego sesje zostały unieważnione.`
  });

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
    return failWithAudit(req, res, 404, 'USER_DELETE', 'Użytkownik nie istnieje.', `Usuwanie użytkownika (id: ${req.params.id})`);
  }

  if (user.isPermanentAdmin) {
    return failWithAudit(req, res, 400, 'USER_DELETE', 'Nie można usunąć stałego konta administratora.', `Usuwanie użytkownika "${user.username}"`);
  }

  sessionService.destroyUserSessions(user.id);
  db.deleteUser(user.id);

  auditService.log(req, {
    action: 'USER_DELETE',
    success: true,
    description: `Usunięto użytkownika "${user.username}" (rola: ${user.role}).`
  });

  res.json({ success: true, message: 'Użytkownik został pomyślnie usunięty.' });
});

/**
 * GET /api/admin/policy
 * Pobranie aktualnej konfiguracji polityki haseł i sesji bezpieczeństwa
 */
router.get('/policy', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const config = db.getConfig();
  res.json({ success: true, config });
});

const POLICY_LABELS = {
  minPasswordLength: 'min. długość hasła',
  checkHaveIBeenPwned: 'sprawdzanie HIBP',
  passwordValidityDays: 'ważność hasła (dni)',
  sessionInactivityTimeoutMinutes: 'bezczynność sesji (min)',
  maxFailedLoginAttempts: 'limit błędnych logowań'
};

/**
 * PUT /api/admin/policy
 * Aktualizacja polityki haseł i sesji bezpieczeństwa
 */
router.put('/policy', requirePermission(PERMISSIONS.POLICY_MANAGE), (req, res) => {
  const {
    minPasswordLength,
    checkHaveIBeenPwned,
    passwordValidityDays,
    sessionInactivityTimeoutMinutes,
    maxFailedLoginAttempts
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

  // Limit błędnych logowań
  if (maxFailedLoginAttempts !== undefined) {
    if (!Number.isInteger(maxFailedLoginAttempts) || maxFailedLoginAttempts < 0 || maxFailedLoginAttempts > 20) {
      return failWithAudit(req, res, 400, 'SETTINGS_CHANGE', 'Limit błędnych logowań musi być liczbą całkowitą od 0-20.', 'Zmiana polityki bezpieczeństwa');
    }
    updates.maxFailedLoginAttempts = maxFailedLoginAttempts;
  }

  const previousConfig = db.getConfig();
  const updatedConfig = db.updateConfig(updates);

  const changes = Object.keys(updates)
    .filter(key => previousConfig[key] !== updates[key])
    .map(key => `${POLICY_LABELS[key] || key}: ${previousConfig[key]} → ${updates[key]}`);
  auditService.log(req, {
    action: 'SETTINGS_CHANGE',
    success: true,
    description: changes.length
      ? `Zmieniono politykę bezpieczeństwa: ${changes.join('; ')}.`
      : 'Zapisano politykę bezpieczeństwa bez zmian wartości.'
  });

  res.json({
    success: true,
    message: 'Polityka bezpieczeństwa została zaktualizowana.',
    config: updatedConfig
  });
});

function getAuditFilters(query) {
  const { action, result, user, q, from, to } = query;
  return { action, result, user, query: q, from, to };
}

/**
 * GET /api/admin/audit-log
 * Przeglądarka logów: dziennik zdarzeń z filtrowaniem i stronicowaniem
 * Parametry: action, result (sukces|błąd), user (dokładny login), q (użytkownik/IP/opis),
 * from, to (ISO), limit (1-1000), offset
 */
router.get('/audit-log', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 1000);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

  const { entries, total } = auditService.getEntries({ ...getAuditFilters(req.query), limit, offset });

  res.json({
    success: true,
    actions: auditService.ACTIONS,
    usernames: auditService.getUsernames(),
    total,
    offset,
    limit,
    entries,
    summary24h: auditService.getSummary(24)
  });
});

/**
 * GET /api/admin/audit-log/export
 * Eksport wszystkich wpisów spełniających filtry do pliku
 * Parametry: format (csv|json) oraz te same filtry co GET /api/admin/audit-log
 */
router.get('/audit-log/export', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  const format = req.query.format === 'json' ? 'json' : 'csv';
  const filters = getAuditFilters(req.query);
  const { entries } = auditService.getEntries({ ...filters, limit: null });
  const file = auditService.buildExport(entries, format);

  const activeFilters = Object.entries(filters)
    .filter(([, value]) => value)
    .map(([key, value]) => `${key}=${value}`);
  auditService.log(req, {
    action: 'AUDIT_EXPORT',
    success: true,
    description: `Eksport dziennika do pliku ${file.fileName}, liczba wpisów: ${entries.length}` +
      (activeFilters.length ? ` (filtry: ${activeFilters.join(', ')}).` : ' (bez filtrów).')
  });

  res.setHeader('Content-Type', file.mimeType);
  res.setHeader('Content-Disposition', `attachment; filename="${file.fileName}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(file.content);
});

/**
 * POST /api/admin/audit-log/verify
 * Weryfikacja integralności całego dziennika (SHA-256 pliku vs suma w osobnym pliku)
 */
router.post('/audit-log/verify', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  res.json({ success: true, verification: auditService.verifyIntegrity(req) });
});

/**
 * POST /api/admin/audit-log/integrity/acknowledge
 * Potwierdzenie wyjaśnionych incydentów integralności
 */
router.post('/audit-log/integrity/acknowledge', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  const count = auditService.acknowledgeIncidents(req);
  res.json({
    success: true,
    message: count ? `Potwierdzono incydenty integralności: ${count}.` : 'Brak niepotwierdzonych incydentów.'
  });
});

/**
 * GET /api/admin/canary-alerts
 * Lista aktywnych Canarytokens i zarejestrowanych alertów
 */
router.get('/canary-alerts', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  res.json({
    success: true,
    tokens: canaryService.getTokensOverview(),
    alerts: canaryService.getAlerts()
  });
});

/**
 * DELETE /api/admin/canary-alerts
 * Wyczyszczenie historii alertów
 */
router.delete('/canary-alerts', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  canaryService.clearAlerts();
  auditService.log(req, {
    action: 'SETTINGS_CHANGE',
    success: true,
    description: 'Wyczyszczono historię alertów Canarytokens.'
  });
  res.json({ success: true, message: 'Historia alertów Canarytokens została wyczyszczona.' });
});

/**
 * POST /api/admin/reset-database
 * Reset bazy do 6 początkowych użytkowników
 */
router.post('/reset-database', requirePermission(PERMISSIONS.ADMIN_ACCESS), (req, res) => {
  const data = db.resetToInitial();
  authService.clearPhantomLockouts();
  auditService.log(req, {
    action: 'DATABASE_RESET',
    success: true,
    description: `Reset bazy do ${data.users.length} kont początkowych (użytkownicy i polityka bezpieczeństwa).`
  });
  res.json({
    success: true,
    message: 'Baza danych została zresetowana do 6 użytkowników początkowych.',
    usersCount: data.users.length
  });
});

module.exports = router;
