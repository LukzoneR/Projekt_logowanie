const express = require('express');
const router = express.Router();
const sessionMiddleware = require('../middleware/sessionMiddleware');
const { requirePermission, requirePasswordChanged } = require('../middleware/rbacMiddleware');
const { PERMISSIONS } = require('../services/rbacService');

router.use(sessionMiddleware);
router.use(requirePasswordChanged);

/**
 * GET /api/employee/data
 * Strefa pracownika (wymaga uprawnienia employee:access)
 * Dostępne dla: Administrator, Pracownik
 */
router.get('/employee/data', requirePermission(PERMISSIONS.EMPLOYEE_ACCESS), (req, res) => {
  res.json({
    success: true,
    title: 'Strefa Pracownika',
    description: 'Dostęp wyłącznie dla ról: Administrator oraz Pracownik.',
    items: [
      { id: 1, title: 'Wewnętrzny grafik zmian', status: 'Zaktualizowany' },
      { id: 2, title: 'Dokumentacja procedur bezpieczeństwa', status: 'Wersja 2.4' },
      { id: 3, title: 'Raport zadań bieżącego sprintu', status: 'W toku' }
    ],
    userRole: req.user.role
  });
});

/**
 * GET /api/guest/data
 * Strefa gościa (wymaga uprawnienia guest:access)
 * Dostępne dla: Administrator, Pracownik, Gość
 */
router.get('/guest/data', requirePermission(PERMISSIONS.GUEST_ACCESS), (req, res) => {
  res.json({
    success: true,
    title: 'Strefa Gościa',
    description: 'Dostęp dla wszystkich uwierzytelnionych ról: Administrator, Pracownik, Gość.',
    announcements: [
      { date: '2026-10-14', text: 'Witamy w systemie weryfikacji tożsamości i uprawnień RBAC.' },
      { date: '2026-10-14', text: 'Projekt modułowy - baza dla modułów 2 i 3.' }
    ],
    userRole: req.user.role
  });
});

module.exports = router;
