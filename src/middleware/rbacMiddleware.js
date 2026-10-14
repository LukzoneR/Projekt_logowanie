const { hasPermission } = require('../services/rbacService');

/**
 * Middleware autoryzacji RBAC na podstawie uprawnienia
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Wymagane uwierzytelnienie.'
      });
    }

    if (!hasPermission(req.user.role, permission)) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: `Brak uprawnienia (${permission}) dla roli: ${req.user.role}.`
      });
    }

    next();
  };
}

/**
 * Middleware wymuszający zmianę hasła przed dostępem do zasobów
 */
function requirePasswordChanged(req, res, next) {
  if (req.user && req.user.mustChangePassword) {
    return res.status(403).json({
      error: 'PASSWORD_CHANGE_REQUIRED',
      message: 'Wymagana zmiana hasła przy pierwszym logowaniu. Brak dostępu do pozostałych funkcji systemu.'
    });
  }
  next();
}

module.exports = {
  requirePermission,
  requirePasswordChanged
};
