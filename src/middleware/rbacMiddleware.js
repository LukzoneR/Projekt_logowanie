const { hasPermission } = require('../services/rbacService');
const auditService = require('../services/auditService');

/**
 * Middleware autoryzacji RBAC na podstawie uprawnienia
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      auditService.log(req, {
        action: 'ACCESS_DENIED',
        success: false,
        description: `Brak uwierzytelnienia. Żądanie: ${req.method} ${req.originalUrl}`
      });
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Wymagane uwierzytelnienie.'
      });
    }

    if (!hasPermission(req.user.role, permission)) {
      auditService.log(req, {
        action: 'ACCESS_DENIED',
        success: false,
        description: `Brak uprawnienia ${permission} dla roli ${req.user.role}. Żądanie: ${req.method} ${req.originalUrl}`
      });
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
    auditService.log(req, {
      action: 'ACCESS_DENIED',
      success: false,
      description: `Wymagana zmiana hasła przed dostępem do zasobów. Żądanie: ${req.method} ${req.originalUrl}`
    });
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
