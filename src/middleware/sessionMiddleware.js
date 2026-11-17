const sessionService = require('../services/sessionService');
const auditService = require('../services/auditService');
const db = require('../data/database');

function logAccessDenied(req, description, username) {
  auditService.log(req, {
    action: 'ACCESS_DENIED',
    success: false,
    username,
    description: `${description} Żądanie: ${req.method} ${req.originalUrl}`
  });
}

/**
 * Middleware weryfikacji sesji i bezczynności
 */
function sessionMiddleware(req, res, next) {
  let sessionId = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessionId = authHeader.substring(7).trim();
  } else if (req.headers['x-session-id']) {
    sessionId = req.headers['x-session-id'];
  }

  if (!sessionId) {
    logAccessDenied(req, 'Brak tokenu sesji.');
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Brak aktywnej sesji. Zaloguj się ponownie.'
    });
  }

  const config = db.getConfig();
  const sessionResult = sessionService.getSession(sessionId, config.sessionInactivityTimeoutMinutes);

  if (sessionResult.expired) {
    auditService.log(req, {
      action: 'LOGOUT',
      success: true,
      username: sessionResult.session.username,
      description: `Automatyczne wylogowanie - sesja wygasła po ${config.sessionInactivityTimeoutMinutes} min bezczynności.`
    });
    return res.status(401).json({
      error: 'SESSION_EXPIRED',
      message: 'Sesja wygasła z powodu bezczynności.'
    });
  }

  if (!sessionResult.valid || !sessionResult.session) {
    logAccessDenied(req, 'Nieprawidłowy lub unieważniony token sesji.');
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Nieprawidłowa lub unieważniona sesja.'
    });
  }

  // Pobranie aktualnego stanu użytkownika z bazy
  const user = db.getUserById(sessionResult.session.userId);
  if (!user || user.isBlocked) {
    sessionService.destroySession(sessionId);
    logAccessDenied(
      req,
      user ? 'Sesja zablokowanego konta została unieważniona.' : 'Sesja usuniętego konta została unieważniona.',
      sessionResult.session.username
    );
    return res.status(403).json({
      error: 'ACCOUNT_BLOCKED',
      message: 'Konto zostało zablokowane lub usunięte.'
    });
  }

  req.sessionId = sessionId;
  req.session = sessionResult.session;
  req.user = user;
  next();
}

module.exports = sessionMiddleware;
