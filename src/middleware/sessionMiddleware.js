const sessionService = require('../services/sessionService');
const db = require('../data/database');

/**
 * Middleware weryfikacji sesji i bezczynności
 */
function sessionMiddleware(req, res, next) {
  // Pobranie identyfikatora sesji z nagłówka Authorization lub x-session-id
  let sessionId = null;
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessionId = authHeader.substring(7).trim();
  } else if (req.headers['x-session-id']) {
    sessionId = req.headers['x-session-id'];
  }

  if (!sessionId) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Brak aktywnej sesji. Zaloguj się ponownie.'
    });
  }

  const config = db.getConfig();
  const sessionResult = sessionService.getSession(sessionId, config.sessionInactivityTimeoutMinutes);

  if (sessionResult.expired) {
    return res.status(401).json({
      error: 'SESSION_EXPIRED',
      message: 'Sesja wygasła z powodu bezczynności.'
    });
  }

  if (!sessionResult.valid || !sessionResult.session) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Nieprawidłowa lub unieważniona sesja.'
    });
  }

  // Pobranie aktualnego stanu użytkownika z bazy
  const user = db.getUserById(sessionResult.session.userId);
  if (!user || user.isBlocked) {
    sessionService.destroySession(sessionId);
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
