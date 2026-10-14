const crypto = require('crypto');

/**
 * Serwis zarządzania sesjami
 * Odpowiada za:
 * - tworzenie unikalnych sesji (kryptograficzny token)
 * - śledzenie czasu ostatniej aktywności (lastActivity)
 * - automatyczne wygaszanie sesji po okresie bezczynności
 * - unieważnianie sesji przy wylogowaniu lub zablokowaniu konta
 */
class SessionService {
  constructor() {
    // Mapa: sessionId -> sessionData
    this.sessions = new Map();
  }

  /**
   * Tworzy nową sesję dla zalogowanego użytkownika
   * @param {Object} user 
   * @returns {Object} sesja z wygenerowanym identyfikatorem
   */
  createSession(user) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const now = Date.now();

    const session = {
      id: sessionId,
      userId: user.id,
      username: user.username,
      role: user.role,
      mustChangePassword: !!user.mustChangePassword,
      createdAt: now,
      lastActivity: now
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  /**
   * Pobiera sesję i weryfikuje czas bezczynności
   * @param {string} sessionId 
   * @param {number} timeoutMinutes 
   * @returns {{ valid: boolean, session?: Object, expired?: boolean }}
   */
  getSession(sessionId, timeoutMinutes = 15) {
    if (!sessionId || !this.sessions.has(sessionId)) {
      return { valid: false, expired: false };
    }

    const session = this.sessions.get(sessionId);
    const now = Date.now();
    const timeoutMs = timeoutMinutes * 60 * 1000;

    // Sprawdzenie bezczynności
    if (now - session.lastActivity > timeoutMs) {
      this.sessions.delete(sessionId);
      return { valid: false, expired: true };
    }

    // Aktualizacja czasu ostatniej aktywności
    session.lastActivity = now;
    return { valid: true, session };
  }

  /**
   * Unieważnia (usuwa) pojedynczą sesję przy wylogowaniu
   * @param {string} sessionId 
   * @returns {boolean}
   */
  destroySession(sessionId) {
    if (!sessionId) return false;
    return this.sessions.delete(sessionId);
  }

  /**
   * Unieważnia wszystkie sesje danego użytkownika (np. przy blokadzie konta)
   * @param {string} userId 
   */
  destroyUserSessions(userId) {
    for (const [id, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        this.sessions.delete(id);
      }
    }
  }

  /**
   * Aktualizuje dane w sesji (np. po zmianie hasła)
   * @param {string} sessionId 
   * @param {Object} updates 
   */
  updateSession(sessionId, updates) {
    const session = this.sessions.get(sessionId);
    if (session) {
      Object.assign(session, updates);
    }
  }
}

const sessionService = new SessionService();
module.exports = sessionService;
