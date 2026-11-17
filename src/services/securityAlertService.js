const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Alerty bezpieczeństwa - reguły detekcji oceniane po każdym wpisie dziennika zdarzeń.
 * Kanał alertu (wariant 5): osobny plik alertów.
 */

const ALERTS_FILE = 'security_alerts.json';
const ALERTS_PATH = path.join(__dirname, '..', 'data', ALERTS_FILE);
const ANONYMOUS = 'anonim';

function userSubject(entry) {
  return { key: `user:${String(entry.username).toLowerCase()}`, type: 'konto', value: entry.username };
}

const RULES = [
  {
    id: 'FAILED_LOGIN_BURST',
    name: '≥ 5 nieudanych logowań na jedno konto w ciągu 5 min',
    threshold: 5,
    windowMs: 5 * 60 * 1000,
    matches: e => e.action === 'LOGIN' && e.result === 'błąd' && String(e.username || '').trim() !== '' && e.username !== ANONYMOUS,
    subject: userSubject
  },
  {
    // Wariant 5. Odmowy bez zalogowanego użytkownika liczone są osobno dla każdego adresu IP,
    // aby różni anonimowi klienci nie sumowali się w jednego "użytkownika"
    id: 'ACCESS_DENIED_BURST',
    name: '≥ 3 odmowy dostępu dla jednego użytkownika w ciągu 10 min',
    threshold: 3,
    windowMs: 10 * 60 * 1000,
    matches: e => e.action === 'ACCESS_DENIED',
    subject: e => e.username === ANONYMOUS
      ? { key: `ip:${e.ip}`, type: 'adres IP (anonim)', value: e.ip }
      : { ...userSubject(e), type: 'użytkownik' }
  }
];

function loadAlerts() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ALERTS_PATH, 'utf-8'));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function sendToAlertFile(alert) {
  const alerts = loadAlerts();
  alerts.push(alert);
  fs.writeFileSync(ALERTS_PATH, JSON.stringify(alerts, null, 2), 'utf-8');
}

function buildAlert(rule, subject, matching, triggeredAt) {
  return {
    id: 'sec_' + crypto.randomBytes(6).toString('hex'),
    ruleId: rule.id,
    rule: rule.name,
    triggeredAt,
    subjectType: subject.type,
    subject: subject.value,
    subjectKey: subject.key,
    count: matching.length,
    threshold: rule.threshold,
    windowMinutes: rule.windowMs / 60000,
    firstAt: matching[0].timestamp,
    lastAt: matching[matching.length - 1].timestamp,
    ips: [...new Set(matching.map(e => e.ip))],
    events: matching.map(e => ({ id: e.id, timestamp: e.timestamp, ip: e.ip, description: e.description }))
  };
}

/**
 * Ocenia reguły dla nowego wpisu. Jeden alert na serię: kolejny dla tej samej reguły
 * i tego samego podmiotu dopiero po upływie okna od poprzedniego alertu.
 * @param {Object} entry - właśnie zapisany wpis
 * @param {Object[]} entries - cały dziennik (z nowym wpisem)
 * @returns {{ alert: Object, delivered: boolean, error: string|null }[]}
 */
function evaluate(entry, entries) {
  const results = [];
  const now = new Date(entry.timestamp).getTime();

  for (const rule of RULES.filter(r => r.matches(entry))) {
    const subject = rule.subject(entry);
    const matching = entries.filter(e => {
      if (!rule.matches(e) || rule.subject(e).key !== subject.key) return false;
      const ts = new Date(e.timestamp).getTime();
      return ts >= now - rule.windowMs && ts <= now;
    });
    if (matching.length < rule.threshold) continue;

    const alreadyAlerted = loadAlerts().some(a =>
      a.ruleId === rule.id && a.subjectKey === subject.key &&
      now - new Date(a.triggeredAt).getTime() < rule.windowMs
    );
    if (alreadyAlerted) continue;

    const alert = buildAlert(rule, subject, matching, entry.timestamp);
    let error = null;
    try {
      sendToAlertFile(alert);
    } catch (err) {
      error = err.message;
    }

    console.warn(`!!! ALERT BEZPIECZEŃSTWA: ${rule.name} | ${subject.type}: ${subject.value} | zdarzeń: ${alert.count}` +
      (error ? ` | BŁĄD zapisu do pliku alertów: ${error}` : ''));
    results.push({ alert, delivered: !error, error });
  }
  return results;
}

module.exports = {
  ALERTS_FILE,
  RULES,
  evaluate
};
