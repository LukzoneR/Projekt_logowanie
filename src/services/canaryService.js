const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { CANARY_WEBHOOK_URL } = require('../config/config');

/**
 * Canarytokens - przynęty, których jakiekolwiek użycie oznacza intruza.
 * Uprawniony użytkownik nigdy ich nie dotyka, więc każde wyzwolenie jest alertem
 * (brak fałszywych alarmów, w przeciwieństwie do klasycznej detekcji anomalii).
 */

const ALERTS_PATH = path.join(__dirname, '..', 'data', 'canary_alerts.json');
const MAX_STORED_ALERTS = 500;

const TOKEN_TYPES = {
  HONEY_ACCOUNT: 'Konto-pułapka',
  DB_DUMP: 'Zrzut bazy danych'
};

// Token 1: konto-pułapka. Celowo NIE istnieje w db.json - logowanie zawsze kończy się
// tym samym błędem co dla nieistniejącego loginu, ale każda próba wyzwala alert.
const HONEY_ACCOUNT = {
  tokenId: 'ct_honey_backup_admin',
  username: 'backup_admin',
  password: 'Bkp!Svc#2024-Restore',
  passwordHash: bcrypt.hashSync('Bkp!Svc#2024-Restore', 10)
};

// Token 2: fałszywy zrzut bazy wystawiony pod kuszącą ścieżką (wskazaną w robots.txt)
const DB_DUMP = {
  tokenId: 'ct_dbdump_20261028',
  directory: '/backup',
  fileName: 'db_backup_2026-10-28.sql'
};

function loadAlerts() {
  try {
    return JSON.parse(fs.readFileSync(ALERTS_PATH, 'utf-8'));
  } catch (e) {
    return [];
  }
}

function saveAlerts(alerts) {
  fs.writeFileSync(ALERTS_PATH, JSON.stringify(alerts.slice(-MAX_STORED_ALERTS), null, 2), 'utf-8');
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  return (forwarded ? String(forwarded).split(',')[0].trim() : req.ip) || 'nieznany';
}

async function sendWebhook(alert) {
  if (!CANARY_WEBHOOK_URL) return;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const text = `[CANARYTOKEN] ${alert.tokenType} (${alert.tokenId}) wyzwolony z IP ${alert.ip}: ${alert.description}`;
    await fetch(CANARY_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // "text" - Slack/Mattermost, "content" - Discord; pozostałe pola dla własnych odbiorników
      body: JSON.stringify({ text, content: text, alert }),
      signal: controller.signal
    });
    clearTimeout(timeout);
  } catch (err) {
    console.warn('Canarytokens: nie udało się wysłać webhooka:', err.message);
  }
}

/**
 * Rejestruje wyzwolenie tokenu: konsola + trwały zapis + opcjonalny webhook
 */
function triggerAlert({ tokenId, tokenType, severity, description, req, details = {} }) {
  const alert = {
    id: 'alr_' + crypto.randomBytes(6).toString('hex'),
    tokenId,
    tokenType,
    severity,
    description,
    triggeredAt: new Date().toISOString(),
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'] || 'brak',
    method: req.method,
    path: req.originalUrl,
    details
  };

  const alerts = loadAlerts();
  alerts.push(alert);
  saveAlerts(alerts);

  console.warn('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  console.warn(`ALERT CANARYTOKEN [${severity.toUpperCase()}] ${tokenType} (${tokenId})`);
  console.warn(`${description}`);
  console.warn(`IP: ${alert.ip} | UA: ${alert.userAgent} | ${alert.method} ${alert.path}`);
  console.warn('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');

  sendWebhook(alert);
  return alert;
}

function isHoneyAccount(username) {
  return typeof username === 'string' && username.trim().toLowerCase() === HONEY_ACCOUNT.username;
}

/**
 * Wywoływane przy każdej próbie logowania na konto-pułapkę.
 * Poprawne hasło oznacza, że atakujący posiada wykradzione dane (np. ze zrzutu bazy).
 */
function handleHoneyAccountLogin(req, password) {
  const passwordMatches = bcrypt.compareSync(password || '', HONEY_ACCOUNT.passwordHash);
  return triggerAlert({
    tokenId: HONEY_ACCOUNT.tokenId,
    tokenType: TOKEN_TYPES.HONEY_ACCOUNT,
    severity: passwordMatches ? 'krytyczny' : 'wysoki',
    description: passwordMatches
      ? `Logowanie na konto-pułapkę "${HONEY_ACCOUNT.username}" POPRAWNYM hasłem - dane z przynęty zostały wykradzione i użyte.`
      : `Próba logowania na konto-pułapkę "${HONEY_ACCOUNT.username}".`,
    req,
    details: { username: HONEY_ACCOUNT.username, passwordMatches }
  });
}

function handleDbDumpAccess(req) {
  return triggerAlert({
    tokenId: DB_DUMP.tokenId,
    tokenType: TOKEN_TYPES.DB_DUMP,
    severity: 'wysoki',
    description: `Pobrano fałszywy zrzut bazy "${DB_DUMP.fileName}".`,
    req,
    details: { fileName: DB_DUMP.fileName }
  });
}

/**
 * Treść przynęty: wiarygodnie wyglądający zrzut MySQL. Zawiera dane konta-pułapki,
 * więc atakujący, który go użyje, wyzwoli drugi alert. Pozostałe hashe są losowe.
 */
function buildDbDumpContent() {
  const fakeHash = () => '$2b$10$' + crypto.randomBytes(40).toString('base64').replace(/[^A-Za-z0-9./]/g, '').slice(0, 53);
  return `-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: 10.0.12.5    Database: auth_prod
-- ------------------------------------------------------
-- Server version	8.0.36-0ubuntu0.22.04.1
-- Dump ref: ${DB_DUMP.tokenId}

/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;

DROP TABLE IF EXISTS \`users\`;
CREATE TABLE \`users\` (
  \`id\` int NOT NULL AUTO_INCREMENT,
  \`username\` varchar(64) NOT NULL,
  \`password_hash\` varchar(255) NOT NULL,
  \`role\` varchar(32) NOT NULL,
  \`created_at\` datetime NOT NULL,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`username\` (\`username\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

LOCK TABLES \`users\` WRITE;
INSERT INTO \`users\` VALUES
(1,'admin','${fakeHash()}','Administrator','2024-01-15 09:12:44'),
(2,'k.nowak','${fakeHash()}','Pracownik','2024-03-02 11:40:03'),
(3,'m.wisniewska','${fakeHash()}','Pracownik','2024-05-20 08:05:19'),
(4,'${HONEY_ACCOUNT.username}','${HONEY_ACCOUNT.passwordHash}','Administrator','2024-06-01 02:00:00');
UNLOCK TABLES;

-- TODO(ops): konto serwisowe do odtwarzania kopii - usunąć po migracji!
-- login: ${HONEY_ACCOUNT.username}  haslo: ${HONEY_ACCOUNT.password}

/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
-- Dump completed on 2026-10-28  3:00:01
`;
}

function getTokensOverview() {
  return [
    {
      tokenId: HONEY_ACCOUNT.tokenId,
      tokenType: TOKEN_TYPES.HONEY_ACCOUNT,
      bait: `Login "${HONEY_ACCOUNT.username}" (dane w zrzucie bazy i komentarzu HTML strony logowania)`
    },
    {
      tokenId: DB_DUMP.tokenId,
      tokenType: TOKEN_TYPES.DB_DUMP,
      bait: `${DB_DUMP.directory}/${DB_DUMP.fileName} (wskazany w robots.txt)`
    }
  ];
}

function getAlerts() {
  return loadAlerts().slice().reverse();
}

function clearAlerts() {
  saveAlerts([]);
}

module.exports = {
  HONEY_ACCOUNT,
  DB_DUMP,
  isHoneyAccount,
  handleHoneyAccountLogin,
  handleDbDumpAccess,
  buildDbDumpContent,
  getTokensOverview,
  getAlerts,
  clearAlerts
};
