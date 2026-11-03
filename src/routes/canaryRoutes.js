const express = require('express');
const router = express.Router();
const canaryService = require('../services/canaryService');

const { directory, fileName } = canaryService.DB_DUMP;

/**
 * GET /backup/
 * Imitacja listingu katalogu serwera (autoindex) - prowadzi do przynęty
 */
router.get(`${directory}/`, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(`<html>
<head><title>Index of ${directory}/</title></head>
<body>
<h1>Index of ${directory}/</h1><hr><pre><a href="../">../</a>
<a href="${fileName}">${fileName}</a>                    28-Oct-2026 03:00              48213
</pre><hr></body>
</html>`);
});

/**
 * GET /backup/db_backup_2026-10-28.sql
 * Canarytoken: fałszywy zrzut bazy - każde pobranie wyzwala alert
 */
router.get(`${directory}/${fileName}`, (req, res) => {
  canaryService.handleDbDumpAccess(req);
  // Wyświetlenie inline jako tekst: przeglądarki potrafią blokować pobieranie plików .sql,
  // a no-store gwarantuje, że każde otwarcie trafia do serwera i wyzwala alert
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', `inline; filename="${fileName}"`);
  res.type('text/plain').send(canaryService.buildDbDumpContent());
});

module.exports = router;
