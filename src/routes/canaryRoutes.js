const express = require('express');
const router = express.Router();
const canaryService = require('../services/canaryService');
const auditService = require('../services/auditService');

const { directory, fileName } = canaryService.DB_DUMP;

/**
 * GET /backup/
 * Imitacja listingu katalogu serwera
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
 * Canarytoken: fałszywy zrzut bazy
 */
router.get(`${directory}/${fileName}`, (req, res) => {
  const alert = canaryService.handleDbDumpAccess(req);
  auditService.log(req, {
    action: 'CANARY_DB_DUMP',
    success: false,
    description: `${alert.description} Alert ${alert.id}, waga: ${alert.severity}.`
  });
  // Wyświetlenie inline jako tekst
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', `inline; filename="${fileName}"`);
  res.type('text/plain').send(canaryService.buildDbDumpContent());
});

module.exports = router;
