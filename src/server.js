const express = require('express');
const path = require('path');
const config = require('./config/config');
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const resourceRoutes = require('./routes/resourceRoutes');
const db = require('./data/database');

const app = express();

// Parsowanie JSON
app.use(express.json());

// Obsługa plików statycznych (frontend)
app.use(express.static(path.join(__dirname, '..', 'public'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-cache');
  }
}));

// Trasy API
app.use('/api', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/resources', resourceRoutes);

// Fallback dla SPA - serwowanie index.html
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) {
    return res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  }
  next();
});

// Obsługa błędów
app.use((err, req, res, next) => {
  console.error('Błąd serwera:', err);
  res.status(500).json({
    error: 'SERVER_ERROR',
    message: err.message || 'Wystąpił wewnętrzny błąd serwera.'
  });
});

const PORT = config.PORT;
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`Aplikacja Uwierzytelniania i RBAC (Wariant 5)`);
  console.log(`Serwer działa pod adresem: http://localhost:${PORT}`);
  console.log(`====================================================`);
  console.log(`Konta testowe (6 użytkowników):`);
  console.log(`1. admin / Admin12345678! (Administrator - stałe konto)`);
  console.log(`2. pracownik1 / Prac1234Temp01 (Pracownik - pierwsze logowanie)`);
  console.log(`3. pracownik2 / Pracownik2026! (Pracownik - aktywne)`);
  console.log(`4. gosc1 / GoscHaslo2026! (Gość - aktywne)`);
  console.log(`5. gosc2 / GoscTemp123456 (Gość - pierwsze logowanie)`);
  console.log(`6. zablokowany / Zablokowane12! (Gość - zablokowane)`);
  console.log(`====================================================`);
});

module.exports = app;
