const bcrypt = require('bcryptjs');
const { ROLES } = require('../services/rbacService');

// 6 użytkowników testowych zgodnie z Wariantem 5
const RAW_TEST_USERS = [
  {
    id: 'usr_admin',
    username: 'admin',
    rawPassword: 'Admin12345678!',
    role: ROLES.ADMINISTRATOR,
    mustChangePassword: false,
    isBlocked: false,
    isPermanentAdmin: true,
    description: 'Stałe konto administratora (pełne uprawnienia)'
  },
  {
    id: 'usr_pracownik1',
    username: 'pracownik1',
    rawPassword: 'Prac1234Temp01', // 14 znaków alfanumerycznych
    role: ROLES.PRACOWNIK,
    mustChangePassword: true,
    isBlocked: false,
    isPermanentAdmin: false,
    description: 'Pracownik z hasłem jednorazowym (test pierwszego logowania)'
  },
  {
    id: 'usr_pracownik2',
    username: 'pracownik2',
    rawPassword: 'Pracownik2026!',
    role: ROLES.PRACOWNIK,
    mustChangePassword: false,
    isBlocked: false,
    isPermanentAdmin: false,
    description: 'Aktywny pracownik (standardowe konto)'
  },
  {
    id: 'usr_gosc1',
    username: 'gosc1',
    rawPassword: 'GoscHaslo2026!',
    role: ROLES.GOSC,
    mustChangePassword: false,
    isBlocked: false,
    isPermanentAdmin: false,
    description: 'Aktywny gość (podstawowe uprawnienia)'
  },
  {
    id: 'usr_gosc2',
    username: 'gosc2',
    rawPassword: 'GoscTemp123456', // 14 znaków alfanumerycznych
    role: ROLES.GOSC,
    mustChangePassword: true,
    isBlocked: false,
    isPermanentAdmin: false,
    description: 'Gość z hasłem jednorazowym (test pierwszego logowania)'
  },
  {
    id: 'usr_zablokowany',
    username: 'zablokowany',
    rawPassword: 'Zablokowane12!',
    role: ROLES.GOSC,
    mustChangePassword: false,
    isBlocked: true,
    isPermanentAdmin: false,
    description: 'Konto zablokowane (test blokady)'
  }
];

/**
 * Generuje początkową strukturę danych z haszami haseł (bcrypt)
 */
function getInitialSeedData() {
  const now = new Date().toISOString();
  const expires24h = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const users = RAW_TEST_USERS.map(u => {
    const passwordHash = bcrypt.hashSync(u.rawPassword, 10);
    return {
      id: u.id,
      username: u.username,
      passwordHash: passwordHash,
      // Historia haseł (wymóg: nowe hasło musi różnić się od poprzednich)
      passwordHistory: [passwordHash],
      role: u.role,
      mustChangePassword: u.mustChangePassword,
      temporaryPasswordExpiresAt: u.mustChangePassword ? expires24h : null,
      isBlocked: u.isBlocked,
      isPermanentAdmin: !!u.isPermanentAdmin,
      passwordChangedAt: now,
      createdAt: now
    };
  });

  return { users };
}

module.exports = {
  RAW_TEST_USERS,
  getInitialSeedData
};
