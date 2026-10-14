// Konfiguracja domyślna systemu (Wariant 5)
module.exports = {
  PORT: process.env.PORT || 3000,
  DEFAULT_CONFIG: {
    // Minimalna domyślna długość hasła (Wariant 5: min. 12 znaków)
    minPasswordLength: 12,
    // Dodatkowa reguła polityki haseł: Sprawdzanie w Have I Been Pwned (Wariant 5)
    checkHaveIBeenPwned: true,
    // Ważność hasła w dniach (konfigurowalna przez admina)
    passwordValidityDays: 90,
    // Czas bezczynności sesji w minutach (konfigurowalny przez admina)
    sessionInactivityTimeoutMinutes: 15,
    // Hasło jednorazowe: 14 znaków alfanumerycznych, ważne 24 h
    oneTimePasswordLength: 14,
    oneTimePasswordValidityHours: 24
  }
};
