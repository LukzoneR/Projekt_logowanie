// Konfiguracja domyślna systemu (Wariant 5)
module.exports = {
  PORT: process.env.PORT || 3000,
  RECAPTCHA_SITE_KEY: process.env.RECAPTCHA_SITE_KEY || '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
  RECAPTCHA_SECRET_KEY: process.env.RECAPTCHA_SECRET_KEY || '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
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
    oneTimePasswordValidityHours: 24,
    // Limit błędnych logowań (konfigurowalny przez admina, 0 = wyłączony)
    maxFailedLoginAttempts: 5,
    // Czas czasowej blokady konta po przekroczeniu limitu (stałe 15 minut)
    lockoutDurationMinutes: 15
  }
};
