// Konfiguracja domyślna systemu (Wariant 5)

// Publiczne klucze testowe Google: każdy token przechodzi weryfikację - tylko do developmentu
const RECAPTCHA_TEST_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
const RECAPTCHA_TEST_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

const RECAPTCHA_SITE_KEY = process.env.RECAPTCHA_SITE_KEY || RECAPTCHA_TEST_SITE_KEY;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY || RECAPTCHA_TEST_SECRET_KEY;

module.exports = {
  PORT: process.env.PORT || 3000,
  IS_PRODUCTION: process.env.NODE_ENV === 'production',
  RECAPTCHA_SITE_KEY,
  RECAPTCHA_SECRET_KEY,
  RECAPTCHA_USING_TEST_KEYS: RECAPTCHA_SITE_KEY === RECAPTCHA_TEST_SITE_KEY || RECAPTCHA_SECRET_KEY === RECAPTCHA_TEST_SECRET_KEY,
  CANARY_WEBHOOK_URL: process.env.CANARY_WEBHOOK_URL || '',
  DEFAULT_CONFIG: {
    // Minimalna domyślna długość hasła
    minPasswordLength: 12,
    // Dodatkowa reguła polityki haseł: Sprawdzanie w Have I Been Pwned 
    checkHaveIBeenPwned: true,
    // Ważność hasła w dniach 
    passwordValidityDays: 90,
    // Czas bezczynności sesji w minutach 
    sessionInactivityTimeoutMinutes: 15,
    // Hasło jednorazowe
    oneTimePasswordLength: 14,
    oneTimePasswordValidityHours: 24,
    // Limit błędnych logowań 
    maxFailedLoginAttempts: 5,
    // Czas czasowej blokady konta po przekroczeniu limitu 
    lockoutDurationMinutes: 15
  }
};
