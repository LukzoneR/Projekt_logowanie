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
  // Canarytokens: opcjonalny webhook (Slack/Discord/własny), na który wysyłane są alerty
  CANARY_WEBHOOK_URL: process.env.CANARY_WEBHOOK_URL || '',
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
