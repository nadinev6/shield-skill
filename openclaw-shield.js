const { detectNonLatinScript, normalizeHomoglyphs, hasHomoglyphSubstitution } = require('./script-detector');

class OpenClawShield {
  constructor(options = {}) {
    this.dangerousKeywords = options.dangerousKeywords || [
      'ignore',
      'system',
      'password',
      'prompt',
      'instructions',
      'override',
      'bypass',
      'admin',
      'root',
      'sudo',
      'execute',
      'eval',
      'script',
      'inject'
    ];
    this.enableLogging = options.enableLogging ?? true;
    this.detectHomoglyphs = options.detectHomoglyphs ?? true;
  }

  containsDangerousKeywords(text) {
    const lowerText = text.toLowerCase();
    return this.dangerousKeywords.some(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'i');
      return regex.test(lowerText);
    });
  }

  async checkMessage(message) {
    const result = {
      allowed: true,
      reason: null,
      hasNonLatin: false,
      detectedScripts: [],
      homoglyphsDetected: false,
      translationUsed: false,
      originalMessage: message,
      checkedText: message
    };

    if (this.detectHomoglyphs && hasHomoglyphSubstitution(message)) {
      const normalized = normalizeHomoglyphs(message);
      result.homoglyphsDetected = true;
      result.checkedText = normalized;

      if (this.enableLogging) {
        console.log('[OpenClaw Shield] ⚠ Homoglyph substitution detected - normalizing');
        console.log('[OpenClaw Shield]   Normalized:', normalized);
      }

      if (this.containsDangerousKeywords(normalized)) {
        result.allowed = false;
        result.reason = 'Dangerous keywords detected after homoglyph normalization';
        if (this.enableLogging) {
          console.log('[OpenClaw Shield] BLOCKED - Homoglyph-disguised keywords found');
        }
        return result;
      }
    }

    const scriptCheck = detectNonLatinScript(message);

    if (!scriptCheck.detected) {
      if (this.enableLogging) {
        console.log('[OpenClaw Shield] Latin-only input - passed through');
      }
      return result;
    }

    result.hasNonLatin = true;
    result.detectedScripts = scriptCheck.scripts;

    if (this.enableLogging) {
      console.log(`[OpenClaw Shield] Non-Latin script detected: ${scriptCheck.scripts.join(', ')} - blocking without translation`);
    }

    result.allowed = false;
    result.reason = `Non-Latin script detected (${scriptCheck.scripts.join(', ')}). Translation service required for safety check.`;

    return result;
  }

  getStats() {
    return {
      dangerousKeywordsCount: this.dangerousKeywords.length,
      loggingEnabled: this.enableLogging,
      homoglyphDetectionEnabled: this.detectHomoglyphs,
      scriptsMonitored: 33
    };
  }
}

module.exports = OpenClawShield;
