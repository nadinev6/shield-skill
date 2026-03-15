const { detectNonLatinScript, normalizeHomoglyphs, hasHomoglyphSubstitution } = require('./script-detector');
const { screenForSuspicion, estimateTokenCount, SUSPICIOUS_THRESHOLDS } = require('./pre-screener');

const DEFAULT_TOKEN_BUDGET = {
  windowMs: 60_000,
  maxTokensPerWindow: 10_000,
  maxTokensPerMessage: 500,
};

class TokenBudget {
  constructor(options = {}) {
    this.windowMs = options.windowMs ?? DEFAULT_TOKEN_BUDGET.windowMs;
    this.maxTokensPerWindow = options.maxTokensPerWindow ?? DEFAULT_TOKEN_BUDGET.maxTokensPerWindow;
    this.maxTokensPerMessage = options.maxTokensPerMessage ?? DEFAULT_TOKEN_BUDGET.maxTokensPerMessage;
    this._usage = [];
  }

  _pruneWindow() {
    const cutoff = Date.now() - this.windowMs;
    this._usage = this._usage.filter(entry => entry.ts > cutoff);
  }

  windowTotal() {
    this._pruneWindow();
    return this._usage.reduce((sum, e) => sum + e.tokens, 0);
  }

  canAfford(tokens) {
    if (tokens > this.maxTokensPerMessage) return false;
    return this.windowTotal() + tokens <= this.maxTokensPerWindow;
  }

  record(tokens) {
    this._usage.push({ ts: Date.now(), tokens });
  }

  getStats() {
    return {
      windowUsed: this.windowTotal(),
      windowLimit: this.maxTokensPerWindow,
      windowMs: this.windowMs,
      perMessageLimit: this.maxTokensPerMessage,
    };
  }
}

class OpenClawShieldLingo {
  constructor(lingoClient, options = {}) {
    if (!lingoClient) {
      throw new Error('Lingo.dev client is required for OpenClawShieldLingo');
    }

    this.lingoClient = lingoClient;
    this.dangerousKeywords = options.dangerousKeywords || [
      'ignore', 'system', 'password', 'prompt', 'instructions',
      'override', 'bypass', 'admin', 'root', 'sudo',
      'execute', 'eval', 'script', 'inject'
    ];
    this.enableLogging = options.enableLogging ?? true;
    this.targetLanguage = options.targetLanguage || 'en';
    this.detectHomoglyphs = options.detectHomoglyphs ?? true;
    this.tokenBudget = new TokenBudget(options.tokenBudget || {});
  }

  containsDangerousKeywords(text) {
    const lowerText = text.toLowerCase();
    return this.dangerousKeywords.some(keyword => {
      const regex = new RegExp('\\b' + keyword + '\\b', 'i');
      return regex.test(lowerText);
    });
  }

  async translateWithLingo(text) {
    try {
      const result = await this.lingoClient.localizeText({ text, targetLanguage: this.targetLanguage });
      return result.translatedText || result.text || text;
    } catch (error) {
      if (this.enableLogging) console.error('[OpenClaw Shield] Translation error:', error.message);
      throw new Error('Translation failed: ' + error.message);
    }
  }

  _log(msg) {
    if (this.enableLogging) console.log('[OpenClaw Shield] ' + msg);
  }

  async checkMessage(message) {
    const result = {
      allowed: true,
      reason: null,
      hasNonLatin: false,
      detectedScripts: [],
      homoglyphsDetected: false,
      translationUsed: false,
      preScreenResult: null,
      skippedTranslation: false,
      tokenBudgetExceeded: false,
      originalMessage: message,
      checkedText: message,
      translatedText: null,
    };

    if (this.detectHomoglyphs && hasHomoglyphSubstitution(message)) {
      const normalized = normalizeHomoglyphs(message);
      result.homoglyphsDetected = true;
      result.checkedText = normalized;
      this._log('Homoglyph substitution detected - normalizing');
      this._log('  Normalized: ' + normalized);
      if (this.containsDangerousKeywords(normalized)) {
        result.allowed = false;
        result.reason = 'Dangerous keywords detected after homoglyph normalization';
        this._log('BLOCKED - Homoglyph-disguised keywords found');
        return result;
      }
    }

    const scriptCheck = detectNonLatinScript(message);

    if (!scriptCheck.detected) {
      this._log('Latin-only input - passed through (no translation needed)');
      return result;
    }

    result.hasNonLatin = true;
    result.detectedScripts = scriptCheck.scripts;

    const preScreen = screenForSuspicion(message);
    result.preScreenResult = preScreen;

    this._log(
      'Non-Latin script detected: ' + scriptCheck.scripts.join(', ') +
      ' | Pre-screen: ' + preScreen.reason +
      ' (~' + preScreen.tokenEstimate + ' tokens)'
    );

    if (!preScreen.suspicious) {
      result.skippedTranslation = true;
      this._log('Pre-screen CLEARED - ' + preScreen.details + ' - skipping translation API call');
      return result;
    }

    this._log('Pre-screen FLAGGED - ' + preScreen.details);

    if (!this.tokenBudget.canAfford(preScreen.tokenEstimate)) {
      result.allowed = false;
      result.tokenBudgetExceeded = true;
      result.reason =
        'Token budget exceeded: ' +
        this.tokenBudget.windowTotal() + '/' + this.tokenBudget.maxTokensPerWindow +
        ' tokens used in current window. Message (~' + preScreen.tokenEstimate + ' tokens) blocked to prevent rate-limit cascade.';
      this._log('BLOCKED - ' + result.reason);
      return result;
    }

    try {
      const translatedText = await this.translateWithLingo(message);
      this.tokenBudget.record(preScreen.tokenEstimate);
      result.translatedText = translatedText;
      result.translationUsed = true;
      result.checkedText = translatedText;
      this._log('Translation received: ' + translatedText);

      if (this.containsDangerousKeywords(translatedText)) {
        result.allowed = false;
        result.reason = 'Malicious keywords detected in translated text';
        this._log('BLOCKED - Malicious keywords found in translation');
      } else {
        this._log('Translation is safe - message allowed');
      }
    } catch (error) {
      result.allowed = false;
      result.reason = 'Translation service error: ' + error.message;
      this._log('BLOCKED - Translation service failed');
    }

    return result;
  }

  getStats() {
    return {
      dangerousKeywordsCount: this.dangerousKeywords.length,
      loggingEnabled: this.enableLogging,
      targetLanguage: this.targetLanguage,
      homoglyphDetectionEnabled: this.detectHomoglyphs,
      lingoIntegration: true,
      scriptsMonitored: 33,
      tokenBudget: this.tokenBudget.getStats(),
      preScreenThresholds: SUSPICIOUS_THRESHOLDS,
    };
  }
}

module.exports = OpenClawShieldLingo;
