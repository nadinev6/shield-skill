const INJECTION_PHRASE_FRAGMENTS = [
  'ignore', 'bypass', 'override', 'disregard', 'forget', 'skip',
  'admin', 'root', 'sudo', 'system', 'prompt', 'instructions',
  'password', 'token', 'secret', 'execute', 'eval', 'inject', 'script',
  'previous', 'prior', 'above', 'following', 'below',
  'pretend', 'act as', 'roleplay', 'jailbreak', 'dan', 'developer mode',
  'new instructions', 'new task', 'new role', 'new persona',
  'instead', 'actually', 'really', 'true purpose', 'real task',
];

const EMBEDDED_LATIN_INJECTION_REGEX = new RegExp(
  '(' + INJECTION_PHRASE_FRAGMENTS.map(f => f.replace(/\s+/g, '[\\s\\p{L}]{0,3}')).join('|') + ')',
  'i'
);

const MIXED_SCRIPT_REGEX = /[\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF\u0600-\u06FF\u0590-\u05FF\u0900-\u097F\u0400-\u04FF\u0370-\u03FF\u0E00-\u0E7F]/;
const LATIN_WORD_REGEX = /[a-zA-Z]{3,}/;

const SUSPICIOUS_THRESHOLDS = {
  longMessageChars: 120,
  latinRatioInForeignText: 0.15,
  maxWordCountForShortMessage: 6,
};

const KNOWN_SAFE_SHORT_PATTERNS = [
  /^[\u4F60\u597D\u3053\u3093\uC548\uB155]{1,10}[\s\?\!\u3002\uFF01\uFF1F]*$/,
];

function estimateTokenCount(text) {
  const charCount = text.length;
  const wordCount = text.trim().split(/\s+/).length;
  return Math.ceil(Math.max(charCount / 4, wordCount * 1.3));
}

function getLatinRatio(text) {
  const latinChars = (text.match(/[a-zA-Z]/g) || []).length;
  return text.length > 0 ? latinChars / text.length : 0;
}

function hasEmbeddedLatinKeywords(text) {
  const latinWords = text.match(/[a-zA-Z]{3,}/g);
  if (!latinWords || latinWords.length === 0) return false;
  const joined = latinWords.join(' ').toLowerCase();
  return INJECTION_PHRASE_FRAGMENTS.some(phrase => joined.includes(phrase));
}

function hasMixedScripts(text) {
  return MIXED_SCRIPT_REGEX.test(text) && LATIN_WORD_REGEX.test(text);
}

function isLikelySafeShortMessage(text) {
  const wordCount = text.trim().split(/\s+/).length;
  if (wordCount > SUSPICIOUS_THRESHOLDS.maxWordCountForShortMessage) return false;
  return KNOWN_SAFE_SHORT_PATTERNS.some(pattern => pattern.test(text.trim()));
}

function screenForSuspicion(text) {
  const tokenEstimate = estimateTokenCount(text);
  const charCount = text.length;
  const latinRatio = getLatinRatio(text);

  if (hasEmbeddedLatinKeywords(text)) {
    return {
      suspicious: true,
      reason: 'embedded-latin-keywords',
      tokenEstimate,
      details: 'Latin injection keywords found embedded in foreign-script text',
    };
  }

  if (hasMixedScripts(text) && latinRatio > SUSPICIOUS_THRESHOLDS.latinRatioInForeignText) {
    return {
      suspicious: true,
      reason: 'mixed-script-high-latin',
      tokenEstimate,
      details: `Mixed scripts with ${Math.round(latinRatio * 100)}% Latin chars — possible obfuscated injection`,
    };
  }

  if (charCount >= SUSPICIOUS_THRESHOLDS.longMessageChars) {
    return {
      suspicious: true,
      reason: 'long-message',
      tokenEstimate,
      details: `Message length ${charCount} chars exceeds threshold — warrants translation scan`,
    };
  }

  if (isLikelySafeShortMessage(text)) {
    return {
      suspicious: false,
      reason: 'known-safe-short-pattern',
      tokenEstimate,
      details: 'Short greeting-style message matched safe pattern — skipping translation',
    };
  }

  return {
    suspicious: true,
    reason: 'unrecognised-foreign-content',
    tokenEstimate,
    details: 'Foreign content not matched to a known-safe pattern — translating to be safe',
  };
}

module.exports = {
  screenForSuspicion,
  estimateTokenCount,
  SUSPICIOUS_THRESHOLDS,
};
