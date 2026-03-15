const NON_LATIN_SCRIPTS = [
  { name: 'CJK Unified Ideographs',    range: /[\u4E00-\u9FFF]/ },
  { name: 'CJK Extension A',           range: /[\u3400-\u4DBF]/ },
  { name: 'CJK Compatibility',         range: /[\uF900-\uFAFF]/ },
  { name: 'Hiragana',                  range: /[\u3040-\u309F]/ },
  { name: 'Katakana',                  range: /[\u30A0-\u30FF]/ },
  { name: 'Hangul',                    range: /[\uAC00-\uD7AF]/ },
  { name: 'Arabic',                    range: /[\u0600-\u06FF]/ },
  { name: 'Arabic Supplement',         range: /[\u0750-\u077F]/ },
  { name: 'Arabic Extended',           range: /[\u08A0-\u08FF]/ },
  { name: 'Hebrew',                    range: /[\u0590-\u05FF]/ },
  { name: 'Devanagari',                range: /[\u0900-\u097F]/ },
  { name: 'Bengali',                   range: /[\u0980-\u09FF]/ },
  { name: 'Gujarati',                  range: /[\u0A80-\u0AFF]/ },
  { name: 'Gurmukhi',                  range: /[\u0A00-\u0A7F]/ },
  { name: 'Kannada',                   range: /[\u0C80-\u0CFF]/ },
  { name: 'Malayalam',                 range: /[\u0D00-\u0D7F]/ },
  { name: 'Oriya',                     range: /[\u0B00-\u0B7F]/ },
  { name: 'Tamil',                     range: /[\u0B80-\u0BFF]/ },
  { name: 'Telugu',                    range: /[\u0C00-\u0C7F]/ },
  { name: 'Sinhala',                   range: /[\u0D80-\u0DFF]/ },
  { name: 'Thai',                      range: /[\u0E00-\u0E7F]/ },
  { name: 'Lao',                       range: /[\u0E80-\u0EFF]/ },
  { name: 'Tibetan',                   range: /[\u0F00-\u0FFF]/ },
  { name: 'Myanmar',                   range: /[\u1000-\u109F]/ },
  { name: 'Georgian',                  range: /[\u10A0-\u10FF]/ },
  { name: 'Ethiopic',                  range: /[\u1200-\u137F]/ },
  { name: 'Khmer',                     range: /[\u1780-\u17FF]/ },
  { name: 'Mongolian',                 range: /[\u1800-\u18AF]/ },
  { name: 'Cyrillic',                  range: /[\u0400-\u04FF]/ },
  { name: 'Cyrillic Supplement',       range: /[\u0500-\u052F]/ },
  { name: 'Greek',                     range: /[\u0370-\u03FF]/ },
  { name: 'Coptic',                    range: /[\u2C80-\u2CFF]/ },
  { name: 'Armenian',                  range: /[\u0530-\u058F]/ },
];

const COMBINED_NON_LATIN_REGEX = new RegExp(
  NON_LATIN_SCRIPTS.map(s => s.range.source).join('|')
);

const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'r',
  '\u0441': 'c', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i',
  '\u0454': 'e', '\u0461': 'o', '\u04CF': 'i',
  '\u03B1': 'a', '\u03B5': 'e', '\u03BF': 'o', '\u03C1': 'p',
  '\u03BD': 'v', '\u03C5': 'u', '\u03C7': 'x', '\u03B9': 'i',
  '\uFF41': 'a', '\uFF45': 'e', '\uFF4F': 'o', '\uFF49': 'i',
  '\uFF55': 'u', '\uFF53': 's', '\uFF54': 't', '\uFF4E': 'n',
  '\u2080': '0', '\u2081': '1', '\u2082': '2',
  '\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E4': 'a',
  '\u00E8': 'e', '\u00E9': 'e', '\u00EA': 'e', '\u00EB': 'e',
  '\u00EC': 'i', '\u00ED': 'i', '\u00EE': 'i', '\u00EF': 'i',
  '\u00F2': 'o', '\u00F3': 'o', '\u00F4': 'o', '\u00F6': 'o',
  '\u00F9': 'u', '\u00FA': 'u', '\u00FB': 'u', '\u00FC': 'u',
};

function detectNonLatinScript(text) {
  if (!COMBINED_NON_LATIN_REGEX.test(text)) {
    return { detected: false, scripts: [] };
  }

  const detectedScripts = NON_LATIN_SCRIPTS
    .filter(s => s.range.test(text))
    .map(s => s.name);

  return { detected: true, scripts: detectedScripts };
}

function normalizeHomoglyphs(text) {
  return text.split('').map(char => HOMOGLYPH_MAP[char] || char).join('');
}

function hasHomoglyphSubstitution(text) {
  return text.split('').some(char => HOMOGLYPH_MAP[char] !== undefined);
}

module.exports = {
  detectNonLatinScript,
  normalizeHomoglyphs,
  hasHomoglyphSubstitution,
  NON_LATIN_SCRIPTS,
};
