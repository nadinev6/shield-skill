#!/usr/bin/env python3
"""Script detection and homoglyph normalization for OpenClaw Shield.

This module provides functions to detect non-Latin Unicode scripts and
normalize homoglyph substitutions that could be used for prompt injection attacks.

Ported from script-detector.js
"""

import re
from typing import TypedDict


class ScriptCheckResult(TypedDict):
    """Result of non-Latin script detection."""
    detected: bool
    scripts: list[str]


# 33 non-Latin script ranges with Unicode code point ranges
NON_LATIN_SCRIPTS = [
    {"name": "CJK Unified Ideographs", "range": r"[\u4E00-\u9FFF]"},
    {"name": "CJK Extension A", "range": r"[\u3400-\u4DBF]"},
    {"name": "CJK Compatibility", "range": r"[\uF900-\uFAFF]"},
    {"name": "Hiragana", "range": r"[\u3040-\u309F]"},
    {"name": "Katakana", "range": r"[\u30A0-\u30FF]"},
    {"name": "Hangul", "range": r"[\uAC00-\uD7AF]"},
    {"name": "Arabic", "range": r"[\u0600-\u06FF]"},
    {"name": "Arabic Supplement", "range": r"[\u0750-\u077F]"},
    {"name": "Arabic Extended", "range": r"[\u08A0-\u08FF]"},
    {"name": "Hebrew", "range": r"[\u0590-\u05FF]"},
    {"name": "Devanagari", "range": r"[\u0900-\u097F]"},
    {"name": "Bengali", "range": r"[\u0980-\u09FF]"},
    {"name": "Gujarati", "range": r"[\u0A80-\u0AFF]"},
    {"name": "Gurmukhi", "range": r"[\u0A00-\u0A7F]"},
    {"name": "Kannada", "range": r"[\u0C80-\u0CFF]"},
    {"name": "Malayalam", "range": r"[\u0D00-\u0D7F]"},
    {"name": "Oriya", "range": r"[\u0B00-\u0B7F]"},
    {"name": "Tamil", "range": r"[\u0B80-\u0BFF]"},
    {"name": "Telugu", "range": r"[\u0C00-\u0C7F]"},
    {"name": "Sinhala", "range": r"[\u0D80-\u0DFF]"},
    {"name": "Thai", "range": r"[\u0E00-\u0E7F]"},
    {"name": "Lao", "range": r"[\u0E80-\u0EFF]"},
    {"name": "Tibetan", "range": r"[\u0F00-\u0FFF]"},
    {"name": "Myanmar", "range": r"[\u1000-\u109F]"},
    {"name": "Georgian", "range": r"[\u10A0-\u10FF]"},
    {"name": "Ethiopic", "range": r"[\u1200-\u137F]"},
    {"name": "Khmer", "range": r"[\u1780-\u17FF]"},
    {"name": "Mongolian", "range": r"[\u1800-\u18AF]"},
    {"name": "Cyrillic", "range": r"[\u0400-\u04FF]"},
    {"name": "Cyrillic Supplement", "range": r"[\u0500-\u052F]"},
    {"name": "Greek", "range": r"[\u0370-\u03FF]"},
    {"name": "Coptic", "range": r"[\u2C80-\u2CFF]"},
    {"name": "Armenian", "range": r"[\u0530-\u058F]"},
]

# Build combined regex pattern for fast initial detection
_COMBINED_PATTERN = "|".join(script["range"] for script in NON_LATIN_SCRIPTS)
COMBINED_NON_LATIN_PATTERN = re.compile(_COMBINED_PATTERN)

# Pre-compile individual patterns for detailed detection
_COMPILED_SCRIPT_PATTERNS = [
    {"name": script["name"], "pattern": re.compile(script["range"])}
    for script in NON_LATIN_SCRIPTS
]

# Homoglyph map: Unicode confusable characters that look like Latin letters
# Keys are confusable chars, values are their Latin equivalents
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small ie
    "\u043E": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0445": "x",  # Cyrillic small ha
    "\u0443": "y",  # Cyrillic small u
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0454": "e",  # Cyrillic small ukrainian ie
    "\u0461": "o",  # Cyrillic small omega
    "\u04CF": "i",  # Cyrillic small palochka
    # Greek lookalikes
    "\u03B1": "a",  # Greek small alpha
    "\u03B5": "e",  # Greek small epsilon
    "\u03BF": "o",  # Greek small omicron
    "\u03C1": "p",  # Greek small rho
    "\u03BD": "v",  # Greek small nu
    "\u03C5": "u",  # Greek small upsilon
    "\u03C7": "x",  # Greek small chi
    "\u03B9": "i",  # Greek small iota
    # Fullwidth Latin
    "\uFF41": "a",  # Fullwidth small a
    "\uFF45": "e",  # Fullwidth small e
    "\uFF4F": "o",  # Fullwidth small o
    "\uFF49": "i",  # Fullwidth small i
    "\uFF55": "u",  # Fullwidth small u
    "\uFF53": "s",  # Fullwidth small s
    "\uFF54": "t",  # Fullwidth small t
    "\uFF4E": "n",  # Fullwidth small n
    # Subscript digits
    "\u2080": "0",  # Subscript 0
    "\u2081": "1",  # Subscript 1
    "\u2082": "2",  # Subscript 2
    # Accented characters (normalize to base letter)
    "\u00E0": "a",  # a grave
    "\u00E1": "a",  # a acute
    "\u00E2": "a",  # a circumflex
    "\u00E4": "a",  # a diaeresis
    "\u00E8": "e",  # e grave
    "\u00E9": "e",  # e acute
    "\u00EA": "e",  # e circumflex
    "\u00EB": "e",  # e diaeresis
    "\u00EC": "i",  # i grave
    "\u00ED": "i",  # i acute
    "\u00EE": "i",  # i circumflex
    "\u00EF": "i",  # i diaeresis
    "\u00F2": "o",  # o grave
    "\u00F3": "o",  # o acute
    "\u00F4": "o",  # o circumflex
    "\u00F6": "o",  # o diaeresis
    "\u00F9": "u",  # u grave
    "\u00FA": "u",  # u acute
    "\u00FB": "u",  # u circumflex
    "\u00FC": "u",  # u diaeresis
}

# Pre-compute set of homoglyph characters for fast lookup
_HOMOGLYPH_CHARS = set(HOMOGLYPH_MAP.keys())


def detect_non_latin_script(text: str) -> ScriptCheckResult:
    """Detect if text contains non-Latin Unicode scripts.
    
    Args:
        text: The text to analyze.
        
    Returns:
        A dict with:
        - detected: True if non-Latin scripts found
        - scripts: List of detected script names
    """
    if not COMBINED_NON_LATIN_PATTERN.search(text):
        return ScriptCheckResult(detected=False, scripts=[])
    
    detected_scripts = [
        script["name"]
        for script in _COMPILED_SCRIPT_PATTERNS
        if script["pattern"].search(text)
    ]
    
    return ScriptCheckResult(detected=True, scripts=detected_scripts)


def normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with their Latin equivalents.
    
    This helps detect attacks that use visually similar characters
    from different Unicode blocks to bypass keyword filters.
    
    Args:
        text: The text to normalize.
        
    Returns:
        Text with homoglyphs replaced by Latin equivalents.
    """
    return "".join(HOMOGLYPH_MAP.get(char, char) for char in text)


def has_homoglyph_substitution(text: str) -> bool:
    """Check if text contains any homoglyph characters.
    
    Args:
        text: The text to check.
        
    Returns:
        True if any homoglyph characters are present.
    """
    return any(char in _HOMOGLYPH_CHARS for char in text)


# Export list for module consumers
__all__ = [
    "NON_LATIN_SCRIPTS",
    "COMBINED_NON_LATIN_PATTERN",
    "HOMOGLYPH_MAP",
    "detect_non_latin_script",
    "normalize_homoglyphs",
    "has_homoglyph_substitution",
    "ScriptCheckResult",
]
