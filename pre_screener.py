#!/usr/bin/env python3
"""Pre-screener for suspicious message content.

This module provides functions to estimate token counts and screen messages
for potential injection attack patterns before expensive translation operations.

Ported from pre-screener.js
"""

import re
from typing import TypedDict


class PreScreenResult(TypedDict):
    """Result of pre-screening a message."""
    suspicious: bool
    reason: str
    token_estimate: int
    details: str


# Injection attack phrase fragments to detect
INJECTION_PHRASE_FRAGMENTS = [
    "ignore all", "ignore previous", "ignore prior", "ignore your instructions",
    "ignore the above", "ignore everything",
    "bypass", "override", "disregard",
    "admin access", "root", "sudo", "system prompt", "override instructions",
    "password", "token", "secret", "execute", "eval", "inject", "script",
    "previous", "prior", "above", "following", "below",
    "pretend", "act as", "roleplay", "jailbreak", "dan", "developer mode",
    "new instructions", "new task", "new role", "new persona",
    "instead", "actually", "really", "true purpose", "real task",
]

# Build regex for embedded Latin injection keywords
# This matches injection phrases with optional spacing/letters between words
_EMBEDDED_PATTERNS = "|".join(
    re.escape(phrase).replace(r"\ ", r"[\s\p{L}]{0,3}")
    for phrase in INJECTION_PHRASE_FRAGMENTS
)
# Note: Python re doesn't support \p{L}, so we use a simpler approach
_EMBEDDED_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(phrase) for phrase in INJECTION_PHRASE_FRAGMENTS) + r")\b",
    re.IGNORECASE
)

# Regex for detecting mixed scripts (non-Latin + Latin words)
MIXED_SCRIPT_REGEX = re.compile(
    r"[\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7AF\u0600-\u06FF"
    r"\u0590-\u05FF\u0900-\u097F\u0400-\u04FF\u0370-\u03FF\u0E00-\u0E7F]"
)
LATIN_WORD_REGEX = re.compile(r"[a-zA-Z]{3,}")

# Thresholds for suspicion detection
SUSPICIOUS_THRESHOLDS = {
    "long_message_chars": 120,
    "latin_ratio_in_foreign_text": 0.15,
    "max_word_count_for_short_message": 6,
}

# Known safe short message patterns (greetings)
# Matches common greetings in CJK languages
KNOWN_SAFE_SHORT_PATTERNS = [
    re.compile(r"^[\u4F60\u597D\u3053\u3093\uC548\uB155]{1,10}[\s\?\!\u3002\uFF01\uFF1F]*$"),
]


def estimate_token_count(text: str) -> int:
    """Estimate the token count for a message.
    
    Uses a simple heuristic: max of (chars/4) or (words * 1.3).
    
    Args:
        text: The text to estimate tokens for.
        
    Returns:
        Estimated token count.
    """
    char_count = len(text)
    word_count = len(text.strip().split()) if text.strip() else 0
    return int(max(char_count / 4, word_count * 1.3))


def get_latin_ratio(text: str) -> float:
    """Calculate the ratio of Latin characters in text.
    
    Args:
        text: The text to analyze.
        
    Returns:
        Ratio of Latin characters (0.0 to 1.0).
    """
    if not text:
        return 0.0
    latin_chars = sum(1 for char in text if char.isascii() and char.isalpha())
    return latin_chars / len(text)


def has_embedded_latin_keywords(text: str) -> bool:
    """Check if text contains embedded Latin injection keywords.
    
    Args:
        text: The text to check.
        
    Returns:
        True if injection keywords are found in Latin portions.
    """
    # Extract Latin words (3+ chars)
    latin_words = LATIN_WORD_REGEX.findall(text)
    if not latin_words:
        return False
    
    # Join and check for injection phrases
    joined = " ".join(latin_words).lower()
    return any(phrase in joined for phrase in INJECTION_PHRASE_FRAGMENTS)


def has_mixed_scripts(text: str) -> bool:
    """Check if text contains both non-Latin scripts and Latin words.
    
    Args:
        text: The text to check.
        
    Returns:
        True if both non-Latin and Latin content present.
    """
    return bool(MIXED_SCRIPT_REGEX.search(text)) and bool(LATIN_WORD_REGEX.search(text))


def is_likely_safe_short_message(text: str) -> bool:
    """Check if text matches known safe short message patterns.
    
    Args:
        text: The text to check.
        
    Returns:
        True if text matches a safe pattern.
    """
    word_count = len(text.strip().split())
    if word_count > SUSPICIOUS_THRESHOLDS["max_word_count_for_short_message"]:
        return False
    return any(pattern.match(text.strip()) for pattern in KNOWN_SAFE_SHORT_PATTERNS)


def screen_for_suspicion(text: str) -> PreScreenResult:
    """Screen a message for suspicious patterns.
    
    This function analyzes text for potential injection attack indicators
    to determine if translation/analysis is needed.
    
    Args:
        text: The message text to screen.
        
    Returns:
        PreScreenResult with:
        - suspicious: Whether the message needs further analysis
        - reason: Category of detection
        - token_estimate: Estimated token count
        - details: Human-readable explanation
    """
    token_estimate = estimate_token_count(text)
    char_count = len(text)
    latin_ratio = get_latin_ratio(text)
    
    # Check for embedded Latin injection keywords
    if has_embedded_latin_keywords(text):
        return PreScreenResult(
            suspicious=True,
            reason="embedded-latin-keywords",
            token_estimate=token_estimate,
            details="Latin injection keywords found embedded in foreign-script text",
        )
    
    # Check for mixed scripts with high Latin ratio
    if has_mixed_scripts(text) and latin_ratio > SUSPICIOUS_THRESHOLDS["latin_ratio_in_foreign_text"]:
        return PreScreenResult(
            suspicious=True,
            reason="mixed-script-high-latin",
            token_estimate=token_estimate,
            details=f"Mixed scripts with {int(latin_ratio * 100)}% Latin chars — possible obfuscated injection",
        )
    
    # Check for long messages
    if char_count >= SUSPICIOUS_THRESHOLDS["long_message_chars"]:
        return PreScreenResult(
            suspicious=True,
            reason="long-message",
            token_estimate=token_estimate,
            details=f"Message length {char_count} chars exceeds threshold — warrants translation scan",
        )
    
    # Check for known safe patterns
    if is_likely_safe_short_message(text):
        return PreScreenResult(
            suspicious=False,
            reason="known-safe-short-pattern",
            token_estimate=token_estimate,
            details="Short greeting-style message matched safe pattern — skipping translation",
        )
    
    # Default: treat unrecognised foreign content as suspicious
    return PreScreenResult(
        suspicious=True,
        reason="unrecognised-foreign-content",
        token_estimate=token_estimate,
        details="Foreign content not matched to a known-safe pattern — translating to be safe",
    )


__all__ = [
    "INJECTION_PHRASE_FRAGMENTS",
    "SUSPICIOUS_THRESHOLDS",
    "KNOWN_SAFE_SHORT_PATTERNS",
    "estimate_token_count",
    "get_latin_ratio",
    "has_embedded_latin_keywords",
    "has_mixed_scripts",
    "is_likely_safe_short_message",
    "screen_for_suspicion",
    "PreScreenResult",
]
