#!/usr/bin/env python3
"""OpenClaw Shield - Security layer for message screening.

This module provides a unified interface for detecting potential prompt
injection attacks, including homoglyph substitution, non-Latin scripts,
and suspicious content patterns.

Usage:
    python shield.py check --message "Hello world"
    python shield.py check --message "你好" --json
    echo "Hello" | python shield.py check
    python shield.py stats

Ported from openclaw-shield.js
"""

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from typing import Optional

from script_detector import (
    detect_non_latin_script,
    normalize_homoglyphs,
    has_homoglyph_substitution,
)
from pre_screener import screen_for_suspicion


# Default dangerous keywords to detect
DEFAULT_DANGEROUS_KEYWORDS = [
    "ignore all",
    "ignore previous",
    "ignore prior",
    "ignore your instructions",
    "ignore the above",
    "ignore everything",
    "reveal system",
    "reveal prompt",
    "reveal instructions",
    "override instructions",
    "bypass filter",
    "bypass safety",
    "admin access",
    "sudo",
    "execute",
    "eval",
    "inject",
]


@dataclass
class CheckResult:
    """Result of checking a message for security issues."""
    allowed: bool
    reason: Optional[str]
    has_non_latin: bool
    detected_scripts: list[str]
    homoglyphs_detected: bool
    pre_screen_result: Optional[dict]
    original_message: str
    checked_text: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


def clean_text(text: str) -> tuple[str, str]:
    """Clean and normalize text for keyword matching.
    
    Args:
        text: The text to clean.
        
    Returns:
        Tuple of (collapsed, despaced) text variants.
    """
    collapsed = " ".join(text.lower().split())
    despaced = "".join(text.lower().split())
    return collapsed, despaced


def contains_dangerous_keywords(
    text: str, 
    keywords: Optional[list[str]] = None
) -> bool:
    """Check if text contains dangerous injection keywords.
    
    Args:
        text: The text to check.
        keywords: List of keywords to detect (uses defaults if None).
        
    Returns:
        True if any dangerous keywords found.
    """
    if keywords is None:
        keywords = DEFAULT_DANGEROUS_KEYWORDS
    
    collapsed, despaced = clean_text(text)
    
    for keyword in keywords:
        clean_keyword = keyword.lower()
        despaced_keyword = "".join(clean_keyword.split())
        
        if clean_keyword in collapsed or despaced_keyword in despaced:
            return True
    
    return False


def check_message(
    message: str,
    keywords: Optional[list[str]] = None,
    enable_logging: bool = True,
    detect_homoglyphs: bool = True,
) -> CheckResult:
    """Check a message for security issues.
    
    This is the main entry point for message screening. It performs:
    1. Homoglyph detection and normalization
    2. Non-Latin script detection
    3. Suspicious pattern pre-screening
    4. Dangerous keyword detection
    
    Args:
        message: The message to check.
        keywords: Custom dangerous keywords (uses defaults if None).
        enable_logging: Whether to log detection details.
        detect_homoglyphs: Whether to check for homoglyph substitution.
        
    Returns:
        CheckResult with security analysis.
    """
    result = CheckResult(
        allowed=True,
        reason=None,
        has_non_latin=False,
        detected_scripts=[],
        homoglyphs_detected=False,
        pre_screen_result=None,
        original_message=message,
        checked_text=message,
    )
    
    # Step 1: Check for homoglyph substitution
    if detect_homoglyphs and has_homoglyph_substitution(message):
        normalized = normalize_homoglyphs(message)
        result.homoglyphs_detected = True
        result.checked_text = normalized
        
        if enable_logging:
            print("[OpenClaw Shield] ⚠ Homoglyph substitution detected - normalizing", file=sys.stderr)
            print(f"[OpenClaw Shield]   Normalized: {normalized}", file=sys.stderr)
        
        # Check normalized text for dangerous keywords
        if contains_dangerous_keywords(normalized, keywords):
            result.allowed = False
            result.reason = "Dangerous keywords detected after homoglyph normalization"
            if enable_logging:
                print("[OpenClaw Shield] BLOCKED - Homoglyph-disguised keywords found", file=sys.stderr)
            return result
    
    # Step 2: Detect non-Latin scripts
    script_check = detect_non_latin_script(message)
    
    if not script_check["detected"]:
        if enable_logging:
            print("[OpenClaw Shield] Latin-only input - passed through", file=sys.stderr)
        return result
    
    result.has_non_latin = True
    result.detected_scripts = script_check["scripts"]
    
    # Step 3: Pre-screen for suspicious patterns
    pre_screen = screen_for_suspicion(message)
    result.pre_screen_result = pre_screen
    
    if enable_logging:
        print(
            f"[OpenClaw Shield] Non-Latin script detected: {', '.join(script_check['scripts'])} "
            f"| Pre-screen: {pre_screen['reason']} (~{pre_screen['token_estimate']} tokens)",
            file=sys.stderr
        )
    
    # Step 4: Decide based on pre-screen result
    if not pre_screen["suspicious"]:
        if enable_logging:
            print(f"[OpenClaw Shield] Pre-screen CLEARED - {pre_screen['details']}", file=sys.stderr)
        return result
    
    # Suspicious content detected - check for dangerous keywords
    if enable_logging:
        print(f"[OpenClaw Shield] Pre-screen FLAGGED - {pre_screen['details']}", file=sys.stderr)
    
    # Check for dangerous keywords in the message
    if contains_dangerous_keywords(message, keywords) or contains_dangerous_keywords(result.checked_text, keywords):
        result.allowed = False
        result.reason = f"Dangerous keywords detected in non-Latin message ({', '.join(script_check['scripts'])})"
        if enable_logging:
            print("[OpenClaw Shield] BLOCKED - Dangerous keywords in foreign script", file=sys.stderr)
        return result
    
    # Message has non-Latin content but no obvious attack patterns
    # Allow but flag for potential translation (future feature)
    if enable_logging:
        print(f"[OpenClaw Shield] Non-Latin message allowed - {pre_screen['reason']}", file=sys.stderr)
    
    return result


def get_stats() -> dict:
    """Get shield configuration statistics.
    
    Returns:
        Dictionary with shield stats.
    """
    return {
        "dangerous_keywords_count": len(DEFAULT_DANGEROUS_KEYWORDS),
        "scripts_monitored": 33,
        "homoglyph_detection_enabled": True,
        "pre_screen_enabled": True,
        "translation_support": "planned",
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="OpenClaw Shield - Security layer for message screening"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # check command
    check_parser = subparsers.add_parser("check", help="Check a message for security issues")
    check_parser.add_argument(
        "--message", "-m",
        help="Message to check (reads from stdin if not provided)"
    )
    check_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output result as JSON"
    )
    check_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress logging output"
    )
    
    # stats command
    subparsers.add_parser("stats", help="Show shield statistics")
    
    args = parser.parse_args()
    
    if args.command == "check":
        # Get message from args or stdin
        if args.message:
            message = args.message
        else:
            message = sys.stdin.read().strip()
        
        if not message:
            print("ERROR: No message provided", file=sys.stderr)
            sys.exit(1)
        
        # Check the message
        result = check_message(
            message,
            enable_logging=not args.quiet,
        )
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            # Simple text output
            if result.allowed:
                print("ALLOWED")
            else:
                print(f"BLOCKED: {result.reason}")
            
            if result.has_non_latin:
                print(f"Scripts: {', '.join(result.detected_scripts)}")
            if result.homoglyphs_detected:
                print("Homoglyphs: detected")
    
    elif args.command == "stats":
        print(json.dumps(get_stats(), indent=2))
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
