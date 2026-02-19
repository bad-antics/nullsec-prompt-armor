"""
NullSec Prompt Armor — AI Security Toolkit

Two tools in one package:
  • prompt_armor.armor — Prompt injection detection and sanitization
  • prompt_armor.racer — AI race condition auditing

Usage:
    from prompt_armor import analyze, sanitize, ThreatLevel
    verdict = analyze("user input here")
    if verdict.threat_level != ThreatLevel.CLEAN:
        cleaned = sanitize("user input here")
"""

from prompt_armor.armor.engine import (
    analyze,
    sanitize,
    lexical_scan,
    structural_scan,
    entropy_scan,
    semantic_drift_scan,
    armor_guard,
    CanarySystem,
    ArmorVerdict,
    Finding,
    ThreatLevel,
    AttackVector,
)

__version__ = "1.0.0"

__all__ = [
    "analyze",
    "sanitize",
    "lexical_scan",
    "structural_scan",
    "entropy_scan",
    "semantic_drift_scan",
    "armor_guard",
    "CanarySystem",
    "ArmorVerdict",
    "Finding",
    "ThreatLevel",
    "AttackVector",
    "__version__",
]
