"""
crescendo.py - Multi-Turn Crescendo Attack and Context Drift Circuit Breaker
"""
import re
from dataclasses import dataclass
from typing import ClassVar

from not_sandboxed.context import Context, Trust
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding, Severity

RULE_CIRCUIT_BREAKER_TRIPPED = "crescendo.circuit_breaker_tripped"
RULE_DRIFT_WARNING = "crescendo.drift_warning"


@dataclass
class SessionHistory:
    session_id: str
    turn_count: int = 0
    cumulative_risk: float = 0.0
    trip_threshold: float = 6.0

    def add_turn(self, turn_risk: float) -> bool:
        self.turn_count += 1
        self.cumulative_risk += turn_risk
        return self.cumulative_risk >= self.trip_threshold

    def reset(self) -> None:
        self.turn_count = 0
        self.cumulative_risk = 0.0


class MultiTurnDriftLayer:
    name: str = "crescendo"

    PROBING_PATTERNS: ClassVar[list[tuple[re.Pattern[str], float]]] = [
        (re.compile(r"\b(?:hypothetical(?:ly)?|purely\s+academic|fictional\s+scenario)\b", re.I), 1.0),
        (re.compile(r"\b(?:what\s+if|pretend|imagine|roleplay\s+as)\b", re.I), 1.0),
        (re.compile(r"\b(?:bypass|override|ignore|disregard|filter)\b", re.I), 2.5),
        (re.compile(r"\b(?:exploit\w*|vulnerabilit\w*|payload\w*|malware|hack\w*)\b", re.I), 1.0),
        (re.compile(r"\b(?:how\s+would\s+an\s+attacker|for\s+educational\s+purposes)\b", re.I), 1.0),
    ]

    def __init__(self, sessions: dict[str, SessionHistory] | None = None) -> None:
        self.sessions = sessions if sessions is not None else {}

    def get_or_create_session(self, session_id: str) -> SessionHistory:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionHistory(session_id=session_id)
        return self.sessions[session_id]

    def inspect(self, ctx: Context, policy: Policy, session_id: str = "default") -> list[Finding]:
        findings: list[Finding] = []

        session = self.get_or_create_session(session_id)
        turn_risk = 0.0
        matched_reasons: list[str] = []

        for span in ctx.spans:
            if span.trust is Trust.USER:
                for pattern, score in self.PROBING_PATTERNS:
                    if match := pattern.search(span.text):
                        turn_risk += score
                        matched_reasons.append(match.group(0))

        tripped = session.add_turn(turn_risk)
        if tripped:
            findings.append(
                Finding(
                    layer=self.name,
                    rule=RULE_CIRCUIT_BREAKER_TRIPPED,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    evidence=f"Crescendo attack detected across {session.turn_count} turns (cumulative risk {session.cumulative_risk:.1f}/{session.trip_threshold})",
                )
            )
        elif turn_risk > 0:
            reasons_str = ", ".join(matched_reasons)
            findings.append(
                Finding(
                    layer=self.name,
                    rule=RULE_DRIFT_WARNING,
                    severity=Severity.MEDIUM,
                    invariant=False,
                    evidence=f"Suspicious probing pattern detected: {reasons_str} (turn risk {turn_risk:.1f})",
                )
            )

        return findings