"""
cAngelaMos | 2026
pii_vault.py - Zero-Knowledge PII Token Vault Layer (OWASP LLM06)
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from not_sandboxed.context import Context, Span, Trust
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding, Severity

RULE_PII_DETECTED = "pii.secret_detected"
RULE_PII_LEAK_PREVENTED = "pii.leak_prevented"


class PIIType(StrEnum):
    API_KEY = "API_KEY"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"


@dataclass(frozen=True)
class PIIEntity:
    kind: PIIType
    raw_value: str
    token: str


class PIIVault:
    """
    Deterministic Token Vault for PII and sensitive credentials.
    Replaces sensitive data with ephemeral tokens before reaching the model.
    """

    PATTERNS: ClassVar[list[tuple[PIIType, re.Pattern[str]]]] = [
        (
            PIIType.API_KEY,
            re.compile(
                r"\b(?:sk-[a-zA-Z0-9]{20,}|gh[pousr]_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.]{20,})\b",
                re.IGNORECASE,
            ),
        ),
        (
            PIIType.SSN,
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ),
        (
            PIIType.CREDIT_CARD,
            re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
        ),
        (
            PIIType.EMAIL,
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"),
        ),
        (
            PIIType.PHONE,
            re.compile(r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"),
        ),
    ]

    def __init__(self) -> None:
        self._token_to_raw: dict[str, str] = {}
        self._raw_to_token: dict[str, str] = {}
        self._counters: dict[PIIType, int] = {t: 0 for t in PIIType}

    @property
    def entries(self) -> dict[str, str]:
        return dict(self._token_to_raw)

    def _generate_token(self, kind: PIIType) -> str:
        self._counters[kind] += 1
        return f"<<VAULT:{kind}:{self._counters[kind]}>>"

    def tokenize(self, text: str) -> tuple[str, list[PIIEntity]]:
        """
        Scan text, extract secrets, store in vault, and return
        anonymized text with surrogate tokens.
        """
        entities: list[PIIEntity] = []
        anonymized = text

        for kind, pattern in self.PATTERNS:
            matches = list(pattern.finditer(anonymized))
            for match in reversed(matches):
                raw = match.group(0)
                if raw in self._raw_to_token:
                    token = self._raw_to_token[raw]
                else:
                    token = self._generate_token(kind)
                    self._raw_to_token[raw] = token
                    self._token_to_raw[token] = raw

                entities.append(PIIEntity(kind=kind, raw_value=raw, token=token))
                start, end = match.span()
                anonymized = anonymized[:start] + token + anonymized[end:]

        return anonymized, entities

    def rehydrate(self, text: str) -> str:
        """
        Restore original values from surrogate tokens.
        """
        restored = text
        for token, raw in self._token_to_raw.items():
            restored = restored.replace(token, raw)
        return restored

    def detect_leakage(self, text: str) -> list[str]:
        """
        Check if any raw secret from the vault appears in text.
        """
        leaks: list[str] = []
        for raw in self._raw_to_token:
            if raw in text:
                leaks.append(raw)
        return leaks


class PIIVaultLayer:
    """
    Firewall inspection layer that intercepts sensitive PII and enforces
    zero-leakage invariants.
    """

    name: str = "pii_vault"

    def __init__(self, vault: PIIVault | None = None) -> None:
        self.vault = vault or PIIVault()

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []
        for idx, span in enumerate(ctx.spans):
            _, entities = self.vault.tokenize(span.text)
            for ent in entities:
                findings.append(
                    Finding(
                        layer=self.name,
                        rule=RULE_PII_DETECTED,
                        severity=Severity.HIGH,
                        invariant=False,
                        span_index=idx,
                        evidence=f"Detected sensitive {ent.kind.value} tokenized to {ent.token}",
                    )
                )
        return findings

    def inspect_reply(self, reply_text: str) -> list[Finding]:
        findings: list[Finding] = []
        leaks = self.vault.detect_leakage(reply_text)
        for leak in leaks:
            findings.append(
                Finding(
                    layer=self.name,
                    rule=RULE_PII_LEAK_PREVENTED,
                    severity=Severity.CRITICAL,
                    invariant=True,
                    evidence=f"Attempted exfiltration of vaulted secret: {leak[:6]}...",
                )
            )
        return findings


def anonymize_context(ctx: Context, vault: PIIVault | None = None) -> tuple[Context, PIIVault]:
    """
    Sanitize all spans in a context by replacing PII with surrogate tokens.
    """
    v = vault or PIIVault()
    new_spans: list[Span] = []
    for span in ctx.spans:
        anon_text, _ = v.tokenize(span.text)
        new_spans.append(Span(trust=span.trust, text=anon_text, origin=span.origin))
    return Context(spans=tuple(new_spans), nonce=ctx.nonce), v
