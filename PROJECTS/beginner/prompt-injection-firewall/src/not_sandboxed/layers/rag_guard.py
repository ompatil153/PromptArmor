"""
rag_guard.py - RAG Poisoning and Indirect Prompt Injection Guard
"""
import re
from typing import ClassVar

from not_sandboxed.context import Context, Trust
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Finding, Severity

RULE_RAG_INJECTION = "rag.indirect_injection"
RULE_RAG_FORGED_DELIMITER = "rag.forged_delimiter"
RULE_RAG_IMPERATIVE_ANOMALY = "rag.imperative_anomaly"


class RagGuardLayer:
    name: str = "rag_guard"

    INJECTION_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|directives?|prompts?|rules?)\b", re.I),
        re.compile(r"\b(?:system\s+override|admin\s+override|developer\s+mode)\b", re.I),
        re.compile(r"\b(?:new\s+instruction|updated\s+directive|special\s+command)\s*:", re.I),
        re.compile(r"\b(?:you\s+must\s+(?:now\s+)?(?:act|behave|respond|pretend)\s+as)\b", re.I),
        re.compile(r"\b(?:do\s+not\s+reveal|keep\s+this\s+secret\s+from\s+the\s+user)\b", re.I),
    ]

    FORGED_DELIMITERS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"<\s*\|(?:im_start|im_end|endoftext)\|\s*>", re.I),
        re.compile(r"\[\s*/?(?:INST|SYS)\s*\]", re.I),
        re.compile(r"<\s*<\s*/?(?:SYS|SYSTEM)\s*>\s*>", re.I),
        re.compile(r"<<<\s*(?:SYSTEM|UNTRUSTED|END)[\s\->]", re.I),
    ]

    IMPERATIVE_KEYWORDS: ClassVar[set[str]] = {
        "ignore", "override", "execute", "must", "disregard", "bypass",
        "exfiltrate", "forward", "transmit", "delete", "reveal", "print",
    }

    def inspect(self, ctx: Context, policy: Policy) -> list[Finding]:
        findings: list[Finding] = []

        for idx, span in enumerate(ctx.spans):
            if span.trust is not Trust.DATA:
                continue

            channel = span.origin.channel if span.origin else "unknown"
            ref = span.origin.ref if span.origin else "unknown"
            text = span.text

            for pattern in self.INJECTION_PATTERNS:
                if match := pattern.search(text):
                    findings.append(
                        Finding(
                            layer=self.name,
                            rule=RULE_RAG_INJECTION,
                            severity=Severity.CRITICAL,
                            invariant=True,
                            span_index=idx,
                            evidence=f"Indirect injection in {channel}:{ref} -> '{match.group(0)}'",
                        )
                    )
                    break

            for pattern in self.FORGED_DELIMITERS:
                if match := pattern.search(text):
                    findings.append(
                        Finding(
                            layer=self.name,
                            rule=RULE_RAG_FORGED_DELIMITER,
                            severity=Severity.CRITICAL,
                            invariant=True,
                            span_index=idx,
                            evidence=f"Forged delimiter in {channel}:{ref} -> '{match.group(0)}'",
                        )
                    )
                    break

            words = re.findall(r"\b\w+\b", text.lower())
            if len(words) >= 5:
                command_count = sum(1 for w in words if w in self.IMPERATIVE_KEYWORDS)
                density = command_count / len(words)
                if density >= 0.20:
                    findings.append(
                        Finding(
                            layer=self.name,
                            rule=RULE_RAG_IMPERATIVE_ANOMALY,
                            severity=Severity.HIGH,
                            invariant=False,
                            span_index=idx,
                            evidence=f"High command verb density ({density:.1%}) in {channel}:{ref}",
                        )
                    )

        return findings