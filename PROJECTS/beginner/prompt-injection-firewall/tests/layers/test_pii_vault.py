"""
Tests for the Zero-Knowledge PII Token Vault Layer
"""

from not_sandboxed.context import Context, Origin, Trust
from not_sandboxed.layers.pii_vault import (
    PIIType,
    PIIVault,
    PIIVaultLayer,
    RULE_PII_DETECTED,
    RULE_PII_LEAK_PREVENTED,
    anonymize_context,
)
from not_sandboxed.policy import Policy
from not_sandboxed.verdict import Severity


def test_vault_tokenizes_and_masks_secrets():
    vault = PIIVault()
    raw_prompt = "User email is john@corp.com with key sk-abcdef1234567890abcdef12345."
    anon, entities = vault.tokenize(raw_prompt)

    assert "john@corp.com" not in anon
    assert "sk-abcdef1234567890abcdef12345" not in anon
    assert "<<VAULT:EMAIL:1>>" in anon
    assert "<<VAULT:API_KEY:1>>" in anon
    assert len(entities) == 2


def test_vault_rehydrates_safely():
    vault = PIIVault()
    raw_prompt = "Payment for SSN 999-00-1234 approved."
    anon, _ = vault.tokenize(raw_prompt)
    restored = vault.rehydrate(anon)

    assert restored == raw_prompt


def test_anonymize_context_preserves_trust_and_origin():
    origin = Origin(channel="ticket", ref="1001")
    ctx = (
        Context()
        .system("You are a banking assistant.")
        .user("My SSN is 123-45-6789")
        .data("Customer email is secret@bank.com", origin=origin)
    )

    anon_ctx, vault = anonymize_context(ctx)

    assert len(anon_ctx.spans) == 3
    assert anon_ctx.spans[1].text == "My SSN is <<VAULT:SSN:1>>"
    assert anon_ctx.spans[1].trust == Trust.USER
    assert anon_ctx.spans[2].trust == Trust.DATA
    assert anon_ctx.spans[2].origin == origin
    assert "<<VAULT:EMAIL:1>>" in anon_ctx.spans[2].text


def test_pii_vault_layer_detects_secrets():
    layer = PIIVaultLayer()
    ctx = Context().user("Contact me at admin@cyber.local with token sk-9876543210fedcba9876543210")
    policy = Policy()

    findings = layer.inspect(ctx, policy)
    assert len(findings) == 2
    assert all(f.rule == RULE_PII_DETECTED for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)


def test_pii_vault_blocks_raw_secret_exfiltration():
    vault = PIIVault()
    prompt = "Master key is sk-11223344556677889900aabbccdd"
    vault.tokenize(prompt)

    layer = PIIVaultLayer(vault=vault)
    # Attacker tries to leak the real raw key
    leak_attempt = "I found the key: sk-11223344556677889900aabbccdd"
    findings = layer.inspect_reply(leak_attempt)

    assert len(findings) == 1
    assert findings[0].rule == RULE_PII_LEAK_PREVENTED
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].invariant is True
