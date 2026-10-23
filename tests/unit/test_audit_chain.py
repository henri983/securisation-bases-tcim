"""
Tests unitaires pour la chaîne d'audit inaltérable (Tamper-Evident Hash Chain).
"""

import pytest
from src.db.audit.tamper_evident_log import TamperEvidentAuditTrail


@pytest.mark.unit
def test_audit_chain_recording_and_genesis(audit_trail: TamperEvidentAuditTrail):
    """Vérifie que la première entrée se lie au bloc genesis et que les suivantes s'enchaînent."""
    entry0 = audit_trail.record_access("USER-1", "SELECT", "patient", "P-100", "payload_a")
    assert entry0.index == 0
    assert entry0.previous_hash == TamperEvidentAuditTrail.GENESIS_HASH
    assert len(entry0.entry_hash) == 64

    entry1 = audit_trail.record_access("USER-2", "UPDATE", "plant_formula", "F-200", "payload_b")
    assert entry1.index == 1
    assert entry1.previous_hash == entry0.entry_hash

    is_valid, corrupted_idx = audit_trail.verify_integrity()
    assert is_valid is True
    assert corrupted_idx is None


@pytest.mark.unit
def test_audit_chain_detects_data_tampering(audit_trail: TamperEvidentAuditTrail):
    """Vérifie qu'une modification discrète du contenu ou de l'action rompt la chaîne."""
    audit_trail.record_access("USER-1", "INSERT", "remedy", "R-1", "formula1")
    audit_trail.record_access("USER-2", "SELECT", "remedy", "R-1", "formula1")
    audit_trail.record_access("USER-3", "DELETE", "remedy", "R-1", "formula1")

    # Altération frauduleuse directe de l'action de l'index 1
    audit_trail.chain[1].action = "INSERT"

    is_valid, corrupted_idx = audit_trail.verify_integrity()
    assert is_valid is False
    assert corrupted_idx == 1, "La vérification doit identifier exactement le bloc corrompu."


@pytest.mark.unit
def test_audit_chain_detects_previous_hash_break(audit_trail: TamperEvidentAuditTrail):
    """Vérifie qu'une rupture du lien de chaînage (suppression de log) est immédiatement détectée."""
    audit_trail.record_access("U1", "SELECT", "doc", "D1")
    audit_trail.record_access("U2", "SELECT", "doc", "D2")
    audit_trail.record_access("U3", "SELECT", "doc", "D3")

    # Remplacer previous_hash de l'entrée 2
    audit_trail.chain[2].previous_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    is_valid, corrupted_idx = audit_trail.verify_integrity()
    assert is_valid is False
    assert corrupted_idx == 2
