"""
Tests unitaires pour le contrôle d'accès RBAC/ABAC et le masquage dynamique DDM.
"""

import pytest
from src.access_control.rbac_abac import AccessControlPolicy, TCIMPermission, TCIMRole
from src.masking.dynamic_masking import DynamicDataMasker


@pytest.mark.unit
def test_phytotherapeute_permissions():
    """Le praticien phytothérapeute a accès aux PII démasquées et à la prescription."""
    role = TCIMRole.PHYTOTHERAPEUTE
    assert AccessControlPolicy.has_permission(role, TCIMPermission.READ_UNMASKED_PII)
    assert AccessControlPolicy.has_permission(role, TCIMPermission.WRITE_PRESCRIPTION)
    assert AccessControlPolicy.has_permission(role, TCIMPermission.READ_PATIENT_HISTORY)
    assert not AccessControlPolicy.has_permission(role, TCIMPermission.MANAGE_SECURITY_POLICIES)


@pytest.mark.unit
def test_chercheur_restricted_permissions():
    """Le chercheur a accès à la recherche clinique mais JAMAIS aux PII non masquées."""
    role = TCIMRole.CHERCHEUR
    assert AccessControlPolicy.has_permission(role, TCIMPermission.READ_CLINICAL_RESEARCH)
    assert AccessControlPolicy.has_permission(role, TCIMPermission.EXPORT_ANONYMIZED)
    assert not AccessControlPolicy.has_permission(role, TCIMPermission.READ_UNMASKED_PII)
    assert not AccessControlPolicy.has_permission(role, TCIMPermission.WRITE_PRESCRIPTION)


@pytest.mark.unit
def test_dynamic_masking_applied_for_researcher():
    """Le masquage dynamique masque les PII pour un chercheur."""
    raw_record = {
        "prescription_id": "RX-0001",
        "patient_name": "Jean Dupont",
        "email": "jean.dupont@sante.fr",
        "diagnosis": "Insomnie",
        "dosage": "1 gélule le soir",
    }

    masked = DynamicDataMasker.apply_masking(raw_record, TCIMRole.CHERCHEUR)

    assert masked["prescription_id"] == "RX-0001"
    assert masked["diagnosis"] == "Insomnie"
    assert masked["patient_name"] != "Jean Dupont"
    assert masked["patient_name"].startswith("J")
    assert "*" in masked["patient_name"]
    assert masked["email"].startswith("j")
    assert "*" in masked["email"]


@pytest.mark.unit
def test_dynamic_masking_bypass_for_authorized_doctor():
    """Le phytothérapeute habilité voit les données médicales nominatives en clair."""
    raw_record = {
        "prescription_id": "RX-0001",
        "patient_name": "Jean Dupont",
        "email": "jean.dupont@sante.fr",
        "diagnosis": "Insomnie",
    }

    unmasked = DynamicDataMasker.apply_masking(raw_record, TCIMRole.PHYTOTHERAPEUTE)

    assert unmasked["patient_name"] == "Jean Dupont"
    assert unmasked["email"] == "jean.dupont@sante.fr"
