"""
Tests du module IA de Classification Intelligente des Données TCIM.
"""

import pytest
from src.ai.classifier.intelligent_data_classifier import (
    DataSensitivityLevel,
    TCIMDataClassifier,
)


@pytest.mark.unit
def test_public_botanical_classification(ai_classifier: TCIMDataClassifier):
    """Un extrait de flore publique est classifié comme PUBLIC."""
    text = "La Camomille romaine (Chamaemelum nobile) est une plante herbacée vivace de la famille des Astéracées."
    report = ai_classifier.classify_text(text)

    assert report.sensitivity_level == DataSensitivityLevel.PUBLIC
    assert report.confidence >= 0.8
    assert not report.required_encryption
    assert not report.requires_masking
    assert len(report.detected_pii) == 0


@pytest.mark.unit
def test_internal_research_classification(ai_classifier: TCIMDataClassifier):
    """Des données statistiques de cohorte ou in vitro sont classifiées comme INTERNAL_RESEARCH."""
    text = "Résultats de l'essai in vitro sur une cohorte de 50 échantillons pour mesurer le taux de réponse immunitaire."
    report = ai_classifier.classify_text(text)

    assert report.sensitivity_level == DataSensitivityLevel.INTERNAL_RESEARCH
    assert not report.requires_masking


@pytest.mark.unit
def test_confidential_medical_patient_data(ai_classifier: TCIMDataClassifier):
    """Un texte contenant des données cliniques de patient est classé CONFIDENTIAL_MEDICAL."""
    text = "Consultation du patient: antécédent d'hypertension artérielle et diagnostic de fatigue chronique."
    report = ai_classifier.classify_text(text)

    assert report.sensitivity_level == DataSensitivityLevel.CONFIDENTIAL_MEDICAL
    assert report.required_encryption is True


@pytest.mark.unit
def test_restricted_critical_substance_detection(ai_classifier: TCIMDataClassifier):
    """La présence d'une plante toxique réglementée (ex: Aconit) déclenche le niveau RESTRICTED_CRITICAL."""
    text = "Préparation spéciale contenant de l'Aconitum en teinture mère pour névralgie faciale."
    report = ai_classifier.classify_text(text)

    assert report.sensitivity_level == DataSensitivityLevel.RESTRICTED_CRITICAL
    assert report.required_encryption is True
    assert report.requires_masking is True
    assert any("Aconit" in sub for sub in report.detected_risk_substances)


@pytest.mark.unit
def test_restricted_critical_pii_with_clinical(ai_classifier: TCIMDataClassifier):
    """La détection d'une PII (email, téléphone) associée à des données cliniques élève le niveau à RESTRICTED_CRITICAL."""
    text = "Fiche patient Jean avec diagnostic d'asthme sévère, joignable à jean.dupont@test.fr"
    report = ai_classifier.classify_text(text)

    assert report.sensitivity_level == DataSensitivityLevel.RESTRICTED_CRITICAL
    assert "Email" in report.detected_pii
    assert report.required_encryption is True
    assert report.requires_masking is True
