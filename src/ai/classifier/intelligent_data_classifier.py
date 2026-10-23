"""
Moteur IA de Classification Intelligente des Données Médicales TCIM.

Analyse sémantique et catégorisation automatisée de la sensibilité
des formulations, herboristeries, prescriptions et fiches cliniques.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set


class DataSensitivityLevel(str, Enum):
    PUBLIC = "PUBLIC"                        # Botanique générale, remèdes en vente libre
    INTERNAL_RESEARCH = "INTERNAL_RESEARCH"  # Statistiques, essais observationnels, posologies
    CONFIDENTIAL_MEDICAL = "CONFIDENTIAL_MEDICAL"  # Fiche clinique patient, antécédents
    RESTRICTED_CRITICAL = "RESTRICTED_CRITICAL"    # Plantes toxiques réglementées, interactions létales, PII directes


@dataclass
class ClassificationReport:
    """Rapport généré par le classificateur IA."""

    sensitivity_level: DataSensitivityLevel
    confidence: float
    detected_pii: List[str] = field(default_factory=list)
    detected_risk_substances: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    required_encryption: bool = False
    requires_masking: bool = False


# Référentiel pharmacologique de surveillance (Pharmacovigilance & Plantes à risque)
HIGH_RISK_SUBSTANCES: Dict[str, str] = {
    "aconitum": "Aconit (Alcaloïde cardiotoxique puissant)",
    "digitalis": "Digitale pourpre (Glucosides cardiotoniques à marge thérapeutique étroite)",
    "belladonna": "Belladone (Alcaloïdes tropaniques / atropine)",
    "ephedra": "Éphédra (Alcaloïdes sympathomimétiques / risque cardio-vasculaire)",
    "aristolochia": "Aristoloche (Néphrotoxique et cancérogène avéré)",
    "colchicum": "Colchique (Mito-inhibiteur cytotoxique létal à faible dose)",
    "st_johns_wort": "Millepertuis (Inducteur enzymatique CYP3A4 / interactions médicamenteuses majeures)",
}


class TCIMDataClassifier:
    """Classificateur de données par règles expertes et traitement du langage naturel."""

    def __init__(self) -> None:
        self.email_regex = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
        self.phone_regex = re.compile(r"(?:\+33|0)[1-9](?:[\s.-]*\d{2}){4}")
        self.ssn_regex = re.compile(r"[12]\s*\d{2}\s*\d{2}\s*\d{2}\s*\d{3}\s*\d{3}")

    def classify_text(self, text: str) -> ClassificationReport:
        """Évalue le niveau de sensibilité du texte fourni."""
        lower_text = text.lower()
        detected_pii: List[str] = []
        detected_substances: List[str] = []
        reasons: List[str] = []

        # 1. Détection de PII
        if self.email_regex.search(text):
            detected_pii.append("Email")
        if self.phone_regex.search(text):
            detected_pii.append("Numéro de téléphone")
        if self.ssn_regex.search(text):
            detected_pii.append("Numéro de Sécurité Sociale (NIR)")

        # 2. Détection de termes cliniques et patients
        clinical_markers = ["patient", "diagnostic", "antécédent", "posologie personnalisée", "symptôme", "traitement en cours"]
        found_clinical = [m for m in clinical_markers if m in lower_text]

        # 3. Détection de substances toxiques ou réglementées
        for keyword, desc in HIGH_RISK_SUBSTANCES.items():
            if keyword in lower_text or keyword.replace("_", " ") in lower_text:
                detected_substances.append(desc)

        # 4. Détermination du niveau de sensibilité
        # A. Si substances létales/réglementées OU PII combinée à des données médicales
        if len(detected_substances) > 0 or (len(detected_pii) > 0 and len(found_clinical) > 0):
            level = DataSensitivityLevel.RESTRICTED_CRITICAL
            confidence = 0.96
            if detected_substances:
                reasons.append(f"Substance réglementée ou toxique détectée : {', '.join(detected_substances)}")
            if detected_pii:
                reasons.append(f"Données identifiantes de santé détectées : {', '.join(detected_pii)}")
            req_enc = True
            req_mask = True

        # B. Données cliniques patient sans substance critique
        elif len(found_clinical) > 0 or len(detected_pii) > 0:
            level = DataSensitivityLevel.CONFIDENTIAL_MEDICAL
            confidence = 0.90
            reasons.append("Présence d'informations cliniques individuelles.")
            req_enc = True
            req_mask = len(detected_pii) > 0

        # C. Données de recherche, études agrégées
        elif any(w in lower_text for w in ["cohorte", "posologie", "essai", "taux de réponse", "statistique", "in vitro"]):
            level = DataSensitivityLevel.INTERNAL_RESEARCH
            confidence = 0.85
            reasons.append("Données scientifiques ou résultats cliniques agrégés.")
            req_enc = False
            req_mask = False

        # D. Connaissances botaniques publiques
        else:
            level = DataSensitivityLevel.PUBLIC
            confidence = 0.80
            reasons.append("Informations botaniques et médicinales générales.")
            req_enc = False
            req_mask = False

        return ClassificationReport(
            sensitivity_level=level,
            confidence=confidence,
            detected_pii=detected_pii,
            detected_risk_substances=detected_substances,
            reasons=reasons,
            required_encryption=req_enc,
            requires_masking=req_mask,
        )
