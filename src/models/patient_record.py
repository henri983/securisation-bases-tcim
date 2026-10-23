"""
Modèles pour les dossiers patients et prescriptions TCIM.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class TCIMPrescription:
    """Prescription de médecine traditionnelle ou intégrative."""

    prescription_id: str
    patient_id: str
    doctor_id: str
    diagnosis_encrypted: bytes
    remedy_formula_encrypted: bytes
    dosage_instructions: str
    date: str
