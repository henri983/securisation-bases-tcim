"""
Modèles pour la pharmacopée et formules traditionnelles.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PlantFormula:
    """Formule ou monographie de plante médicinale."""

    formula_id: str
    scientific_name: str
    common_name: str
    traditional_indications: List[str]
    contraindications: List[str]
    toxicity_alert: bool = False
    sensitivity_tag: str = "PUBLIC"
