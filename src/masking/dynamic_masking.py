"""
Masquage dynamique des données (Dynamic Data Masking - DDM).

Applique un masquage contextuel en temps réel selon le rôle de l'utilisateur requêtant la BDD.
"""

from copy import deepcopy
from typing import Any, Dict
from src.access_control.rbac_abac import AccessControlPolicy, TCIMPermission, TCIMRole


class DynamicDataMasker:
    """Moteur de masquage dynamique à l'affichage et à l'exportation."""

    @staticmethod
    def mask_string(val: str, prefix_len: int = 1) -> str:
        """Masque une chaîne en gardant le premier caractère."""
        if not val:
            return "***"
        if len(val) <= prefix_len:
            return "***"
        return f"{val[:prefix_len]}{'*' * min(len(val) - prefix_len, 6)}"

    @classmethod
    def apply_masking(cls, record: Dict[str, Any], role: TCIMRole) -> Dict[str, Any]:
        """Applique les règles de masquage selon les permissions associées au rôle."""
        has_unmask_perm = AccessControlPolicy.has_permission(role, TCIMPermission.READ_UNMASKED_PII)
        if has_unmask_perm:
            return deepcopy(record)

        result = deepcopy(record)
        pii_fields = ["patient_name", "full_name", "first_name", "last_name", "email", "phone", "ssn", "address"]

        for key in list(result.keys()):
            if key in pii_fields and isinstance(result[key], str):
                result[key] = cls.mask_string(result[key])

        return result
