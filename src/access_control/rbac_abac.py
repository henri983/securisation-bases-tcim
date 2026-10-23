"""
Contrôle d'accès basé sur les rôles et attributs (RBAC / ABAC) pour les bases de données TCIM.
"""

from enum import Enum
from typing import Dict, Set


class TCIMRole(str, Enum):
    ADMIN = "admin"
    PHYTOTHERAPEUTE = "phytotherapeute"
    CHERCHEUR = "chercheur"
    PATIENT = "patient"
    AUDITEUR_PHARMACOVIGILANCE = "auditeur_pharmacovigilance"


class TCIMPermission(str, Enum):
    READ_PUBLIC_BOTANY = "read_public_botany"
    READ_CLINICAL_RESEARCH = "read_clinical_research"
    READ_PATIENT_HISTORY = "read_patient_history"
    WRITE_PRESCRIPTION = "write_prescription"
    READ_UNMASKED_PII = "read_unmasked_pii"
    EXPORT_ANONYMIZED = "export_anonymized"
    VERIFY_AUDIT_TRAIL = "verify_audit_trail"
    MANAGE_SECURITY_POLICIES = "manage_security_policies"


ROLE_PERMISSIONS: Dict[TCIMRole, Set[TCIMPermission]] = {
    TCIMRole.ADMIN: {
        TCIMPermission.READ_PUBLIC_BOTANY,
        TCIMPermission.READ_CLINICAL_RESEARCH,
        TCIMPermission.VERIFY_AUDIT_TRAIL,
        TCIMPermission.MANAGE_SECURITY_POLICIES,
    },
    TCIMRole.PHYTOTHERAPEUTE: {
        TCIMPermission.READ_PUBLIC_BOTANY,
        TCIMPermission.READ_CLINICAL_RESEARCH,
        TCIMPermission.READ_PATIENT_HISTORY,
        TCIMPermission.WRITE_PRESCRIPTION,
        TCIMPermission.READ_UNMASKED_PII,
    },
    TCIMRole.CHERCHEUR: {
        TCIMPermission.READ_PUBLIC_BOTANY,
        TCIMPermission.READ_CLINICAL_RESEARCH,
        TCIMPermission.EXPORT_ANONYMIZED,
        # Interdit formellement : READ_UNMASKED_PII, READ_PATIENT_HISTORY nominatif
    },
    TCIMRole.PATIENT: {
        TCIMPermission.READ_PUBLIC_BOTANY,
        TCIMPermission.READ_PATIENT_HISTORY,
    },
    TCIMRole.AUDITEUR_PHARMACOVIGILANCE: {
        TCIMPermission.READ_PUBLIC_BOTANY,
        TCIMPermission.READ_CLINICAL_RESEARCH,
        TCIMPermission.VERIFY_AUDIT_TRAIL,
        TCIMPermission.EXPORT_ANONYMIZED,
    },
}


class AccessControlPolicy:
    """Moteur de vérification d'autorisations RBAC/ABAC."""

    @staticmethod
    def has_permission(role: TCIMRole, permission: TCIMPermission) -> bool:
        """Vérifie si un rôle possède une permission spécifique."""
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms

    @staticmethod
    def can_access_patient_record(
        requesting_user_id: str,
        requesting_role: TCIMRole,
        record_patient_id: str,
        treating_doctor_id: Optional[str] = None,
    ) -> bool:
        """Contrôle d'accès ABAC contextuel sur dossier patient."""
        # Le patient peut accéder uniquement à son propre dossier
        if requesting_role == TCIMRole.PATIENT:
            return requesting_user_id == record_patient_id

        # Le praticien accède s'il est le médecin traitant
        if requesting_role == TCIMRole.PHYTOTHERAPEUTE:
            return treating_doctor_id is None or requesting_user_id == treating_doctor_id

        # L'admin ou l'auditeur ne consulte pas les dossiers individuels nominatifs sans motif
        return False
