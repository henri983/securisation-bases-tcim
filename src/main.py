"""
Application FastAPI - Plateforme de Sécurisation des Bases TCIM et Classification IA.
"""

from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel, Field

from src.access_control.rbac_abac import (
    AccessControlPolicy,
    TCIMPermission,
    TCIMRole,
)
from src.ai.classifier.intelligent_data_classifier import (
    ClassificationReport,
    TCIMDataClassifier,
)
from src.config import Settings, get_settings
from src.db.audit.tamper_evident_log import TamperEvidentAuditTrail
from src.db.encryption.column_crypto import ColumnEncryptionEngine
from src.masking.dynamic_masking import DynamicDataMasker


class TextClassificationRequest(BaseModel):
    content: str = Field(..., examples=["Fiche posologie d'Aconitum napellus pour patient Jean Dupont"])


class CreatePrescriptionRequest(BaseModel):
    patient_id: str = Field(..., examples=["PAT-1001"])
    patient_name: str = Field(..., examples=["Marie Curie"])
    diagnosis: str = Field(..., examples=["Asthénie et troubles du sommeil"])
    remedy_formula: str = Field(..., examples=["Millepertuis 300mg + Passiflore 200mg"])
    dosage: str = Field(..., examples=["1 gélule le soir au coucher"])


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    current_settings = settings or get_settings()

    app = FastAPI(
        title="Plateforme Sécurisée des Bases de Données TCIM",
        description="Chiffrement granulaire, traçabilité inaltérable et classification intelligente IA sous RGPD",
        version="1.0.0",
    )

    # Initialisation des briques singletons
    crypto = ColumnEncryptionEngine(master_key_hex=current_settings.DATABASE_MASTER_KEY_HEX)
    audit = TamperEvidentAuditTrail()
    classifier = TCIMDataClassifier()

    # Stockage en mémoire simulant la table de BDD chiffrée
    db_prescriptions: Dict[str, Dict[str, Any]] = {}

    @app.get("/health", tags=["Monitoring"])
    async def health() -> dict:
        is_audit_valid, _ = audit.verify_integrity()
        return {
            "status": "healthy",
            "service": "securisation-bases-tcim",
            "audit_chain_valid": is_audit_valid,
            "stored_prescriptions": len(db_prescriptions),
        }

    @app.post("/api/v1/classify/text", tags=["Intelligence Artificielle"])
    async def classify_text(payload: TextClassificationRequest) -> dict:
        """Classifie intelligemment la sensibilité d'une donnée TCIM et détecte les risques."""
        report: ClassificationReport = classifier.classify_text(payload.content)
        return {
            "sensitivity_level": report.sensitivity_level.value,
            "confidence": report.confidence,
            "detected_pii": report.detected_pii,
            "detected_risk_substances": report.detected_risk_substances,
            "reasons": report.reasons,
            "required_encryption": report.required_encryption,
            "requires_masking": report.requires_masking,
        }

    @app.post(
        "/api/v1/records/prescriptions",
        status_code=status.HTTP_201_CREATED,
        tags=["Prescriptions Médicales"],
    )
    async def create_prescription(
        payload: CreatePrescriptionRequest,
        x_user_id: str = Header("DR-DEFAULT", alias="X-User-ID"),
        x_user_role: str = Header("phytotherapeute", alias="X-User-Role"),
    ) -> dict:
        """Enregistre une prescription avec chiffrement granulaire et traçabilité scellée."""
        try:
            role = TCIMRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur non valide.")

        if not AccessControlPolicy.has_permission(role, TCIMPermission.WRITE_PRESCRIPTION):
            raise HTTPException(status_code=403, detail="Privilèges insuffisants pour rédiger une prescription.")

        prescription_id = f"RX-{len(db_prescriptions) + 1:04d}"

        # 1. Chiffrement granulaire des colonnes sensibles
        diag_enc = crypto.encrypt_column("prescriptions", "diagnosis", payload.diagnosis)
        formula_enc = crypto.encrypt_column("prescriptions", "remedy_formula", payload.remedy_formula)
        name_enc = crypto.encrypt_column("prescriptions", "patient_name", payload.patient_name)
        blind_idx = crypto.generate_blind_index("prescriptions", "patient_id", payload.patient_id)

        # 2. Stockage chiffré
        db_prescriptions[prescription_id] = {
            "prescription_id": prescription_id,
            "patient_id_blind_index": blind_idx,
            "patient_id": payload.patient_id,
            "patient_name_encrypted": name_enc,
            "diagnosis_encrypted": diag_enc,
            "remedy_formula_encrypted": formula_enc,
            "dosage": payload.dosage,
            "doctor_id": x_user_id,
        }

        # 3. Scellement inaltérable dans la chaîne d'audit
        audit.record_access(
            user_id=x_user_id,
            action="INSERT",
            resource_type="prescription",
            resource_id=prescription_id,
            data_content=f"{payload.patient_id}:{payload.dosage}",
        )

        return {
            "message": "Prescription chiffrée et enregistrée avec succès.",
            "prescription_id": prescription_id,
            "blind_index": blind_idx,
        }

    @app.get("/api/v1/records/prescriptions/{prescription_id}", tags=["Prescriptions Médicales"])
    async def get_prescription(
        prescription_id: str,
        x_user_id: str = Header("USER-DEFAULT", alias="X-User-ID"),
        x_user_role: str = Header("chercheur", alias="X-User-Role"),
    ) -> dict:
        """Consulte une prescription avec déchiffrement et masquage dynamique DDM selon le rôle."""
        try:
            role = TCIMRole(x_user_role.lower())
        except ValueError:
            raise HTTPException(status_code=403, detail="Rôle utilisateur non valide.")

        record = db_prescriptions.get(prescription_id)
        if not record:
            raise HTTPException(status_code=404, detail="Prescription introuvable.")

        # Vérification d'autorisation
        if role == TCIMRole.PATIENT and record["patient_id"] != x_user_id:
            raise HTTPException(status_code=403, detail="Accès interdit au dossier d'un tiers.")

        # Déchiffrement à la volée
        decrypted_diag = crypto.decrypt_column("prescriptions", "diagnosis", record["diagnosis_encrypted"])
        decrypted_formula = crypto.decrypt_column("prescriptions", "remedy_formula", record["remedy_formula_encrypted"])
        decrypted_name = crypto.decrypt_column("prescriptions", "patient_name", record["patient_name_encrypted"])

        raw_result = {
            "prescription_id": record["prescription_id"],
            "patient_id": record["patient_id"],
            "patient_name": decrypted_name,
            "diagnosis": decrypted_diag,
            "remedy_formula": decrypted_formula,
            "dosage": record["dosage"],
        }

        # Journalisation d'accès
        audit.record_access(
            user_id=x_user_id,
            action="SELECT",
            resource_type="prescription",
            resource_id=prescription_id,
        )

        # Application du masquage dynamique (DDM)
        masked_output = DynamicDataMasker.apply_masking(raw_result, role)
        return masked_output

    @app.get("/api/v1/audit/verify", tags=["Audit & Traçabilité"])
    async def verify_audit() -> dict:
        """Vérifie l'intégrité mathématique de toute la chaîne d'audit."""
        is_valid, corrupted_idx = audit.verify_integrity()
        return {
            "audit_chain_valid": is_valid,
            "total_entries": len(audit.chain),
            "corrupted_index": corrupted_idx,
        }

    return app


app = create_app()
