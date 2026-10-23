"""
Journal d'audit cryptographiquement chaîné (Tamper-Evident Hash Chain).

Garantit la traçabilité inaltérable de chaque lecture, écriture et modification
de la base de données de pharmacopée et dossiers patients TCIM.
"""

import hashlib
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class AuditEntry:
    """Entrée d'audit scellée cryptographiquement."""

    index: int
    timestamp: float
    user_id: str
    action: str  # SELECT, INSERT, UPDATE, DELETE, EXPORT
    resource_type: str  # plant_formula, patient_history, clinical_trial
    resource_id: str
    data_fingerprint: str  # SHA-256 du contenu consulté ou altéré
    previous_hash: str
    entry_hash: str


class TamperEvidentAuditTrail:
    """Registre de traçabilité chaîné type append-only ledger."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self) -> None:
        self.chain: List[AuditEntry] = []

    def _compute_hash(
        self,
        index: int,
        timestamp: float,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        data_fingerprint: str,
        previous_hash: str,
    ) -> str:
        """Calcule l'empreinte SHA-256 scellant l'entrée et le lien avec la précédente."""
        payload = f"{index}|{timestamp:.4f}|{user_id}|{action}|{resource_type}|{resource_id}|{data_fingerprint}|{previous_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def record_access(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        data_content: str = "",
    ) -> AuditEntry:
        """Enregistre et scelle une action dans la chaîne d'audit."""
        index = len(self.chain)
        timestamp = time.time()
        prev_hash = self.chain[-1].entry_hash if self.chain else self.GENESIS_HASH
        fingerprint = hashlib.sha256(data_content.encode("utf-8")).hexdigest()

        entry_hash = self._compute_hash(
            index, timestamp, user_id, action, resource_type, resource_id, fingerprint, prev_hash
        )

        entry = AuditEntry(
            index=index,
            timestamp=timestamp,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            data_fingerprint=fingerprint,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.chain.append(entry)
        return entry

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Vérifie l'intégrité intégrale de la chaîne d'audit.
        Retourne (True, None) si saine, ou (False, index_corrompu) en cas d'altération.
        """
        for i, entry in enumerate(self.chain):
            # 1. Vérification du lien de chaînage
            expected_prev = self.chain[i - 1].entry_hash if i > 0 else self.GENESIS_HASH
            if entry.previous_hash != expected_prev:
                return False, i

            # 2. Recalcul du hash de l'entrée
            recomputed = self._compute_hash(
                entry.index,
                entry.timestamp,
                entry.user_id,
                entry.action,
                entry.resource_type,
                entry.resource_id,
                entry.data_fingerprint,
                entry.previous_hash,
            )
            if recomputed != entry.entry_hash:
                return False, i

        return True, None
