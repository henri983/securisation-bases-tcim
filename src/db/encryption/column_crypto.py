"""
Chiffrement au niveau de la colonne (Column-Level Encryption) et index aveugle (Blind Index).

Garantit que même un dump brut de la base de données ne révèle aucune donnée de santé TCIM.
Utilise AES-256-GCM avec dérivation de clé HKDF par table et colonne.
"""

import hmac
import hashlib
import os
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class ColumnEncryptionEngine:
    """Moteur de chiffrement granulaire par champ pour bases de données TCIM."""

    def __init__(self, master_key_hex: Optional[str] = None) -> None:
        if master_key_hex:
            self.master_key = bytes.fromhex(master_key_hex)
        else:
            self.master_key = os.urandom(32)

        if len(self.master_key) != 32:
            raise ValueError("La Master Key de la base de données doit faire 32 octets (256 bits).")

    def _derive_column_key(self, table_name: str, column_name: str) -> bytes:
        """Dérive une sous-clé cryptographique dédiée à un champ spécifique via HKDF."""
        info = f"{table_name}:{column_name}".encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"TCIM-DB-SALT-v1",
            info=info,
        )
        return hkdf.derive(self.master_key)

    def encrypt_column(self, table_name: str, column_name: str, plaintext: str) -> bytes:
        """Chiffre la valeur d'une colonne avec AES-256-GCM."""
        if plaintext is None:
            raise ValueError("Le texte à chiffrer ne peut pas être None.")

        col_key = self._derive_column_key(table_name, column_name)
        aesgcm = AESGCM(col_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce + ciphertext

    def decrypt_column(self, table_name: str, column_name: str, encrypted_bytes: bytes) -> str:
        """Déchiffre la valeur d'une colonne chiffrée."""
        if not encrypted_bytes or len(encrypted_bytes) < 28:
            raise ValueError("Données chiffrées invalides ou tronquées.")

        col_key = self._derive_column_key(table_name, column_name)
        aesgcm = AESGCM(col_key)
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")

    def generate_blind_index(self, table_name: str, column_name: str, value: str) -> str:
        """
        Génère un index aveugle (Blind Index) par HMAC pour permettre
        des recherches de correspondance exacte (SELECT WHERE) sans jamais
        déchiffrer la colonne en base de données.
        """
        col_key = self._derive_column_key(table_name, f"{column_name}_blind_index")
        canonical_val = value.strip().lower().encode("utf-8")
        return hmac.new(col_key, canonical_val, hashlib.sha256).hexdigest()
