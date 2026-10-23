"""
Tests unitaires pour le moteur de chiffrement granulaire de colonnes (AES-256-GCM + Blind Indexing).
"""

import pytest
from cryptography.exceptions import InvalidTag
from src.db.encryption.column_crypto import ColumnEncryptionEngine


@pytest.mark.unit
def test_aes_gcm_encrypt_decrypt_roundtrip(crypto_engine: ColumnEncryptionEngine):
    """Vérifie le cycle complet chiffrement / déchiffrement."""
    table = "prescriptions"
    column = "diagnosis"
    plaintext = "Insomnie chronique sévère avec anxiété réactionnelle"

    encrypted_data = crypto_engine.encrypt_column(table, column, plaintext)
    assert encrypted_data != plaintext.encode("utf-8")
    assert isinstance(encrypted_data, bytes)

    decrypted_text = crypto_engine.decrypt_column(table, column, encrypted_data)
    assert decrypted_text == plaintext


@pytest.mark.unit
def test_encrypt_produces_non_deterministic_ciphertexts(crypto_engine: ColumnEncryptionEngine):
    """Deux chiffrements du même texte doivent produire des résultats distincts grâce au vecteur d'initialisation (nonce)."""
    table = "prescriptions"
    column = "remedy_formula"
    formula = "Valeriana officinalis 500mg"

    enc1 = crypto_engine.encrypt_column(table, column, formula)
    enc2 = crypto_engine.encrypt_column(table, column, formula)

    assert enc1 != enc2, "Les ciphertexts doivent différer en raison du nonce aléatoire."
    assert crypto_engine.decrypt_column(table, column, enc1) == formula
    assert crypto_engine.decrypt_column(table, column, enc2) == formula


@pytest.mark.unit
def test_column_isolation_key_derivation(crypto_engine: ColumnEncryptionEngine):
    """Chaque colonne dérive une clé cryptographique unique via HKDF."""
    secret_value = "Donnée confidentielle"

    enc_col1 = crypto_engine.encrypt_column("table_a", "col_1", secret_value)

    # Tenter de déchiffrer avec une colonne différente doit échouer (InvalidTag)
    with pytest.raises(Exception):
        crypto_engine.decrypt_column("table_a", "col_2", enc_col1)


@pytest.mark.unit
def test_blind_indexing_deterministic_and_one_way(crypto_engine: ColumnEncryptionEngine):
    """L'index aveugle HMAC-SHA256 doit être déterministe pour permettre la recherche sans révéler la valeur."""
    table = "patients"
    column = "nir_ss"
    patient_id = "1850575123456"

    idx1 = crypto_engine.generate_blind_index(table, column, patient_id)
    idx2 = crypto_engine.generate_blind_index(table, column, patient_id)
    different_idx = crypto_engine.generate_blind_index(table, column, "1850575123457")

    assert idx1 == idx2, "L'index aveugle pour la même valeur doit être déterministe."
    assert idx1 != different_idx
    assert len(idx1) == 64  # SHA-256 hex string length
    assert patient_id not in idx1


@pytest.mark.unit
def test_tampered_ciphertext_rejection(crypto_engine: ColumnEncryptionEngine):
    """Toute altération du ciphertext ou du tag d'authentification doit lever une exception d'intégrité."""
    encrypted = crypto_engine.encrypt_column("prescriptions", "dosage", "2 gouttes par jour")

    # Corrompre un octet du ciphertext
    corrupted = bytes([(encrypted[0] ^ 0xFF)]) + encrypted[1:]

    with pytest.raises(Exception):
        crypto_engine.decrypt_column("prescriptions", "dosage", corrupted)
