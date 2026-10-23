"""
Fixtures pytest pour les tests de sécurisation des bases TCIM.
"""

import os
import pytest
import pytest_asyncio
import httpx
from fastapi import FastAPI

from src.config import Settings
from src.db.encryption.column_crypto import ColumnEncryptionEngine
from src.db.audit.tamper_evident_log import TamperEvidentAuditTrail
from src.ai.classifier.intelligent_data_classifier import TCIMDataClassifier
from src.main import create_app


@pytest.fixture
def test_settings() -> Settings:
    """Paramètres sécurisés dédiés aux tests."""
    return Settings(
        APP_ENV="test",
        LOG_LEVEL="DEBUG",
        DATABASE_MASTER_KEY_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )


@pytest.fixture
def crypto_engine(test_settings: Settings) -> ColumnEncryptionEngine:
    """Moteur de chiffrement granulaire initialisé avec une clé de test."""
    return ColumnEncryptionEngine(master_key_hex=test_settings.DATABASE_MASTER_KEY_HEX)


@pytest.fixture
def audit_trail() -> TamperEvidentAuditTrail:
    """Chaîne d'audit inaltérable isolée."""
    return TamperEvidentAuditTrail()


@pytest.fixture
def ai_classifier() -> TCIMDataClassifier:
    """Classifieur intelligent de données TCIM."""
    return TCIMDataClassifier()


@pytest.fixture
def test_app(test_settings: Settings) -> FastAPI:
    """Instance FastAPI avec paramètres de test."""
    return create_app(settings=test_settings)


@pytest_asyncio.fixture
async def async_client(test_app: FastAPI):
    """Client HTTP asynchrone httpx pour tester les routes FastAPI."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
