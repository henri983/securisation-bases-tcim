"""
Tests d'intégration end-to-end de l'API FastAPI TCIM.
"""

import pytest
import httpx


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: httpx.AsyncClient):
    """Vérifie l'endpoint de santé du service."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["audit_chain_valid"] is True


@pytest.mark.asyncio
async def test_ai_classification_api(async_client: httpx.AsyncClient):
    """Vérifie l'analyse et classification d'un texte par l'endpoint IA."""
    payload = {
        "content": "Patient Marc sous traitement avec de la Belladonna pour spasmes abdominaux."
    }
    response = await async_client.post("/api/v1/classify/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["sensitivity_level"] == "RESTRICTED_CRITICAL"
    assert data["required_encryption"] is True
    assert len(data["detected_risk_substances"]) > 0


@pytest.mark.asyncio
async def test_prescription_lifecycle_and_rbac(async_client: httpx.AsyncClient):
    """Cycle de vie complet : création sécurisée, contrôle d'accès et masquage DDM."""
    # 1. Tentative non autorisée par un chercheur (interdit en écriture)
    prescription_payload = {
        "patient_id": "PAT-99",
        "patient_name": "Sophie Martin",
        "diagnosis": "Stress aigu et migraines",
        "remedy_formula": "Mélisse + Eschscholtzia",
        "dosage": "2 gélules au dîner",
    }
    unauthorized_res = await async_client.post(
        "/api/v1/records/prescriptions",
        json=prescription_payload,
        headers={"X-User-ID": "CHERCHEUR-1", "X-User-Role": "chercheur"},
    )
    assert unauthorized_res.status_code == 403

    # 2. Création légitime par un phytothérapeute
    create_res = await async_client.post(
        "/api/v1/records/prescriptions",
        json=prescription_payload,
        headers={"X-User-ID": "DR-PHYT-1", "X-User-Role": "phytotherapeute"},
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    rx_id = created_data["prescription_id"]
    assert "blind_index" in created_data

    # 3. Lecture autorisée en clair par le phytothérapeute
    doc_read_res = await async_client.get(
        f"/api/v1/records/prescriptions/{rx_id}",
        headers={"X-User-ID": "DR-PHYT-1", "X-User-Role": "phytotherapeute"},
    )
    assert doc_read_res.status_code == 200
    doc_data = doc_read_res.json()
    assert doc_data["patient_name"] == "Sophie Martin"
    assert doc_data["diagnosis"] == "Stress aigu et migraines"

    # 4. Lecture anonymisée / masquée dynamiquement par un chercheur
    researcher_res = await async_client.get(
        f"/api/v1/records/prescriptions/{rx_id}",
        headers={"X-User-ID": "CHERCHEUR-1", "X-User-Role": "chercheur"},
    )
    assert researcher_res.status_code == 200
    res_data = researcher_res.json()
    assert res_data["patient_name"] != "Sophie Martin"
    assert "*" in res_data["patient_name"]
    # La formule reste accessible pour la recherche
    assert res_data["remedy_formula"] == "Mélisse + Eschscholtzia"

    # 5. Vérification de la chaîne d'audit inaltérable
    audit_res = await async_client.get("/api/v1/audit/verify")
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["audit_chain_valid"] is True
    assert audit_data["total_entries"] >= 3  # create + 2 reads
