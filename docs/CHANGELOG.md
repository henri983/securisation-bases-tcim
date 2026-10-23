# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) et adhère au [Versionnage Sémantique (SemVer)](https://semver.org/).

## [1.0.0] - 2026-10-23

### Ajouts Initiaux (v1.0.0 Release)
- **Moteur de Chiffrement de Colonnes :**
  - Chiffrement symétrique authentifié AES-256-GCM.
  - Dérivation de clés isolées par table et colonne via HKDF-SHA256.
  - Blind Indexing déterministe HMAC-SHA256 pour la recherche sécurisée sans déchiffrement.
- **Chaîne d'Audit Inaltérable (Tamper-Evident Hash Chain) :**
  - Journalisation append-only scellée par hachage SHA-256 chaîné.
  - Vérification cryptographique automatisée détectant toute altération ou suppression.
- **Contrôle d'Accès RBAC & ABAC :**
  - Gestion fine des rôles (Admin, Phytothérapeute, Chercheur, Patient, Auditeur Pharmacovigilance).
  - Principe du moindre privilège appliqué à l'ensemble des endpoints.
- **Masquage Dynamique des Données (DDM) :**
  - Masquage contextuel en temps réel des données nominatives (PII) pour les chercheurs.
- **Variante Intelligence Artificielle :**
  - Moteur de classification intelligente NLP et règles pharmacologiques expertes.
  - Détection automatique des PII et des 4 niveaux de sensibilité (`PUBLIC`, `INTERNAL_RESEARCH`, `CONFIDENTIAL_MEDICAL`, `RESTRICTED_CRITICAL`).
  - Pharmacovigilance et alertes en temps réel sur substances à marge étroite (Aconit, Belladone, Digitale, etc.).
- **Assurance Qualité & Tests :**
  - Suite complète pytest (unitaires, intégration, IA) avec 100% de réussite.
- **DevSecOps & CI/CD :**
  - Workflow GitHub Actions CI pour linter, tests automatisés et audit de sécurité.
