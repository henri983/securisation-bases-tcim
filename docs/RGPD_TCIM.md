# Conformité RGPD & Données de Santé TCIM

Le présent document formalise la conformité du projet aux articles clés du Règlement Général sur la Protection des Données (RGPD 2016/679) et à la réglementation française et européenne relative aux données de santé.

## 1. Bases Légales et Catégories Particulières de Données (Articles 6 & 9)

Les bases de données TCIM contiennent des informations relatives à la santé physique et mentale des patients, qui constituent des **données sensibles au sens de l'Article 9 du RGPD**.

- **Article 6.1 (c) & (e) :** Nécessité pour l'exécution d'une mission d'intérêt public et la recherche médicale.
- **Article 9.2 (i) & (j) :** Traitement nécessaire pour des motifs d'intérêt public dans le domaine de la santé publique (pharmacovigilance) et à des fins de recherche scientifique.

## 2. Mesures Techniques & Organisationnelles (Article 32)

| Exigence Article 32 RGPD | Implémentation dans la Solution |
|---|---|
| **Pseudonymisation & Chiffrement** | Chiffrement granulaire AES-256-GCM par colonne sensible + Blind indexing HMAC-SHA256 |
| **Confidentialité et Intégrité** | Contrôle d'accès RBAC/ABAC strict et politique de moindre privilège |
| **Disponibilité et Résilience** | Architecture conteneurisée sans état avec réplication de base de données |
| **Évaluation de l'Efficacité** | Tests d'intégrité automatisés dans le pipeline CI/CD (`test_tampered_ciphertext_rejection`) |

## 3. Registre des Activités de Traitement (Article 30)

| Traitement | Finalité | Catégories de Données | Destinataires | Conservation |
|---|---|---|---|---|
| Prescription TCIM | Dispensation de soins et suivi thérapeutique | Identité, formule galénique, posologie, diagnostic | Phytothérapeutes traitants | 20 ans légaux |
| Recherche Pharmaco-clinique | Évaluation de l'efficacité et innocuité | Posologies, ratios galéniques, effets observés (PII masquées) | Équipes de recherche agréées | Durée de l'étude + 5 ans |
| Journalisation d'accès | Traçabilité légale et pharmacovigilance | Identifiant utilisateur, horodatage, action, empreinte cryptographique | DPO, Auditeurs de sécurité | 5 ans glissants |

## 4. Droits des Personnes Concernées (Articles 15 à 21)

1. **Droit d'accès et de rectification (Art. 15, 16) :** L'endpoint `/api/v1/records/prescriptions/{id}` permet la consultation des données du patient avec déchiffrement vérifié.
2. **Droit à l'effacement (« Droit à l'oubli » - Art. 17) :** Destruction cryptographique par purge de la clé dérivée ou suppression scellée dans la chaîne d'audit.
3. **Droit à la portabilité (Art. 20) :** Extraction structurée au format JSON standardisé.
4. **Minimisation des données (Art. 5.1.c) :** Le module DDM garantit qu'aucun acteur non habilité n'accède à des données non indispensables.
