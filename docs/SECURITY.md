# Politique de Sécurité & Modèle de Menace - Bases TCIM

## 1. Modèle de Menace (Threat Model)

| Menace | Vecteur d'Attaque | Contre-mesure Implémentée |
|---|---|---|
| Fuite de la base de données (Dump SQL) | Exfiltration de disque ou backup non chiffré | Chiffrement granulaire AES-256-GCM : chaque valeur est un ciphertext indéchiffrable sans la clé principale et le contexte de colonne. |
| Inférence statistique par égalité | Analyse fréquentielle des ciphertexts identiques | Vecteur d'initialisation (nonce de 12 octets) aléatoire et unique par opération d'écriture. |
| Altération frauduleuse des logs d'audit | Effacement de traces par un administrateur corrompu | Tamper-evident Hash Chain : altérer un log invalide les signatures de tous les blocs subséquents. |
| Fuite de PII lors d'études de recherche | Extraction non autorisée par un analyste clinique | Dynamic Data Masking (DDM) forcé selon le rôle RBAC (règle du moindre privilège). |
| Confusion ou interaction toxique de remèdes | Prescription accidentelle d'une plante létale | Surveillance IA en temps réel détectant les substances de pharmacovigilance (Aconit, Belladone, etc.). |

## 2. Gestion et Rotation des Clés

1. **Clé Maître (Master Key) :** Clé cryptographique de 256 bits (32 octets hexadécimaux) injectée exclusivement via variable d'environnement chiffrée ou coffre-fort de secrets (HashiCorp Vault, AWS KMS).
2. **Dérivation HKDF :** Les clés éphémères de colonne ne sont jamais stockées sur disque ; elles sont régénérées à la volée en mémoire sécurisée.
3. **Séparation de la Recherche :** La clé de hachage aveugle (Blind Index) est distincte de la clé de chiffrement, évitant toute corrélation d'état.

## 3. Signalement de Vulnérabilité (Responsible Disclosure)

Pour tout signalement lié à la sécurité des données ou à une vulnérabilité potentielle, veuillez contacter directement l'équipe de sécurité à : `henrinyame2001@gmail.com`.
