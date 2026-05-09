# Crimson Desert Mod Manager — macOS Compatibility

## Supported Mod Types

### 1. JSON Modpatch (hex patching)

**Format** : fichier `.json` avec des patches hex à des offsets précis.

**Fonctionnement** :
1. Lit le fichier original depuis les archives du jeu (PAZ)
2. Déchiffre (ChaCha20) si nécessaire
3. Décompresse (LZ4)
4. Applique les modifications d'octets aux offsets spécifiés
5. Recompresse (LZ4)
6. Rechiffre (ChaCha20)
7. Écrit dans l'overlay `0036/`

**Fichiers concernés** : CSS, HTML, fichiers de config (groupe `0008` ou `0012`)

**Exemple** : Worldmap Darkmode — modifie les couleurs dans `worldmapview.css`

---

### 2. File Replacement (crimson_browser_mod_v1)

**Format** : dossier avec `manifest.json` + arborescence `files/<group>/<vfs_path>`

**Fonctionnement** :
1. Lit le fichier de remplacement fourni par le mod
2. Détermine les flags originaux depuis le PAMT du jeu
3. Compresse (LZ4) si flags indiquent compression type 2
4. Chiffre (ChaCha20) si flags indiquent encryption type 3
5. Écrit dans l'overlay `0036/`

**Fichiers supportés** (flags `0x0032`, `0x0030`, `0x0000`) :
- CSS, HTML (chiffrés ChaCha20 + compressés LZ4) ✅
- DDS textures non-compressées (flags `0x0000`, petits fichiers) ✅

**Fichiers NON supportés** (flags `0x0001`) :
- DDS textures avec compression Patrical ❌
  - Le moteur BlackSpace utilise un format de compression propriétaire
  - Les fichiers originaux sont ~45 KB, les DDS standard font ~262 KB
  - Le jeu ne sait pas lire un DDS standard en remplacement
  - Nécessiterait le compresseur Patrical (non disponible)

---

## Flags PAMT (référence)

| Flags  | Compression (low nibble) | Encryption (high nibble) | Support |
|--------|--------------------------|--------------------------|---------|
| 0x0000 | Raw                      | None                     | ✅      |
| 0x0001 | Patrical (propriétaire)  | None                     | ❌ lecture seule |
| 0x0002 | LZ4                      | None                     | ✅      |
| 0x0030 | Raw                      | ChaCha20                 | ✅      |
| 0x0032 | LZ4                      | ChaCha20                 | ✅      |

## Mods testés

| Mod | Type | Compatibilité macOS |
|-----|------|---------------------|
| Worldmap Darkmode | JSON patch | ✅ Fonctionne |
| Bigger Minimap | File replacement (CSS/HTML/DDS raw) | ✅ Fonctionne |
| Better Inventory UI | File replacement (CSS/HTML/DDS) | ✅ Fonctionne |
| JerK's Map Icons | File replacement (DDS Patrical) | ❌ Incompatible |
