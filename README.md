# NEW UPDATE

Cle Xor scindé en 4 parties avec ajouts de codes leurres . 




# XOR Packer

Un packer d'exécutables utilisant le chiffrement XOR pour macOS, écrit en C.

## Description

Ce packer chiffre un exécutable avec une clé XOR aléatoire et génère un stub C autonome qui déchiffre et exécute le payload original en mémoire.

## Structure du projet

```
packer/
└── src/
    ├── stub_generate.c    # Générateur de stub principal
    ├── stub_generate      # Exécutable compilé du générateur
    ├── packer.sh          # Script d'automatisation
    └── README.md          # Cette documentation
```

## Fonctionnalités

- **Chiffrement XOR** avec clé aléatoire de 32 bytes
- **Génération de stub C** autonome
- **Vérification d'intégrité** avec checksum
- **Exécution en mémoire** du payload déchiffré
- **Interface ligne de commande** simple
- **Script d'automatisation** inclus

## Installation

1. Cloner ou télécharger le projet
2. Naviguer vers le dossier `src/`
3. Compiler le générateur :
   ```bash
   gcc -o stub_generate stub_generate.c
   ```

Ou utiliser le script d'automatisation :
```bash
chmod +x packer.sh
./packer.sh build
```

## Utilisation

### Méthode 1: Directe
```bash
# Générer un stub
./stub_generate <executable> <output_stub.c>

# Compiler le stub
gcc -o packed_executable output_stub.c

# Exécuter
./packed_executable
```

### Méthode 2: Script d'automatisation (recommandé)
```bash
# Packer un exécutable
./packer.sh pack <executable> [nom_sortie]

# Test rapide
./packer.sh test <executable>

# Nettoyer les fichiers générés
./packer.sh clean

# Aide
./packer.sh help
```

## Exemples

```bash
# Packer la commande 'ls'
./packer.sh pack /bin/ls my_packed_ls
./my_packed_ls -la

# Packer votre propre programme
./packer.sh pack ./mon_programme
./packed_mon_programme

# Test rapide avec echo
./packer.sh test /bin/echo
```

## Comment ça marche

1. **Lecture** : Le générateur lit l'exécutable cible
2. **Chiffrement** : Le payload est chiffré avec une clé XOR aléatoire
3. **Génération** : Un stub C est généré contenant :
   - Le header avec métadonnées
   - La clé XOR
   - Le payload chiffré
   - Le code de déchiffrement et d'exécution
4. **Compilation** : Le stub est compilé en exécutable autonome
5. **Exécution** : À l'exécution, le stub déchiffre et lance le payload

## Sécurité

- **Signature magique** : Vérification "PAKE" (0x50414B45)
- **Checksum** : Validation de l'intégrité des données
- **Clé aléatoire** : Chaque packing génère une clé unique
- **Nettoyage** : Suppression automatique des fichiers temporaires

## Limitations

- Compatible macOS uniquement (peut être adapté pour Linux)
- Pas de compression (XOR uniquement)
- Fichier temporaire créé lors de l'exécution
- Taille augmentée due au code du stub

## Structure du stub généré

```c
// Header avec métadonnées
static unsigned char packed_header[] = { ... };

// Clé de déchiffrement
static unsigned char xor_key[] = { ... };

// Payload chiffré
static unsigned char encrypted_payload[] = { ... };

// Fonctions de déchiffrement et d'exécution
int main() {
    // Vérifications
    // Déchiffrement
    // Validation checksum
    // Exécution
}
```

## Développement

Le code est modulaire et peut être étendu pour ajouter :
- Compression (zlib, lz4, etc.)
- Chiffrements plus avancés (AES, RC4, etc.)
- Techniques anti-debug
- Obfuscation du code

## Compilation avancée

Pour des optimisations spécifiques :
```bash
# Optimisation taille
gcc -Os -o stub_generate stub_generate.c

# Optimisation vitesse
gcc -O3 -o stub_generate stub_generate.c

# Debug
gcc -g -DDEBUG -o stub_generate stub_generate.c
```

## Licence

Code libre d'utilisation pour l'éducation et la recherche.

---
*Généré par XOR Packer - Septembre 2025*