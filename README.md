# ShiftEncryption

Prototype de recherche en cryptographie hybride : chiffrement à clé publique post-quantique (Ring-LWE) combiné à un flux chaotique multi-lanes et une authentification HMAC-SHA256.

> [!WARNING]
> **Ceci est un schéma cryptographique expérimental, non audité et sans preuve de sécurité formelle.**
> La couche de flux chaotique est heuristique (pas de réduction prouvée type IND-CCA). Ce projet est publié à des fins de recherche, d'apprentissage et de relecture par la communauté — **pas comme solution de production pour protéger des données sensibles, commerciales, ou appartenant à des tiers.** Voir [Sécurité](#sécurité--lire-avant-utilisation) pour le détail complet.
>
> Si vous cherchez une solution de chiffrement éprouvée pour de la production : utilisez **AES-256-GCM** ou **ChaCha20-Poly1305** (bibliothèques standard de votre langage), pas ce projet.

---

## Sommaire

- [Aperçu](#aperçu)
- [Architecture](#architecture)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Format des fichiers](#format-des-fichiers)
- [Sécurité — lire avant utilisation](#sécurité--lire-avant-utilisation)
- [Performance](#performance)
- [Historique des versions](#historique-des-versions)
- [Contribuer](#contribuer)
- [Licence](#licence)

---

## Aperçu

ShiftEncryption combine quatre couches :

| Couche | Rôle | Fondement |
|---|---|---|
| **1. Ring-LWE** | Échange de clé à clé publique | Problème du réseau euclidien (Ring Learning With Errors), post-quantique, réduction prouvée |
| **2. Flux chaotique** | Génération du keystream (16 lanes couplées, double round de diffusion) | Heuristique — **non prouvé** |
| **3. XOR parallélisé** | Chiffrement du flux (goroutines seekables, AVX2) | Standard (XOR sur flux pseudo-aléatoire) |
| **4. HMAC-SHA256** | Authentification (Encrypt-then-MAC) | Standard, prouvé (PRF sous hypothèse standard) |

L'idée : obtenir un chiffrement post-quantique performant en combinant une primitive éprouvée (RLWE) avec une couche de diffusion rapide custom, sans sacrifier l'intégrité (MAC couvrant l'intégralité du ciphertext).

## Architecture

```
                    ┌─────────────────────┐
   Clé publique ───▶│   Encapsulation RLWE │───▶  C0, C1  (seed chiffré)
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
        seed ──────▶│  Ring-LWR (état init) │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  Flux chaotique      │
                    │  16 lanes, 2 rounds   │───▶ keystream
                    │  burn-in 48 rounds    │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
   plaintext ──────▶│   XOR (parallélisé)   │───▶ ciphertext (Stream)
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
mode+len+C0+C1+     │   HMAC-SHA256         │───▶ MAC (32 octets)
   Stream ─────────▶│  (clé dérivée du seed)│
                    └─────────────────────┘
```

- **N = 1024**, **Q ≈ 2^54** — paramètres du réseau Ring-LWE
- Clé publique : **~7 Ko** (seed pour la matrice A + coefficients compactés à 55 bits)
- Clé privée : **~1 Ko** (coefficients gaussiens ∈ [-32, 32], stockés en `int8`)
- Débit : chiffrement/déchiffrement parallélisés sur tous les cœurs disponibles

### Un avantage structurel : deux clés, pas une seule

AES-256 (comme tout chiffrement symétrique) repose sur **une seule clé partagée** : la même sert à chiffrer et déchiffrer. Ça implique un problème non résolu par AES lui-même — comment transmettre cette clé à l'autre partie sans qu'elle soit interceptée ? En pratique, AES seul ne répond jamais à cette question ; il faut lui adjoindre autre chose (échange manuel, canal séparé, ou un mécanisme d'échange de clé comme ECDH).

ShiftEncryption, via sa couche RLWE, est nativement **asymétrique** : une clé publique (`.pub`) pour chiffrer, une clé privée (`.key`) pour déchiffrer. La clé publique peut être diffusée librement — même interceptée, elle ne permet pas de déchiffrer. C'est un vrai avantage architectural pour tout scénario où la clé de déchiffrement doit rester à un seul endroit (ex. : un backend qui doit être seul capable de lire des fichiers uploadés par des clients qui n'ont besoin que de la clé publique).

**Nuance importante** : la comparaison honnête n'est pas "Shift vs AES nu", mais "Shift vs KEM+AES" — en pratique, personne ne déploie AES seul pour de l'asymétrique ; on le combine toujours avec un mécanisme d'échange de clé (ECDH, RSA-OAEP, ou un KEM post-quantique comme ML-KEM/Kyber), exactement comme TLS le fait. La couche RLWE de ce projet joue ce rôle de KEM. L'avantage réel de Shift ici, c'est d'intégrer nativement un KEM **post-quantique** dans un seul binaire, sans dépendance externe — pas d'inventer un concept qu'AES n'aurait pas. Ça ne change rien non plus au point central de la section [Sécurité](#sécurité--lire-avant-utilisation) : la couche RLWE est solide, la couche chaotique reste heuristique.

## Installation

Nécessite [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/<ton-repo>/shiftencryption.git
cd shiftencryption
go build -o shiftenc main.go
```

Aucune dépendance externe — uniquement la bibliothèque standard Go.

## Utilisation

### Générer une paire de clés

```bash
./shiftenc keygen -key mesclefs
# → mesclefs.pub (clé publique, à partager)
# → mesclefs.key (clé privée, à garder secrète)
```

### Chiffrer

```bash
# Texte direct
./shiftenc encrypt -text "message secret" -pub mesclefs.pub -fmt hex

# Fichier, sortie en base64
./shiftenc encrypt -file document.pdf -pub mesclefs.pub -fmt base64 -out document.b64

# Sortie brute (binaire)
./shiftenc encrypt -file document.pdf -pub mesclefs.pub -out document.shft
```

Options de format (`-fmt`) : `raw` (binaire, défaut), `hex`, `base64`.

### Déchiffrer

```bash
./shiftenc decrypt -in document.shft -key mesclefs.key -out document.pdf
```

Le format d'entrée (hex / base64 / binaire) est auto-détecté.

### Benchmark

```bash
./shiftenc bench -size 128 -iter 5
```

Mesure le débit du flux chaotique et le temps chiffrement/déchiffrement complet sur des blocs de la taille indiquée (en Mo), répété `iter` fois.

## Format des fichiers

### Clé publique (`.pub`)

```
[8 octets: version]  [32 octets: seed matrice A]  [packed(C0), 55 bits/coeff]
```

### Clé privée (`.key`)

```
[8 octets: version]  [N octets: coefficients int8]
```

### Ciphertext (`.shft`)

```
"SHFTCT3"  mode(1)  C0(packed)  C1(packed)  MAC(32)  len(8)  Stream(len octets)
```

Le MAC couvre `mode || len || C0 || C1 || Stream` dans son intégralité (pas seulement le flux chiffré) — toute altération d'une des parties invalide le déchiffrement.

## Sécurité — lire avant utilisation

### Ce qui est solide

- La couche RLWE repose sur un problème mathématique difficile, étudié depuis 15+ ans, avec des paramètres (N=1024, Q~2^54) dimensionnés pour viser ~128 bits de sécurité classique et post-quantique.
- Le HMAC-SHA256 est une primitive standard et éprouvée.
- La vérification du MAC est en temps constant (`hmac.Equal`).
- Batterie de tests statistiques passée sur le keystream généré (monobit, chi², runs, autocorrélation, effet avalanche, compression) — aucun biais détecté.

### Ce qui ne l'est pas

- **La couche de flux chaotique n'a aucune preuve de sécurité formelle.** C'est une construction heuristique. L'absence de défaut détecté par des tests statistiques génériques ne prouve pas la résistance à une cryptanalyse ciblée (différentielle, linéaire, algébrique) menée par quelqu'un qui connaît la structure interne.
- **Aucun audit externe n'a été réalisé.** Ni par des cryptographes académiques, ni par un cabinet de sécurité, ni par une compétition ouverte (type NIST).
- **Principe de Kerckhoffs respecté** (la sécurité ne repose pas sur le secret du code), mais ça ne compense pas l'absence de preuve mathématique sur la couche chaotique elle-même.

### Recommandation

- **Usage personnel, apprentissage, recherche** : approprié, en connaissance de cause.
- **Protection de données commerciales, de tiers, ou sensibles** : utilisez AES-256-GCM ou ChaCha20-Poly1305 (implémentations standard de votre langage), pas ce projet, tant qu'il n'a pas fait l'objet d'un audit cryptographique externe sérieux et de plusieurs années d'exposition publique sans faille trouvée.

### Signaler une faille

Si vous êtes cryptographe (ou juste curieux/curieuse) et que vous repérez une faiblesse structurelle, une ouverture d'issue ou une pull request est la bienvenue — c'est exactement le genre de retour qui fait avancer ce projet vers un statut plus fiable.

## Performance

*(Indicatif — dépend du matériel ; lancez `./shiftenc bench` pour vos propres chiffres)*

| Opération | Débit approximatif |
|---|---|
| Génération de clés | quelques ms |
| Flux chaotique (keystream) | parallélisé sur tous les cœurs, plusieurs centaines de Mo/s selon le CPU |
| Chiffrement/déchiffrement complet | dominé par l'encapsulation/décapsulation RLWE (une fois par opération, indépendant de la taille du fichier) |

## Historique des versions

- **v3.2** — Double round de diffusion par pas (lanes distantes, rotation 41 vs 17) ; burn-in 32→48 rounds ; MAC dérivé via HMAC (séparation de domaine) et élargi à l'intégralité du ciphertext (mode+len+C0+C1+stream, au lieu du stream seul).
- **v3.1** — AEAD via MAC intégré, sorties hex/base64, burn-in 32 rounds, corrections NTT.
- **v3.0** — Réécriture : clé publique 16 Ko→7 Ko, clé privée 8 Ko→1 Ko, 8→16 lanes, état chaotique dérivé via Ring-LWR.

> [!NOTE]
> Les ciphertexts produits par une version ne sont pas garantis lisibles par une autre version (le format de MAC a changé entre v3.1 et v3.2, par exemple). Si vous avez des fichiers `.shft` existants importants, déchiffrez-les avec la version qui les a produits avant de migrer.

## Contribuer

Les contributions sont bienvenues, en particulier :
- Analyse cryptographique de la couche chaotique (différentielle, linéaire, algébrique)
- Vérification des paramètres RLWE via un [LWE estimator](https://github.com/malb/lattice-estimator)
- Tests supplémentaires, fuzzing, vecteurs de test

## Licence

*(à compléter selon votre choix — MIT, Apache 2.0, GPL, etc.)*
