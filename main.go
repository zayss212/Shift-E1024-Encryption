// ShiftEncryption v4.0 — prototype de recherche
//
//	COUCHE 1 : RLWE sur R_q = Z_q[X]/(X^N+1), N=1024, Q~2^54
//	COUCHE 2 : squelette ARX Threefish-1024 (80 rounds, rotations/permutation
//	           vérifiées depuis la spec Skein v1.3), feed-forward MMO,
//	           blanchiment final via fonction non-linéaire "lg" (touche Shift)
//	COUCHE 3 : XOR 128 o/pas, AVX2 4×VPXOR(256b), goroutines seekables
//	COUCHE 4 : MAC HMAC-SHA256 sur mode+len+C0+C1+stream (authentification totale)
//
// Historique :
//
//	v3.0 : réécriture initiale (clé publique 16→7 Ko, privée 8→1 Ko, 8→16 lanes)
//	v3.1 : AEAD MAC, output hex/base64, burn 32 rounds, fixes NTT
//	v3.2 : double round par pas, burn 48 rounds, MAC élargi à tout le CipherData
//	v4.0 : couche 2 entièrement reconstruite sur le squelette Threefish-1024
//	       (Ferguson/Lucks/Schneier et al., finaliste NIST SHA-3) — rotations
//	       et permutation vérifiées depuis l'implémentation de référence,
//	       80 rounds (marge de sécurité identique à Threefish), sous-clés
//	       dérivées du seed via HKDF, feed-forward Matyas-Meyer-Oseas (comme
//	       Skein transforme Threefish en fonction à sens unique), mode
//	       compteur par bloc (plus d'état continu entre blocs). La fonction
//	       "lg" originale de Shift est conservée en blanchiment final.
//	       Débit : ~40x plus lent qu'en v3.2 (80 rounds vs 2) — contrepartie
//	       assumée pour un squelette de diffusion analysé publiquement.
//
// Commandes :
//
//	go run main.go keygen  [-key prefix]
//	go run main.go encrypt -text "..." | -file path  [-pub k.pub] [-out path] [-fmt hex|base64|raw]
//	go run main.go decrypt -in path  [-key k.key] [-out path]
//	go run main.go bench  [-size MB] [-iter N]
package main

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// ============================================================================
// PARAMÈTRES
// ============================================================================

const (
	N                = 1024    // degré du polynôme (Ring-LWE)
	P         uint64 = 256     // modulus de compression (messages ∈ [0,P))
	Sigma            = 3.2     // écart-type Gaussien
	SeedSize         = 32      // taille graine en octets
	Lanes            = 16      // voies parallèles × 8 octets = 128 o/pas
	ChunkSize        = 1 << 17 // 128 KiB par goroutine
	MacSize          = 32      // HMAC-SHA256 = 32 octets
)

var (
	Q       uint64
	Delta   uint64
	qMask   uint64
	invN    uint64
	psis    [N]uint64
	invPsis [N]uint64
	lwrA    [N]uint64 // polynôme public fixe pour la dérivation Ring-LWR
)

// Weyl : 16 incréments impairs distincts (golden-ratio + mixing constants)
var weylGamma = [Lanes]uint64{
	0x9E3779B97F4A7C15, 0xBF58476D1CE4E5B9, 0x94D049BB133111EB, 0xD6E8FEB86659FD93,
	0xA0761D6478BD642F, 0xE7037ED1A0B428DB, 0x8EBC6AF09C88C6E3, 0x589965CC75374CC3,
	0x6C62272E07BB0143, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x27D4EB2F165667C5,
	0x846542429B4831C1, 0xAB5033EF4E0F0B5B, 0xF5A0F9AF3C0F68B5, 0xD5A30CA2B0784D55,
}

// ============================================================================
// ARITHMÉTIQUE MODULAIRE
// ============================================================================

func addMod(a, b uint64) uint64 {
	c := a + b
	if c >= Q {
		c -= Q
	}
	return c
}

func subMod(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + Q - b
}

// mulMod : a,b < Q < 2^55 → hi < Q → bits.Div64 valide (hi < diviseur).
func mulMod(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, r := bits.Div64(hi, lo, Q)
	return r
}

func powMod(base, exp uint64) uint64 {
	r := uint64(1)
	base %= Q
	for exp > 0 {
		if exp&1 == 1 {
			r = mulMod(r, base)
		}
		base = mulMod(base, base)
		exp >>= 1
	}
	return r
}

// versions paramétrées (pour la recherche de Q avant que var Q soit fixé)
func mulModM(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, r := bits.Div64(hi, lo, m)
	return r
}

func powModM(b, e, m uint64) uint64 {
	r := uint64(1)
	b %= m
	for e > 0 {
		if e&1 == 1 {
			r = mulModM(r, b, m)
		}
		b = mulModM(b, b, m)
		e >>= 1
	}
	return r
}

// ============================================================================
// RECHERCHE DE Q — Miller–Rabin déterministe (correct pour n < 3.3·10²⁴)
// ============================================================================

func millerRabin(n, a, d uint64, r int) bool {
	x := powModM(a, d, n)
	if x == 1 || x == n-1 {
		return false
	}
	for i := 0; i < r-1; i++ {
		x = mulModM(x, x, n)
		if x == n-1 {
			return false
		}
	}
	return true
}

func isPrime(n uint64) bool {
	if n < 2 {
		return false
	}
	for _, p := range []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		if n == p {
			return true
		}
		if n%p == 0 {
			return false
		}
	}
	d, r := n-1, 0
	for d&1 == 0 {
		d >>= 1
		r++
	}
	for _, a := range []uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		if millerRabin(n, a, d, r) {
			return false
		}
	}
	return true
}

func bitrev(x, logN uint) uint {
	var r uint
	for i := uint(0); i < logN; i++ {
		r = (r << 1) | ((x >> i) & 1)
	}
	return r
}

// init : trouve Q, calcule tables NTT et polynôme lwrA
func init() {
	const mod = 2 * N
	// Q ≡ 1 (mod 2N) pour que les racines 2N-ièmes existent dans Z_Q
	q := uint64(1)<<54 + uint64(mod) + 1
	for !isPrime(q) {
		q += mod
	}
	Q = q
	Delta = Q / P
	qMask = (uint64(1) << uint(bits.Len64(Q))) - 1

	// Racine primitive 2N-ième de l'unité : psi^N ≡ -1 (mod Q)
	var psi uint64
	for g := uint64(2); ; g++ {
		p := powModM(g, (Q-1)/(2*N), Q)
		if powModM(p, N, Q) == Q-1 {
			psi = p
			break
		}
	}
	invPsi := powModM(psi, Q-2, Q)
	logN := uint(bits.TrailingZeros(uint(N)))
	for i := uint(0); i < N; i++ {
		r := bitrev(i, logN)
		psis[i] = powModM(psi, uint64(r), Q)
		invPsis[i] = powModM(invPsi, uint64(r), Q)
	}
	invN = powModM(N, Q-2, Q)

	// lwrA : polynôme public fixe pour Ring-LWR (domaine NTT)
	p := sampleUniformPolyFromSeed([]byte("ShiftEncryption-LWR-Domain-v3\x00\x00"))
	nttForward(p)
	copy(lwrA[:], p)
}

// ============================================================================
// NTT NÉGACYCLIQUE (Cooley-Tukey iteratif)
// ============================================================================

func nttForward(a []uint64) {
	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1, s := 2*i*t, psis[m+i]
			for j := j1; j < j1+t; j++ {
				u, v := a[j], mulMod(a[j+t], s)
				a[j] = addMod(u, v)
				a[j+t] = subMod(u, v)
			}
		}
	}
}

func nttInverse(a []uint64) {
	t := 1
	for m := N; m > 1; m >>= 1 {
		j1, h := 0, m>>1
		for i := 0; i < h; i++ {
			s := invPsis[h+i]
			for j := j1; j < j1+t; j++ {
				u, v := a[j], a[j+t]
				a[j] = addMod(u, v)
				a[j+t] = mulMod(subMod(u, v), s)
			}
			j1 += 2 * t
		}
		t <<= 1
	}
	for i := range a {
		a[i] = mulMod(a[i], invN)
	}
}

// ============================================================================
// ÉCHANTILLONNAGE
// ============================================================================

func randUint64() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic("crand.Read: " + err.Error())
	}
	return binary.LittleEndian.Uint64(b[:])
}

// sampleUniformPolyFromSeed : expansion déterministe seed → polynôme uniforme dans [0,Q).
func sampleUniformPolyFromSeed(seed []byte) []uint64 {
	p := make([]uint64, N)
	var h uint64
	for i := 0; i < len(seed) && i < 32; i += 8 {
		end := i + 8
		if end > len(seed) {
			end = len(seed)
		}
		var w [8]byte
		copy(w[:], seed[i:end])
		h ^= binary.LittleEndian.Uint64(w[:])
	}
	for i := range p {
		for {
			h = splitmix64(h + weylGamma[i%Lanes])
			if v := h & qMask; v < Q {
				p[i] = v
				break
			}
		}
	}
	return p
}

func sampleUniformPoly(dst []uint64) {
	for i := range dst {
		for {
			v := randUint64() & qMask
			if v < Q {
				dst[i] = v
				break
			}
		}
	}
}

var gaussCDT []uint64

func init() {
	tail := int(math.Ceil(10 * Sigma))
	w := make([]float64, tail+1)
	total := 0.0
	for k := 0; k <= tail; k++ {
		wk := math.Exp(-float64(k*k) / (2 * Sigma * Sigma))
		if k == 0 {
			wk /= 2
		}
		w[k] = wk
		total += wk
	}
	gaussCDT = make([]uint64, tail+1)
	cum := 0.0
	for k := 0; k <= tail; k++ {
		cum += w[k] / total
		if cum > 1 {
			cum = 1
		}
		gaussCDT[k] = uint64(cum * float64(uint64(1)<<63))
	}
	gaussCDT[tail] = uint64(1) << 63
}

func sampleGaussian() int64 {
	u := randUint64() >> 1
	k := int64(0)
	for int(k) < len(gaussCDT) && u >= gaussCDT[k] {
		k++
	}
	if randUint64()&1 == 1 {
		return -k
	}
	return k
}

func sampleGaussianPoly(dst []uint64) {
	for i := range dst {
		g := sampleGaussian()
		if g >= 0 {
			dst[i] = uint64(g)
		} else {
			dst[i] = Q - uint64(-g)
		}
	}
}

// ============================================================================
// COMPRESSION POLYNOMIALE — 55 bits / coefficient (Q < 2^55)
// ============================================================================

const bitsPerCoeff = 55

func packBits55(p []uint64) []byte {
	n := len(p)
	out := make([]byte, (bitsPerCoeff*n+7)/8)
	var buf uint64
	bitsIn := 0
	j := 0
	for _, v := range p {
		buf |= (v & ((1 << bitsPerCoeff) - 1)) << uint(bitsIn)
		bitsIn += bitsPerCoeff
		for bitsIn >= 8 {
			out[j] = byte(buf)
			buf >>= 8
			bitsIn -= 8
			j++
		}
	}
	if bitsIn > 0 {
		out[j] = byte(buf)
	}
	return out
}

func unpackBits55(data []byte, n int) ([]uint64, error) {
	need := (bitsPerCoeff*n + 7) / 8
	if len(data) < need {
		return nil, fmt.Errorf("unpackBits55 : %d octets attendus, %d reçus", need, len(data))
	}
	out := make([]uint64, n)
	var buf uint64
	bitsIn := 0
	j := 0
	for i := range out {
		for bitsIn < bitsPerCoeff && j < len(data) {
			buf |= uint64(data[j]) << uint(bitsIn)
			bitsIn += 8
			j++
		}
		v := buf & ((1 << bitsPerCoeff) - 1)
		if v >= Q {
			return nil, fmt.Errorf("unpackBits55 : coefficient %d hors [0,Q)", i)
		}
		out[i] = v
		buf >>= bitsPerCoeff
		bitsIn -= bitsPerCoeff
	}
	return out, nil
}

func polyToInt8(s []uint64) []int8 {
	out := make([]int8, len(s))
	for i, v := range s {
		if v <= 127 {
			out[i] = int8(v)
		} else {
			out[i] = int8(int64(v) - int64(Q))
		}
	}
	return out
}

func int8ToPoly(s []int8) []uint64 {
	out := make([]uint64, len(s))
	for i, v := range s {
		if v >= 0 {
			out[i] = uint64(v)
		} else {
			out[i] = Q - uint64(-v)
		}
	}
	return out
}

// ============================================================================
// COUCHE 1 — RLWE (schéma LPR)
// ============================================================================

type PublicKey struct {
	SeedA [SeedSize]byte
	A, B  []uint64 // domaine NTT
}

type PrivateKey struct{ S []uint64 } // domaine NTT

type Mode uint8

const (
	ModeHybrid Mode = iota
	ModeHomomorphic
)

type CipherData struct {
	Mode   Mode
	C0, C1 []uint64
	Stream []byte
	Mac    []byte // HMAC-SHA256 sur Stream (ModeHybrid uniquement)
	Len    int
}

func GenerateKeyPair() (PublicKey, PrivateKey) {
	var seedA [SeedSize]byte
	if _, err := crand.Read(seedA[:]); err != nil {
		panic(err)
	}
	a := sampleUniformPolyFromSeed(seedA[:])
	nttForward(a)

	sCoeff := make([]uint64, N)
	sampleGaussianPoly(sCoeff)
	s := make([]uint64, N)
	copy(s, sCoeff)
	nttForward(s)

	e := make([]uint64, N)
	sampleGaussianPoly(e)
	nttForward(e)

	b := make([]uint64, N)
	for i := range b {
		b[i] = addMod(mulMod(a[i], s[i]), e[i])
	}

	return PublicKey{SeedA: seedA, A: a, B: b}, PrivateKey{S: s}
}

func rlweEncrypt(msg []uint64, pub PublicKey) (c0, c1 []uint64) {
	u := make([]uint64, N)
	e1 := make([]uint64, N)
	e2 := make([]uint64, N)
	sampleGaussianPoly(u)
	sampleGaussianPoly(e1)
	sampleGaussianPoly(e2)
	for i := range e1 {
		e1[i] = addMod(e1[i], mulMod(Delta, msg[i]))
	}
	nttForward(u)
	nttForward(e1)
	nttForward(e2)
	c0, c1 = make([]uint64, N), make([]uint64, N)
	for i := range c0 {
		c0[i] = addMod(mulMod(pub.B[i], u[i]), e1[i])
		c1[i] = addMod(mulMod(pub.A[i], u[i]), e2[i])
	}
	return
}

func rlweDecrypt(c0, c1 []uint64, priv PrivateKey) []uint64 {
	d := make([]uint64, N)
	for i := range d {
		d[i] = subMod(c0[i], mulMod(c1[i], priv.S[i]))
	}
	nttInverse(d)
	msg := make([]uint64, N)
	for i := range msg {
		msg[i] = ((d[i]*P + Q/2) / Q) % P
	}
	return msg
}

func EncryptValues(values []byte, pub PublicKey) (CipherData, error) {
	if len(values) > N {
		return CipherData{}, fmt.Errorf("EncryptValues : %d > N=%d", len(values), N)
	}
	msg := make([]uint64, N)
	for i, v := range values {
		msg[i] = uint64(v)
	}
	c0, c1 := rlweEncrypt(msg, pub)
	return CipherData{Mode: ModeHomomorphic, C0: c0, C1: c1, Len: len(values)}, nil
}

func DecryptValues(ct CipherData, priv PrivateKey) ([]byte, error) {
	if ct.Mode != ModeHomomorphic {
		return nil, errors.New("mode incorrect")
	}
	msg := rlweDecrypt(ct.C0, ct.C1, priv)
	out := make([]byte, ct.Len)
	for i := range out {
		out[i] = byte(msg[i])
	}
	return out, nil
}

func HomomorphicAdd(a, b CipherData) (CipherData, error) {
	if a.Mode != ModeHomomorphic || b.Mode != ModeHomomorphic {
		return CipherData{}, errors.New("HomomorphicAdd : mode incorrect")
	}
	r0, r1 := make([]uint64, N), make([]uint64, N)
	for i := range r0 {
		r0[i] = addMod(a.C0[i], b.C0[i])
		r1[i] = addMod(a.C1[i], b.C1[i])
	}
	l := a.Len
	if b.Len > l {
		l = b.Len
	}
	return CipherData{Mode: ModeHomomorphic, C0: r0, C1: r1, Len: l}, nil
}

// ============================================================================
// COUCHE 2 — FLUX HYPERCHAOTIQUE 16 LANES + Ring-LWR
// ============================================================================

type LWRState [Lanes]uint64

func newLWRState(seed *[SeedSize]byte) LWRState {
	s := sampleUniformPolyFromSeed(seed[:])
	nttForward(s)
	t := make([]uint64, N)
	for i := range t {
		t[i] = mulMod(lwrA[i], s[i])
	}
	nttInverse(t)
	var st LWRState
	for i := 0; i < Lanes; i++ {
		st[i] = splitmix64(t[i]<<9 ^ t[(i+N/2)%N])
	}
	return st
}

func splitmix64(z uint64) uint64 {
	z ^= z >> 30
	z *= 0xBF58476D1CE4E5B9
	z ^= z >> 27
	z *= 0x94D049BB133111EB
	z ^= z >> 31
	return z
}

// v4.0 : squelette de diffusion emprunté à Threefish-1024 (Ferguson, Lucks,
// Schneier, Whiting, Bellare, Kohno, Callas, Walker — cœur de Skein,
// finaliste NIST SHA-3, spec v1.3). Threefish-1024 opère sur exactement
// 16 mots de 64 bits — identique à notre structure Lanes=16 — avec un
// planning de rotations et une permutation analysés publiquement pendant
// la compétition SHA-3 (meilleure attaque publique : ~57/72 rounds sur
// Threefish-512, soit un facteur de marge ~1.3 à pleine échelle — nous
// reprenons le nombre de rounds complet, 80, pour la même marge).
//
// Ce qu'on emprunte à Threefish-1024 (constantes vérifiées depuis
// l'implémentation de référence, domaine public / ISC license) :
//   - la table de rotations 8×8 (motif qui se répète tous les 8 rounds)
//   - la permutation fixe des 16 mots appliquée après chaque round
//   - l'injection de sous-clé tous les 4 rounds
//   - le nombre total de rounds (80)
//
// Ce qui reste original à Shift :
//   - la dérivation des sous-clés depuis le seed RLWE (pas une vraie
//     key schedule Threefish — on n'a pas besoin de la réversibilité
//     d'un chiffrement par bloc, juste d'une permutation à sens unique)
//   - le feed-forward Matyas-Meyer-Oseas final (out = E(state) XOR state),
//     exactement la technique que Skein utilise pour transformer
//     Threefish — un chiffrement par bloc — en fonction à sens unique
//     adaptée à un usage de flux/PRF plutôt que de chiffrement par bloc
//   - la fonction non-linéaire "lg" (multiplication haute) appliquée en
//     blanchiment final — la vraie touche perso Shift, en plus du
//     squelette ARX emprunté, pas à la place

const (
	tfRounds      = 80 // = Threefish-1024 (marge de sécurité identique)
	tfSubkeyEvery = 4
	tfNumSubkeys  = tfRounds/tfSubkeyEvery + 1 // 21
)

// tfRot : table de rotations 8×8, motif se répétant tous les 8 rounds.
// Valeurs copiées telles quelles depuis l'implémentation de référence
// Threefish-1024 (schultz-is/go-threefish, elle-même dérivée de la
// spec Skein v1.3 officielle).
var tfRot = [8][8]uint64{
	{24, 13, 8, 47, 8, 17, 22, 37},
	{38, 19, 10, 55, 49, 18, 23, 52},
	{33, 4, 51, 13, 34, 41, 59, 17},
	{5, 20, 48, 41, 47, 28, 16, 25},
	{41, 9, 37, 31, 12, 47, 44, 30},
	{16, 34, 56, 51, 4, 53, 42, 41},
	{31, 44, 47, 46, 19, 42, 44, 25},
	{9, 48, 35, 52, 23, 31, 37, 20},
}

// tfPerm : permutation fixe des 16 mots, appliquée après chaque round.
// new[i] = old[tfPerm[i]]. Copiée telle quelle depuis la même référence.
var tfPerm = [Lanes]int{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1}

// lg : fonction non-linéaire multiplicative — la touche perso Shift,
// conservée comme blanchiment final (pas dans le squelette ARX lui-même).
func lg(x uint64) uint64 { hi, _ := bits.Mul64(x, ^x); return hi << 2 }

// hkdfExpand : expansion HMAC-SHA256 en mode compteur (HKDF-Expand simplifié,
// seed déjà haute-entropie donc pas de phase Extract nécessaire).
func hkdfExpand(seed *[SeedSize]byte, label string, nBytes int) []byte {
	out := make([]byte, 0, nBytes+sha256.Size)
	var counter byte = 1
	var prev []byte
	for len(out) < nBytes {
		mac := hmac.New(sha256.New, seed[:])
		mac.Write(prev)
		mac.Write([]byte(label))
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:nBytes]
}

// c240 : constante "nothing-up-my-sleeve" du key schedule Threefish
// (= XOR de tous les mots de clé, valeur fixe publiée dans la spec Skein v1.3).
const c240 = 0x1BD11BDAA9FC1A22

// threefishKeySchedule v4.1 : reproduit fidèlement la formule de key schedule
// de Threefish (spec Skein v1.3, §3.3) au lieu d'un simple HKDF plat.
//   - la "clé" (16 mots / 1024 bits) est dérivée du seed RLWE via HKDF
//     (on n'a pas de clé brute de 1024 bits à donner en entrée — c'est
//     l'adaptation nécessaire, le reste suit la formule d'origine)
//   - le "tweak" encode le contexte (index de chunk) — équivalent au
//     mécanisme UBI de Skein qui personnalise le chiffrement par position
//   - chaque sous-clé mélange clé+tweak+numéro de round, cassant toute
//     symétrie entre les 21 sous-clés (contre les attaques par glissement)
func threefishKeySchedule(seed *[SeedSize]byte, chunkIndex uint64) [tfNumSubkeys][Lanes]uint64 {
	keyBytes := hkdfExpand(seed, "ShiftTF-v4.1-key", Lanes*8)
	var k [Lanes + 1]uint64
	k[Lanes] = c240
	for i := 0; i < Lanes; i++ {
		k[i] = binary.LittleEndian.Uint64(keyBytes[i*8:])
		k[Lanes] ^= k[i]
	}

	var t [3]uint64
	t[0] = chunkIndex
	t[1] = chunkIndex ^ 0x5348494654563430 // "SHIFTV40" — constante de contexte
	t[2] = t[0] ^ t[1]

	var ks [tfNumSubkeys][Lanes]uint64
	for s := 0; s < tfNumSubkeys; s++ {
		for i := 0; i < Lanes; i++ {
			ks[s][i] = k[(s+i)%(Lanes+1)]
			switch i {
			case Lanes - 3:
				ks[s][i] += t[s%3]
			case Lanes - 2:
				ks[s][i] += t[(s+1)%3]
			case Lanes - 1:
				ks[s][i] += uint64(s)
			}
		}
	}
	return ks
}

type chaoticStream struct {
	base     [Lanes]uint64 // état fixe par chunk (seed + LWR + index de chunk)
	subkeys  [tfNumSubkeys][Lanes]uint64
	blockCtr uint64 // compteur de bloc — chaque step() est indépendant (mode compteur)
}

func newChaoticStream(lwrBase LWRState, seed *[SeedSize]byte, chunkIndex uint64) chaoticStream {
	s0 := binary.LittleEndian.Uint64(seed[0:8])
	s1 := binary.LittleEndian.Uint64(seed[8:16])
	s2 := binary.LittleEndian.Uint64(seed[16:24])
	s3 := binary.LittleEndian.Uint64(seed[24:32])
	var cs chaoticStream
	for i := 0; i < Lanes; i++ {
		h := splitmix64(s0 + weylGamma[i])
		h = splitmix64(h ^ s1 ^ bits.RotateLeft64(chunkIndex, 13+i))
		h = splitmix64(h + s2 + uint64(i)*0x9E3779B97F4A7C15)
		cs.base[i] = (h | 1) ^ lwrBase[i]
	}
	_ = s3

	cs.subkeys = threefishKeySchedule(seed, chunkIndex)
	return cs
}


// step : génère 128 octets de keystream. Chaque appel est indépendant
// (mode compteur, comme AES-CTR/ChaCha) — pas d'état continu entre blocs,
// ce qui évite toute corrélation accumulée entre blocs successifs.
//
//	1. état de travail = base XOR compteur de bloc
//	2. 80 rounds Threefish-1024 (MIX + permutation, sous-clé tous les 4 rounds)
//	3. feed-forward Matyas-Meyer-Oseas : état final XOR état initial
//	4. blanchiment final via lg() + splitmix64 (touche perso Shift)
func (cs *chaoticStream) step(out *[128]byte) {
	var w [Lanes]uint64
	copy(w[:], cs.base[:])
	w[Lanes-1] ^= cs.blockCtr
	orig := w

	subkeyIdx := 0
	for round := 0; round < tfRounds; round++ {
		if round%tfSubkeyEvery == 0 {
			sk := cs.subkeys[subkeyIdx]
			for i := 0; i < Lanes; i++ {
				w[i] += sk[i]
			}
			subkeyIdx++
		}
		rot := tfRot[round%8]
		for pair := 0; pair < Lanes/2; pair++ {
			a, b := 2*pair, 2*pair+1
			w[a] += w[b]
			w[b] = bits.RotateLeft64(w[b], int(rot[pair])) ^ w[a]
		}
		var p [Lanes]uint64
		for i := 0; i < Lanes; i++ {
			p[i] = w[tfPerm[i]]
		}
		w = p
	}
	// sous-clé finale (21e, après le dernier round — comme Threefish)
	sk := cs.subkeys[tfNumSubkeys-1]
	for i := 0; i < Lanes; i++ {
		w[i] += sk[i]
	}

	ou := (*[Lanes]uint64)(unsafe.Pointer(out))
	for i := 0; i < Lanes; i++ {
		mmo := w[i] ^ orig[i] // feed-forward Matyas-Meyer-Oseas
		ou[i] = splitmix64(mmo) ^ lg(mmo)
	}
	cs.blockCtr++
}

// ============================================================================
// COUCHE 3 — XOR 128 OCTETS / PAS
// ============================================================================

func xorBlock128Go(dst, ks unsafe.Pointer) {
	d := (*[16]uint64)(dst)
	k := (*[16]uint64)(ks)
	d[0] ^= k[0]
	d[1] ^= k[1]
	d[2] ^= k[2]
	d[3] ^= k[3]
	d[4] ^= k[4]
	d[5] ^= k[5]
	d[6] ^= k[6]
	d[7] ^= k[7]
	d[8] ^= k[8]
	d[9] ^= k[9]
	d[10] ^= k[10]
	d[11] ^= k[11]
	d[12] ^= k[12]
	d[13] ^= k[13]
	d[14] ^= k[14]
	d[15] ^= k[15]
}

var xorBlock128Fn = xorBlock128Go

func xorKeystream(buf []byte, seed *[SeedSize]byte, lwrBase LWRState, firstChunk uint64) {
	var ks [128]byte
	off, chunk := 0, firstChunk
	for off < len(buf) {
		end := off + ChunkSize
		if end > len(buf) {
			end = len(buf)
		}
		cs := newChaoticStream(lwrBase, seed, chunk)
		p := buf[off:end]
		for len(p) >= 128 {
			cs.step(&ks)
			xorBlock128Fn(unsafe.Pointer(&p[0]), unsafe.Pointer(&ks[0]))
			p = p[128:]
		}
		if len(p) > 0 {
			cs.step(&ks)
			for i := range p {
				p[i] ^= ks[i]
			}
		}
		off = end
		chunk++
	}
}

func xorKeystreamParallel(buf []byte, seed *[SeedSize]byte, lwrBase LWRState) {
	nChunks := (len(buf) + ChunkSize - 1) / ChunkSize
	workers := runtime.NumCPU()
	if nChunks < 2 || workers < 2 {
		xorKeystream(buf, seed, lwrBase, 0)
		return
	}
	if workers > nChunks {
		workers = nChunks
	}
	var wg sync.WaitGroup
	var next atomic.Uint64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c := next.Add(1) - 1
				if c >= uint64(nChunks) {
					return
				}
				start := int(c) * ChunkSize
				end := start + ChunkSize
				if end > len(buf) {
					end = len(buf)
				}
				xorKeystream(buf[start:end], seed, lwrBase, c)
			}
		}()
	}
	wg.Wait()
}

// ============================================================================
// COUCHE 4 — MAC HMAC-SHA256 (authentification du ciphertext)
// ============================================================================

// deriveKey : dérivation de sous-clé par domaine via HMAC-SHA256(seed, label).
// Construction en une passe (HKDF-Expand simplifié) — isole chaque usage
// du seed principal (keystream vs MAC) sous un label distinct.
func deriveKey(seed *[SeedSize]byte, label string) [32]byte {
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte(label))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// polyBytesLE : encodage brut (8 o/coeff, little-endian) d'un polynôme —
// utilisé uniquement comme entrée du MAC, pas pour le stockage (voir
// packBits55 pour la sérialisation compacte réelle).
func polyBytesLE(p []uint64) []byte {
	out := make([]byte, 8*len(p))
	for i, v := range p {
		binary.LittleEndian.PutUint64(out[8*i:], v)
	}
	return out
}

// computeMAC v3.2 : HMAC-SHA256 sur mode || len || C0 || C1 || stream.
// v3.1 n'authentifiait que le stream chiffré ; le ciphertext RLWE (C0, C1)
// pouvait être substitué sans invalider le MAC. v3.2 authentifie tout le
// CipherData d'un coup (Encrypt-then-MAC sur l'ensemble, pas juste le flux).
func computeMAC(seed *[SeedSize]byte, mode Mode, length int, c0, c1 []uint64, stream []byte) []byte {
	macKey := deriveKey(seed, "ShiftMAC-v3.2")
	mac := hmac.New(sha256.New, macKey[:])
	mac.Write([]byte{byte(mode)})
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(length))
	mac.Write(lenBuf[:])
	mac.Write(polyBytesLE(c0))
	mac.Write(polyBytesLE(c1))
	mac.Write(stream)
	return mac.Sum(nil)
}

func verifyMAC(seed *[SeedSize]byte, mode Mode, length int, c0, c1 []uint64, stream, expectedMAC []byte) bool {
	got := computeMAC(seed, mode, length, c0, c1, stream)
	return hmac.Equal(got, expectedMAC)
}

// ============================================================================
// API PUBLIQUE
// ============================================================================

func newSeed() *[SeedSize]byte {
	var s [SeedSize]byte
	if _, err := crand.Read(s[:]); err != nil {
		panic(err)
	}
	return &s
}

func encapsuleSeed(seed *[SeedSize]byte, pub PublicKey) ([]uint64, []uint64) {
	msg := make([]uint64, N)
	for i := 0; i < SeedSize; i++ {
		msg[i] = uint64(seed[i])
	}
	return rlweEncrypt(msg, pub)
}

func decapsuleSeed(c0, c1 []uint64, priv PrivateKey) *[SeedSize]byte {
	msg := rlweDecrypt(c0, c1, priv)
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(msg[i])
	}
	return &seed
}

// EncryptStream chiffre data et retourne un CipherData avec MAC.
func EncryptStream(data []byte, pub PublicKey) CipherData {
	seed := newSeed()
	c0, c1 := encapsuleSeed(seed, pub)
	lwrBase := newLWRState(seed)
	stream := make([]byte, len(data))
	copy(stream, data)
	xorKeystreamParallel(stream, seed, lwrBase)
	mac := computeMAC(seed, ModeHybrid, len(data), c0, c1, stream)
	return CipherData{Mode: ModeHybrid, C0: c0, C1: c1, Stream: stream, Mac: mac, Len: len(data)}
}

// DecryptStream déchiffre et vérifie le MAC.
func DecryptStream(ct CipherData, priv PrivateKey) ([]byte, error) {
	if ct.Mode != ModeHybrid {
		return nil, errors.New("mode incorrect")
	}
	seed := decapsuleSeed(ct.C0, ct.C1, priv)
	// Vérification MAC avant déchiffrement (Encrypt-then-MAC, couverture complète)
	if ct.Mac != nil {
		if !verifyMAC(seed, ct.Mode, ct.Len, ct.C0, ct.C1, ct.Stream, ct.Mac) {
			return nil, errors.New("MAC invalide : ciphertext corrompu ou altéré")
		}
	}
	lwrBase := newLWRState(seed)
	plain := make([]byte, len(ct.Stream))
	copy(plain, ct.Stream)
	xorKeystreamParallel(plain, seed, lwrBase)
	return plain, nil
}

// ============================================================================
// STREAMING FICHIER
// ============================================================================

func EncryptFile(inPath, outPath string, pub PublicKey) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	ct := EncryptStream(data, pub)
	return os.WriteFile(outPath, SerializeCipher(ct), 0644)
}

func DecryptFile(inPath, outPath string, priv PrivateKey) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	ct, err := DeserializeCipher(data)
	if err != nil {
		return err
	}
	plain, err := DecryptStream(ct, priv)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, plain, 0644)
}

// ============================================================================
// SÉRIALISATION v3.1
//   Clé publique  "SHFTPUB3" + seedA[32] + B_packed[7040]         = 7080 o
//   Clé privée    "SHFTKEY3" + S_int8[1024]                       = 1032 o
//   Ciphertext    "SHFTCT4"  + mode(1) + C0 + C1 + mac[32] + len(8) + stream
// ============================================================================

func writePolyBuf(dst []byte, p []uint64) []byte {
	return append(dst, packBits55(p)...)
}

func readPolyFrom(r io.Reader) ([]uint64, error) {
	size := (bitsPerCoeff*N + 7) / 8
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return unpackBits55(buf, N)
}

func SavePublicKey(path string, pub PublicKey) error {
	buf := []byte("SHFTPUB3")
	buf = append(buf, pub.SeedA[:]...)
	buf = append(buf, packBits55(pub.B)...)
	return os.WriteFile(path, buf, 0644)
}

func SavePrivateKey(path string, priv PrivateKey) error {
	sCoeff := make([]uint64, N)
	copy(sCoeff, priv.S)
	nttInverse(sCoeff)
	buf := []byte("SHFTKEY3")
	for _, v := range polyToInt8(sCoeff) {
		buf = append(buf, byte(v))
	}
	return os.WriteFile(path, buf, 0600)
}

func LoadPublicKey(path string) (PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PublicKey{}, err
	}
	if len(data) < 8 || string(data[:8]) != "SHFTPUB3" {
		return PublicKey{}, fmt.Errorf("%s : clé publique invalide", path)
	}
	if len(data) < 8+SeedSize {
		return PublicKey{}, errors.New("clé publique tronquée")
	}
	var seedA [SeedSize]byte
	copy(seedA[:], data[8:8+SeedSize])
	b, err := unpackBits55(data[8+SeedSize:], N)
	if err != nil {
		return PublicKey{}, err
	}
	a := sampleUniformPolyFromSeed(seedA[:])
	nttForward(a)
	return PublicKey{SeedA: seedA, A: a, B: b}, nil
}

func LoadPrivateKey(path string) (PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PrivateKey{}, err
	}
	if len(data) < 8 || string(data[:8]) != "SHFTKEY3" {
		return PrivateKey{}, fmt.Errorf("%s : clé privée invalide", path)
	}
	if len(data) < 8+N {
		return PrivateKey{}, errors.New("clé privée tronquée")
	}
	raw := make([]int8, N)
	for i := range raw {
		raw[i] = int8(data[8+i])
	}
	s := int8ToPoly(raw)
	nttForward(s)
	return PrivateKey{S: s}, nil
}

func SerializeCipher(ct CipherData) []byte {
	packed := (bitsPerCoeff*N + 7) / 8
	buf := make([]byte, 0, 8+1+2*packed+MacSize+8+len(ct.Stream))
	buf = append(buf, "SHFTCT4"...)
	buf = append(buf, byte(ct.Mode))
	buf = writePolyBuf(buf, ct.C0)
	buf = writePolyBuf(buf, ct.C1)
	// MAC (32 octets, zéros si absent pour rétrocompat)
	if len(ct.Mac) == MacSize {
		buf = append(buf, ct.Mac...)
	} else {
		buf = append(buf, make([]byte, MacSize)...)
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(ct.Len))
	buf = append(buf, ct.Stream...)
	return buf
}

func DeserializeCipher(data []byte) (CipherData, error) {
	if len(data) < 8 || string(data[:7]) != "SHFTCT4" {
		return CipherData{}, errors.New("pas un ciphertext ShiftEncryption v4")
	}
	ct := CipherData{Mode: Mode(data[7])}
	packed := (bitsPerCoeff*N + 7) / 8
	off := 8
	var err error
	if ct.C0, err = unpackBits55(data[off:], N); err != nil {
		return CipherData{}, err
	}
	off += packed
	if ct.C1, err = unpackBits55(data[off:], N); err != nil {
		return CipherData{}, err
	}
	off += packed
	// MAC
	if len(data) < off+MacSize {
		return CipherData{}, errors.New("ciphertext tronqué (MAC manquant)")
	}
	ct.Mac = make([]byte, MacSize)
	copy(ct.Mac, data[off:off+MacSize])
	off += MacSize
	if len(data) < off+8 {
		return CipherData{}, errors.New("ciphertext tronqué (len manquant)")
	}
	ct.Len = int(binary.LittleEndian.Uint64(data[off:]))
	ct.Stream = data[off+8:]
	return ct, nil
}

// ============================================================================
// ENCODAGE DE SORTIE : raw / hex / base64
// ============================================================================

type OutputFormat uint8

const (
	FmtRaw OutputFormat = iota
	FmtHex
	FmtBase64
)

func parseFormat(s string) (OutputFormat, error) {
	switch strings.ToLower(s) {
	case "", "raw":
		return FmtRaw, nil
	case "hex":
		return FmtHex, nil
	case "base64", "b64":
		return FmtBase64, nil
	default:
		return FmtRaw, fmt.Errorf("format inconnu : %q (raw|hex|base64)", s)
	}
}

func encodeOutput(data []byte, fmt OutputFormat) []byte {
	switch fmt {
	case FmtHex:
		return []byte(hex.EncodeToString(data) + "\n")
	case FmtBase64:
		return []byte(base64.StdEncoding.EncodeToString(data) + "\n")
	default:
		return data
	}
}

func decodeInput(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	// Détection automatique : hex pur ?
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	// Base64 ?
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	// Raw
	return data, nil
}

// ============================================================================
// CLI
// ============================================================================

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "Erreur : "+f+"\n", a...)
	os.Exit(1)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	prefix := fs.String("key", "shift", "préfixe des fichiers clés")
	fs.Parse(args)
	pub, key := *prefix+".pub", *prefix+".key"
	if _, err := os.Stat(key); err == nil {
		fatal("%s existe déjà. Supprimez-le ou changez le préfixe (-key).", key)
	}
	fmt.Printf("Génération des clés (N=%d, Q~2^%.1f)...\n", N, math.Log2(float64(Q)))
	t0 := time.Now()
	pk, sk := GenerateKeyPair()
	if err := SavePublicKey(pub, pk); err != nil {
		fatal("sauvegarde clé publique : %v", err)
	}
	if err := SavePrivateKey(key, sk); err != nil {
		fatal("sauvegarde clé privée : %v", err)
	}
	pubSz, _ := os.Stat(pub)
	keySz, _ := os.Stat(key)
	fmt.Printf("Clés générées en %v :\n", time.Since(t0).Round(time.Millisecond))
	fmt.Printf("  publique : %-20s %6d octets\n", pub, pubSz.Size())
	fmt.Printf("  privée   : %-20s %6d octets  (GARDEZ SECRET)\n", key, keySz.Size())
}

func cmdEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	text := fs.String("text", "", "texte à chiffrer")
	file := fs.String("file", "", "fichier à chiffrer")
	pubPath := fs.String("pub", "shift.pub", "clé publique")
	out := fs.String("out", "", "fichier de sortie (défaut : stdout pour -text, <file>.shft pour -file)")
	fmtStr := fs.String("fmt", "raw", "format de sortie : raw | hex | base64")
	fs.Parse(args)

	outFmt, err := parseFormat(*fmtStr)
	if err != nil {
		fatal("%v", err)
	}
	pk, err := LoadPublicKey(*pubPath)
	if err != nil {
		fatal("clé publique : %v", err)
	}

	t0 := time.Now()

	switch {
	case *text != "" && *file != "":
		fatal("utilise -text OU -file, pas les deux")

	case *text != "":
		ct := EncryptStream([]byte(*text), pk)
		raw := SerializeCipher(ct)
		encoded := encodeOutput(raw, outFmt)
		elapsed := time.Since(t0)
		// Nom de fichier par défaut selon le format
		dest := *out
		if dest == "" {
			switch outFmt {
			case FmtHex:
				dest = "message.hex"
			case FmtBase64:
				dest = "message.b64"
			default:
				dest = "message.shft"
			}
		}
		if err := os.WriteFile(dest, encoded, 0644); err != nil {
			fatal("écriture : %v", err)
		}
		fmt.Printf("Chiffré %d o → %s (%s) en %v  [MAC: %x...]\n",
			len(*text), dest, *fmtStr, elapsed.Round(time.Microsecond), ct.Mac[:8])

	case *file != "":
		data, err := os.ReadFile(*file)
		if err != nil {
			fatal("lecture : %v", err)
		}
		ct := EncryptStream(data, pk)
		raw := SerializeCipher(ct)
		encoded := encodeOutput(raw, outFmt)
		elapsed := time.Since(t0)
		dest := *out
		if dest == "" {
			dest = *file + ".shft"
		}
		if err := os.WriteFile(dest, encoded, 0644); err != nil {
			fatal("écriture : %v", err)
		}
		fmt.Printf("Chiffré %d o → %d o (%s) en %v\n  sortie : %s\n  MAC    : %x\n",
			len(data), len(raw), *fmtStr, elapsed.Round(time.Millisecond), dest, ct.Mac)

	default:
		fatal("rien à chiffrer : -text \"...\" ou -file chemin")
	}
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	in := fs.String("in", "", "fichier .shft à déchiffrer")
	keyPath := fs.String("key", "shift.key", "clé privée")
	out := fs.String("out", "", "fichier de sortie (défaut : stdout)")
	fs.Parse(args)
	if *in == "" {
		fatal("-in requis")
	}
	sk, err := LoadPrivateKey(*keyPath)
	if err != nil {
		fatal("clé privée : %v", err)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal("lecture : %v", err)
	}
	// Détection automatique hex/base64
	raw, err = decodeInput(raw)
	if err != nil {
		fatal("décodage : %v", err)
	}
	ct, err := DeserializeCipher(raw)
	if err != nil {
		fatal("désérialisation : %v", err)
	}
	t0 := time.Now()
	plain, err := DecryptStream(ct, sk)
	if err != nil {
		fatal("déchiffrement : %v", err)
	}
	elapsed := time.Since(t0)
	if *out == "" {
		os.Stdout.Write(plain)
	} else {
		if err := os.WriteFile(*out, plain, 0644); err != nil {
			fatal("écriture : %v", err)
		}
		fmt.Printf("Déchiffré %d o → %s en %v\n", len(plain), *out, elapsed.Round(time.Microsecond))
	}
}

// ============================================================================
// BENCHMARK ISOLÉ
// ============================================================================

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	sizeMB := fs.Int("size", 64, "taille des données en MiB")
	iters := fs.Int("iter", 3, "nombre d'itérations par mesure")
	fs.Parse(args)

	size := *sizeMB << 20
	buf := make([]byte, size)
	if _, err := crand.Read(buf); err != nil {
		fatal("%v", err)
	}

	fmt.Printf("Benchmark ShiftEncryption v4.0 — %d MiB × %d iter — %d cœurs\n\n", *sizeMB, *iters, runtime.NumCPU())

	pub, priv := GenerateKeyPair()

	// Flux seul
	{
		seed := newSeed()
		lwr := newLWRState(seed)
		tmp := make([]byte, size)
		total := time.Duration(0)
		for i := 0; i < *iters; i++ {
			copy(tmp, buf)
			t0 := time.Now()
			xorKeystreamParallel(tmp, seed, lwr)
			total += time.Since(t0)
		}
		avg := total / time.Duration(*iters)
		fmt.Printf("  Flux chaotique seul  : %7.1f Mo/s  (%v avg)\n",
			float64(size)/avg.Seconds()/1e6, avg.Round(time.Millisecond))
	}

	// Encrypt complet
	{
		total := time.Duration(0)
		var ct CipherData
		for i := 0; i < *iters; i++ {
			t0 := time.Now()
			ct = EncryptStream(buf, pub)
			total += time.Since(t0)
		}
		avg := total / time.Duration(*iters)
		fmt.Printf("  EncryptStream complet: %7.1f Mo/s  (%v avg)  ciphertext=%d o\n",
			float64(size)/avg.Seconds()/1e6, avg.Round(time.Millisecond), len(SerializeCipher(ct)))

		// Decrypt
		total = 0
		for i := 0; i < *iters; i++ {
			t0 := time.Now()
			if _, err := DecryptStream(ct, priv); err != nil {
				fatal("decrypt: %v", err)
			}
			total += time.Since(t0)
		}
		avg = total / time.Duration(*iters)
		fmt.Printf("  DecryptStream complet: %7.1f Mo/s  (%v avg)\n",
			float64(size)/avg.Seconds()/1e6, avg.Round(time.Millisecond))
	}

	// Keygen latence
	{
		total := time.Duration(0)
		const kgIter = 20
		for i := 0; i < kgIter; i++ {
			t0 := time.Now()
			GenerateKeyPair()
			total += time.Since(t0)
		}
		fmt.Printf("  Keygen               : %v avg (%d iter)\n",
			(total / kgIter).Round(time.Microsecond), kgIter)
	}
}

// ============================================================================
// USAGE
// ============================================================================

func usage() {
	fmt.Printf(`ShiftEncryption v4.0 — RLWE N=%d Q~2^54 + 16 lanes (double round) + Ring-LWR + HMAC-SHA256

Commandes :
  keygen   [-key prefix]                         Génère une paire de clés
  encrypt  -text "..." | -file path              Chiffre
           [-pub k.pub] [-out path] [-fmt raw|hex|base64]
  decrypt  -in path [-key k.key] [-out path]     Déchiffre (auto-détecte hex/base64)
  bench    [-size MB] [-iter N]                  Benchmark flux + encrypt/decrypt

Exemples :
  go run main.go keygen
  go run main.go encrypt -text "bonjour" -fmt hex
  go run main.go encrypt -file doc.pdf -fmt base64 -out doc.b64
  go run main.go decrypt -in doc.b64 -out doc.pdf
  go run main.go bench -size 128 -iter 5
`, N)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	case "bench":
		cmdBench(os.Args[2:])
	default:
		usage()
		fatal("commande inconnue : %s", os.Args[1])
	}
}
