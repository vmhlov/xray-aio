package amneziawg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// X25519Keys is one Curve25519 keypair encoded the way the
// WireGuard / AmneziaWG userspace tools accept: standard base64
// (with '=' padding), 32 raw bytes per half. This matches the
// output of `wg genkey | tee /dev/stderr | wg pubkey` and the input
// `awg setconf` expects in the [Interface]/[Peer] PrivateKey/
// PublicKey/PresharedKey lines.
type X25519Keys struct {
	Private string
	Public  string
}

// GenerateX25519 returns a fresh keypair using crypto/rand.
func GenerateX25519() (X25519Keys, error) {
	return generateX25519(rand.Reader)
}

// GenerateX25519FromReader is the same as [GenerateX25519] but takes
// an injectable randomness source. The orchestrator uses it to drive
// deterministic tests; production callers should prefer
// [GenerateX25519].
func GenerateX25519FromReader(r io.Reader) (X25519Keys, error) {
	return generateX25519(r)
}

func generateX25519(r io.Reader) (X25519Keys, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(r)
	if err != nil {
		return X25519Keys{}, fmt.Errorf("x25519: %w", err)
	}
	enc := base64.StdEncoding
	return X25519Keys{
		Private: enc.EncodeToString(priv.Bytes()),
		Public:  enc.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// GeneratePresharedKey returns a fresh 32-byte PSK encoded as standard
// base64 — the format `awg setconf` accepts in `PresharedKey`.
// PSK is optional (AmneziaWG falls back to "no preshared key" when
// the line is absent), but adding one strengthens forward secrecy
// against future quantum-capable adversaries who might compromise
// the long-term Curve25519 keys later.
func GeneratePresharedKey() (string, error) {
	return generatePresharedKey(rand.Reader)
}

// GeneratePresharedKeyFromReader is the test-friendly form.
func GeneratePresharedKeyFromReader(r io.Reader) (string, error) {
	return generatePresharedKey(r)
}

func generatePresharedKey(r io.Reader) (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// Obfuscation is the set of AmneziaWG transport-obfuscation
// parameters that have to match between server and client. Picked
// in narrow ranges that empirically pass DPI without crippling
// throughput; see comments below.
type Obfuscation struct {
	Jc         int    // junk packet count
	Jmin       int    // junk packet min size in bytes
	Jmax       int    // junk packet max size in bytes
	S1         int    // init message extra padding
	S2         int    // response message extra padding
	H1, H2, H3 uint32 // magic header replacements (init, response, cookie)
	H4         uint32 // magic header replacement (transport)
}

// Validate returns nil when the obfuscation is internally consistent
// and within the ranges the AmneziaWG kernel/userspace accepts.
//
// Constraints enforced:
//
//   - Jc in [1,128]; we recommend [4,10] but accept the wider native range
//     so an operator who pins a specific value in Options.Extra isn't
//     rejected.
//   - 0 <= Jmin <= Jmax <= 1280 — Jmin == Jmax is allowed (fixed-size junk).
//   - S1 in [15,150], S2 in [15,150]; S1+56 != S2+88 so the obfuscated
//     init/response messages can't collide with each other on the wire.
//   - H1..H4 must be pairwise distinct and none may be in {1,2,3,4}
//     (those are WireGuard's fixed message-type numbers; reusing
//     them would degrade obfuscation to wire-compatible WG).
func (o Obfuscation) Validate() error {
	if o.Jc < 1 || o.Jc > 128 {
		return fmt.Errorf("amneziawg: Jc %d out of range [1,128]", o.Jc)
	}
	if o.Jmin < 0 || o.Jmin > 1280 {
		return fmt.Errorf("amneziawg: Jmin %d out of range [0,1280]", o.Jmin)
	}
	if o.Jmax < o.Jmin || o.Jmax > 1280 {
		return fmt.Errorf("amneziawg: Jmax %d out of range [%d,1280]", o.Jmax, o.Jmin)
	}
	if o.S1 < 15 || o.S1 > 150 {
		return fmt.Errorf("amneziawg: S1 %d out of range [15,150]", o.S1)
	}
	if o.S2 < 15 || o.S2 > 150 {
		return fmt.Errorf("amneziawg: S2 %d out of range [15,150]", o.S2)
	}
	// AmneziaWG init message size is `<base init> + S1 + 56`; response
	// is `<base resp> + S2 + 88`. If those sums collide an on-path
	// observer could conflate the two message types, which defeats
	// the whole point of S1/S2. The +56/+88 deltas are constants in
	// the AWG protocol, see amnezia-vpn/amneziawg-go for the
	// derivation.
	if o.S1+56 == o.S2+88 {
		return fmt.Errorf("amneziawg: S1+56 (%d) must not equal S2+88 (%d)", o.S1+56, o.S2+88)
	}
	hs := []uint32{o.H1, o.H2, o.H3, o.H4}
	for i, h := range hs {
		if h == 1 || h == 2 || h == 3 || h == 4 {
			return fmt.Errorf("amneziawg: H%d (%d) collides with WireGuard message_type", i+1, h)
		}
		for j := i + 1; j < len(hs); j++ {
			if hs[j] == h {
				return fmt.Errorf("amneziawg: H%d and H%d both equal %d (must be pairwise distinct)", i+1, j+1, h)
			}
		}
	}
	return nil
}

// GenerateObfuscation returns a fresh Obfuscation drawing from
// crypto/rand. Values are sampled from the recommended-default
// sub-ranges (tighter than what Validate accepts) so a bare-bones
// install doesn't wind up with pathological-but-legal numbers like
// Jc=128 (would prepend 128 junk packets per handshake).
//
// Recommended ranges:
//   - Jc: [4, 10]
//   - Jmin: [50, 100]
//   - Jmax: [Jmin+50, 1000]
//   - S1, S2: [15, 150], avoiding S1+56==S2+88 collision
//   - H1..H4: uniform uint32, retried until pairwise distinct and none in {1,2,3,4}
func GenerateObfuscation() (Obfuscation, error) {
	return generateObfuscation(rand.Reader)
}

// GenerateObfuscationFromReader is the test-friendly form.
func GenerateObfuscationFromReader(r io.Reader) (Obfuscation, error) {
	return generateObfuscation(r)
}

func generateObfuscation(r io.Reader) (Obfuscation, error) {
	jc, err := intRange(r, 4, 10)
	if err != nil {
		return Obfuscation{}, err
	}
	jmin, err := intRange(r, 50, 100)
	if err != nil {
		return Obfuscation{}, err
	}
	jmax, err := intRange(r, jmin+50, 1000)
	if err != nil {
		return Obfuscation{}, err
	}
	s1, err := intRange(r, 15, 150)
	if err != nil {
		return Obfuscation{}, err
	}
	// Resample S2 if it collides with S1. The probability of
	// collision is 1 in 136 (one specific value: s1 + 56 - 88 =
	// s1 - 32), so the loop terminates fast in practice; we cap
	// at 256 attempts to keep the test-time deterministic-reader
	// case from spinning forever on an adversarial stream.
	var s2 int
	for attempt := 0; attempt < 256; attempt++ {
		s2, err = intRange(r, 15, 150)
		if err != nil {
			return Obfuscation{}, err
		}
		if s1+56 != s2+88 {
			break
		}
		if attempt == 255 {
			return Obfuscation{}, errors.New("amneziawg: failed to sample non-colliding S2 in 256 attempts")
		}
	}
	hs, err := generateMagicHeaders(r)
	if err != nil {
		return Obfuscation{}, err
	}
	return Obfuscation{
		Jc:   jc,
		Jmin: jmin,
		Jmax: jmax,
		S1:   s1,
		S2:   s2,
		H1:   hs[0],
		H2:   hs[1],
		H3:   hs[2],
		H4:   hs[3],
	}, nil
}

// generateMagicHeaders draws four pairwise-distinct uint32 headers,
// none of them in {1,2,3,4}.
func generateMagicHeaders(r io.Reader) ([4]uint32, error) {
	var out [4]uint32
	seen := make(map[uint32]struct{}, 4)
	filled := 0
	// 4 slots × ~4×10⁻⁹ collision probability per draw → ~256
	// attempts is generous. Ceiling protects deterministic
	// low-entropy readers in tests.
	for attempt := 0; attempt < 4096 && filled < 4; attempt++ {
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return [4]uint32{}, fmt.Errorf("rand: %w", err)
		}
		v := binary.LittleEndian.Uint32(b[:])
		if v >= 1 && v <= 4 {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out[filled] = v
		filled++
	}
	if filled < 4 {
		return [4]uint32{}, errors.New("amneziawg: failed to sample 4 pairwise-distinct H1..H4 headers")
	}
	return out, nil
}

// intRange returns a uniformly-random integer in [lo, hi] inclusive.
// Uses 4 random bytes per draw and a modulo bias rejection that
// keeps the result inside the requested band exactly (no off-by-one
// at the upper bound). lo must be <= hi.
func intRange(r io.Reader, lo, hi int) (int, error) {
	if lo > hi {
		return 0, fmt.Errorf("amneziawg: intRange lo %d > hi %d", lo, hi)
	}
	if lo == hi {
		return lo, nil
	}
	span := uint32(hi - lo + 1)
	// Reject samples that would skew the modulo: keep only the
	// largest multiple of span <= 2^32. Worst-case retry rate for
	// span ≤ 2¹² is < 1.0001x, so the loop almost always exits
	// on first iteration.
	limit := (^uint32(0) / span) * span
	for {
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, fmt.Errorf("rand: %w", err)
		}
		v := binary.LittleEndian.Uint32(b[:])
		if v < limit {
			return lo + int(v%span), nil
		}
	}
}
