package encryption

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// A password is stored as an argon2id hash in the PHC string format,
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// with the parameters OWASP gives as the minimum: 19 MiB, two passes, one lane.
// They are read back from the stored string, so they can be raised later and a
// hash made with the old ones still verifies; NeedsRehash says when one should be
// made again.
//
// What this service stored until now, and what IceWhale's still does, is an
// unsalted MD5 in hex, which a stolen user.db gives back to a wordlist in
// minutes. Such a value still verifies, so nobody is locked out by the upgrade,
// and the first successful sign-in of its owner replaces it.
const (
	argonMemory  uint32 = 19 * 1024 // KiB
	argonTime    uint32 = 2
	argonThreads uint8  = 1
	argonKeyLen         = 32
	argonSaltLen        = 16

	// What a stored hash may ask of this box. The database is the box's own, so
	// this guards a damaged row, not an attacker, from asking for gigabytes.
	argonMaxMemory  = 256 * 1024
	argonMaxTime    = 10
	argonMaxThreads = 16
)

var encoding = base64.RawStdEncoding

// argonSlots bounds how many hashes are computed at once. Each takes 19 MiB, and
// not every endpoint that checks a password is rate limited, changing one's own
// for one: a hundred requests in parallel would be two gigabytes on a box that
// may have one. The others wait their turn, a few tens of milliseconds each.
var argonSlots = make(chan struct{}, 2)

func idKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()

	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

type argonHash struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// HashPassword is the argon2id hash to store for password.
func HashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt) // never fails since Go 1.24: it ends the program rather than return weak bytes
	key := idKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

// VerifyPassword reports whether candidate is the password stored as stored, an
// argon2id hash or the legacy MD5 hex, in constant time.
func VerifyPassword(stored, candidate string) bool {
	if h, ok := parseArgon(stored); ok {
		key := idKey([]byte(candidate), h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
		return subtle.ConstantTimeCompare(key, h.key) == 1
	}

	return subtle.ConstantTimeCompare([]byte(stored), []byte(GetMD5ByStr(candidate))) == 1
}

// NeedsRehash is whether stored, a value VerifyPassword just accepted, should be
// replaced by a fresh hash: it is the legacy MD5, or an argon2id hash made with
// other parameters than today's.
func NeedsRehash(stored string) bool {
	h, ok := parseArgon(stored)

	return !ok || h.memory != argonMemory || h.time != argonTime || h.threads != argonThreads || len(h.key) != argonKeyLen
}

// parseArgon reads a PHC string. It is strict: the parameters are printed back
// and compared, so trailing text is not ignored, and a hash that asks for more
// than this box would give is refused rather than attempted.
func parseArgon(stored string) (argonHash, bool) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argonHash{}, false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version || parts[2] != fmt.Sprintf("v=%d", version) {
		return argonHash{}, false
	}

	var h argonHash
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.time, &h.threads); err != nil || n != 3 ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", h.memory, h.time, h.threads) {
		return argonHash{}, false
	}
	if h.threads == 0 || h.threads > argonMaxThreads || h.time == 0 || h.time > argonMaxTime ||
		h.memory < 8*uint32(h.threads) || h.memory > argonMaxMemory {
		return argonHash{}, false
	}

	var err error
	if h.salt, err = encoding.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return argonHash{}, false
	}
	if h.key, err = encoding.DecodeString(parts[5]); err != nil || len(h.key) < 16 || len(h.key) > 64 {
		return argonHash{}, false
	}

	return h, true
}
