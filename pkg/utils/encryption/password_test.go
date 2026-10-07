package encryption

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// madeWith is a hash of password with parameters of the caller's choosing, the way
// an older or a later release would have stored it.
func madeWith(password string, memory, time uint32, threads uint8) string {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, time, memory, threads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads, encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

func TestAHashVerifiesItsPasswordAndNoOther(t *testing.T) {
	stored := HashPassword("correct horse")

	if !strings.HasPrefix(stored, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("stored %q is not an argon2id PHC string with the expected parameters", stored)
	}
	if !VerifyPassword(stored, "correct horse") {
		t.Fatal("the password does not verify against its own hash")
	}
	for _, wrong := range []string{"", "correct horse ", "Correct horse", "correct hors"} {
		if VerifyPassword(stored, wrong) {
			t.Fatalf("%q verifies against the hash of another password", wrong)
		}
	}
}

func TestTwoHashesOfOnePasswordDiffer(t *testing.T) {
	if HashPassword("same") == HashPassword("same") {
		t.Fatal("the same salt was used twice: two users with one password would show it")
	}
}

func TestAnythingLongAndAnythingNotASCIIIsHashedWhole(t *testing.T) {
	// bcrypt stops at 72 bytes; two passwords that differ only after them must not collide.
	long := strings.Repeat("a", 100)
	stored := HashPassword(long + "x")
	if VerifyPassword(stored, long+"y") {
		t.Fatal("a password that differs after the 72nd byte verifies")
	}
	if !VerifyPassword(HashPassword("pässwörd 🔑"), "pässwörd 🔑") {
		t.Fatal("a password with accents and an emoji does not verify")
	}
}

func TestTheLegacyMD5StillVerifiesAndIsReplaced(t *testing.T) {
	legacy := GetMD5ByStr("password") // 5f4dcc3b5aa765d61d8327deb882cf99

	if !VerifyPassword(legacy, "password") {
		t.Fatal("an unsalted MD5, as older releases and IceWhale's store it, no longer verifies: the upgrade would lock everyone out")
	}
	if VerifyPassword(legacy, "Password") {
		t.Fatal("the legacy path accepts another password")
	}
	if !NeedsRehash(legacy) {
		t.Fatal("a legacy MD5 is not flagged for replacement")
	}
	if NeedsRehash(HashPassword("password")) {
		t.Fatal("a hash made with today's parameters is flagged for replacement")
	}
}

func TestAHashMadeWithOtherParametersVerifiesAndIsFlagged(t *testing.T) {
	older := madeWith("secret", 8*1024, 1, 1)

	if !VerifyPassword(older, "secret") || VerifyPassword(older, "other") {
		t.Fatal("the parameters are not read back from the stored hash")
	}
	if !NeedsRehash(older) {
		t.Fatal("a hash made with weaker parameters is not flagged")
	}
	if !NeedsRehash(madeWith("secret", argonMemory, argonTime, 2)) {
		t.Fatal("a hash made with another lane count is not flagged")
	}
}

func TestWhatIsNotAHashNeverVerifies(t *testing.T) {
	good := HashPassword("secret")
	parts := strings.Split(good, "$") // "", argon2id, v=19, m=..., salt, key

	for name, stored := range map[string]string{
		"empty":                   "",
		"not a hash":              "secret",
		"the password itself":     "5f4dcc3b5aa765d61d8327deb882cf9", // 31 hex digits
		"only the prefix":         "$argon2id$",
		"missing the key":         strings.Join(parts[:5], "$"),
		"another algorithm":       strings.Replace(good, "argon2id", "argon2i", 1),
		"another version":         strings.Replace(good, "v=19", "v=16", 1),
		"trailing text":           good + "$extra",
		"parameters with a tail":  strings.Replace(good, "p=1", "p=1x", 1),
		"no lanes":                strings.Replace(good, "p=1", "p=0", 1),
		"no passes":               strings.Replace(good, "t=2", "t=0", 1),
		"too much memory":         strings.Replace(good, "m=19456", "m=4000000", 1),
		"too many passes":         strings.Replace(good, "t=2", "t=99", 1),
		"memory below 8 per lane": strings.Replace(good, "m=19456", "m=4", 1),
		"salt not base64":         parts[0] + "$" + parts[1] + "$" + parts[2] + "$" + parts[3] + "$!!!$" + parts[5],
		"salt too short":          parts[0] + "$" + parts[1] + "$" + parts[2] + "$" + parts[3] + "$AAAA$" + parts[5],
		"key too short":           parts[0] + "$" + parts[1] + "$" + parts[2] + "$" + parts[3] + "$" + parts[4] + "$AAAA",
	} {
		// the parser is what must refuse them: a value it let through, with other
		// parameters or a shorter salt or key, would give another key and fail
		// to verify for that reason alone, and the row would prove nothing
		if _, ok := parseArgon(stored); ok {
			t.Errorf("%s: %q is accepted as an argon2id hash", name, stored)

			continue
		}
		if VerifyPassword(stored, "secret") {
			t.Errorf("%s: %q verifies", name, stored)
		}
	}
}

func TestHashesComputedAtTheSameTimeAllComeOutRight(t *testing.T) {
	stored := HashPassword("shared")
	done := make(chan bool)
	for i := 0; i < 24; i++ {
		go func() { done <- VerifyPassword(stored, "shared") && !VerifyPassword(stored, "other") }()
	}
	for i := 0; i < 24; i++ {
		if !<-done {
			t.Fatal("a verification run alongside others gave the wrong answer")
		}
	}
}
